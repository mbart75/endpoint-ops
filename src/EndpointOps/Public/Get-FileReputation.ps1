Set-StrictMode -Version 3.0

function Get-FileReputation {
    <#
    .SYNOPSIS
        Returns a file hash reputation result with per-source evidence.
    .DESCRIPTION
        Always queries VirusTotal, then queries MalwareBazaar when VirusTotal flags the file, does
        not know the hash, or is unavailable. Additional sources can only make the aggregate verdict
        Malicious; missing evidence and provider failures never promote the existing verdict.
    .PARAMETER Hash
        File hash supplied by EPM.
    .PARAMETER MinIntervalMs
        Minimum interval forwarded to VirusTotal.
    .PARAMETER SkipCascade
        Queries VirusTotal only and skips all additional sources.
    .PARAMETER UseCache
        Enables the persistent cache, which is disabled by default. When enabled, it writes file
        hashes observed in the fleet and their verdicts to disk. This constitutes a partial software
        inventory and must therefore remain an explicit operator choice.

        Cache lifetimes are asymmetric. Clean and Unknown verdicts expire after seven days because a
        file not detected today may be detected tomorrow. Malicious verdicts remain valid for 90
        days because malicious evidence should not disappear quickly.
    .PARAMETER CachePath
        Persistent cache path. The default location is outside the repository in the user profile.
    .PARAMETER ReferenceDate
        UTC reference time used to evaluate cache entry freshness.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string]$Hash,
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 15000,
        [switch]$SkipCascade,
        [switch]$UseCache,
        [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json'),
        [datetime]$ReferenceDate = ([datetime]::UtcNow)
    )

    # Do not restrict cascading to VirusTotal detections. An unknown hash is exactly where
    # MalwareBazaar can add value: abuse.ch may already hold a recent sample that has not yet been
    # submitted to VirusTotal.
    begin {
        $cascadeVerdicts = @('Malicious', 'Unknown', 'Unavailable')
    }

    process {
        if ($UseCache) {
            $cachedEntries = @(Get-ReputationCacheEntry -Hash $Hash -CachePath $CachePath -ReferenceDate $ReferenceDate)
            $cachedEntriesToServe = [System.Collections.Generic.List[object]]::new()
            $cachedVtEntries = @($cachedEntries | Where-Object Source -eq 'VirusTotal')
            if ($cachedVtEntries.Count -eq 1) {
                $cachedVtEntry = $cachedVtEntries[0]
                if ($SkipCascade -or $cachedVtEntry.Verdict -eq 'Clean') {
                    $cachedEntriesToServe.Add($cachedVtEntry)
                }
                elseif ($cachedVtEntry.Verdict -in $cascadeVerdicts) {
                    $cachedMbEntries = @($cachedEntries | Where-Object Source -eq 'MalwareBazaar')
                    if ($cachedMbEntries.Count -eq 1) {
                        $cachedMbEntry = $cachedMbEntries[0]
                        $requiresThirdStage = $cachedVtEntry.Verdict -eq 'Malicious' -or
                            $cachedMbEntry.Verdict -eq 'Malicious'
                        if (-not $requiresThirdStage -and $cachedEntries.Count -eq 2) {
                            $cachedEntriesToServe.Add($cachedVtEntry)
                            $cachedEntriesToServe.Add($cachedMbEntry)
                        }
                        elseif ($requiresThirdStage -and $cachedEntries.Count -eq 4) {
                            $cachedHaEntries = @($cachedEntries | Where-Object Source -eq 'HybridAnalysis')
                            $cachedTfEntries = @($cachedEntries | Where-Object Source -eq 'ThreatFox')
                            if ($cachedHaEntries.Count -eq 1 -and $cachedTfEntries.Count -eq 1) {
                                $cachedEntriesToServe.Add($cachedVtEntry)
                                $cachedEntriesToServe.Add($cachedMbEntry)
                                $cachedEntriesToServe.Add($cachedHaEntries[0])
                                $cachedEntriesToServe.Add($cachedTfEntries[0])
                            }
                        }
                    }
                }
            }

            if ($cachedEntriesToServe.Count -gt 0) {
                $cachedSources = [System.Collections.Generic.List[object]]::new()
                foreach ($sourceName in @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox')) {
                    foreach ($entry in @($cachedEntriesToServe | Where-Object Source -eq $sourceName)) {
                        $cachedSources.Add([pscustomobject]@{
                                PSTypeName = 'EndpointOps.Reputation.Verdict'
                                Source     = $entry.Source
                                Verdict    = $entry.Verdict
                                Detail     = "$($entry.Source) result was served from the persistent cache."
                                HashUsed   = $entry.Hash
                                HashSource = 'EPM'
                                QueryDate  = $entry.QueryDate
                            })
                    }
                }

                $cachedVerdict = if (@($cachedSources | Where-Object Verdict -eq 'Malicious').Count -gt 0) {
                    'Malicious'
                }
                elseif (@($cachedSources | Where-Object Source -eq 'VirusTotal').Count -gt 0) {
                    @($cachedSources | Where-Object Source -eq 'VirusTotal')[0].Verdict
                }
                else {
                    $cachedSources[0].Verdict
                }

                return [pscustomobject]@{
                    PSTypeName = 'EndpointOps.Reputation.FileResult'
                    Hash       = $Hash
                    Verdict    = $cachedVerdict
                    Sources    = @($cachedSources)
                }
            }
        }

        $vtReport = Get-VtFileReport -Hash $Hash -MinIntervalMs $MinIntervalMs
        $vtDetail = switch ($vtReport.Verdict) {
            'Malicious' {
                "VirusTotal reports $($vtReport.MaliciousCount) malicious engine result(s) out of $($vtReport.TotalEngines)."
            }
            'Clean' {
                "VirusTotal reports no malicious engine results out of $($vtReport.TotalEngines)."
            }
            'Unknown' {
                'VirusTotal does not know this hash. Missing evidence does not establish that the file is clean.'
            }
            default {
                'VirusTotal is unavailable for this hash.'
            }
        }

        $vtVerdict = [pscustomobject]@{
            PSTypeName = 'EndpointOps.Reputation.Verdict'
            Source     = 'VirusTotal'
            Verdict    = $vtReport.Verdict
            Detail     = $vtDetail
            HashUsed   = $Hash
            HashSource = 'EPM'
            QueryDate  = [datetime]::UtcNow
        }
        $sources = [System.Collections.Generic.List[object]]::new()
        $sources.Add($vtVerdict)
        $globalVerdict = $vtReport.Verdict

        if (-not $SkipCascade -and $vtReport.Verdict -in $cascadeVerdicts) {
            $mbVerdict = Get-MbFileVerdict -Hash $Hash
            $sources.Add($mbVerdict)
            if ($mbVerdict.Verdict -eq 'Malicious') {
                $globalVerdict = 'Malicious'
            }
        }

        if (-not $SkipCascade -and $globalVerdict -eq 'Malicious') {
            $haVerdict = Get-HaFileVerdict -Hash $Hash
            $sources.Add($haVerdict)

            $vtSha256 = [string]$vtReport.Sha256
            if ($vtSha256 -match '^[0-9A-Fa-f]{64}$') {
                $tfVerdict = Get-TfFileVerdict -Hash $vtSha256
                $sources.Add($tfVerdict)
            }
        }

        $fileResult = [pscustomobject]@{
            PSTypeName = 'EndpointOps.Reputation.FileResult'
            Hash       = $Hash
            Verdict    = $globalVerdict
            Sources    = @($sources)
        }

        if ($UseCache) {
            foreach ($source in $sources) {
                Write-ReputationCacheEntry -SourceResult $source -CachePath $CachePath
            }
        }

        return $fileResult
    }

    end {}
}
