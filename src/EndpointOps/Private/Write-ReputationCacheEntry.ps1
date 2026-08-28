Set-StrictMode -Version 3.0

function Write-ReputationCacheEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$SourceResult,
        [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json')
    )

    try {
        $hash = [string]$SourceResult.HashUsed
        $source = [string]$SourceResult.Source
        $verdict = [string]$SourceResult.Verdict
        $queryDate = ([datetime]$SourceResult.QueryDate).ToUniversalTime()
        if ($verdict -eq 'Unavailable' -or
            $source -notin @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox') -or
            $verdict -notin @('Clean', 'Unknown', 'Malicious') -or
            $hash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$') {
            return
        }

        $resolvedCachePath = if ([System.IO.Path]::IsPathRooted($CachePath)) {
            $CachePath
        }
        else {
            Join-Path (Get-Location).Path $CachePath
        }
        $entries = [System.Collections.Generic.List[object]]::new()
        if (Test-Path -LiteralPath $resolvedCachePath -PathType Leaf) {
            try {
                $json = Get-Content -LiteralPath $resolvedCachePath -Raw -ErrorAction Stop
                if ($json.TrimStart().StartsWith('[')) {
                    foreach ($entry in @($json | ConvertFrom-Json -ErrorAction Stop)) {
                        if ($null -eq $entry) {
                            continue
                        }

                        $propertyNames = @($entry.PSObject.Properties.Name)
                        if ($entry.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject] -or
                            $propertyNames.Count -ne 4 -or
                            $propertyNames[0] -cne 'Hash' -or
                            $propertyNames[1] -cne 'Source' -or
                            $propertyNames[2] -cne 'Verdict' -or
                            $propertyNames[3] -cne 'QueryDate') {
                            continue
                        }

                        $entryHash = [string]$entry.Hash
                        $entrySource = [string]$entry.Source
                        $entryVerdict = [string]$entry.Verdict
                        $entryDate = [datetimeoffset]::MinValue
                        $hasEntryDate = $false
                        if ($entry.QueryDate -is [datetime]) {
                            $entryDate = [datetimeoffset]::new(([datetime]$entry.QueryDate).ToUniversalTime())
                            $hasEntryDate = $true
                        }
                        else {
                            $hasEntryDate = [datetimeoffset]::TryParse(
                                [string]$entry.QueryDate,
                                [Globalization.CultureInfo]::InvariantCulture,
                                [Globalization.DateTimeStyles]::RoundtripKind,
                                [ref]$entryDate)
                        }

                        if ($entryHash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -or
                            $entrySource -notin @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox') -or
                            $entryVerdict -notin @('Clean', 'Unknown', 'Malicious') -or
                            -not $hasEntryDate) {
                            continue
                        }

                        if ([string]::Equals($entryHash, $hash, [System.StringComparison]::OrdinalIgnoreCase) -and
                            [string]::Equals($entrySource, $source, [System.StringComparison]::OrdinalIgnoreCase)) {
                            continue
                        }

                        $entries.Add([pscustomobject][ordered]@{
                                Hash      = $entryHash
                                Source    = $entrySource
                                Verdict   = $entryVerdict
                                QueryDate = $entryDate.UtcDateTime.ToString('o')
                            })
                    }
                }
            }
            catch {
                $entries.Clear()
            }
        }

        $entries.Add([pscustomobject][ordered]@{
                Hash      = $hash
                Source    = $source
                Verdict   = $verdict
                QueryDate = $queryDate.ToString('o')
        })

        $directory = Split-Path -Path $resolvedCachePath -Parent
        if (-not [string]::IsNullOrWhiteSpace($directory)) {
            [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        }
        $cacheJson = ConvertTo-Json -InputObject $entries -Depth 4
        [System.IO.File]::WriteAllText($resolvedCachePath, $cacheJson, [System.Text.UTF8Encoding]::new($false))
    }
    catch {
        return
    }
}
