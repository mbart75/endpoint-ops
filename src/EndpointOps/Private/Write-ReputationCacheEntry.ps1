Set-StrictMode -Version 3.0

function Write-ReputationCacheEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$SourceResult,
        [string]$LookupHash,
        [AllowNull()][string]$CanonicalSha256,
        [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json')
    )

    try {
        $hash = [string]$SourceResult.HashUsed
        $hashSource = if ($SourceResult.PSObject.Properties.Name -contains 'HashSource') {
            [string]$SourceResult.HashSource
        }
        else {
            'EPM'
        }
        $source = [string]$SourceResult.Source
        $verdict = [string]$SourceResult.Verdict
        $queryDate = ([datetime]$SourceResult.QueryDate).ToUniversalTime()
        $candidateAge = [datetime]::UtcNow - $queryDate
        $writeVersion2 = -not [string]::IsNullOrWhiteSpace($LookupHash)
        if ($verdict -eq 'Unavailable' -or
            $source -notin @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox') -or
            $verdict -notin @('Clean', 'Unknown', 'Malicious') -or
            $hash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$') {
            return
        }

        if ($writeVersion2) {
            if ($LookupHash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -or
                (-not [string]::IsNullOrEmpty($CanonicalSha256) -and
                    $CanonicalSha256 -notmatch '^[0-9A-Fa-f]{64}$')) {
                return
            }

            $hasValidEvidenceBinding = if ($source -eq 'ThreatFox') {
                -not [string]::IsNullOrEmpty($CanonicalSha256) -and
                [string]::Equals($hash, $CanonicalSha256,
                    [System.StringComparison]::OrdinalIgnoreCase) -and
                $hashSource -ceq 'VirusTotal'
            }
            else {
                [string]::Equals($hash, $LookupHash,
                    [System.StringComparison]::OrdinalIgnoreCase) -and
                $hashSource -ceq 'EPM'
            }
            if (-not $hasValidEvidenceBinding) {
                return
            }
        }

        $resolvedCachePath = [System.IO.Path]::GetFullPath($CachePath, (Get-Location).Path)
        Invoke-WithReputationCacheLock -CachePath $resolvedCachePath -ScriptBlock {
            $suppressCandidate = $false
            $candidateCanonicalSha256 = $CanonicalSha256
            $entries = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $resolvedCachePath -PathType Leaf) {
                try {
                    $json = Get-Content -LiteralPath $resolvedCachePath -Raw -ErrorAction Stop
                    # WARNING: parseable unrelated files are not disposable cache data.
                    # Preserve corrupt-cache recovery only after distinguishing a parse failure.
                    $null = ConvertFrom-Json -InputObject $json -NoEnumerate -ErrorAction Stop
                    $cache = Test-ReputationCacheFile -CachePath $resolvedCachePath
                    if (-not $cache.IsValid) { return }
                    if ($json.TrimStart().StartsWith('[')) {
                        $parsedEntries = @($json | ConvertFrom-Json -ErrorAction Stop)
                        if ($writeVersion2) {
                            $establishedBindings = @($parsedEntries | Where-Object {
                                    $_.PSObject.Properties.Name -contains 'Version' -and
                                    $_.Version -eq 2 -and
                                    [string]::Equals([string]$_.LookupHash, $LookupHash,
                                        [System.StringComparison]::OrdinalIgnoreCase) -and
                                    -not [string]::IsNullOrEmpty([string]$_.CanonicalSha256)
                                } | ForEach-Object { [string]$_.CanonicalSha256 } | Select-Object -Unique)
                            if ($establishedBindings.Count -gt 0) {
                                $establishedBinding = $establishedBindings[0]
                                if ([string]::IsNullOrEmpty($candidateCanonicalSha256)) {
                                    # WARNING: only fresh malicious evidence for this exact lookup may
                                    # inherit an already-established canonical binding. Weaker unbound
                                    # updates remain rejected so they cannot silently loosen identity.
                                    if ($source -eq 'ThreatFox' -or $verdict -ne 'Malicious' -or
                                        $candidateAge -lt [timespan]::Zero -or
                                        $candidateAge -gt [timespan]::FromDays(90)) {
                                        return
                                    }
                                    $candidateCanonicalSha256 = $establishedBinding
                                }
                                elseif (-not [string]::Equals(
                                        $establishedBinding, $candidateCanonicalSha256,
                                        [System.StringComparison]::OrdinalIgnoreCase)) {
                                    return
                                }
                            }
                        }

                        foreach ($entry in $parsedEntries) {
                            if ($null -eq $entry -or
                                $entry.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
                                continue
                            }

                            $propertyNames = @($entry.PSObject.Properties.Name)
                            $isLegacyEntry = $propertyNames.Count -eq 4 -and
                                $propertyNames[0] -ceq 'Hash' -and
                                $propertyNames[1] -ceq 'Source' -and
                                $propertyNames[2] -ceq 'Verdict' -and
                                $propertyNames[3] -ceq 'QueryDate'
                            $isVersion2Entry = $propertyNames.Count -eq 8 -and
                                $propertyNames[0] -ceq 'Version' -and
                                $propertyNames[1] -ceq 'LookupHash' -and
                                $propertyNames[2] -ceq 'CanonicalSha256' -and
                                $propertyNames[3] -ceq 'Hash' -and
                                $propertyNames[4] -ceq 'HashSource' -and
                                $propertyNames[5] -ceq 'Source' -and
                                $propertyNames[6] -ceq 'Verdict' -and
                                $propertyNames[7] -ceq 'QueryDate'
                            if (-not $isLegacyEntry -and -not $isVersion2Entry) {
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

                            if ($isVersion2Entry) {
                                $entryLookupHash = [string]$entry.LookupHash
                                $entryCanonicalSha256 = [string]$entry.CanonicalSha256
                                $entryHashSource = [string]$entry.HashSource
                                $hasValidVersion2Entry = $entry.Version -is [long] -and
                                    $entry.Version -eq 2 -and
                                    $entryLookupHash -match '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -and
                                    ($null -eq $entry.CanonicalSha256 -or
                                        $entryCanonicalSha256 -match '^[0-9A-Fa-f]{64}$')
                                if ($hasValidVersion2Entry) {
                                    $hasValidVersion2Entry = if ($entrySource -eq 'ThreatFox') {
                                        -not [string]::IsNullOrEmpty($entryCanonicalSha256) -and
                                        [string]::Equals($entryHash, $entryCanonicalSha256,
                                            [System.StringComparison]::OrdinalIgnoreCase) -and
                                        $entryHashSource -ceq 'VirusTotal'
                                    }
                                    else {
                                        [string]::Equals($entryHash, $entryLookupHash,
                                            [System.StringComparison]::OrdinalIgnoreCase) -and
                                        $entryHashSource -ceq 'EPM'
                                    }
                                }
                                if (-not $hasValidVersion2Entry) {
                                    continue
                                }

                                $learnsCanonicalBinding = $false
                                $candidateLookupHash = if ($writeVersion2) { $LookupHash } else { $hash }
                                if ([string]::Equals(
                                        $entryLookupHash, $candidateLookupHash,
                                        [System.StringComparison]::OrdinalIgnoreCase)) {
                                    # An established identity cannot be silently replaced or unbound.
                                    $learnsCanonicalBinding = [string]::IsNullOrEmpty($entryCanonicalSha256) -and
                                        -not [string]::IsNullOrEmpty($candidateCanonicalSha256)
                                    $canonicalBindingsMatch = if ($learnsCanonicalBinding -or (
                                            [string]::IsNullOrEmpty($entryCanonicalSha256) -and
                                            [string]::IsNullOrEmpty($candidateCanonicalSha256))) {
                                        $true
                                    }
                                    else {
                                        [string]::Equals($entryCanonicalSha256, $candidateCanonicalSha256,
                                            [System.StringComparison]::OrdinalIgnoreCase)
                                    }
                                    $sameSource = [string]::Equals($entrySource, $source,
                                        [System.StringComparison]::OrdinalIgnoreCase)
                                    $age = [datetime]::UtcNow - $entryDate.UtcDateTime
                                    $retainMalicious = $canonicalBindingsMatch -and $sameSource -and
                                        $entryVerdict -eq 'Malicious' -and $verdict -in @('Clean', 'Unknown') -and
                                        $age -ge [timespan]::Zero -and $age -le [timespan]::FromDays(90)
                                    if ($retainMalicious) { $suppressCandidate = $true }
                                    elseif (-not $canonicalBindingsMatch -or $sameSource) {
                                        continue
                                    }
                                }

                                $entries.Add([pscustomobject][ordered]@{
                                        Version          = 2
                                        LookupHash       = $entryLookupHash
                                        CanonicalSha256  = if ($learnsCanonicalBinding) {
                                            $candidateCanonicalSha256
                                        }
                                        elseif ($null -eq $entry.CanonicalSha256) { $null }
                                        else { $entryCanonicalSha256 }
                                        Hash             = $entryHash
                                        HashSource       = $entryHashSource
                                        Source           = $entrySource
                                        Verdict          = $entryVerdict
                                        QueryDate        = $entryDate.UtcDateTime.ToString('o')
                                    })
                            }
                            else {
                                $replacementHash = if ($writeVersion2) { $LookupHash } else { $hash }
                                $replacesLegacyEntry = [string]::Equals($entryHash, $replacementHash,
                                    [System.StringComparison]::OrdinalIgnoreCase) -and
                                    [string]::Equals($entrySource, $source,
                                        [System.StringComparison]::OrdinalIgnoreCase)
                                $age = [datetime]::UtcNow - $entryDate.UtcDateTime
                                $retainMalicious = $replacesLegacyEntry -and
                                    $entryVerdict -eq 'Malicious' -and $verdict -in @('Clean', 'Unknown') -and
                                    $age -ge [timespan]::Zero -and $age -le [timespan]::FromDays(90)
                                if ($retainMalicious) { $suppressCandidate = $true }
                                elseif ($replacesLegacyEntry) {
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
                }
                catch {
                    $entries.Clear()
                }
            }

            if (-not $suppressCandidate) {
                if ($writeVersion2) {
                    $entries.Add([pscustomobject][ordered]@{
                            Version          = 2
                            LookupHash       = $LookupHash
                            CanonicalSha256  = if ([string]::IsNullOrEmpty($candidateCanonicalSha256)) {
                                $null
                            }
                            else { $candidateCanonicalSha256 }
                            Hash             = $hash
                            HashSource       = $hashSource
                            Source           = $source
                            Verdict          = $verdict
                            QueryDate        = $queryDate.ToString('o')
                        })
                }
                else {
                    $entries.Add([pscustomobject][ordered]@{
                            Hash      = $hash
                            Source    = $source
                            Verdict   = $verdict
                            QueryDate = $queryDate.ToString('o')
                        })
                }
            }
            Write-ReputationCacheFile -CachePath $resolvedCachePath -Entries $entries.ToArray()
        }
    }
    catch {
        return
    }
}
