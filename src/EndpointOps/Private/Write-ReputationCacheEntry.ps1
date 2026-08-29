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

                            if ($writeVersion2 -and [string]::Equals(
                                    $entryLookupHash, $LookupHash,
                                    [System.StringComparison]::OrdinalIgnoreCase)) {
                                $canonicalBindingsMatch = if (
                                    [string]::IsNullOrEmpty($entryCanonicalSha256) -and
                                    [string]::IsNullOrEmpty($CanonicalSha256)) {
                                    $true
                                }
                                else {
                                    [string]::Equals($entryCanonicalSha256, $CanonicalSha256,
                                        [System.StringComparison]::OrdinalIgnoreCase)
                                }
                                if (-not $canonicalBindingsMatch -or
                                    [string]::Equals($entrySource, $source,
                                        [System.StringComparison]::OrdinalIgnoreCase)) {
                                    continue
                                }
                            }

                            $entries.Add([pscustomobject][ordered]@{
                                    Version          = 2
                                    LookupHash       = $entryLookupHash
                                    CanonicalSha256  = if ($null -eq $entry.CanonicalSha256) { $null } else { $entryCanonicalSha256 }
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
                            if ($replacesLegacyEntry) {
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

        if ($writeVersion2) {
            $entries.Add([pscustomobject][ordered]@{
                    Version          = 2
                    LookupHash       = $LookupHash
                    CanonicalSha256  = if ([string]::IsNullOrEmpty($CanonicalSha256)) { $null } else { $CanonicalSha256 }
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
