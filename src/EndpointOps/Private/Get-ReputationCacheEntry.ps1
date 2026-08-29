Set-StrictMode -Version 3.0

function Get-ReputationCacheEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$')][string]$Hash,
        [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json'),
        [datetime]$ReferenceDate = ([datetime]::UtcNow)
    )

    try {
        if (-not (Test-Path -LiteralPath $CachePath -PathType Leaf)) {
            return
        }

        $json = Get-Content -LiteralPath $CachePath -Raw -ErrorAction Stop
        if (-not $json.TrimStart().StartsWith('[')) {
            return
        }

        $entries = @($json | ConvertFrom-Json -ErrorAction Stop)
        $validEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $entries) {
            if ($null -eq $entry) {
                return
            }

            if ($entry.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
                return
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
                return
            }

            $queryDate = [datetimeoffset]::MinValue
            if ($entry.QueryDate -is [datetime]) {
                $queryDate = [datetimeoffset]::new(([datetime]$entry.QueryDate).ToUniversalTime())
            }
            elseif (-not [datetimeoffset]::TryParse(
                    [string]$entry.QueryDate,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind,
                    [ref]$queryDate)) {
                return
            }

            $entryHash = [string]$entry.Hash
            $lookupHash = if ($isVersion2Entry) { [string]$entry.LookupHash } else { $entryHash }
            $canonicalSha256 = if ($isVersion2Entry) { [string]$entry.CanonicalSha256 } else { $null }
            $hashSource = if ($isVersion2Entry) { [string]$entry.HashSource } else { 'EPM' }
            $source = [string]$entry.Source
            $verdict = [string]$entry.Verdict
            if ($entryHash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -or
                $lookupHash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -or
                $source -notin @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox') -or
                $verdict -notin @('Clean', 'Unknown', 'Malicious')) {
                return
            }

            if ($isVersion2Entry) {
                if ($entry.Version -isnot [long] -or $entry.Version -ne 2 -or
                    ($null -ne $entry.CanonicalSha256 -and
                        $canonicalSha256 -notmatch '^[0-9A-Fa-f]{64}$')) {
                    return
                }

                $hasValidEvidenceBinding = if ($source -eq 'ThreatFox') {
                    -not [string]::IsNullOrEmpty($canonicalSha256) -and
                    [string]::Equals($entryHash, $canonicalSha256,
                        [System.StringComparison]::OrdinalIgnoreCase) -and
                    $hashSource -ceq 'VirusTotal'
                }
                else {
                    [string]::Equals($entryHash, $lookupHash,
                        [System.StringComparison]::OrdinalIgnoreCase) -and
                    $hashSource -ceq 'EPM'
                }
                if (-not $hasValidEvidenceBinding) {
                    return
                }
            }

            if (-not [string]::Equals($lookupHash, $Hash, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $validityDays = if ($verdict -eq 'Malicious') { 90 } else { 7 }
            $age = $ReferenceDate.ToUniversalTime() - $queryDate.UtcDateTime
            if ($age -lt [timespan]::Zero -or $age -gt [timespan]::FromDays($validityDays)) {
                continue
            }

            $validEntries.Add([pscustomobject][ordered]@{
                    CacheVersion   = if ($isVersion2Entry) { 2 } else { 1 }
                    LookupHash     = $lookupHash
                    CanonicalSha256 = $canonicalSha256
                    Hash           = $entryHash
                    HashSource     = $hashSource
                    Source         = $source
                    Verdict        = $verdict
                    QueryDate      = $queryDate.UtcDateTime
                })
        }

        $version2Entries = @($validEntries | Where-Object CacheVersion -eq 2)
        $canonicalBindings = @($version2Entries |
                Where-Object { -not [string]::IsNullOrEmpty($_.CanonicalSha256) } |
                ForEach-Object { $_.CanonicalSha256.ToUpperInvariant() } |
                Select-Object -Unique)
        if ($canonicalBindings.Count -gt 1) {
            return
        }

        $threatFoxEntries = @($version2Entries | Where-Object Source -eq 'ThreatFox')
        if ($threatFoxEntries.Count -gt 0) {
            if ($canonicalBindings.Count -ne 1) {
                return
            }

            $canonicalBinding = $canonicalBindings[0]
            $virusTotalBindings = @($version2Entries | Where-Object {
                    $_.Source -eq 'VirusTotal' -and
                    [string]::Equals($_.CanonicalSha256, $canonicalBinding,
                        [System.StringComparison]::OrdinalIgnoreCase)
                })
            if ($virusTotalBindings.Count -eq 0 -or
                ($Hash.Length -eq 64 -and
                    -not [string]::Equals($Hash, $canonicalBinding,
                        [System.StringComparison]::OrdinalIgnoreCase))) {
                return
            }
        }

        foreach ($validEntry in $validEntries) {
            $validEntry
        }
    }
    catch {
        return
    }
}
