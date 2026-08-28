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

            $propertyNames = @($entry.PSObject.Properties.Name)
            if ($entry.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject] -or
                $propertyNames.Count -ne 4 -or
                $propertyNames[0] -cne 'Hash' -or
                $propertyNames[1] -cne 'Source' -or
                $propertyNames[2] -cne 'Verdict' -or
                $propertyNames[3] -cne 'QueryDate') {
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
            $source = [string]$entry.Source
            $verdict = [string]$entry.Verdict
            if ([string]::IsNullOrWhiteSpace($entryHash) -or
                $source -notin @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox') -or
                $verdict -notin @('Clean', 'Unknown', 'Malicious')) {
                return
            }

            if (-not [string]::Equals($entryHash, $Hash, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $validityDays = if ($verdict -eq 'Malicious') { 90 } else { 7 }
            $age = $ReferenceDate.ToUniversalTime() - $queryDate.UtcDateTime
            if ($age -lt [timespan]::Zero -or $age -gt [timespan]::FromDays($validityDays)) {
                continue
            }

            $validEntries.Add([pscustomobject][ordered]@{
                    Hash      = $entryHash
                    Source    = $source
                    Verdict   = $verdict
                    QueryDate = $queryDate.UtcDateTime
                })
        }

        foreach ($validEntry in $validEntries) {
            $validEntry
        }
    }
    catch {
        return
    }
}
