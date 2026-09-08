function Test-ReputationCacheFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CachePath)

    $result = [pscustomobject]@{ Exists = $false; IsValid = $true; Entries = @() }
    if (-not [System.IO.File]::Exists($CachePath)) { return $result }
    $result.Exists = $true
    $result.IsValid = $false
    try {
        $json = [System.IO.File]::ReadAllText($CachePath)
        $entries = ConvertFrom-Json -InputObject $json -NoEnumerate -ErrorAction Stop
        if ($entries -isnot [array]) { return $result }
        $bindings = @{}
        foreach ($entry in $entries) {
            if ($null -eq $entry -or $entry.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
                return $result
            }
            $names = @($entry.PSObject.Properties.Name) -join ','
            $legacy = $names -ceq 'Hash,Source,Verdict,QueryDate'
            $version2 = $names -ceq 'Version,LookupHash,CanonicalSha256,Hash,HashSource,Source,Verdict,QueryDate'
            if (-not $legacy -and -not $version2) { return $result }

            $date = [datetimeoffset]::MinValue
            $validDate = if ($entry.QueryDate -is [datetime]) { $true }
            else {
                [datetimeoffset]::TryParse([string]$entry.QueryDate,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind, [ref]$date)
            }
            if (-not $validDate -or
                [string]$entry.Hash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -or
                [string]$entry.Source -notin @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox') -or
                [string]$entry.Verdict -notin @('Clean', 'Unknown', 'Malicious')) { return $result }

            if ($version2) {
                if ($entry.Version -isnot [long] -or $entry.Version -ne 2 -or
                    [string]$entry.LookupHash -notmatch '^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$' -or
                    ($null -ne $entry.CanonicalSha256 -and [string]$entry.CanonicalSha256 -notmatch '^[0-9A-Fa-f]{64}$')) {
                    return $result
                }
                $validBinding = if ($entry.Source -eq 'ThreatFox') {
                    -not [string]::IsNullOrEmpty($entry.CanonicalSha256) -and
                    [string]::Equals($entry.Hash, $entry.CanonicalSha256, [System.StringComparison]::OrdinalIgnoreCase) -and
                    $entry.HashSource -ceq 'VirusTotal'
                }
                else {
                    [string]::Equals($entry.Hash, $entry.LookupHash, [System.StringComparison]::OrdinalIgnoreCase) -and
                    $entry.HashSource -ceq 'EPM'
                }
                if (-not $validBinding) { return $result }
                if (-not [string]::IsNullOrEmpty($entry.CanonicalSha256)) {
                    $key = [string]$entry.LookupHash
                    if ($bindings.ContainsKey($key) -and
                        -not [string]::Equals($bindings[$key], $entry.CanonicalSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return $result
                    }
                    $bindings[$key] = [string]$entry.CanonicalSha256
                }
            }
        }
        foreach ($entry in $entries) {
            if ($entry.PSObject.Properties.Name -contains 'Version' -and $entry.Source -eq 'ThreatFox') {
                $authority = @($entries | Where-Object {
                        $_.PSObject.Properties.Name -contains 'Version' -and $_.Source -eq 'VirusTotal' -and
                        [string]::Equals($_.LookupHash, $entry.LookupHash, [System.StringComparison]::OrdinalIgnoreCase) -and
                        [string]::Equals($_.CanonicalSha256, $entry.CanonicalSha256, [System.StringComparison]::OrdinalIgnoreCase)
                    })
                if ($authority.Count -eq 0 -or
                    ($entry.LookupHash.Length -eq 64 -and
                        -not [string]::Equals($entry.LookupHash, $entry.CanonicalSha256, [System.StringComparison]::OrdinalIgnoreCase))) {
                    return $result
                }
            }
        }
        $result.IsValid = $true
        $result.Entries = $entries
    }
    catch { return $result }
    return $result
}
