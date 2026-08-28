Set-StrictMode -Version 3.0

function Clear-ReputationCache {
    <#
    .SYNOPSIS
        Removes the persistent reputation cache.
    .DESCRIPTION
        Persistent caching is disabled by default. When enabled, it writes file hashes observed in
        the fleet and their verdicts to disk. This constitutes a partial software inventory and must
        therefore remain an explicit operator choice.

        Cache lifetimes are asymmetric. Clean and Unknown verdicts expire after seven days because a
        file not detected today may be detected tomorrow. Malicious verdicts remain valid for 90
        days because malicious evidence should not disappear quickly.
    .PARAMETER CachePath
        Path to the cache file. The default location is outside the repository in the user profile.
    #>
    [CmdletBinding()]
    param(
        [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json')
    )

    if (Test-Path -LiteralPath $CachePath -PathType Leaf) {
        Remove-Item -LiteralPath $CachePath -Force -ErrorAction Stop
    }
}
