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
    .PARAMETER Force
        Allows removal of an unrecognized or corrupt cache at the explicitly selected path.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json'),
        [switch]$Force
    )

    $resolvedCachePath = [System.IO.Path]::GetFullPath($CachePath, (Get-Location).Path)
    $allowUnrecognized = $Force.IsPresent
    if (-not (Test-Path -LiteralPath $resolvedCachePath -PathType Leaf)) { return }
    if ($PSCmdlet.ShouldProcess($resolvedCachePath, 'Remove the EndpointOps reputation cache')) {
        Invoke-WithReputationCacheLock -CachePath $resolvedCachePath -ScriptBlock {
            $cache = Test-ReputationCacheFile -CachePath $resolvedCachePath
            if (-not $cache.Exists) { return }
            if (-not $cache.IsValid -and -not $allowUnrecognized) {
                throw 'EndpointOps: the supplied path is not a recognized reputation cache.'
            }
            Remove-Item -LiteralPath $resolvedCachePath -Force -ErrorAction Stop
        }
    }
}
