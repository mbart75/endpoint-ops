function Invoke-WithReputationCacheLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CachePath,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [ValidateRange(100, 60000)][int]$LockTimeoutMs = 5000
    )

    $resolvedCachePath = [System.IO.Path]::GetFullPath($CachePath, (Get-Location).Path)
    $lockPath = "$resolvedCachePath.lock"
    $directory = Split-Path $lockPath -Parent
    if ([string]::IsNullOrEmpty($directory)) { $directory = (Get-Location).Path }
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $lockStream = $null
    try {
        while ($null -eq $lockStream) {
            try {
                $lockStream = [System.IO.FileStream]::new(
                    $lockPath,
                    [System.IO.FileMode]::OpenOrCreate,
                    [System.IO.FileAccess]::ReadWrite,
                    [System.IO.FileShare]::None)
            }
            catch [System.IO.IOException] {
                if ($timer.ElapsedMilliseconds -ge $LockTimeoutMs) {
                    throw "EndpointOps: timed out waiting for the reputation cache lock at $CachePath"
                }
                Start-Sleep -Milliseconds 50
            }
        }
        & $ScriptBlock
    }
    finally {
        if ($null -ne $lockStream) { $lockStream.Dispose() }
    }
}
