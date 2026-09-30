function Move-ReputationCacheFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows) -and
        [System.IO.File]::Exists($DestinationPath)) {
        # WARNING: File.Move replaces the destination ACL with the staging file ACL on Windows.
        # File.Replace preserves the destination ACL and fails rather than weakening that guarantee.
        $backupPath = "$SourcePath.backup"
        try {
            Invoke-ReputationCacheReplace -SourcePath $SourcePath `
                -DestinationPath $DestinationPath -BackupPath $backupPath
        }
        catch {
            if (-not [System.IO.File]::Exists($DestinationPath) -and
                [System.IO.File]::Exists($backupPath)) {
                try {
                    [System.IO.File]::Move($backupPath, $DestinationPath)
                }
                catch {
                    # WARNING: Keep the protected backup if restoration cannot complete.
                    Write-Warning "EndpointOps: cache restoration failed; the original is retained at $backupPath."
                    throw
                }
            }
            throw
        }
        [System.IO.File]::Delete($backupPath)
        return
    }

    [System.IO.File]::Move($SourcePath, $DestinationPath, $true)
}
