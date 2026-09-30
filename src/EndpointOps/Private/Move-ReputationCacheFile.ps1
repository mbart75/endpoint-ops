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
        [System.IO.File]::Replace($SourcePath, $DestinationPath, $null)
        return
    }

    [System.IO.File]::Move($SourcePath, $DestinationPath, $true)
}
