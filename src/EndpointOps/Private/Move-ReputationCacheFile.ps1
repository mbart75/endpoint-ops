function Move-ReputationCacheFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    [System.IO.File]::Move($SourcePath, $DestinationPath, $true)
}
