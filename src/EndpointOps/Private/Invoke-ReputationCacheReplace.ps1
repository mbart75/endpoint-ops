function Invoke-ReputationCacheReplace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][string]$BackupPath
    )

    [System.IO.File]::Replace($SourcePath, $DestinationPath, $BackupPath, $false)
}
