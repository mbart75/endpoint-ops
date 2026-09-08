function Write-ReputationCacheFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CachePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries
    )

    $temporaryPath = "$CachePath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    try {
        $json = ConvertTo-Json -InputObject $Entries -Depth 4 -ErrorAction Stop
        $writer = [System.IO.StreamWriter]::new($temporaryPath, $false, [System.Text.UTF8Encoding]::new($false))
        try {
            $writer.Write($json)
            $writer.Flush()
            $writer.BaseStream.Flush($true)
        }
        finally { $writer.Dispose() }
        Move-ReputationCacheFile -SourcePath $temporaryPath -DestinationPath $CachePath
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}
