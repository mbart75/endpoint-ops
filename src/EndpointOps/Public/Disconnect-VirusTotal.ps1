function Disconnect-VirusTotal {
    <#
    .SYNOPSIS
        Closes the VirusTotal session and clears the key.
    .DESCRIPTION
        No effect if no connection is open: closing twice should not be an error.
    .EXAMPLE
        Disconnect-VirusTotal
    #>
    [CmdletBinding()]
    param()

    $script:VtConnection = $null
    $script:VtFileReportCache.Clear()
    $script:VtUrlReportCache.Clear()
}
