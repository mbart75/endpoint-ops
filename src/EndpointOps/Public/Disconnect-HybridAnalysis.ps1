Set-StrictMode -Version 3.0

function Disconnect-HybridAnalysis {
    <#
    .SYNOPSIS
        Closes the Hybrid Analysis session and clears the API key.
    #>
    [CmdletBinding()]
    param()

    $script:HaConnection = $null
}
