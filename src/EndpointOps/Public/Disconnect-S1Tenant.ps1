function Disconnect-S1Tenant {
    <#
    .SYNOPSIS
        Closes the SentinelOne session and clears the token.
    .DESCRIPTION
        No effect if no connection is open: closing twice should not be an error.
    .EXAMPLE
        Disconnect-S1Tenant
    #>
    [CmdletBinding()]
    param()

    $script:S1Connection = $null
}
