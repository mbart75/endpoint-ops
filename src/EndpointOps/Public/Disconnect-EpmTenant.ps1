function Disconnect-EpmTenant {
    <#
    .SYNOPSIS
        Closes the CyberArk EPM session and clears the token.
    .DESCRIPTION
        No effect if no connection is open: closing twice should not be an error.

        Nothing is sent to the server: the EPM documentation does not expose a disconnect entry
        point, and the token expires only according to the session setting of the tenant.
    .EXAMPLE
        Disconnect-EpmTenant
    #>
    [CmdletBinding()]
    param()

    $script:EpmConnection = $null
}
