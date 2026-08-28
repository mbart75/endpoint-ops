# CyberArk EPM connection state: in memory, within the module scope, never on disk. It is
# initialized at module load because Set-StrictMode 3.0 throws when reading an unassigned variable.
$script:EpmConnection = $null

function Get-EpmConnectionState {
    <#
    .SYNOPSIS
        Returns the current CyberArk EPM connection status.
    .DESCRIPTION
        It raises an explicit error if no connection is open. The message says what to do: a
        "property not found" three calls away would cost much more to diagnose.

        The state has two URLs, and this is the defining feature of the EPM model: DispatcherUri is the
        address where the authentication took place, kept for a readable error message; ManagerUri
        is the address returned by the dispatcher, and this is where all subsequent calls go.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($null -eq $script:EpmConnection) {
        throw "EndpointOps: no active CyberArk EPM connection. Call Connect-EpmTenant first."
    }

    return $script:EpmConnection
}
