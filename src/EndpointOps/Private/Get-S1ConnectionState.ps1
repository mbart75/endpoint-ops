# SentinelOne connection state: in memory, within the module scope, never on disk. It is initialized
# at module load because Set-StrictMode 3.0 throws when reading an unassigned variable.
$script:S1Connection = $null

function Get-S1ConnectionState {
    <#
    .SYNOPSIS
        Returns the current SentinelOne connection status.
    .DESCRIPTION
        It raises an explicit error if no connection is open. The message says what to do: a
        "property not found" three calls away would cost much more to diagnose.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($null -eq $script:S1Connection) {
        throw "EndpointOps: no active SentinelOne connection. Call Connect-S1Tenant first."
    }

    return $script:S1Connection
}
