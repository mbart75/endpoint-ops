Set-StrictMode -Version 3.0

# MalwareBazaar connection state remains in module memory and is never written to disk. Initializing
# it at module load keeps reads before the first connection compatible with StrictMode.
$script:MbConnection = $null

function Get-MbConnectionState {
    <#
    .SYNOPSIS
        Returns the current MalwareBazaar connection state.
    .DESCRIPTION
        Throws an explicit error when no connection is open. The key remains a SecureString in this
        private state and is never returned.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($null -eq $script:MbConnection) {
        throw 'EndpointOps: no active MalwareBazaar connection. Call Connect-MalwareBazaar first.'
    }

    return $script:MbConnection
}
