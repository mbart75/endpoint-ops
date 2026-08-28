# VirusTotal connection state: in memory, within the module scope, never on disk. It is initialized
# at module load because Set-StrictMode 3.0 throws when reading an unassigned variable.
$script:VtConnection = $null

function Get-VtConnectionState {
    <#
    .SYNOPSIS
        Returns the current VirusTotal connection status.
    .DESCRIPTION
        Raises an explicit error if no connection is open. The key remains a SecureString in this
        private state and is never returned.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($null -eq $script:VtConnection) {
        throw "EndpointOps: no active VirusTotal connection. Call Connect-VirusTotal first."
    }

    return $script:VtConnection
}
