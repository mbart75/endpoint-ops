Set-StrictMode -Version 3.0

# Hybrid Analysis connection state remains in module memory and stores only the service base URL and
# the SecureString supplied by the operator. Nothing is written to disk.
$script:HaConnection = $null

function Get-HaConnectionState {
    <#
    .SYNOPSIS
        Returns the current Hybrid Analysis connection state.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($null -eq $script:HaConnection) {
        throw 'EndpointOps: no active Hybrid Analysis connection. Call Connect-HybridAnalysis first.'
    }

    return $script:HaConnection
}
