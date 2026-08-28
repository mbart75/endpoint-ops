Set-StrictMode -Version 3.0

function Connect-HybridAnalysis {
    <#
    .SYNOPSIS
        Opens a Hybrid Analysis session for the module.
    .DESCRIPTION
        Stores the service base URL and SecureString API key in module memory. The key is never written
        to disk or returned in public connection metadata. HTTPS is required except for loopback
        addresses used by the test server.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNull()][securestring]$ApiKey,
        [ValidateNotNullOrEmpty()][string]$BaseUri = 'https://www.hybrid-analysis.com'
    )

    $normalized = $BaseUri.TrimEnd('/')
    $isLoopback = $normalized -match '^http://(localhost|127\.0\.0\.1)(:\d+)?$'
    if (-not $isLoopback -and $normalized -notmatch '^https://') {
        throw "EndpointOps: BaseUri must use HTTPS ('$BaseUri'). An API key must not be sent in clear text."
    }

    $connectedAt = Get-Date
    $script:HaConnection = [pscustomobject]@{
        BaseUri     = $normalized
        ApiKey      = $ApiKey
        ConnectedAt = $connectedAt
    }

    return [pscustomobject]@{
        PSTypeName  = 'EndpointOps.HybridAnalysis.Connection'
        BaseUri     = $normalized
        ConnectedAt = $connectedAt
    }
}
