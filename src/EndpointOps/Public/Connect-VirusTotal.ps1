function Connect-VirusTotal {
    <#
    .SYNOPSIS
        Opens a VirusTotal session for the module.
    .DESCRIPTION
        Stores the service URL and API key in memory within module scope. The key is never written to
        disk or returned to the caller, and is converted to plain text only while building a request
        header.

        HTTPS is required except for loopback addresses so that the mock server can operate
        without a certificate.
    .EXAMPLE
        $apiKey = Read-Host -AsSecureString 'VirusTotal API key'
        Connect-VirusTotal -ApiKey $apiKey
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNull()][securestring]$ApiKey,
        [ValidateNotNullOrEmpty()][string]$BaseUri = 'https://www.virustotal.com'
    )

    $normalized = $BaseUri.TrimEnd('/')
    $isLoopback = $normalized -match '^http://(localhost|127\.0\.0\.1)(:\d+)?$'

    if (-not $isLoopback -and $normalized -notmatch '^https://') {
        throw "EndpointOps: BaseUri must use HTTPS ('$BaseUri'). An API key must not be sent in clear text."
    }

    $connectedAt = Get-Date
    if ($null -eq $script:VtConnection) {
        $script:VtConnection = [pscustomobject]@{
            BaseUri             = $normalized
            ApiKey              = $ApiKey
            ConnectedAt         = $connectedAt
            LastRequestAtUtc    = $null
            DailyRequestDateUtc = [datetime]::UtcNow.Date
            DailyRequestCount   = 0
        }
    }
    else {
        $script:VtConnection.BaseUri = $normalized
        $script:VtConnection.ApiKey = $ApiKey
        $script:VtConnection.ConnectedAt = $connectedAt
    }

    return [pscustomobject]@{
        PSTypeName  = 'EndpointOps.VirusTotal.Connection'
        BaseUri     = $normalized
        ConnectedAt = $connectedAt
    }
}
