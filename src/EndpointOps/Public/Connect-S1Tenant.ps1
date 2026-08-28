function Connect-S1Tenant {
    <#
    .SYNOPSIS
        Opens a SentinelOne session for the module.
    .DESCRIPTION
        Keeps the console URL and API token in memory within module scope. The token is never written
        to disk or returned to the caller, and is converted to plain text only while building a
        request header.

        HTTPS is required except for loopback addresses, which allows mock server tests to run
        without a certificate while preventing clear-text token transmission over a network.

        By default, the connection is immediately validated by a single-item request.
        -SkipValidation bypasses this check, for example when preparing an offline connection.
    .EXAMPLE
        $token = Read-Host -AsSecureString 'SentinelOne API token'
        Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $token
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BaseUri,
        [Parameter(Mandatory)][ValidateNotNull()][securestring]$ApiToken,
        [switch]$SkipValidation
    )

    $normalized = $BaseUri.TrimEnd('/')
    $isLoopback = $normalized -match '^http://(localhost|127\.0\.0\.1)(:\d+)?$'

    if (-not $isLoopback -and $normalized -notmatch '^https://') {
        throw "EndpointOps: BaseUri must use HTTPS ('$BaseUri'). An API token must not be sent in clear text."
    }

    $script:S1Connection = [pscustomobject]@{
        BaseUri     = $normalized
        ApiToken    = $ApiToken
        ConnectedAt = Get-Date
    }

    if (-not $SkipValidation) {
        try {
            # Validate with a single-item request to the endpoint confirmed in docs/api-notes.md instead
            # of inventing a health endpoint. Failing here provides a clearer error than a later 401.
            $null = Invoke-S1Request -Path '/web/api/v2.1/agents' -Query @{ limit = 1 }
        }
        catch {
            # Do not leave a connection half open behind a failure.
            $script:S1Connection = $null
            throw "EndpointOps: connection to $normalized refused ($($_.Exception.Message))"
        }
    }

    return [pscustomobject]@{
        PSTypeName  = 'EndpointOps.S1.Connection'
        BaseUri     = $normalized
        ConnectedAt = $script:S1Connection.ConnectedAt
        Validated   = -not $SkipValidation
    }
}
