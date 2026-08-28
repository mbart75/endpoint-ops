function Invoke-S1Request {
    <#
    .SYNOPSIS
        Calls a SentinelOne endpoint with the current authentication.
    .DESCRIPTION
        Central entry point for SentinelOne calls. It resolves the base URL from connection state,
        builds the request URI, injects the authentication header, and delegates retries, backoff,
        and pagination to the shared transport layer.

        The token is converted to plain text only while constructing the request header and is never
        assigned to longer-lived module state in that form.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [hashtable]$Query = @{},
        [switch]$Paginate,
        [string]$Method = 'Get',
        [string]$Body
    )

    $state = Get-S1ConnectionState
    $uri   = "$($state.BaseUri)$Path"

    if ($Query.Count -gt 0) {
        $pairs = foreach ($key in $Query.Keys) {
            "$([uri]::EscapeDataString($key))=$([uri]::EscapeDataString([string]$Query[$key]))"
        }
        # Escape '?' so PowerShell does not treat it as the start of a subexpression in the
        # interpolated string.
        $uri = "$uri`?$($pairs -join '&')"
    }

    $headers = @{
        Authorization = "ApiToken $(ConvertFrom-SecureString -SecureString $state.ApiToken -AsPlainText)"
    }

    $arguments = @{
        Uri      = $uri
        Headers  = $headers
        Method   = $Method
        Paginate = $Paginate
    }
    if ($PSBoundParameters.ContainsKey('Body') -and $Body) {
        $arguments['Body'] = $Body
        $headers['Content-Type'] = 'application/json'
    }

    return Invoke-EndpointOpsRequest @arguments
}
