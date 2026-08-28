Set-StrictMode -Version 3.0

function Invoke-HaRequest {
    <#
    .SYNOPSIS
        Queries Hybrid Analysis by hash and exposes its opaque quota header.
    .DESCRIPTION
        Calls the shared HTTP transport directly so response headers remain available. Api-Limits is
        returned verbatim because its JSON content has no stable public schema and must not be
        inferred.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$')]
        [string]$Hash
    )

    $state = Get-HaConnectionState
    $escapedHash = [uri]::EscapeDataString($Hash)
    $uri = "$($state.BaseUri)/api/v2/search/hash?hash=$escapedHash"
    $headers = @{
        'api-key' = ConvertFrom-SecureString -SecureString $state.ApiKey -AsPlainText
    }

    $response = Invoke-EndpointOpsHttpRequest -Uri $uri -Method Get -Headers $headers -MaxAttempts 1
    if ($null -eq $response -or [string]::IsNullOrWhiteSpace([string]$response.Content)) {
        throw [System.IO.InvalidDataException]::new('Hybrid Analysis: response content is missing.')
    }

    try {
        $data = $response.Content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw [System.IO.InvalidDataException]::new('Hybrid Analysis: response contains invalid JSON.', $_.Exception)
    }

    if ($null -eq $data -or $data.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
        throw [System.IO.InvalidDataException]::new('Hybrid Analysis: SearchByHash must be a JSON object.')
    }

    $apiLimits = $null
    $quotaKnown = $false
    if ($response.Headers.Keys -contains 'Api-Limits') {
        $apiLimitValues = @($response.Headers['Api-Limits'])
        if ($apiLimitValues.Count -gt 0) {
            $apiLimits = [string]$apiLimitValues[0]
            $quotaKnown = $true
        }
    }

    return [pscustomobject]@{
        Data       = $data
        ApiLimits  = $apiLimits
        QuotaKnown = [bool]$quotaKnown
    }
}
