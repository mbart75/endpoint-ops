Set-StrictMode -Version 3.0

function Invoke-MbRequest {
    <#
    .SYNOPSIS
        Queries MalwareBazaar for a SHA-1 hash.
    .DESCRIPTION
        Builds an application/x-www-form-urlencoded POST request with the in-memory key. The key is
        converted to plain text only while constructing the Auth-Key header.

        MalwareBazaar returns HTTP 200 even when a hash is unknown. The query_status field, rather
        than the HTTP status, carries the application result. Validating that field prevents an empty
        body from being treated as a successful lookup under StrictMode.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Hash
    )

    $state = Get-MbConnectionState
    $headers = @{
        'Auth-Key'     = ConvertFrom-SecureString -SecureString $state.AuthKey -AsPlainText
        'Content-Type' = 'application/x-www-form-urlencoded'
    }
    $body = "query=get_info&hash=$([uri]::EscapeDataString($Hash))"
    $response = Invoke-EndpointOpsRequest -Uri "$($state.BaseUri)/api/v1/" -Method Post `
        -Headers $headers -Body $body -MaxAttempts 1

    if ($null -eq $response -or $response.PSObject.Properties.Name -notcontains 'query_status') {
        throw [System.IO.InvalidDataException]::new('MalwareBazaar: query_status is missing.')
    }

    $queryStatus = [string]$response.query_status
    if ([string]::IsNullOrWhiteSpace($queryStatus)) {
        throw [System.IO.InvalidDataException]::new('MalwareBazaar: query_status is invalid.')
    }

    switch ($queryStatus) {
        'ok' {
            if ($response.PSObject.Properties.Name -notcontains 'data') {
                throw [System.IO.InvalidDataException]::new('MalwareBazaar: query_status is ok but data is missing.')
            }
            return [pscustomobject]@{
                QueryStatus = $queryStatus
                Data        = $response.data
            }
        }
        'hash_not_found' {
            return [pscustomobject]@{
                QueryStatus = $queryStatus
                Data        = $null
            }
        }
        'illegal_hash' {
            return [pscustomobject]@{
                QueryStatus = $queryStatus
                Data        = $null
            }
        }
        'no_selector' {
            return [pscustomobject]@{
                QueryStatus = $queryStatus
                Data        = $null
            }
        }
        default {
            return [pscustomobject]@{
                QueryStatus = $queryStatus
                Data        = $null
            }
        }
    }
}
