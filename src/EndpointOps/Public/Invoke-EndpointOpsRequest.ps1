function Invoke-EndpointOpsRequest {
    <#
    .SYNOPSIS
        Entry point for module transport.
    .DESCRIPTION
        Execute a query and return the deserialized object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'Get',
        [hashtable]$Headers = @{},
        [int]$MaxAttempts = 4,
        [int]$TimeoutSec = 30,
        [double]$BackoffBaseSec = 1,
        [switch]$Paginate,
        [string]$ItemsProperty = 'data',
        [string]$CursorQueryParam = 'cursor',
        [string]$Body
    )

    $callArgs = @{
        Method         = $Method
        Headers        = $Headers
        MaxAttempts    = $MaxAttempts
        TimeoutSec     = $TimeoutSec
        BackoffBaseSec = $BackoffBaseSec
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $Body) {
        $callArgs['Body'] = $Body
    }

    if (-not $Paginate) {
        $response = Invoke-EndpointOpsHttpRequest -Uri $Uri @callArgs
        return $response.Content | ConvertFrom-Json
    }

    $items   = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    $seen    = [System.Collections.Generic.HashSet[string]]::new()

    while ($nextUri) {
        # A previously seen cursor means the API is looping.
        if (-not $seen.Add($nextUri)) {
            throw "EndpointOps: repeated pagination cursor on $nextUri; stopped to avoid an infinite loop"
        }

        $page = (Invoke-EndpointOpsHttpRequest -Uri $nextUri @callArgs).Content | ConvertFrom-Json

        foreach ($item in $page.$ItemsProperty) {
            $items.Add($item)
        }

        # SentinelOne supplies its cursor in pagination.nextCursor. Read the property defensively
        # because the final page may omit pagination entirely under StrictMode.
        $hasPagination = $page.PSObject.Properties.Name -contains 'pagination'
        $cursor = if ($hasPagination -and $page.pagination.PSObject.Properties.Name -contains 'nextCursor') {
            $page.pagination.nextCursor
        }
        else {
            $null
        }

        if ([string]::IsNullOrEmpty($cursor)) {
            $nextUri = $null
        }
        else {
            # -like treats '?' as a wildcard, so use .Contains() to test for a literal query marker.
            $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
            $nextUri   = "$Uri$separator$CursorQueryParam=$([uri]::EscapeDataString($cursor))"
        }
    }

    return $items.ToArray()
}
