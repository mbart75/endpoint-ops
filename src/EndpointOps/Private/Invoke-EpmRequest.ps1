function Invoke-EpmRequest {
    <#
    .SYNOPSIS
        Calls a CyberArk EPM endpoint with the current authentication.
    .DESCRIPTION
        All URLs are built on ManagerUri, never on DispatcherUri: the dispatcher is only used to
        authenticate and verify connectivity.

        EPM pagination is handled here rather than by Invoke-EndpointOpsRequest -Paginate. EPM uses
        either an offset that must remain a multiple of the page size or a cursor whose initial value
        is the literal 'start'. Retries and backoff still come from the shared transport layer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [hashtable]$Query = @{},
        [string]$Method = 'Get',
        [string]$Body,
        [ValidateSet('None', 'Offset', 'Cursor')][string]$PaginationStyle = 'None',
        [ValidateRange(1, 1000)][int]$Limit = 250,
        [string]$ItemsProperty = 'events',
        [ValidateRange(1, 10000)][int]$MaxPages = 200,
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 0
    )

    $state = Get-EpmConnectionState

    # The central distinction in the EPM model is ManagerUri, the address returned by the dispatcher.
    # The documentation repeatedly identifies it as the EPM server rather than the dispatcher server.
    $baseUri = "$($state.ManagerUri)".TrimEnd('/') + $Path

    $headers = @{
        # The lowercase 'basic' scheme is followed by the raw token. This is not HTTP Basic auth, and
        # nothing must be encoded.
        Authorization = "basic $(ConvertFrom-SecureString -SecureString $state.Token -AsPlainText)"
    }

    $callArgs = @{
        Headers = $headers
        Method  = $Method
    }
    if ($PSBoundParameters.ContainsKey('Body') -and $Body) {
        $callArgs['Body'] = $Body
        $headers['Content-Type'] = 'application/json'
    }

    $items       = [System.Collections.Generic.List[object]]::new()
    $seenCursors = [System.Collections.Generic.HashSet[string]]::new()
    $offset      = 0
    $cursor      = 'start'
    $pageCount   = 0

    while ($true) {
        # Bound pagination even when a server keeps returning new cursors indefinitely.
        if ($pageCount -ge $MaxPages) {
            throw "EndpointOps: $MaxPages page limit reached on $Path; pagination aborted"
        }

        # EPM documents no rate-limit response header equivalent to Retry-After. Enforce pacing
        # proactively between pages instead of waiting for a recoverable server response.
        if ($pageCount -gt 0 -and $MinIntervalMs -gt 0) {
            Start-Sleep -Milliseconds $MinIntervalMs
        }

        $pageQuery = @{}
        foreach ($key in $Query.Keys) { $pageQuery[$key] = $Query[$key] }

        if ($PaginationStyle -eq 'Offset') {
            $pageQuery['offset'] = $offset
            $pageQuery['limit']  = $Limit
        }
        elseif ($PaginationStyle -eq 'Cursor') {
            $pageQuery['nextCursor'] = $cursor
            $pageQuery['limit']      = $Limit
        }

        $uri = $baseUri
        if ($pageQuery.Count -gt 0) {
            $pairs = foreach ($key in $pageQuery.Keys) {
                "$([uri]::EscapeDataString($key))=$([uri]::EscapeDataString([string]$pageQuery[$key]))"
            }
            # Escape '?' so PowerShell does not treat it as the start of a subexpression in the
            # interpolated string.
            $uri = "$baseUri`?$($pairs -join '&')"
        }

        try {
            # Reuse the request body on every page. Omitting it after the first request would silently
            # return unfiltered data and corrupt the resulting metrics.
            $page = Invoke-EndpointOpsRequest -Uri $uri @callArgs
        }
        catch {
            # A 401 generally means that the EPM session expired; token lifetime depends on tenant
            # configuration. Rephrase the error without exposing the token and explain the one-minute
            # connection limit so callers do not retry immediately.
            #
            # The transport layer does not expose a typed status-code exception, so this fallback
            # extracts the status from its sanitized message.
            if ($_.Exception.Message -match '\b401\b') {
                throw "EndpointOps: the CyberArk EPM session has expired (401) on $Path. Please reconnect with Connect-EpmTenant. Note, CyberArk only allows one connection per minute and per user: if you have just logged in, wait a minute before trying again."
            }
            throw
        }
        $pageCount++

        if ($PaginationStyle -eq 'None') { return $page }

        # Preserve an empty collection as an array; otherwise PowerShell flattens it to $null and
        # .Count fails under StrictMode.
        $pageItems = @(Get-PropertyOrDefault -InputObject $page -Name $ItemsProperty -Default @())
        foreach ($item in $pageItems) { $items.Add($item) }

        if ($PaginationStyle -eq 'Offset') {
            # An empty page is the termination condition when the endpoint does not expose TotalCount.
            if ($pageItems.Count -eq 0) { break }

            $totalCount = Get-PropertyOrDefault -InputObject $page -Name 'TotalCount'
            if ($null -ne $totalCount -and $items.Count -ge [int]$totalCount) { break }

            # Advance by the requested limit, not the received item count. The API requires offsets
            # to remain multiples of the page size.
            $offset += $Limit
        }
        else {
            $next = Get-EpmNextCursor -Page $page
            if ($null -eq $next) { break }

            # A repeated cursor means the API is looping.
            if (-not $seenCursors.Add($next)) {
                throw "EndpointOps: EPM cursor repeats on $Path; pagination stopped to avoid an infinite loop"
            }
            $cursor = $next
        }
    }

    return $items.ToArray()
}
