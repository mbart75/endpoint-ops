function Get-S1DeviceControlEvent {
    <#
    .SYNOPSIS
        Retrieves Device Control connection events.
    .DESCRIPTION
        Returns the normalized connection events of the connected tenant. This function is
        read-only: it does not assess an event or modify any authorization.

        Linux agents do not support Device Control, and this endpoint requires the Control SKU. An
        out-of-scope machine therefore produces NO events, which looks exactly like a machine with
        no connected devices. This function reports the API response without distinguishing those
        cases; the report layer is responsible for doing so.
    .PARAMETER AgentId
        Agent's ID whose events are requested.
    .PARAMETER Since
        Lower EventTime boundary. It is converted to ISO-8601 UTC before transmission to avoid shifting
        the observed period.
    .PARAMETER Limit
        Limits the query to events on the first requested page. Useful for targeted
        enrichment, for example with -Limit 1. The command does not promise any sorting order.
    .PARAMETER CountOnly
        Returns only the number of events. This mode does not follow pagination and therefore sends
        only one request.
    .EXAMPLE
        Get-S1DeviceControlEvent -AgentId '1006' -Since (Get-Date).AddDays(-30)
    #>
    [CmdletBinding()]
    [OutputType([int], [pscustomobject])]
    param(
        [ValidateNotNullOrEmpty()][ValidatePattern('\S')][string]$AgentId,
        [datetime]$Since,
        [ValidateRange(1, 1000)][int]$Limit,
        [switch]$CountOnly
    )

    if ($CountOnly -and $PSBoundParameters.ContainsKey('Limit')) {
        throw 'EndpointOps: Limit and CountOnly cannot be used together'
    }

    $query = @{}
    if ($PSBoundParameters.ContainsKey('AgentId')) {
        $query['agentIds'] = $AgentId
    }
    if ($PSBoundParameters.ContainsKey('Since')) {
        $query['eventTime__gte'] = "$($Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture))Z"
    }

    if ($CountOnly) {
        $query['countOnly'] = 'true'
        $response = Invoke-S1Request -Path '/web/api/v2.1/device-control/events' -Query $query
        if ($null -eq $response -or @($response.PSObject.Properties.Match('pagination')).Count -eq 0) {
            throw 'EndpointOps: CountOnly requires pagination.totalItems to be a non-negative integer in the API response'
        }

        $pagination = Get-PropertyOrDefault -InputObject $response -Name 'pagination'
        if ($null -eq $pagination -or @($pagination.PSObject.Properties.Match('totalItems')).Count -eq 0) {
            throw 'EndpointOps: CountOnly requires pagination.totalItems to be a non-negative integer in the API response'
        }

        $totalItems = Get-PropertyOrDefault -InputObject $pagination -Name 'totalItems'
        [int]$count = 0
        if ($null -eq $totalItems -or -not [int]::TryParse([string]$totalItems, [ref]$count) -or $count -lt 0) {
            throw 'EndpointOps: CountOnly requires pagination.totalItems to be a non-negative integer in the API response'
        }

        $dataProperty = $response.PSObject.Properties['data']
        $data = $null
        if ($null -ne $dataProperty) {
            $data = $dataProperty.Value
        }
        if ($null -eq $data -or $data -is [string] -or
            $data -isnot [System.Collections.IEnumerable] -or
            $data -is [System.Collections.IDictionary] -or @($data).Count -ne 0) {
            throw 'EndpointOps: CountOnly requires data to be an empty collection in the API response'
        }

        $nextCursorProperty = $pagination.PSObject.Properties['nextCursor']
        if ($null -ne $nextCursorProperty -and
            -not [string]::IsNullOrEmpty([string]$nextCursorProperty.Value)) {
            throw 'EndpointOps: CountOnly requires pagination.nextCursor absent, null or empty in the API response'
        }

        return $count
    }

    if ($PSBoundParameters.ContainsKey('Limit')) {
        $query['limit'] = $Limit
        $response = Invoke-S1Request -Path '/web/api/v2.1/device-control/events' -Query $query
        $dataProperty = $null
        if ($null -ne $response) {
            $dataProperty = $response.PSObject.Properties['data']
        }
        $data = $null
        if ($null -ne $dataProperty) {
            $data = $dataProperty.Value
        }
        if ($null -eq $data -or $data -is [string] -or
            $data -isnot [System.Collections.IEnumerable] -or
            $data -is [System.Collections.IDictionary]) {
            throw 'EndpointOps: a limited query requires data to be a collection of non-null, non-primitive objects'
        }

        $raw = @($data)
        foreach ($item in $raw) {
            if ($item -isnot [pscustomobject]) {
                throw 'EndpointOps: a limited query requires data to be a collection of non-null, non-primitive objects'
            }
        }
    }
    else {
        $raw = @(Invoke-S1Request -Path '/web/api/v2.1/device-control/events' -Query $query -Paginate)
    }

    $events = [System.Collections.Generic.List[object]]::new()
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
              [System.Globalization.DateTimeStyles]::AssumeUniversal

    foreach ($deviceEvent in $raw) {
        $eventTime = Get-PropertyOrDefault -InputObject $deviceEvent -Name 'eventTime'

        $events.Add([pscustomobject]@{
            PSTypeName = 'EndpointOps.S1.DeviceControlEvent'
            Id         = [string](Get-PropertyOrDefault -InputObject $deviceEvent -Name 'id' -Default '')
            AgentId    = [string](Get-PropertyOrDefault -InputObject $deviceEvent -Name 'agentId' -Default '')
            GroupId    = [string](Get-PropertyOrDefault -InputObject $deviceEvent -Name 'groupId' -Default '')
            SiteId     = [string](Get-PropertyOrDefault -InputObject $deviceEvent -Name 'siteId' -Default '')
            EventTime  = if ([string]::IsNullOrWhiteSpace([string]$eventTime)) { $null }
                         else { [datetime]::Parse([string]$eventTime, [cultureinfo]::InvariantCulture, $styles) }
        })
    }

    return $events.ToArray()
}
