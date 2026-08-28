# Extraction warning threshold. A named module variable keeps the value visible, documented, and
# testable without creating fifty thousand events.
$script:EpmEventWarningThreshold = 50000

function Get-EpmElevationEvent {
    <#
    .SYNOPSIS
        Retrieves the elevation events of a CyberArk EPM set.
    .DESCRIPTION
        Search is a POST while it is a read: the filter travels in the body of the query. Pagination
        uses a cursor, with the first page requested using the literal value 'start'.

        The Hash field is an SHA1, not an SHA256. Any downstream reputation service will therefore
        need to query a reputation service separately.

        The API caps the extraction at 100,000 events per 24 hours. This limit applies to the
        volume, not the request rate: an excessively wide period can hit it. The function issues a warning beyond
        50,000 events rather than truncating silently.

        Publisher is returned as an empty string rather than $null when absent: an unsigned binary is
        meaningful information, not missing data, and $null would break a report that reads the field
        under Set-StrictMode.
    .PARAMETER SetId
        Identifier of the set, as returned by Get-EpmSet.
    .PARAMETER Since
        Lower boundary applied to eventDate. It is converted to UTC before transmission: the API expects
        ISO-8601 UTC, and a local time would silently shift the observed period. A date without an
        explicit time zone is interpreted as local by .NET, so it is also converted.
    .PARAMETER Until
        Upper boundary applied to eventDate. Uses the same conversion as Since.
    .PARAMETER EventType
        List of types separated by commas, transmitted as is to the eventType IN clause. The default
        covers both forms of elevation requested by a user.
    .PARAMETER Limit
        Page size requested from the server. The documentation allows 1 to 1000.
    .EXAMPLE
        Get-EpmElevationEvent -SetId $setRecord.Id -Since (Get-Date).AddDays(-7)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SetId,
        [datetime]$Since,
        [datetime]$Until,
        [ValidateNotNullOrEmpty()][string]$EventType = 'ElevationRequest,ManualRequest',
        [ValidateRange(1, 1000)][int]$Limit = 250
    )

    $clauses = [System.Collections.Generic.List[string]]::new()
    $clauses.Add("eventType IN $EventType")

    # Convert to UTC, format without an offset, then append the literal 'Z'. This guarantees the
    # exact ISO-8601 form expected by the API.
    if ($PSBoundParameters.ContainsKey('Since')) {
        $clauses.Add("eventDate GE $($Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture))Z")
    }
    if ($PSBoundParameters.ContainsKey('Until')) {
        $clauses.Add("eventDate LE $($Until.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture))Z")
    }

    $requestBody = @{ filter = ($clauses -join ' AND ') } | ConvertTo-Json -Compress

    $rawRecord = @(Invoke-EpmRequest -Path "/EPM/API/Sets/$SetId/Events/Search" `
            -Method 'Post' -Body $requestBody -PaginationStyle Cursor -ItemsProperty 'events' -Limit $Limit)

    if ($rawRecord.Count -gt $script:EpmEventWarningThreshold) {
        # Warn rather than truncate. Silent truncation would produce incomplete and misleading metrics.
        Write-Warning ("EndpointOps: $($rawRecord.Count) events extracted from the $SetId set, beyond the threshold of $($script:EpmEventWarningThreshold)." +
            "The EPM API caps extraction at 100,000 events per 24 hours, and this cap applies to VOLUME, not request rate." +
            'Nothing has been truncated: restrict -Since and -Until rather than relying on a partial result.')
    }

    # EPM dates are documented as UTC. Assume and preserve UTC explicitly so results do not vary with
    # the local time zone of the machine running the report.
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
              [System.Globalization.DateTimeStyles]::AssumeUniversal

    foreach ($eventRecord in $rawRecord) {
        $startTime = Get-PropertyOrDefault -InputObject $eventRecord -Name 'firstEventDate'
        $endTime   = Get-PropertyOrDefault -InputObject $eventRecord -Name 'lastEventDate'

        [pscustomobject]@{
            PSTypeName      = 'EndpointOps.Epm.ElevationEvent'
            Hash            = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'hash' -Default '')
            Publisher       = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'publisher' -Default '')
            EventType       = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'eventType' -Default '')
            UserName        = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'userName' -Default '')
            ComputerName    = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'computerName' -Default '')
            FileName        = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'fileName' -Default '')
            FilePath        = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'filePath' -Default '')
            FileDescription = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'fileDescription' -Default '')
            ProductName     = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'productName' -Default '')
            Company         = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'company' -Default '')
            SourceType      = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'sourceType' -Default '')
            SourceName      = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'sourceName' -Default '')
            PolicyName      = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'policyName' -Default '')
            PolicyAction    = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'policyAction' -Default '')
            Justification   = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'justification' -Default '')
            # Return DateTime values so comparisons remain chronological even when input formats differ.
            FirstEventDate  = if ([string]::IsNullOrWhiteSpace($startTime)) { $null }
                              else { [datetime]::Parse($startTime, [cultureinfo]::InvariantCulture, $styles) }
            LastEventDate   = if ([string]::IsNullOrWhiteSpace($endTime)) { $null }
                              else { [datetime]::Parse($endTime, [cultureinfo]::InvariantCulture, $styles) }
            UserIsAdmin     = [bool](Get-PropertyOrDefault -InputObject $eventRecord -Name 'userIsAdmin' -Default $false)
            AgentId         = [string](Get-PropertyOrDefault -InputObject $eventRecord -Name 'agentId' -Default '')
        }
    }
}
