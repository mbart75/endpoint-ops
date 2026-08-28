function Get-EpmSet {
    <#
    .SYNOPSIS
        Lists the CyberArk EPM sets in the connected tenant.
    .DESCRIPTION
        A set defines the scope of all other EPM queries: policies and events are always requested
        for a specific set. This function is therefore the entry point for any EPM workflow.

        Offset pagination is handled by the request layer, which keeps each offset as an integer
        multiple of the requested page size as required by the API.

        The normalization of fields is delegated to ConvertTo-EpmSet, which handles the naming
        inconsistency in the documentation (Id/Name/Description versus
        SetId/SetName/SetDescription) in one place.
    .PARAMETER Limit
        Page size requested from the server. The documentation allows 1 to 1000.
    .EXAMPLE
        Get-EpmSet | Where-Object { -not $_.Description }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateRange(1, 1000)][int]$Limit = 250
    )

    $rawRecord = Invoke-EpmRequest -Path '/EPM/API/Sets' -PaginationStyle Offset -ItemsProperty 'Sets' -Limit $Limit

    foreach ($setRecord in $rawRecord) {
        ConvertTo-EpmSet -InputObject $setRecord
    }
}
