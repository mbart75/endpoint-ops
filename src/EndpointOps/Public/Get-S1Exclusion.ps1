function Get-S1Exclusion {
    <#
    .SYNOPSIS
        Lists SentinelOne exclusions in the connected tenant.
    .DESCRIPTION
        Returns normalized exclusions without assessing their scope. Risk classification belongs to
        the review workflow built on this layer.

        The Type field distinguishes a hash exclusion from a path exclusion. This is the first review
        criterion because a path exclusion is structurally broader.

        CreatedBy and UpdatedBy make a review actionable: an unjustified exclusion report is of
        limited use if it cannot identify whom to contact for the reason.
    .PARAMETER Filter
        Request parameters forwarded unchanged to the API.
    .EXAMPLE
        Get-S1Exclusion | Where-Object { $_.Type -eq 'path' -and -not $_.Description }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [hashtable]$Filter = @{}
    )

    $raw = Invoke-S1Request -Path '/web/api/v2.1/exclusions' -Query $Filter -Paginate

    foreach ($exclusion in $raw) {
        [pscustomobject]@{
            PSTypeName  = 'EndpointOps.S1.Exclusion'
            Id          = Get-PropertyOrDefault -InputObject $exclusion -Name 'id'
            Type        = Get-PropertyOrDefault -InputObject $exclusion -Name 'type'
            Value       = Get-PropertyOrDefault -InputObject $exclusion -Name 'value'
            OsType      = Get-PropertyOrDefault -InputObject $exclusion -Name 'osType'
            Mode        = Get-PropertyOrDefault -InputObject $exclusion -Name 'mode'
            ScopeLevel  = Get-PropertyOrDefault -InputObject $exclusion -Name 'scopeLevel'
            ScopeName   = Get-PropertyOrDefault -InputObject $exclusion -Name 'scopeName'
            Description = Get-PropertyOrDefault -InputObject $exclusion -Name 'description'
            CreatedBy   = Get-PropertyOrDefault -InputObject $exclusion -Name 'createdBy'
            CreatedAt   = Get-PropertyOrDefault -InputObject $exclusion -Name 'createdAt'
            UpdatedBy   = Get-PropertyOrDefault -InputObject $exclusion -Name 'updatedBy'
            UpdatedAt   = Get-PropertyOrDefault -InputObject $exclusion -Name 'updatedAt'
        }
    }
}
