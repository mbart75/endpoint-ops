function ConvertTo-EpmSet {
    <#
    .SYNOPSIS
        Normalizes an EPM set regardless of the response field shape.
    .DESCRIPTION
        The documentation of Get sets list contradicts itself: its JSON example names the fields
        Id/Name/Description, its descriptive table names them SetId/SetName/SetDescription. In the
        absence of a real tenant to decide, both forms are accepted.

        Missing description becomes an empty string and not $null: a report should not have to
        distinguish between "missing field" and "empty field", both mean the same thing for a human.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject
    )

    if ($null -eq $InputObject) { return $null }

    $id = Get-PropertyOrDefault -InputObject $InputObject -Name 'Id'
    if (-not $id) { $id = Get-PropertyOrDefault -InputObject $InputObject -Name 'SetId' }

    $name = Get-PropertyOrDefault -InputObject $InputObject -Name 'Name'
    if (-not $name) { $name = Get-PropertyOrDefault -InputObject $InputObject -Name 'SetName' }

    $description = Get-PropertyOrDefault -InputObject $InputObject -Name 'Description'
    if (-not $description) {
        $description = Get-PropertyOrDefault -InputObject $InputObject -Name 'SetDescription' -Default ''
    }

    return [pscustomobject]@{
        PSTypeName  = 'EndpointOps.Epm.Set'
        Id          = $id
        Name        = $name
        Description = if ($null -eq $description) { '' } else { $description }
        IsNPVDI     = [bool](Get-PropertyOrDefault -InputObject $InputObject -Name 'IsNPVDI' -Default $false)
    }
}
