function Get-PropertyOrDefault {
    <#
    .SYNOPSIS
        Reads a property that may not exist without throwing under StrictMode.
    .DESCRIPTION
        Under Set-StrictMode -Version 3.0, reading a missing property raises a
        PropertyNotFoundException. API responses regularly omit fields depending on the version or
        state of the object, so all reads from deserialized JSON must go through this helper.

        A present property whose value is $null returns $null, not the default value: the default
        replaces only an absent property, never an explicit null value from the API.
    .EXAMPLE
        Get-PropertyOrDefault -InputObject $agent -Name 'isDecommissioned' -Default $false
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject.PSObject.Properties.Name -contains $Name) {
        return $InputObject.$Name
    }

    return $Default
}
