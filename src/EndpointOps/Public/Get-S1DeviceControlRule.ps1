function Get-S1DeviceControlRule {
    <#
    .SYNOPSIS
        Lists Device Control rules for the connected tenant.
    .DESCRIPTION
        Returns normalized rules. The MatchBy field indicates whether an
        authorization targets a device specified by its serial number, all copies of a model by its
        product identifier, or every device from a vendor by its manufacturer identifier. ScopeLevel
        and ScopeName show whether the rule applies to a site or group.

        This command is read-only and does not modify Device Control rules.

        The '/web/api/v2.1/restrictions' path could not be confirmed in the public API documentation;
        see docs/api-notes.md for the evidence and limitation.
    .PARAMETER Filter
        Request parameters transmitted as they are to the API.
    .EXAMPLE
        Get-S1DeviceControlRule | Where-Object { $_.MatchBy -eq 'vendorId' }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [hashtable]$Filter = @{}
    )

    $raw = Invoke-S1Request -Path '/web/api/v2.1/restrictions' -Query $Filter -Paginate

    foreach ($rule in $raw) {
        [pscustomobject]@{
            PSTypeName     = 'EndpointOps.S1.DeviceControlRule'
            Id             = Get-PropertyOrDefault -InputObject $rule -Name 'id'
            RuleName       = Get-PropertyOrDefault -InputObject $rule -Name 'ruleName'
            Action         = Get-PropertyOrDefault -InputObject $rule -Name 'action'
            MatchBy        = Get-PropertyOrDefault -InputObject $rule -Name 'matchBy'
            VendorId       = Get-PropertyOrDefault -InputObject $rule -Name 'vendorId'
            ProductId      = Get-PropertyOrDefault -InputObject $rule -Name 'productId'
            SerialId       = Get-PropertyOrDefault -InputObject $rule -Name 'serialId'
            UsbDeviceClass = Get-PropertyOrDefault -InputObject $rule -Name 'usbDeviceClass'
            InterfaceType  = Get-PropertyOrDefault -InputObject $rule -Name 'interfaceType'
            ScopeLevel     = Get-PropertyOrDefault -InputObject $rule -Name 'scopeLevel'
            ScopeName      = Get-PropertyOrDefault -InputObject $rule -Name 'scopeName'
            Description    = Get-PropertyOrDefault -InputObject $rule -Name 'description'
            CreatedBy      = Get-PropertyOrDefault -InputObject $rule -Name 'createdBy'
            CreatedAt      = Get-PropertyOrDefault -InputObject $rule -Name 'createdAt'
            UpdatedBy      = Get-PropertyOrDefault -InputObject $rule -Name 'updatedBy'
            UpdatedAt      = Get-PropertyOrDefault -InputObject $rule -Name 'updatedAt'
        }
    }
}
