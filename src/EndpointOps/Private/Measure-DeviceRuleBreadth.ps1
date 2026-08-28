function Measure-DeviceRuleBreadth {
    <#
    .SYNOPSIS
        Assesses the scope of a device control rule.
    .DESCRIPTION
        A well-scoped authorization targets a specific device by serial number. For a smartphone,
        the expected criteria are its serial number and USB class 06 (Image) in the dedicated group.

        Three deviations are rated by severity: a product identifier authorizes every instance of a
        model; a manufacturer identifier authorizes every device from that vendor; and a manufacturer
        identifier in the smartphone group appears narrowly scoped while still covering the vendor's
        entire product range.
    .PARAMETER Rule
        A rule returned by Get-S1DeviceControlRule.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]$Rule
    )

    $reasons  = [System.Collections.Generic.List[object]]::new()
    $matchCriterion = Get-PropertyOrDefault -InputObject $Rule -Name 'MatchBy'
    $deviceClass  = Get-PropertyOrDefault -InputObject $Rule -Name 'UsbDeviceClass'
    $groupName  = Get-PropertyOrDefault -InputObject $Rule -Name 'ScopeName'
    $scopeLevel  = Get-PropertyOrDefault -InputObject $Rule -Name 'ScopeLevel'
    $justification  = Get-PropertyOrDefault -InputObject $Rule -Name 'Description'

    # Check the smartphone group first: this is the same technical issue as an ordinary manufacturer
    # identifier, but it is difficult to detect at first glance because the rule is stored in the
    # expected location.
    if ($matchCriterion -eq 'vendorId' -and $groupName -eq 'Smartphones' -and $deviceClass -eq '06') {
        $reasons.Add([pscustomobject]@{
            Severity = 'Critical'
            Reason   = 'Manufacturer identifier in the smartphone group: allows every phone from the manufacturer; serial number and class 06 are expected'
        })
    }
    elseif ($matchCriterion -eq 'vendorId') {
        $reasons.Add([pscustomobject]@{
            Severity = 'Critical'
            Reason   = 'Manufacturer identifier: authorizes every device produced by the manufacturer'
        })
    }
    elseif ($matchCriterion -eq 'productId') {
        $reasons.Add([pscustomobject]@{
            Severity = 'High'
            Reason   = 'Product identifier: authorizes all copies of the model, not a device'
        })
    }

    if ($scopeLevel -eq 'site') {
        $reasons.Add([pscustomobject]@{
            Severity = 'High'
            Reason   = 'Site-wide scope instead of group scope; the rule affects far more machines than necessary'
        })
    }

    if ([string]::IsNullOrWhiteSpace($justification)) {
        $reasons.Add([pscustomobject]@{
            Severity = 'Medium'
            Reason   = 'No justification; the original request cannot be identified'
        })
    }

    return $reasons.ToArray()
}
