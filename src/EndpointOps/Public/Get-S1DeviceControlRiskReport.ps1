function Get-S1DeviceControlRiskReport {
    <#
    .SYNOPSIS
        Reviews device control rules and classifies them by risk.
    .DESCRIPTION
        Retrieves the rules, assesses the scope of each, and returns a sorted report from the most serious
        to the least serious.

        The MatchBy field is displayed alongside severity because it determines whether an
        authorization targets a specific device, an entire model, or an entire manufacturer.
    .PARAMETER MinimumSeverity
        Only return records at this severity or higher.
    .PARAMETER Filter
        Request parameters forwarded unchanged to the API.
    .EXAMPLE
        Get-S1DeviceControlRiskReport -MinimumSeverity High |
            Format-Table RuleName, MatchBy, ScopeName, Severity, Contact
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
        [string]$MinimumSeverity = 'None',
        [hashtable]$Filter = @{}
    )

    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($rule in Get-S1DeviceControlRule -Filter $Filter) {
        $reasons   = @(Measure-DeviceRuleBreadth -Rule $rule)
        $severity = Get-WorstSeverity -Findings $reasons

        if ($script:SeverityRank[$severity] -lt $script:SeverityRank[$MinimumSeverity]) {
            continue
        }

        $owner = if ($rule.UpdatedBy) { $rule.UpdatedBy } else { $rule.CreatedBy }
        if ($owner -like 'svc-*') { $owner = $null }

        $report.Add([pscustomobject]@{
            PSTypeName     = 'EndpointOps.S1.DeviceControlRisk'
            Id             = $rule.Id
            RuleName       = $rule.RuleName
            MatchBy        = $rule.MatchBy
            UsbDeviceClass = $rule.UsbDeviceClass
            ScopeLevel     = $rule.ScopeLevel
            ScopeName      = $rule.ScopeName
            Severity       = $severity
            Reasons        = @($reasons | ForEach-Object { $_.Reason })
            Description    = $rule.Description
            CreatedBy      = $rule.CreatedBy
            UpdatedBy      = $rule.UpdatedBy
            Contact        = $owner
        })
    }

    return $report.ToArray() | Sort-Object -Property @{ Expression = { $script:SeverityRank[$_.Severity] }; Descending = $true }, Id
}
