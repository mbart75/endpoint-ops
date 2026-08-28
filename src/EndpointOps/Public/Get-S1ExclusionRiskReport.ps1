function Get-S1ExclusionRiskReport {
    <#
    .SYNOPSIS
        Reviews tenant exclusions and classifies them by risk.
    .DESCRIPTION
        Retrieves the exclusions, assesses the scope of each, and returns a sorted report from the most
        serious to the least serious.

        Each record includes clear reasons and a contact person. Reporting that an exclusion is too
        broad without telling who to ask for the reason does not move a review forward: it is the
        Contact field that makes the report actionable. When the exclusion was last modified by a
        service account, Contact is empty, which is itself useful information.
    .PARAMETER MinimumSeverity
        Only return records at this severity or higher.
    .PARAMETER Filter
        Request parameters forwarded unchanged to the API.
    .EXAMPLE
        Get-S1ExclusionRiskReport -MinimumSeverity High | Format-Table Id, Value, Severity, Contact
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
        [string]$MinimumSeverity = 'None',
        [hashtable]$Filter = @{}
    )

    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($exclusion in Get-S1Exclusion -Filter $Filter) {
        $reasons   = @(Measure-ExclusionBreadth -Exclusion $exclusion)
        $severity = Get-WorstSeverity -Findings $reasons

        if ($script:SeverityRank[$severity] -lt $script:SeverityRank[$MinimumSeverity]) {
            continue
        }

        # The last modifier explains the current state of the rule; the creator reflects only the original intent.
        # A service account is not a contact person, so no contact is suggested in that case.
        $owner = if ($exclusion.UpdatedBy) { $exclusion.UpdatedBy } else { $exclusion.CreatedBy }
        if ($owner -like 'svc-*') { $owner = $null }

        $report.Add([pscustomobject]@{
            PSTypeName  = 'EndpointOps.S1.ExclusionRisk'
            Id          = $exclusion.Id
            Type        = $exclusion.Type
            Value       = $exclusion.Value
            ScopeLevel  = $exclusion.ScopeLevel
            ScopeName   = $exclusion.ScopeName
            Severity    = $severity
            Reasons     = @($reasons | ForEach-Object { $_.Reason })
            Description = $exclusion.Description
            CreatedBy   = $exclusion.CreatedBy
            UpdatedBy   = $exclusion.UpdatedBy
            Contact     = $owner
        })
    }

    # Sort explicitly by rank because alphabetical severity order is meaningless.
    return $report.ToArray() | Sort-Object -Property @{ Expression = { $script:SeverityRank[$_.Severity] }; Descending = $true }, Id
}
