function Get-EpmPolicyHygieneReport {
    <#
    .SYNOPSIS
        Reports EPM application policies with missing descriptions.
    .DESCRIPTION
        Identifies policies whose descriptions provide no useful information and sorts them from
        highest to lowest severity. A policy that cannot be explained cannot be reviewed reliably.

        A description is available only from policy details, not from the list response. This
        report therefore retrieves the details of EACH policy in the set, making one call per policy
        at the rate imposed by Get-EpmPolicyDetail. Policy APIs are capped at
        30 calls per minute and no timing header is documented at EPM level: the limit cannot be
        exceeded and then recovered. On a set of 200 policies, the review therefore takes more than
        seven minutes. This duration reflects the cost of retrieving the required data.

        The EPM API does not expose policy authors. The Contact field states this limitation
        explicitly rather than leaving the field blank.
    .PARAMETER SetId
        Identifier of the set, as returned by Get-EpmSet.
    .PARAMETER MinimumSeverity
        Only return the lines of this severity or worse.
    .PARAMETER MinIntervalMs
        Minimum interval between two detail requests, forwarded unchanged to Get-EpmPolicyDetail.
        Only reduce it for good reason.
    .EXAMPLE
        Get-EpmPolicyHygieneReport -SetId $setRecord.Id | Format-Table PolicyName, Severity, Reason
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SetId,
        [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
        [string]$MinimumSeverity = 'None',
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 2100
    )

    $report = [System.Collections.Generic.List[object]]::new()

    $details = @(Get-EpmPolicy -SetId $SetId |
            Get-EpmPolicyDetail -SetId $SetId -MinIntervalMs $MinIntervalMs)

    foreach ($policy in $details) {
        $description = $policy.Description

        # Treat whitespace-only descriptions as missing. IsNullOrWhiteSpace covers null, empty, and
        # whitespace-only values consistently.
        $missingDescription = [string]::IsNullOrWhiteSpace($description)

        if (-not $missingDescription) { continue }

        # Severity is determined by three ordered conditions: maximum scope takes precedence over state,
        # and an inactive policy is assessed last.
        $findings = @()
        if ($policy.IsAppliedToAllComputers) {
            $findings = @([pscustomobject]@{
                    Severity = 'Critical'
                    Reason   = "Policy without description applied to all endpoints: maximum scope, no written justification. No one can say why it exists or what it covers."
                })
        }
        elseif ($policy.IsActive) {
            $findings = @([pscustomobject]@{
                    Severity = 'High'
                    Reason   = "Policy without description and currently active: it has effects that no one can justify."
                })
        }
        else {
            $findings = @([pscustomobject]@{
                    Severity = 'Medium'
                    Reason   = "Policy without description and disabled: the risk is different, not absent. Reactivating a policy that no one understands is an incident waiting to happen."
                })
        }

        # Use the module-wide severity vocabulary so reports remain comparable.
        $severity = Get-WorstSeverity -Findings $findings

        if ($script:SeverityRank[$severity] -lt $script:SeverityRank[$MinimumSeverity]) {
            continue
        }

        $report.Add([pscustomobject]@{
                PSTypeName              = 'EndpointOps.Epm.PolicyHygiene'
                PolicyId                = $policy.PolicyId
                PolicyName              = $policy.PolicyName
                IsActive                = $policy.IsActive
                IsAppliedToAllComputers = $policy.IsAppliedToAllComputers
                Severity                = $severity
                Reason                  = $findings[0].Reason

                # The EPM API does not expose policy authors: Get policies returns only dates, and
                # policyaudits returns application events despite its name. An explicit sentence avoids
                # implying that the field simply has not yet been populated.
                Contact                 = 'Not available through the EPM API'
            })
    }

    # @() envelope mandatory: an empty array flattens to $null, and reading .Count on $null raises under
    # Set-StrictMode. A set without a policy is a normal result, not a failure.
    return @($report.ToArray() |
            Sort-Object -Property @{ Expression = { $script:SeverityRank[$_.Severity] }; Descending = $true }, PolicyId)
}
