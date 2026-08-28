function Get-EpmPolicyDetail {
    <#
    .SYNOPSIS
        Reads the details of an EPM policy, including its description.
    .DESCRIPTION
        The EPM policy APIs are capped at 30 calls per minute, and details are retrieved one policy at
        a time. For a set of 200 policies, a complete retrieval therefore takes more than seven
        minutes. This is an API constraint, and the function deliberately paces requests to remain
        within it.

        Pacing is enforced here rather than in the request layer because each policy detail is a
        separate pipeline request, not another page of the same request.

        Descriptions are returned verbatim, including whitespace. The report layer decides whether
        a value is meaningful; this retrieval command preserves the API response.
    .PARAMETER SetId
        Identifier of the set, as returned by Get-EpmSet.
    .PARAMETER PolicyId
        Policy identifier. Accepts input via pipeline, including objects rendered by Get-EpmPolicy.
    .PARAMETER MinIntervalMs
        Minimum interval between two detail requests. 2100 ms permits 28 calls per minute, below the
        documented limit of 30. Reduce it only with justification: EPM documents no rate-limit header
        that would allow reliable recovery after exceeding the limit.
    .EXAMPLE
        Get-EpmPolicy -SetId $id | Get-EpmPolicyDetail -SetId $id
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SetId,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()][string]$PolicyId,
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 2100
    )

    begin {
        $policyIndex = 0
        $previousRequestAt = [datetime]::UtcNow
    }

    process {
        if ($policyIndex -gt 0 -and $MinIntervalMs -gt 0) {
            # Account for time already spent in the previous call. Sleeping for the entire interval after
            # a one-second call would unnecessarily extend a large review.
            $remainingDelayMs = $MinIntervalMs - ([datetime]::UtcNow - $previousRequestAt).TotalMilliseconds
            if ($remainingDelayMs -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remainingDelayMs)) }
        }

        $policyIndex++
        # Seven minutes without visual feedback looks like a stalled process. No percentage is shown because
        # the pipeline does not know how many items it will receive.
        Write-Progress -Activity 'Reading EPM policy details' `
            -Status "Policy $policyIndex`: $PolicyId" `
            -CurrentOperation "Enforced interval: one call every $MinIntervalMs ms"

        $previousRequestAt = [datetime]::UtcNow

        try {
            $rawRecord = Invoke-EpmRequest -Path "/EPM/API/Sets/$SetId/Policies/Server/$PolicyId"
        }
        catch {
            # EPM uses 404 for an unknown policy, an invalid set identifier, and insufficient
            # permissions. Preserve that ambiguity instead of reporting a false absence.
            if ($_.Exception.Message -match '\b404\b') {
                throw "EndpointOps: 404 response for policy $PolicyId in set $SetId. EPM uses this code for an unknown policy, an incorrect set identifier, or insufficient account permissions. Do not conclude that the policy is absent."
            }
            throw
        }

        [pscustomobject]@{
            PSTypeName              = 'EndpointOps.Epm.PolicyDetail'
            PolicyId                = Get-PropertyOrDefault -InputObject $rawRecord -Name 'PolicyId'
            PolicyName              = Get-PropertyOrDefault -InputObject $rawRecord -Name 'PolicyName'
            # Normalize a missing description to an empty string, matching ConvertTo-EpmSet.
            Description             = [string](Get-PropertyOrDefault -InputObject $rawRecord -Name 'Description' -Default '')
            IsActive                = [bool](Get-PropertyOrDefault -InputObject $rawRecord -Name 'IsActive' -Default $false)
            Action                  = Get-PropertyOrDefault -InputObject $rawRecord -Name 'Action'
            PolicyType              = Get-PropertyOrDefault -InputObject $rawRecord -Name 'PolicyType'
            Order                   = Get-PropertyOrDefault -InputObject $rawRecord -Name 'Order'
            IsAppliedToAllComputers = [bool](Get-PropertyOrDefault -InputObject $rawRecord -Name 'IsAppliedToAllComputers' -Default $false)
            OsType                  = Get-PropertyOrDefault -InputObject $rawRecord -Name 'OsType'
            CreatedDate             = Get-PropertyOrDefault -InputObject $rawRecord -Name 'CreatedDate'
            ModifiedDate            = Get-PropertyOrDefault -InputObject $rawRecord -Name 'ModifiedDate'
        }
    }

    end {
        Write-Progress -Activity 'Reading EPM policy details' -Completed
    }
}
