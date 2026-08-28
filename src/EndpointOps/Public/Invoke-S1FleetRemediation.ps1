function Invoke-S1FleetRemediation {
    <#
    .SYNOPSIS
        Moves tier 1 agents to a tracking group.
    .DESCRIPTION
        This is the module's only write operation. It acts exclusively on tier 1 findings by moving
        agents to a tracking group. Tier 0 requires offline investigation, while tier 2 remains a
        proposal for human review; this command never applies a stricter security policy.

        Confirmation is requested by default. Use -WhatIf to preview the move without changing the
        tenant.
    .PARAMETER Agent
        One or more records from Get-S1FleetHygieneReport. Only tier 1 records trigger an action;
        all other tiers are ignored.
    .PARAMETER TrackingGroupId
        Identifier of the tracking group to which the agents are moved.
    .EXAMPLE
        Get-S1FleetHygieneReport -TargetAgentVersion '23.4.2.350' -SupportedBuilds $supportedBuilds |
            Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Agent,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TrackingGroupId
    )

    begin {
        # Validate the connection once, outside ShouldProcess. This prevents -WhatIf from presenting
        # an operation that the current session could not execute.
        $null = Get-S1ConnectionState
    }

    process {
        foreach ($line in @($Agent)) {
            $remediationTier = Get-PropertyOrDefault -InputObject $line -Name 'Tier'
            if ($remediationTier -ne 1) { continue }

            $computerName = Get-PropertyOrDefault -InputObject $line -Name 'ComputerName'
            $id  = Get-PropertyOrDefault -InputObject $line -Name 'Id'

            $moved = $false

            if ($PSCmdlet.ShouldProcess("$computerName (id $id)", "Move to the $TrackingGroupId tracking group")) {
                $requestBody = @{ agentIds = @([string]$id); groupId = $TrackingGroupId } | ConvertTo-Json -Compress
                $null = Invoke-S1Request -Path '/web/api/v2.1/agents/actions/move-to-group' -Method 'Post' -Body $requestBody
                $moved = $true
            }

            [pscustomobject]@{
                PSTypeName    = 'EndpointOps.S1.RemediationResult'
                Id            = $id
                ComputerName  = $computerName
                TargetGroupId = $TrackingGroupId
                Moved         = $moved
            }
        }
    }
}
