function Get-S1FleetHygieneReport {
    <#
    .SYNOPSIS
        Reports fleet hygiene and the response tier associated with each agent.
    .DESCRIPTION
        Replaces manual sorting of console exports. Flags silent agents, decommissioning
        inconsistencies, outdated agent versions, and outdated system builds or branches that are no longer
        supported.

        The tier summarizes the available response: 0 means the agent is silent and no remote action
        is possible; 1 means the agent communicates but its version is outdated while the system is
        current; 2 means both the agent and system are outdated.

        The build reference is an input, not a value provided by the API: each fleet has its
        own targets. Without a reference, the system status is 'Unknown' rather than giving the
        impression that everything is fine.
    .PARAMETER TargetAgentVersion
        Expected agent version. Any different version is considered outdated.
    .PARAMETER SupportedBuilds
        Table mapping each branch to its minimum revision, for example @{ '22631' = 4890 }. A branch missing
        from the table is considered unsupported.
    .PARAMETER SilentAfterDays
        Number of days without activity beyond which an agent is said to be silent.
    .PARAMETER ReferenceDate
        Reference date used to calculate inactivity. Defaults to the current date and can be set for
        reproducible reporting.
    .PARAMETER OnlyActionable
        Only return agents who have at least one observation.
    .EXAMPLE
        Get-S1FleetHygieneReport -TargetAgentVersion '23.4.2.350' `
            -SupportedBuilds @{ '22631' = 4890 } -OnlyActionable |
            Format-Table ComputerName, Tier, OsBuildStatus, RecommendedAction
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TargetAgentVersion,
        [Parameter(Mandatory)][hashtable]$SupportedBuilds,
        [int]$SilentAfterDays = 30,
        [datetime]$ReferenceDate = (Get-Date),
        [switch]$OnlyActionable,
        [hashtable]$Filter = @{}
    )

    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($agent in Get-S1Agent -Filter $Filter) {
        $findings = [System.Collections.Generic.List[string]]::new()

        $lastActivity = $agent.LastActiveDate
        $inactiveDays = if ($lastActivity) {
            [int]($ReferenceDate - $lastActivity).TotalDays
        }
        else {
            $null
        }

        $silent = ($agent.NetworkStatus -eq 'disconnected') -or
                      ($null -ne $inactiveDays -and $inactiveDays -ge $SilentAfterDays)

        if ($silent) {
            $findings.Add("Silent agent for $inactiveDays days")
        }

        # Track inconsistencies in both directions, but the first case is particularly risky: a machine
        # marked as decommissioned in the console continues to run without being monitored.
        if ($agent.IsDecommissioned -and -not $silent) {
            $findings.Add('Machine marked as decommissioned in the console while the agent is still communicating')
        }

        $agentOutdated = $agent.AgentVersion -ne $TargetAgentVersion
        if ($agentOutdated) {
            $findings.Add("Agent version $($agent.AgentVersion), expected $TargetAgentVersion")
        }

        $osStatus = Test-OsBuildStatus -OsRevision $agent.OsRevision -SupportedBuilds $SupportedBuilds
        if ($osStatus -eq 'OutdatedRevision') {
            $findings.Add("Operating system patch is outdated (build $($agent.OsRevision))")
        }
        elseif ($osStatus -eq 'UnsupportedBranch') {
            $findings.Add("System branch not supported (build $($agent.OsRevision)), no more patches expected")
        }

        $osOutdated = $osStatus -in @('OutdatedRevision', 'UnsupportedBranch')

        $remediationTier = if ($silent) { 0 }
                  elseif ($agentOutdated -and $osOutdated) { 2 }
                  elseif ($agentOutdated) { 1 }
                  else { $null }

        $action = switch ($remediationTier) {
            0       { 'Investigate offline; no remote action is possible while the agent is unreachable' }
            1       { 'Move to the tracking group and collect diagnostic information' }
            2       { 'Review a stricter policy with a human approver before applying any change' }
            default { $null }
        }

        if ($OnlyActionable -and $findings.Count -eq 0) {
            continue
        }

        $report.Add([pscustomobject]@{
            PSTypeName        = 'EndpointOps.S1.FleetHygiene'
            Id                = $agent.Id
            ComputerName      = $agent.ComputerName
            AgentVersion      = $agent.AgentVersion
            OsName            = $agent.OsName
            OsRevision        = $agent.OsRevision
            OsBuildStatus     = $osStatus
            LastActiveDate    = $agent.LastActiveDate
            DaysSinceLastSeen = $inactiveDays
            IsDecommissioned  = $agent.IsDecommissioned
            GroupName         = $agent.GroupName
            SiteName          = $agent.SiteName
            Tier              = $remediationTier
            RecommendedAction = $action
            Findings          = $findings.ToArray()
        })
    }

    return $report.ToArray()
}
