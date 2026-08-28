function Get-S1UnusedAuthorizationReport {
    <#
    .SYNOPSIS
        Reports unused Device Control permissions at two thresholds.
    .DESCRIPTION
        Correlates current permissive groups with Device Control events. The report proposes an
        alert or a removal, without ever modifying an agent or an authorization.

        Device Control covers only Windows and macOS. Other operating systems are explicitly marked
        OutOfScope rather than being confused with a lack of use.

        The Control SKU is not visible in agent data. Without -ControlSkuAvailable, the
        report therefore adopts the fail-safe behavior: the agents of the permissive groups are
        OutOfScope and no Device Control events are queried.

        This report does not say WHEN the machine was moved to its current group, nor BY WHOM. The
        corresponding type of activity is not publicly documented (see docs/api-notes.md). The
        observation stands on its own; enrichment can be added when a real tenant provides the value.
    .PARAMETER PermissiveGroupName
        Names of groups whose Device Control authorization must be reviewed.
    .PARAMETER RetentionDays
        Effective retention of the tenant. No default value is assumed.
    .PARAMETER AlertAfterDays
        Window without an event that triggers an alert. By default, 30 days.
    .PARAMETER RemoveAfterDays
        Event-free window after which removal is proposed. The default is 60 days.
    .PARAMETER ReferenceDate
        Reference date of the two windows. By default, now.
    .PARAMETER ControlSkuAvailable
        Availability of the Control SKU must be explicitly confirmed for the tenant. Without this
        evidence, no absence of use or removal proposal is produced.
    .PARAMETER IncludeLastSeen
        Searches for a connection date only for machines already included in the report. The Device
        Control API does not guarantee sort order.
    .EXAMPLE
        Get-S1UnusedAuthorizationReport -PermissiveGroupName 'grp-usb' `
            -RetentionDays 90 -ReferenceDate (Get-Date) -ControlSkuAvailable
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string[]]$PermissiveGroupName,
        [Parameter(Mandatory)][ValidateRange(1, 3650)][int]$RetentionDays,
        [ValidateRange(1, 3650)][int]$AlertAfterDays = 30,
        [ValidateRange(1, 3650)][int]$RemoveAfterDays = 60,
        [datetime]$ReferenceDate = (Get-Date),
        [switch]$ControlSkuAvailable,
        [switch]$IncludeLastSeen
    )

    if ($AlertAfterDays -ge $RemoveAfterDays) {
        throw 'EndpointOps: AlertAfterDays must be strictly less than RemoveAfterDays'
    }

    $report = [System.Collections.Generic.List[object]]::new()
    $removalWindowStart = Test-ObservationWindow -WindowDays $RemoveAfterDays -RetentionDays $RetentionDays
    $alertWindowStart = Test-ObservationWindow -WindowDays $AlertAfterDays -RetentionDays $RetentionDays

    foreach ($agent in Get-S1Agent) {
        if ($PermissiveGroupName -notcontains [string]$agent.GroupName) {
            continue
        }

        if (-not $ControlSkuAvailable) {
            $report.Add([pscustomobject]@{
                PSTypeName         = 'EndpointOps.S1.UnusedAuthorization'
                ComputerName      = $agent.ComputerName
                AgentId           = $agent.Id
                GroupName         = $agent.GroupName
                SiteName          = $agent.SiteName
                State             = 'OutOfScope'
                Tier              = 'None'
                Severity          = 'Low'
                Reason            = 'Control SKU availability is not confirmed or the SKU is unavailable. The most recent Device Control event was not requested.'
                LastSeenDeviceDate = $null
                ObservedDays       = $null
            })
            continue
        }

        # A machine outside the Device Control scope produces no events, exactly like a machine with no
        # connected devices. These cases must NEVER produce the same conclusion: one is a finding,
        # while the other indicates that no measurement is available.
        if ([string]$agent.OsType -notin @('windows', 'macos')) {
            $report.Add([pscustomobject]@{
                PSTypeName         = 'EndpointOps.S1.UnusedAuthorization'
                ComputerName      = $agent.ComputerName
                AgentId           = $agent.Id
                GroupName         = $agent.GroupName
                SiteName          = $agent.SiteName
                State             = 'OutOfScope'
                Tier              = 'None'
                Severity          = 'Low'
                Reason            = "Device Control does not cover the $($agent.OsType) system. A Device Control event date is therefore unavailable."
                LastSeenDeviceDate = $null
                ObservedDays       = $null
            })
            continue
        }

        $authorizationState = $null
        $remediationTier = $null
        $severity = $null
        $reason = $null
        $observedDays = $null

        if ($removalWindowStart -eq 'Usable') {
            $removalCount = Get-S1DeviceControlEvent -AgentId ([string]$agent.Id) `
                -Since $ReferenceDate.AddDays(-$RemoveAfterDays) -CountOnly

            if ($removalCount -eq 0) {
                $authorizationState = 'NoUsage'
                $remediationTier = 'Removal'
                $severity = 'High'
                $observedDays = $RemoveAfterDays
                $reason = "No Device Control event for $RemoveAfterDays days; removal proposed."
            }
            elseif ($alertWindowStart -eq 'Usable') {
                $alertCount = Get-S1DeviceControlEvent -AgentId ([string]$agent.Id) `
                    -Since $ReferenceDate.AddDays(-$AlertAfterDays) -CountOnly

                if ($alertCount -eq 0) {
                    $authorizationState = 'NoUsage'
                    $remediationTier = 'Alert'
                    $severity = 'Medium'
                    $observedDays = $AlertAfterDays
                    $reason = "No Device Control event for $AlertAfterDays days; alert required."
                }
            }
            else {
                $authorizationState = 'Indeterminate'
                $remediationTier = 'None'
                $severity = 'Low'
                $reason = "The retention of $RetentionDays days does not cover the requested alert period of $AlertAfterDays days."
            }
        }
        elseif ($alertWindowStart -eq 'Usable') {
            $alertCount = Get-S1DeviceControlEvent -AgentId ([string]$agent.Id) `
                -Since $ReferenceDate.AddDays(-$AlertAfterDays) -CountOnly

            if ($alertCount -eq 0) {
                $authorizationState = 'NoUsage'
                $remediationTier = 'Alert'
                $severity = 'Medium'
                $observedDays = $AlertAfterDays
                $reason = "The removal tier of $RemoveAfterDays days could not be evaluated due to insufficient retention: the $RetentionDays-day retention period does not cover the requested $RemoveAfterDays-day period. No Device Control event for $AlertAfterDays days; alert required."
            }
        }
        else {
            $authorizationState = 'Indeterminate'
            $remediationTier = 'None'
            $severity = 'Low'
            $reason = "The retention of $RetentionDays days does not cover either the removal period of $RemoveAfterDays days or the alert period of $AlertAfterDays days."
        }

        if ($null -eq $authorizationState) {
            continue
        }

        $lastEventDate = $null
        if ($IncludeLastSeen -and $authorizationState -eq 'NoUsage') {
            $latestEvent = @(Get-S1DeviceControlEvent -AgentId ([string]$agent.Id) -Limit 1)
            if ($latestEvent.Count -gt 0) {
                $lastEventDate = $latestEvent[0].EventTime
                $reason += ' The most recent Device Control event was requested with Limit 1; API result ordering is not guaranteed.'
            }
            else {
                $reason += ' No Device Control event date is known; API result ordering is not guaranteed.'
            }
        }
        else {
            $reason += ' The most recent Device Control event was not requested.'
        }

        $report.Add([pscustomobject]@{
            PSTypeName         = 'EndpointOps.S1.UnusedAuthorization'
            ComputerName      = $agent.ComputerName
            AgentId           = $agent.Id
            GroupName         = $agent.GroupName
            SiteName          = $agent.SiteName
            State             = $authorizationState
            Tier              = $remediationTier
            Severity          = $severity
            Reason            = $reason
            LastSeenDeviceDate = $lastEventDate
            ObservedDays       = $observedDays
        })
    }

    return $report.ToArray()
}
