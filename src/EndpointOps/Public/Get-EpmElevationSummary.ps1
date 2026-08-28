# Proposal thresholds are named module variables, like the Get-EpmElevationEvent warning threshold,
# so they remain visible, documented, and testable. Tests can lower them temporarily instead of
# creating hundreds of events.
$script:EpmStrongUserThreshold   = 3
$script:EpmModerateUserThreshold = 2

# Numeric ranking of proposal levels. Alphabetical order is meaningless here:
# 'Moderate' would come before 'Strong', and 'None' before 'Weak'.
$script:EpmProposalRank = @{
    None     = 0
    Weak     = 1
    Moderate = 2
    Strong   = 3
}

function Get-EpmElevationSummary {
    <#
    .SYNOPSIS
        Groups EPM elevations into policy proposals.
    .DESCRIPTION
        Retrieves elevation events for a set through Get-EpmElevationEvent and reduces them to
        actionable groups. This turns counted events into proposals that can be reviewed.

        Each binary grouping is keyed by both publisher and hash. The publisher alone is too broad,
        while the hash alone would fragment a publisher across released versions.

        This command is read-only. It proposes elevation policies for human review and never writes
        them to EPM. An observed pattern is evidence for a proposal, not authorization to change a
        security policy.

        AN UNSIGNED BINARY NEVER RISES ABOVE None, EVEN WHEN SEEN EVERYWHERE. Frequency measures
        distribution, not trust: widely deployed unwanted software is more widespread, not more
        legitimate. Raising the level with the request count would reward exactly what this report
        is intended to detect.

        REMOVABLE-MEDIA ORIGIN IS REPORTED SEPARATELY and does not downgrade the level. The two facts
        answer different questions: the level expresses trust in the binary, while the origin shows
        how it arrived. A signed binary launched from a USB drive remains signed, but its origin
        still deserves review. Combining both facts into one number would discard useful context.
    .PARAMETER SetId
        Identifier of the set, as returned by Get-EpmSet.
    .PARAMETER Since
        Lower time bound, passed unchanged to Get-EpmElevationEvent.
    .PARAMETER Until
        Upper time bound, passed unchanged to Get-EpmElevationEvent.
    .PARAMETER EventType
        Event types forwarded unchanged to Get-EpmElevationEvent.
    .PARAMETER Limit
        Page size requested from the server and forwarded unchanged.
    .PARAMETER GroupBy
        'Binary' (default) groups events by publisher and hash to produce policy proposals. 'User'
        ranks users by request count, exposing trends that are difficult to see in individual events.
    .PARAMETER IncludeReputation
        Enriches binary groupings with the VirusTotal reputation. The reputation can remove a
        proposal, never promote it.
    .PARAMETER MinIntervalMs
        Minimum interval passed to VirusTotal calls.
    .EXAMPLE
        Get-EpmElevationSummary -SetId $setRecord.Id -Since (Get-Date).AddDays(-30) |
            Format-Table Publisher, FileName, DistinctUserCount, ProposalLevel
    .EXAMPLE
        Get-EpmElevationSummary -SetId $setRecord.Id -GroupBy User |
            Format-Table UserName, RequestCount, DistinctBinaryCount
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SetId,
        [datetime]$Since,
        [datetime]$Until,
        [ValidateNotNullOrEmpty()][string]$EventType = 'ElevationRequest,ManualRequest',
        [ValidateRange(1, 1000)][int]$Limit = 250,
        [ValidateSet('Binary', 'User')][string]$GroupBy = 'Binary',
        [switch]$IncludeReputation,
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 15000
    )

    if ($IncludeReputation -and $GroupBy -eq 'User') {
        throw 'EndpointOps: -IncludeReputation requires -GroupBy Binary; the User grouping does not carry any reputation.'
    }

    # Validate the VirusTotal connection before querying EPM so an unavailable enrichment service
    # cannot produce a partial report.
    if ($IncludeReputation) {
        $null = Get-VtConnectionState
    }

    # Forward time boundaries only when supplied by the caller. Passing an unassigned [datetime]
    # would send the .NET zero date (year 1) rather than representing an absent boundary.
    $queryParameters = @{ SetId = $SetId; EventType = $EventType; Limit = $Limit }
    if ($PSBoundParameters.ContainsKey('Since')) { $queryParameters['Since'] = $Since }
    if ($PSBoundParameters.ContainsKey('Until')) { $queryParameters['Until'] = $Until }

    # Preserve an empty result as an array; otherwise PowerShell flattens it to $null and .Count fails
    # under StrictMode.
    $eventRecords = @(Get-EpmElevationEvent @queryParameters)

    if ($GroupBy -eq 'User') {
        # Individual events obscure repeated behavior. Aggregating them by user makes recurring
        # elevation requests visible without changing any policy.
        $eventsByUser = [System.Collections.Specialized.OrderedDictionary]::new()

        foreach ($eventRecord in $eventRecords) {
            $userName = $eventRecord.UserName

            if (-not $eventsByUser.Contains($userName)) {
                $eventsByUser[$userName] = @{
                    UserName     = $userName
                    RequestCount = 0
                    Binaries     = [System.Collections.Generic.HashSet[string]]::new()
                    Computers    = [System.Collections.Generic.HashSet[string]]::new()
                    FirstSeen    = $null
                    LastSeen     = $null
                }
            }

            $line = $eventsByUser[$userName]
            $line.RequestCount++

            # Count distinct publisher-and-hash pairs, not requests. This distinguishes repeated
            # launches of one installer from requests for several different tools.
            [void]$line.Binaries.Add("$($eventRecord.Publisher)$([char]0x1F)$($eventRecord.Hash)")
            [void]$line.Computers.Add($eventRecord.ComputerName)

            if ($null -ne $eventRecord.FirstEventDate -and
                ($null -eq $line.FirstSeen -or $eventRecord.FirstEventDate -lt $line.FirstSeen)) {
                $line.FirstSeen = $eventRecord.FirstEventDate
            }
            if ($null -ne $eventRecord.LastEventDate -and
                ($null -eq $line.LastSeen -or $eventRecord.LastEventDate -gt $line.LastSeen)) {
                $line.LastSeen = $eventRecord.LastEventDate
            }
        }

        $ranking = [System.Collections.Generic.List[object]]::new()

        foreach ($userName in @($eventsByUser.Keys)) {
            $line = $eventsByUser[$userName]
            $ranking.Add([pscustomobject]@{
                    PSTypeName          = 'EndpointOps.Epm.UserElevationSummary'
                    UserName            = $line.UserName
                    RequestCount        = $line.RequestCount
                    DistinctBinaryCount = $line.Binaries.Count
                    ComputerCount       = $line.Computers.Count
                    FirstSeen           = $line.FirstSeen
                    LastSeen            = $line.LastSeen
                })
        }

        # Break request-count ties by user name so output order does not depend on pagination.
        return @($ranking.ToArray() |
                Sort-Object -Property @{ Expression = 'RequestCount'; Descending = $true },
                                      @{ Expression = 'UserName'; Descending = $false })
    }

    # Preserve insertion order so output remains deterministic when groups share the same rank and count.
    $groupBuckets = [System.Collections.Specialized.OrderedDictionary]::new()

    foreach ($eventRecord in $eventRecords) {
        # Use the ASCII unit separator (0x1F), not a dash: publishers and file names may contain
        # dashes, which could otherwise make different pairs produce the same key.
        $groupingKey = "$($eventRecord.Publisher)$([char]0x1F)$($eventRecord.Hash)"

        if (-not $groupBuckets.Contains($groupingKey)) {
            $groupBuckets[$groupingKey] = @{
                Publisher   = $eventRecord.Publisher
                Hash        = $eventRecord.Hash
                FileName    = $eventRecord.FileName
                Users       = [System.Collections.Generic.HashSet[string]]::new()
                Computers   = [System.Collections.Generic.HashSet[string]]::new()
                SourceTypes = [System.Collections.Generic.HashSet[string]]::new()
                EventCount  = 0
                FirstSeen   = $null
                LastSeen    = $null
            }
        }

        $group = $groupBuckets[$groupingKey]
        $group.EventCount++
        [void]$group.Users.Add($eventRecord.UserName)
        [void]$group.Computers.Add($eventRecord.ComputerName)
        if (-not [string]::IsNullOrWhiteSpace($eventRecord.SourceType)) {
            [void]$group.SourceTypes.Add($eventRecord.SourceType)
        }

        # Use the earliest start and latest end explicitly because pagination order is not guaranteed
        # to be chronological.
        if ($null -ne $eventRecord.FirstEventDate -and
            ($null -eq $group.FirstSeen -or $eventRecord.FirstEventDate -lt $group.FirstSeen)) {
            $group.FirstSeen = $eventRecord.FirstEventDate
        }
        if ($null -ne $eventRecord.LastEventDate -and
            ($null -eq $group.LastSeen -or $eventRecord.LastEventDate -gt $group.LastSeen)) {
            $group.LastSeen = $eventRecord.LastEventDate
        }
    }

    $lines = [System.Collections.Generic.List[object]]::new()

    # Reputation can DEGRADE a proposal, never promote it.
    #
    # A Clean verdict does not prove that a binary deserves elevation; it only means that no engine
    # flags it today. Reputation may reject a proposal but never authorize one.
    #
    # Unknown leaves the proposal unchanged because missing evidence is neither malicious nor clean.

    foreach ($groupingKey in @($groupBuckets.Keys)) {
        $group = $groupBuckets[$groupingKey]

        # A whitespace-only publisher is not a publisher. IsNullOrWhiteSpace covers missing, empty,
        # and whitespace-only values.
        $signed        = -not [string]::IsNullOrWhiteSpace($group.Publisher)
        $users = $group.Users.Count
        $removable     = $group.SourceTypes.Contains('RemovableDrive')
        $displayName  = "$($group.FileName) ($($group.Hash) hash)"

        if (-not $signed) {
            # An unsigned binary never rises above None, even when seen everywhere. Frequency
            # measures distribution, not trust. This check comes BEFORE user-count thresholds so
            # request volume can never raise an unsigned binary's proposal level.
            $riskLevel = 'None'
            $reason  = "UNSIGNED BINARY: $displayName, requested by $users distinct users across $($group.Computers.Count) endpoints. " +
                      "No rule is proposed regardless of request volume: without a publisher, a rule can target only the hash, " +
                      "and the next version of the same tool will have a different hash. Request volume measures distribution, not trust."
        }
        elseif ($users -ge $script:EpmStrongUserThreshold) {
            $riskLevel = 'Strong'
            $reason  = "Signed binary '$($group.Publisher)': $displayName, requested by $users distinct users across $($group.Computers.Count) endpoints " +
                      "($($group.EventCount) events). A need shared by $users users is organizational rather than an isolated case. " +
                      "A publisher-and-hash elevation rule is proposed for review."
        }
        elseif ($users -ge $script:EpmModerateUserThreshold) {
            $riskLevel = 'Moderate'
            $reason  = "Signed binary '$($group.Publisher)': $displayName, requested by $users distinct users across $($group.Computers.Count) endpoints " +
                      "($($group.EventCount) events). Two requesters suggest a genuine need without confirming it; verify usage before proposing a rule."
        }
        else {
            $riskLevel = 'Weak'
            $reason  = "Signed binary '$($group.Publisher)': $displayName, requested by $users distinct users across $($group.Computers.Count) endpoints " +
                      "($($group.EventCount) events). A single requester does not justify a permanent rule; handle the request case by case."
        }

        $reputation = $null
        if ($IncludeReputation) {
            try {
                $reputation = Get-VtFileReport -Hash $group.Hash -MinIntervalMs $MinIntervalMs
            }
            catch {
                # Enrichment failure must not fail the EPM report. The detail retains the expected
                # public shape.
                $reputation = [pscustomobject]@{
                    PSTypeName       = 'EndpointOps.VirusTotal.FileReport'
                    Hash             = $group.Hash
                    Verdict          = 'Unavailable'
                    MaliciousCount   = $null
                    TotalEngines     = $null
                    LastAnalysisDate = $null
                    Permalink        = $null
                    Sha1             = $null
                    Sha256           = $null
                    Md5               = $null
                }
            }

            if ($reputation.Verdict -eq 'Malicious') {
                $riskLevel = 'None'
                $engines = if ($null -ne $reputation.MaliciousCount) {
                    $reputation.MaliciousCount
                }
                else {
                    0
                }

                if ($signed) {
                    $reason = "Signed binary '$($group.Publisher)': $displayName, flagged by $engines engines. " +
                             'No rule is proposed: reputation downgraded the proposal and can never grant authorization.'
                }
                else {
                    $reason += "Malicious reputation: reported by $engines engines."
                }
            }
            elseif ($reputation.Verdict -eq 'Clean') {
                $reason += 'Clean reputation: no engine reports it today; this finding does not promote the proposal.'
            }
            elseif ($reputation.Verdict -eq 'Unknown') {
                $reason += 'Unknown reputation: no data available; the level remains unchanged.'
            }
            elseif ($reputation.Verdict -eq 'Unavailable') {
                $reason += "The reputation could not be obtained; the level remains based only on EPM observations."
            }
        }

        if ($removable) {
            # Append to the reason rather than replacing it: level and origin answer different
            # questions, and collapsing them would discard useful information.
            $reason += 'REMOVABLE SOURCE: this binary was launched from removable media. ' +
                      'A publisher-and-hash rule would then apply to any removable drive connected to the fleet. Review this origin before proposing anything.'
        }

        $properties = [ordered]@{
                PSTypeName         = 'EndpointOps.Epm.ElevationSummary'
                Publisher          = $group.Publisher
                Hash               = $group.Hash
                FileName           = $group.FileName
                DistinctUserCount  = $users
                EventCount         = $group.EventCount
                ComputerCount      = $group.Computers.Count
                FirstSeen          = $group.FirstSeen
                LastSeen           = $group.LastSeen
                IsSigned           = $signed
                SourceTypes        = @($group.SourceTypes | Sort-Object)
                FromRemovableDrive = $removable
                ProposalLevel      = $riskLevel

                # Expose the rank so callers can filter without reimplementing severity ordering.
                ProposalRank       = $script:EpmProposalRank[$riskLevel]
                Rationale          = $reason
            }

        if ($IncludeReputation) {
            $properties['Reputation'] = $reputation.Verdict
            $properties['ReputationDetail'] = $reputation
        }

        $lines.Add([pscustomobject]$properties)
    }

    # Sort by the ProposalRank property of the completed object rather than looking up values in an
    # indexed table inside the sorting block, which is unreliable under Set-StrictMode.
    return @($lines.ToArray() |
            Sort-Object -Property @{ Expression = 'ProposalRank'; Descending = $true },
                                  @{ Expression = 'DistinctUserCount'; Descending = $true },
                                  @{ Expression = 'EventCount'; Descending = $true },
                                  @{ Expression = 'Hash'; Descending = $false })
}
