function Get-S1Agent {
    <#
    .SYNOPSIS
        Lists SentinelOne agents in the connected tenant.
    .DESCRIPTION
        Follows pagination to the end and returns normalized objects.

        This function reports without assessing: a silent agent or an agent with an inconsistent
        decommissioned state is returned with its raw fields. Ratings and thresholds belong to the
        workflows built on this layer.
    .PARAMETER Filter
        Request parameters forwarded unchanged to the API, for example @{ limit = 100 } or @{ osTypes =
        'windows' }.
    .EXAMPLE
        Get-S1Agent | Where-Object { -not $_.IsActive }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [hashtable]$Filter = @{}
    )

    $raw = Invoke-S1Request -Path '/web/api/v2.1/agents' -Query $Filter -Paginate

    foreach ($agent in $raw) {
        $lastActive = Get-PropertyOrDefault -InputObject $agent -Name 'lastActiveDate'

        [pscustomobject]@{
            PSTypeName       = 'EndpointOps.S1.Agent'
            Id               = Get-PropertyOrDefault -InputObject $agent -Name 'id'
            ComputerName     = Get-PropertyOrDefault -InputObject $agent -Name 'computerName'
            AgentVersion     = Get-PropertyOrDefault -InputObject $agent -Name 'agentVersion'
            LastActiveDate   = if ($lastActive) { [datetime]$lastActive } else { $null }
            IsActive         = Get-PropertyOrDefault -InputObject $agent -Name 'isActive' -Default $false
            IsDecommissioned = Get-PropertyOrDefault -InputObject $agent -Name 'isDecommissioned' -Default $false
            NetworkStatus    = Get-PropertyOrDefault -InputObject $agent -Name 'networkStatus'
            OsName           = Get-PropertyOrDefault -InputObject $agent -Name 'osName'
            OsType           = Get-PropertyOrDefault -InputObject $agent -Name 'osType'
            OsRevision       = Get-PropertyOrDefault -InputObject $agent -Name 'osRevision'
            SiteName         = Get-PropertyOrDefault -InputObject $agent -Name 'siteName'
            GroupName        = Get-PropertyOrDefault -InputObject $agent -Name 'groupName'
        }
    }
}
