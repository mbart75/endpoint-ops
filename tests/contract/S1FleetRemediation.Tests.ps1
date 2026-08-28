BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    $script:Auth   = @{ Authorization = 'ApiToken MOCK-S1-TOKEN' }
    Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null

    function Get-MockMoveLog {
        @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/_test/moves" -Headers $script:Auth).data)
    }

    function Get-Tier1Agent {
        [pscustomobject]@{
            PSTypeName = 'EndpointOps.S1.FleetHygiene'
            Id = '1004'; ComputerName = 'MOCK-WKS-03'; Tier = 1
            RecommendedAction = 'Move to the tracking group and collect diagnostic information'
        }
    }
}

AfterAll {
    Disconnect-S1Tenant
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-S1FleetRemediation' {
    It 'Declares SupportsShouldProcess with high confirmation impact' {
        $cmd = Get-Command Invoke-S1FleetRemediation
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
        $meta = [System.Management.Automation.CommandMetadata]::new($cmd)
        $meta.SupportsShouldProcess | Should -BeTrue
        $meta.ConfirmImpact | Should -Be 'High'
    }

    It 'Does not move any agent with -WhatIf' {
        $before = (Get-MockMoveLog).Count
        Get-Tier1Agent | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -WhatIf
        (Get-MockMoveLog).Count | Should -Be $before -Because '-WhatIf must not produce any write call'
    }

    It 'Moves the agent when confirmation is granted' {
        $before = (Get-MockMoveLog).Count
        Get-Tier1Agent | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -Confirm:$false
        $after = Get-MockMoveLog
        $after.Count | Should -Be ($before + 1)
        $after[-1].agentId | Should -Be '1004'
        $after[-1].groupId | Should -Be 'grp-tracking'
    }

    It 'Ignores agents that are not at tier 1' {
        $before = (Get-MockMoveLog).Count
        $tier0 = [pscustomobject]@{ PSTypeName = 'EndpointOps.S1.FleetHygiene'; Id = '1002'; ComputerName = 'MOCK-WKS-02'; Tier = 0; RecommendedAction = 'x' }
        $tier2 = [pscustomobject]@{ PSTypeName = 'EndpointOps.S1.FleetHygiene'; Id = '1005'; ComputerName = 'MOCK-WKS-04'; Tier = 2; RecommendedAction = 'x' }
        $healthy    = [pscustomobject]@{ PSTypeName = 'EndpointOps.S1.FleetHygiene'; Id = '1001'; ComputerName = 'MOCK-WKS-01'; Tier = $null; RecommendedAction = $null }

        @($tier0, $tier2, $healthy) | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -Confirm:$false

        (Get-MockMoveLog).Count | Should -Be $before -Because 'Only tier 1 triggers a write operation'
    }

    It 'Returns a report of the completed action' {
        $result = Get-Tier1Agent | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -Confirm:$false
        $result.ComputerName  | Should -Be 'MOCK-WKS-03'
        $result.Moved         | Should -BeTrue
        $result.TargetGroupId | Should -Be 'grp-tracking'
    }

    It 'Reports without acting under -WhatIf' {
        # No conditional guarding here: a test that is only executed if the object exists would return an
# empty string on the day the function no longer returns anything. We therefore require the report
# AND its content.
        $result = Get-Tier1Agent | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -WhatIf
        $result       | Should -Not -BeNullOrEmpty
        $result.Moved | Should -BeFalse
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-Tier1Agent | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }

    It 'Also fails under -WhatIf when no connection is open' {
        # A -WhatIf that announces what it would do while the module is disconnected would give false
# assurance: it cannot do anything. The connection is therefore validated BEFORE the ShouldProcess
# block, not inside it.
        Disconnect-S1Tenant
        { Get-Tier1Agent | Invoke-S1FleetRemediation -TrackingGroupId 'grp-tracking' -WhatIf } |
            Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
