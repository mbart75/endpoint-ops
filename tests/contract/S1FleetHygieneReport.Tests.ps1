BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null

    $script:Targets = @{
        '22631' = 4890
        '19045' = 4046
        '17763' = 6414
    }
    # The fixtures have dates for July 2026: we freeze the reference so that the test does not become
# false over time.
    $script:Today = [datetime]'2026-07-24T12:00:00Z'

    $script:Params = @{
        TargetAgentVersion = '23.4.2.350'
        SupportedBuilds    = $script:Targets
        SilentAfterDays    = 30
        ReferenceDate      = $script:Today
    }
}

AfterAll {
    Disconnect-S1Tenant
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Get-S1FleetHygieneReport' {
    It 'Covers all ten agents' {
        (Get-S1FleetHygieneReport @script:Params).Count | Should -Be 10
    }

    It 'Returns typed objects' {
        (Get-S1FleetHygieneReport @script:Params)[0].PSObject.TypeNames | Should -Contain 'EndpointOps.S1.FleetHygiene'
    }

    It 'Does not report a healthy agent' {
        $healthy = Get-S1FleetHygieneReport @script:Params | Where-Object ComputerName -eq 'MOCK-WKS-01'
        @($healthy.Findings).Count | Should -Be 0
        $healthy.Tier | Should -BeNullOrEmpty
    }

    It 'Classifies a silent agent at tier 0' {
        $silent = Get-S1FleetHygieneReport @script:Params | Where-Object ComputerName -eq 'MOCK-WKS-02'
        $silent.Tier | Should -Be 0
        ($silent.Findings -join ' ') | Should -Match 'silent'
        # Tier 0: remediation cannot be performed remotely while the agent is unreachable.
        $silent.RecommendedAction | Should -Match 'no remote action is possible'
    }

    It 'Reports an inconsistent decommissioned state' {
        $inconsistent = Get-S1FleetHygieneReport @script:Params | Where-Object ComputerName -eq 'MOCK-SRV-01'
        ($inconsistent.Findings -join ' ') | Should -Match 'decommissioned'
    }

    It 'Classifies an outdated agent with an up-to-date system at tier 1' {
        $p1 = Get-S1FleetHygieneReport @script:Params | Where-Object ComputerName -eq 'MOCK-WKS-03'
        $p1.Tier | Should -Be 1
        $p1.OsBuildStatus | Should -Be 'UpToDate'
        $p1.RecommendedAction | Should -Match 'tracking group'
    }

    It 'Classifies an outdated agent on an unsupported system branch at tier 2' {
        $p2 = Get-S1FleetHygieneReport @script:Params | Where-Object ComputerName -eq 'MOCK-WKS-04'
        $p2.Tier | Should -Be 2
        $p2.OsBuildStatus | Should -Be 'UnsupportedBranch'
        $p2.RecommendedAction | Should -Match 'human approver'
    }

    It 'Separates tiers 1 and 2 using only the system criterion' {
        # The two machines have exactly the same version of agent. Without the system correction level, they
# would be indistinguishable.
        $r = Get-S1FleetHygieneReport @script:Params
        $p1 = $r | Where-Object ComputerName -eq 'MOCK-WKS-03'
        $p2 = $r | Where-Object ComputerName -eq 'MOCK-WKS-04'
        $p1.AgentVersion | Should -Be $p2.AgentVersion
        $p1.Tier | Should -Not -Be $p2.Tier
    }

    It 'Does not conclude when no build reference is provided' {
        $withoutReference = Get-S1FleetHygieneReport -TargetAgentVersion '23.4.2.350' -SupportedBuilds @{} -ReferenceDate $script:Today
        ($withoutReference | Where-Object ComputerName -eq 'MOCK-WKS-04').OsBuildStatus | Should -Be 'Unknown'
    }

    It 'Returns only actionable agents with -OnlyActionable' {
        $pendingItems = Get-S1FleetHygieneReport @script:Params -OnlyActionable
        $pendingItems.ComputerName | Should -Not -Contain 'MOCK-WKS-01'
        $pendingItems.Count | Should -BeLessThan 5
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-S1FleetHygieneReport @script:Params } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
