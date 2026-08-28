BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:Auth   = @{ Authorization = 'ApiToken MOCK-S1-TOKEN' }
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Mock server - SentinelOne routes' {
    It 'Rejects a call without an authentication header' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents" -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 401
    }

    It 'Rejects an invalid token' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents" `
            -Headers @{ Authorization = 'API Token BAD TOKEN' } -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 401
    }

    It 'Accepts the correct token and returns the first page' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents" -Headers $script:Auth
        $r.data.Count | Should -Be 2
        $r.pagination.nextCursor | Should -Be 'agents-p2'
    }

    It 'Returns a null nextCursor key on the last page' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents?cursor=agents-p2" -Headers $script:Auth
        $r.data.Count | Should -Be 8
        # This deliberately contrasts with the generic /agents route, which omits the key. Both response
        # shapes occur in practice, and the module must support both.
        $r.PSObject.Properties.Name | Should -Contain 'pagination'
        $r.pagination.nextCursor | Should -BeNullOrEmpty
    }

    It 'Honors the limit parameter by short-circuiting the pagination' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents?limit=1" -Headers $script:Auth
        $r.data.Count | Should -Be 1
    }

    It 'Keeps transport test routes accessible without authentication' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/health"
        $r.status | Should -Be 'ok'
    }

    It 'Exposes the Windows patch level required to determine tier 2' {
        # osName is 'Windows 11 Pro': a product name, not an update status. The higher hygiene tier
# requires agent AND Windows to be behind, so it needs a field that actually carries the fix.
        $all = @(
            (Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents" -Headers $script:Auth).data
            (Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents?cursor=agents-p2" -Headers $script:Auth).data
        )

        foreach ($agent in $all) {
            $agent.PSObject.Properties.Name | Should -Contain 'osRevision'
            $agent.osRevision | Should -Not -BeNullOrEmpty
        }
    }

    It 'Contains a separate case for each of the three levels of the graded response' {
        $all = @(
            (Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents" -Headers $script:Auth).data
            (Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/agents?cursor=agents-p2" -Headers $script:Auth).data
        )

        # Level 0: silent, nothing is possible remotely.
        ($all | Where-Object { $_.networkStatus -eq 'disconnected' }) | Should -Not -BeNullOrEmpty

        # Level 1: agent late but Windows is up to date.
        $tier1 = $all | Where-Object { $_.computerName -eq 'MOCK-WKS-03' }
        $tier1.agentVersion | Should -Be '21.7.1.120'
        $tier1.osRevision   | Should -Be '22631.4890'

        # Level 2: agent AND Windows lagging.
        $tier2 = $all | Where-Object { $_.computerName -eq 'MOCK-WKS-04' }
        $tier2.agentVersion | Should -Be '21.7.1.120'
        $tier2.osRevision   | Should -Be '19044.1288'

        # The two tiers must be discriminable: same version of agent, different Windows level. Without this
# difference, the report could not separate them.
        $tier1.osRevision | Should -Not -Be $tier2.osRevision
    }
}

Describe 'Get-S1Agent' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
        Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }

    AfterAll {
        Disconnect-S1Tenant
        Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    }

    It 'Follows the pagination and returns the ten agents' {
        $agentIds = Get-S1Agent
        $agentIds.Count | Should -Be 10
        $agentIds.ComputerName | Should -Contain 'MOCK-SRV-01'
    }

    It 'Returns typed objects, not raw JSON' {
        $agentIds = Get-S1Agent
        $agentIds[0].PSObject.TypeNames | Should -Contain 'EndpointOps.S1.Agent'
    }

    It 'Normalizes property names to PascalCase' {
        $agent = Get-S1Agent | Where-Object ComputerName -eq 'MOCK-WKS-01'
        $agent.AgentVersion | Should -Be '23.4.2.350'
        $agent.NetworkStatus | Should -Be 'connected'
        $agent.SiteName | Should -Be 'MOCK-SITE-EU'
    }

    It 'Converts the date of last activity to a DateTime' {
        $agent = Get-S1Agent | Where-Object ComputerName -eq 'MOCK-WKS-02'
        $agent.LastActiveDate | Should -BeOfType [datetime]
        $agent.LastActiveDate.Year | Should -Be 2026
    }

    It 'Exposes the level of Windows patch' {
        # OsRevision is required to assess patch status; osName is only a product label.
        $tier2 = Get-S1Agent | Where-Object ComputerName -eq 'MOCK-WKS-04'
        $tier2.OsRevision   | Should -Be '19044.1288'
        $tier2.AgentVersion | Should -Be '21.7.1.120'
    }

    It 'Exposes an inconsistent decommissioned state without reinterpreting it' {
        # Get-S1Agent reports raw state without assigning a hygiene tier.
        $agent = Get-S1Agent | Where-Object ComputerName -eq 'MOCK-SRV-01'
        $agent.IsDecommissioned | Should -BeTrue
        $agent.LastActiveDate | Should -BeGreaterThan ([datetime]'2026-07-01')
    }

    It 'Transmits the filters in query parameters' {
        $agentIds = Get-S1Agent -Filter @{ limit = 1 }
        $agentIds.Count | Should -Be 1
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-S1Agent } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }

    It 'Leaves no usable state after a rejected connection' {
        # This is where the zero reset performed by Connect-S1Tenant is proven. The equivalent test in
# S1Connection.Tests.ps1 could not do it: it would reopen a connection, which would overwrite the
# state regardless of its current state. Get-S1Agent, on the other hand, reads the state without
# rewriting it.
        Disconnect-S1Tenant
        $bad = ConvertTo-TestSecureString -PlainText 'BAD TOKEN'
        try { Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken $bad } catch { Write-Verbose 'Expected failure' }

        { Get-S1Agent } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'

        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
