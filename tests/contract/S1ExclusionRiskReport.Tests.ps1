BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
}

AfterAll {
    Disconnect-S1Tenant
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Get-S1ExclusionRiskReport' {
    It 'Reports the four exclusions of the tenant' {
        (Get-S1ExclusionRiskReport).Count | Should -Be 4
    }

    It 'Returns typed objects' {
        (Get-S1ExclusionRiskReport)[0].PSObject.TypeNames | Should -Contain 'EndpointOps.S1.ExclusionRisk'
    }

    It 'Classifies the drive root as Critical and the wildcard as High' {
        $report = Get-S1ExclusionRiskReport
        ($report | Where-Object Id -eq '2003').Severity | Should -Be 'Critical'
        ($report | Where-Object Id -eq '2004').Severity | Should -Be 'High'
    }

    It 'Reports no finding for a correctly scoped exclusion' {
        $correct = Get-S1ExclusionRiskReport | Where-Object Id -eq '2001'
        $correct          | Should -Not -BeNullOrEmpty
        $correct.Severity | Should -Be 'None'
        @($correct.Reasons).Count | Should -Be 0
    }

    It 'Includes explicit reasons, not only a severity' {
        $critical = Get-S1ExclusionRiskReport | Where-Object Id -eq '2003'
        $critical.Reasons | Should -Not -BeNullOrEmpty
        ($critical.Reasons -join ' ') | Should -Match 'Disk root'
        ($critical.Reasons -join ' ') | Should -Match 'Site scope'
    }

    It 'Identifies the person to contact' {
        $critical = Get-S1ExclusionRiskReport | Where-Object Id -eq '2003'
        $critical.CreatedBy | Should -Be 'jordan.lee@mock.invalid'
        $critical.Contact   | Should -Be 'jordan.lee@mock.invalid'
    }

    It 'Reports when the audit trail provides no human contact' {
        # 2004 was created by a service account: the audit trail exists but identifies no contact person.
# The report must say so.
        $deadEnd = Get-S1ExclusionRiskReport | Where-Object Id -eq '2004'
        $deadEnd.CreatedBy | Should -Match '^svc-'
        $deadEnd.Contact   | Should -BeNullOrEmpty
    }

    It 'Prefers the last modifier to the creator when they differ' {
        $retry = Get-S1ExclusionRiskReport | Where-Object Id -eq '2002'
        $retry.CreatedBy | Should -Be 'alex.taylor@mock.invalid'
        $retry.UpdatedBy | Should -Be 'jordan.lee@mock.invalid'
        $retry.Contact   | Should -Be 'jordan.lee@mock.invalid'
    }

    It 'Sorts from the most serious to the least serious' {
        $report = Get-S1ExclusionRiskReport
        $report[0].Severity  | Should -Be 'Critical'
        $report[-1].Severity | Should -Be 'None'
    }

    It 'Filters by minimum severity' {
        $severe = Get-S1ExclusionRiskReport -MinimumSeverity 'High'
        $severe.Count | Should -Be 2
        $severe.Severity | Should -Not -Contain 'None'
        $severe.Severity | Should -Not -Contain 'Low'
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-S1ExclusionRiskReport } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
