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

Describe 'Get-S1DeviceControlRiskReport' {
    It 'Reports the five rules of the tenant' {
        (Get-S1DeviceControlRiskReport).Count | Should -Be 5
    }

    It 'Returns typed objects' {
        (Get-S1DeviceControlRiskReport)[0].PSObject.TypeNames | Should -Contain 'EndpointOps.S1.DeviceControlRisk'
    }

    It 'Reports the expected severities for all five rules' {
        $r = Get-S1DeviceControlRiskReport
        ($r | Where-Object Id -eq '3001').Severity | Should -Be 'None'
        ($r | Where-Object Id -eq '3002').Severity | Should -Be 'High'
        ($r | Where-Object Id -eq '3003').Severity | Should -Be 'Critical'
        ($r | Where-Object Id -eq '3004').Severity | Should -Be 'Critical'
        ($r | Where-Object Id -eq '3005').Severity | Should -Be 'High'
    }

    It 'Uses the dedicated rationale for the smartphone case' {
        $risky = Get-S1DeviceControlRiskReport | Where-Object Id -eq '3004'
        ($risky.Reasons -join ' ') | Should -Match 'smartphone group'
    }

    It 'Exposes the matching criterion central to the finding' {
        $r = Get-S1DeviceControlRiskReport
        ($r | Where-Object Id -eq '3003').MatchBy | Should -Be 'vendorId'
        ($r | Where-Object Id -eq '3001').MatchBy | Should -Be 'serialId'
    }

    It 'Identifies a contact, preferring the last modifier' {
        $risky = Get-S1DeviceControlRiskReport | Where-Object Id -eq '3004'
        $risky.CreatedBy | Should -Be 'jordan.lee@mock.invalid'
        $risky.Contact   | Should -Be 'alex.taylor@mock.invalid'
    }

    It 'Reports when the audit trail provides no human contact' {
        $deadEnd = Get-S1DeviceControlRiskReport | Where-Object Id -eq '3003'
        $deadEnd.CreatedBy | Should -Match '^svc-'
        $deadEnd.Contact   | Should -BeNullOrEmpty
    }

    It 'Sorts from the most serious to the least serious' {
        $r = Get-S1DeviceControlRiskReport
        $r[0].Severity  | Should -Be 'Critical'
        $r[-1].Severity | Should -Be 'None'
    }

    It 'Filters by minimum severity' {
        $severe = Get-S1DeviceControlRiskReport -MinimumSeverity 'Critical'
        $severe.Count | Should -Be 2
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-S1DeviceControlRiskReport } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
