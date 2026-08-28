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

Describe 'Get-S1Exclusion' {
    It 'Returns the four exclusions' {
        (Get-S1Exclusion).Count | Should -Be 4
    }

    It 'Returns typed objects' {
        (Get-S1Exclusion)[0].PSObject.TypeNames | Should -Contain 'EndpointOps.S1.Exclusion'
    }

    It 'Normalizes the type and value' {
        $hash = Get-S1Exclusion | Where-Object Id -eq '2001'
        $hash.Type | Should -Be 'white_hash'
        $hash.Value | Should -Be 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
    }

    It 'Exposes the scope required by the risk review' {
        $large = Get-S1Exclusion | Where-Object Id -eq '2003'
        $large.Value | Should -Be 'C:\'
        $large.ScopeLevel | Should -Be 'site'
    }

    It 'Preserves an empty description without replacement' {
        # An exclusion without justification is a signal, not a hole to fill.
        $withoutJustification = Get-S1Exclusion | Where-Object Id -eq '2004'
        $withoutJustification.Description | Should -BeNullOrEmpty
    }

    It 'Exposes the exclusion creator so that the report is actionable' {
        # Reporting that an exclusion is unjustified without identifying whom to ask does not move the
# review forward.
        $attributable = Get-S1Exclusion | Where-Object Id -eq '2003'
        $attributable.CreatedBy | Should -Be 'jordan.lee@mock.invalid'
        $attributable.CreatedAt | Should -Not -BeNullOrEmpty
    }

    It 'Exposes the last modifier, which is not always the creator' {
        $retry = Get-S1Exclusion | Where-Object Id -eq '2002'
        $retry.CreatedBy | Should -Be 'alex.taylor@mock.invalid'
        $retry.UpdatedBy | Should -Be 'jordan.lee@mock.invalid'
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-S1Exclusion } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
