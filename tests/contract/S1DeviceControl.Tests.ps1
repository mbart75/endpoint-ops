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

Describe 'Get-S1DeviceControlRule' {
    It 'Returns the five rules' {
        (Get-S1DeviceControlRule).Count | Should -Be 5
    }

    It 'Returns typed objects' {
        (Get-S1DeviceControlRule)[0].PSObject.TypeNames | Should -Contain 'EndpointOps.S1.DeviceControlRule'
    }

    It 'Exposes the matching criterion, which is the heart of the review' {
        # Serial number, product identifier or manufacturer identifier: it is this distinction that
# separates a targeted authorization from an authorization that covers an entire brand.
        $rules = Get-S1DeviceControlRule
        $rules.MatchBy | Should -Contain 'serialId'
        $rules.MatchBy | Should -Contain 'productId'
        $rules.MatchBy | Should -Contain 'vendorId'
    }

    It 'Exposes the USB class' {
        $phone = Get-S1DeviceControlRule | Where-Object Id -eq '3005'
        $phone.UsbDeviceClass | Should -Be '06'
    }

    It 'Exposes the high-risk case: VIDEO class in the smartphone group' {
        $risky = Get-S1DeviceControlRule | Where-Object Id -eq '3004'
        $risky.MatchBy | Should -Be 'vendorId'
        $risky.ScopeName | Should -Be 'Smartphones'
        $risky.ScopeLevel | Should -Be 'group'
        $risky.SerialId | Should -BeNullOrEmpty
    }

    It 'Exposes the scope level as site or group' {
        $rules = Get-S1DeviceControlRule
        $rules.ScopeLevel | Should -Contain 'group'
        $rules.ScopeLevel | Should -Contain 'site'
    }

    It 'Exposes both the rule creator and the last modifier' {
        # Even more so on exclusions: a too broad rule must be able to be linked to someone for the
# investigation to move forward.
        $risky = Get-S1DeviceControlRule | Where-Object Id -eq '3004'
        $risky.CreatedBy | Should -Be 'jordan.lee@mock.invalid'
        $risky.UpdatedBy | Should -Be 'alex.taylor@mock.invalid'
        $risky.CreatedAt | Should -Not -BeNullOrEmpty
    }

    It 'Fails with a clear message if no connection is open' {
        Disconnect-S1Tenant
        { Get-S1DeviceControlRule } | Should -Throw -ExpectedMessage '*no active SentinelOne connection*'
        Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken (ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN') | Out-Null
    }
}
