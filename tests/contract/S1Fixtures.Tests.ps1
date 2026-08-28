BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:Auth   = @{ Authorization = 'ApiToken MOCK-S1-TOKEN' }
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Exclusion fixtures' {
    It 'Returns the exclusions' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -Headers $script:Auth
        $r.data.Count | Should -Be 4
    }

    It 'Contains at least one exclusion per hash and one per path' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -Headers $script:Auth
        $r.data.type | Should -Contain 'white_hash'
        $r.data.type | Should -Contain 'path'
    }

    It 'Contains a deliberately broad exclusion for the risk report to detect' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -Headers $script:Auth
        ($r.data | Where-Object { $_.value -eq 'C:\' }) | Should -Not -BeNullOrEmpty
    }

    It 'Records who created each exclusion so that the report is actionable' {
        # Reporting that an exclusion is unjustified without identifying a contact does not move the review
        # forward. The createdBy field makes the report actionable.
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -Headers $script:Auth

        foreach ($exclusion in $r.data) {
            $exclusion.PSObject.Properties.Name | Should -Contain 'createdBy'
            $exclusion.PSObject.Properties.Name | Should -Contain 'createdAt'
            $exclusion.createdBy | Should -Not -BeNullOrEmpty
        }
    }

    It 'Distinguishes an unjustified but attributable exclusion from an exclusion without contact person' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -Headers $script:Auth

        # 2003: too wide and without justification, but a human created it, so we can ask for details.
        $attributable = $r.data | Where-Object { $_.id -eq '2003' }
        $attributable.description | Should -BeNullOrEmpty
        $attributable.createdBy   | Should -Be 'jordan.lee@mock.invalid'

        # 2004: the same problem, but created by a service account. The audit trail provides no human contact,
        # and the risk report must disclose that limitation.
        $deadEnd = $r.data | Where-Object { $_.id -eq '2004' }
        $deadEnd.description | Should -BeNullOrEmpty
        $deadEnd.createdBy   | Should -Match '^svc-'
    }

    It 'Preserves the last modifier, who is not always the creator' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -Headers $script:Auth
        $retry = $r.data | Where-Object { $_.id -eq '2002' }
        $retry.createdBy | Should -Not -Be $retry.updatedBy
    }
}

Describe 'Peripheral control fixtures' {
    It 'Returns the rules' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth
        $r.data.Count | Should -Be 5
    }

    It 'Covers all three relevant USB classes' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth
        $r.data.usbDeviceClass | Should -Contain '06'
        $r.data.usbDeviceClass | Should -Contain '08'
        $r.data.usbDeviceClass | Should -Contain 'FF'
    }

    It 'Contains the high-risk case: unlocking by VID in the smartphone group' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth
        $risky = $r.data | Where-Object { $_.matchBy -eq 'vendorId' -and $_.scopeName -eq 'Smartphones' }
        $risky | Should -Not -BeNullOrEmpty
        $risky.usbDeviceClass | Should -Be '06'
    }

    It 'Contains a correctly scoped serial-number rule to exercise risk differentiation' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth
        ($r.data | Where-Object { $_.matchBy -eq 'serialId' -and $_.scopeLevel -eq 'group' }) | Should -Not -BeNullOrEmpty
    }

    It 'Records who created each rule and includes a description' {
        # As with exclusions, an overly broad rule must be attributable to someone.
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth

        foreach ($rule in $r.data) {
            $rule.PSObject.Properties.Name | Should -Contain 'createdBy'
            $rule.PSObject.Properties.Name | Should -Contain 'createdAt'
            $rule.PSObject.Properties.Name | Should -Contain 'description'
            $rule.createdBy | Should -Not -BeNullOrEmpty
        }
    }

    It 'Contains rules without justification, which must be reviewed first' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth
        $withoutJustification = @($r.data | Where-Object { [string]::IsNullOrEmpty($_.description) })
        $withoutJustification.Count | Should -BeGreaterThan 0
    }

    It 'Preserves the last modifier, as it does for exclusions' {
        # The console records the account that issued a peripheral authorization and the account that later
        # modified it. Both matter in an investigation: the creator explains the original intent, and the
        # last modifier explains the current state.
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/web/api/v2.1/restrictions" -Headers $script:Auth

        foreach ($rule in $r.data) {
            $rule.PSObject.Properties.Name | Should -Contain 'updatedBy'
            $rule.PSObject.Properties.Name | Should -Contain 'updatedAt'
        }

        # Rule 3004, the deceptive smartphone-group case, was modified by someone other than its creator.
        $retry = $r.data | Where-Object { $_.id -eq '3004' }
        $retry.createdBy | Should -Not -Be $retry.updatedBy
    }
}
