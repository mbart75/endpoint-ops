BeforeAll {
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-PropertyOrDefault.ps1')
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Measure-DeviceRuleBreadth.ps1')

    function Get-TestRule {
        param(
            $MatchBy = 'serialId', $UsbDeviceClass = '08', $ScopeLevel = 'group',
            $ScopeName = 'Quality', $Description = 'ticket SCTASK-1'
        )
        [pscustomobject]@{
            Id = '9000'; RuleName = 'Test rule'; Action = 'Allow'
            MatchBy = $MatchBy; VendorId = '0781'; ProductId = '5583'; SerialId = 'AA0102'
            UsbDeviceClass = $UsbDeviceClass; InterfaceType = 'USB'
            ScopeLevel = $ScopeLevel; ScopeName = $ScopeName; Description = $Description
            CreatedBy = 'test@mock.invalid'; CreatedAt = '2026-01-01T00:00:00Z'
            UpdatedBy = 'test@mock.invalid'; UpdatedAt = '2026-01-01T00:00:00Z'
        }
    }
}

Describe 'Measure-DeviceRuleBreadth' {
    It 'Reports no issue for a justified serial-number rule with group scope' {
        @(Measure-DeviceRuleBreadth -Rule (Get-TestRule)).Count | Should -Be 0
    }

    It 'Classifies a product identifier as High' {
        $patterns = @(Measure-DeviceRuleBreadth -Rule (Get-TestRule -MatchBy 'productId'))
        ($patterns | Where-Object { $_.Reason -match 'Copies of the model' }).Severity | Should -Be 'High'
    }

    It 'Classifies a manufacturer identifier as Critical' {
        $patterns = @(Measure-DeviceRuleBreadth -Rule (Get-TestRule -MatchBy 'vendorId'))
        ($patterns | Where-Object { $_.Reason -match 'every device produced by the manufacturer' }).Severity | Should -Be 'Critical'
    }

    It 'Treats a manufacturer identifier in the smartphone group as a separate case' {
        # The deceptive case: the rule is in the expected place, so it looks legitimate, while its scope covers an
# entire brand of telephones.
        $risky = Get-TestRule -MatchBy 'vendorId' -UsbDeviceClass '06' -ScopeName 'Smartphones'
        $patterns  = @(Measure-DeviceRuleBreadth -Rule $risky)
        $reason   = $patterns | Where-Object Severity -eq 'Critical'
        $reason   | Should -Not -BeNullOrEmpty
        $reason.Reason | Should -Match 'smartphone group'
        $reason.Reason | Should -Match 'serial number'
    }

    It 'Does not confuse the smartphone case with an ordinary manufacturer identifier' {
        $ordinary = @(Measure-DeviceRuleBreadth -Rule (Get-TestRule -MatchBy 'vendorId' -ScopeName 'R&D'))
        ($ordinary | Where-Object { $_.Reason -match 'smartphones' }) | Should -BeNullOrEmpty
    }

    It 'Reports site-wide scope' {
        $patterns = @(Measure-DeviceRuleBreadth -Rule (Get-TestRule -ScopeLevel 'site'))
        ($patterns | Where-Object { $_.Reason -match 'Site-wide' }).Severity | Should -Be 'High'
    }

    It 'Indicates an empty description' {
        foreach ($empty in @('', $null)) {
            $patterns = @(Measure-DeviceRuleBreadth -Rule (Get-TestRule -Description $empty))
            ($patterns | Where-Object { $_.Reason -match 'justification' }).Severity | Should -Be 'Medium'
        }
    }

    It 'Accumulates an overly broad identifier and site scope' {
        $patterns = @(Measure-DeviceRuleBreadth -Rule (Get-TestRule -MatchBy 'vendorId' -ScopeLevel 'site' -Description ''))
        $patterns.Count | Should -Be 3
    }

    It 'Returns a usable array even when empty, without throwing' {
        { @(Measure-DeviceRuleBreadth -Rule (Get-TestRule)).Count } | Should -Not -Throw
    }
}
