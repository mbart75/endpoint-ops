BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port

    $script:Production = '11111111-1111-1111-1111-111111111111'
    $script:Servers   = '22222222-2222-2222-2222-222222222222'

    $identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))

    Connect-EpmTenant -DispatcherUri "http://localhost:$($script:Port)" -Credential $identifiers | Out-Null

    # Use -MinIntervalMs 0 throughout: the default request interval is 2100 ms and reads a policy at the
# same time. Relying on it would make this file last a good minute, and lowering it in the module
# would result in a report that no longer respects the limit of 30 calls per minute.
    $script:Report = @(Get-EpmPolicyHygieneReport -SetId $script:Production -MinIntervalMs 0)
}

AfterAll {
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmPolicyHygieneReport' {

    Context 'Flagged policies' {

        It 'Reports four policies across the Production set' {
            $script:Report.Count | Should -Be 4
        }

        It 'Reports exactly the four expected identifiers' {
            @($script:Report.PolicyId | Sort-Object) | Should -Be @(
                '00000000-0000-0000-0000-000000000002',
                '00000000-0000-0000-0000-000000000004',
                '00000000-0000-0000-0000-000000000005',
                '00000000-0000-0000-0000-000000000006')
        }

        It 'Reports the policy whose description contains only three spaces' {
            # Three spaces pass all the naive checks: -ne $null, -ne '', .Length -gt 0. This is the field that
# you fill in to mute a control, and it says nothing to a human.
            @($script:Report.PolicyId) | Should -Contain '00000000-0000-0000-0000-000000000006'
        }

        It 'Does not report the policy that has a meaningful description' {
            @($script:Report.PolicyId) | Should -Not -Contain '00000000-0000-0000-0000-000000000001'
        }

        It 'Does not report the second correctly documented policy' {
            @($script:Report.PolicyId) | Should -Not -Contain '00000000-0000-0000-0000-000000000003'
        }
    }

    Context 'Severity classification' {

        It '<Id> is classified <Severity>' -ForEach @(
            @{ Id = '00000000-0000-0000-0000-000000000002'; Severity = 'Critical' }
            @{ Id = '00000000-0000-0000-0000-000000000004'; Severity = 'High' }
            @{ Id = '00000000-0000-0000-0000-000000000006'; Severity = 'High' }
            @{ Id = '00000000-0000-0000-0000-000000000005'; Severity = 'Medium' }
        ) {
            $finding = $script:Report | Where-Object PolicyId -eq $Id
            $finding.Severity | Should -Be $Severity
        }

        It 'Sorts from the most serious to the least serious' {
            @($script:Report.Severity) | Should -Be @('Critical', 'High', 'High', 'Medium')
        }
    }

    Context 'Readability of the report' {

        It 'Includes a non-empty reason on each line' {
            @($script:Report | Where-Object { [string]::IsNullOrWhiteSpace($_.Reason) }).Count |
                Should -Be 0
        }

        It 'Explains the maximum scope clearly on the Critical line' {
            $critical = $script:Report | Where-Object PolicyId -eq '00000000-0000-0000-0000-000000000002'
            $critical.Reason | Should -Match 'all endpoints'
        }

        It 'Explains the distinct risk clearly on the Medium line' {
            $deferred = $script:Report | Where-Object PolicyId -eq '00000000-0000-0000-0000-000000000005'
            $deferred.Reason | Should -Match 'disabled'
        }

        It 'Does not display numerical scores' {
            # The severity ranking is used to compare, it is not read in a report: no one knows what a 3 is
# value.
            $names = @($script:Report[0].PSObject.Properties.Name)
            @($names | Where-Object { $_ -match 'Score|Rank|Note' }).Count | Should -Be 0
        }
    }

    Context 'Traceability' {

        It 'Explicitly states on every line that author data is unavailable' {
            # The EPM API does not expose the author to any policy. An empty box would read "not yet filled" and
# would send someone looking for nothing: the sentence is written rather than left empty.
            @($script:Report | Where-Object { $_.Contact -ne 'Not available through the EPM API' }).Count |
                Should -Be 0
        }

        It 'Has a non-empty contact on each line' {
            @($script:Report | Where-Object { [string]::IsNullOrWhiteSpace($_.Contact) }).Count |
                Should -Be 0
        }
    }

    Context 'Set without policies' {

        It 'Does not throw on an empty set' {
            { Get-EpmPolicyHygieneReport -SetId $script:Servers -MinIntervalMs 0 } | Should -Not -Throw
        }

        It 'Returns no findings on a set without policies' {
            # PowerShell flattens any empty output: no function can return an empty array WITHOUT the package
# ',@()', which breaks the exchange of the pipeline and counting by @(). The guarantee held is
# therefore the other half of the rule of this repository: the function does NOT emit ANY object, so
# that @() with the call gives a real empty collection whose .Count is read under Set-StrictMode.
            @(Get-EpmPolicyHygieneReport -SetId $script:Servers -MinIntervalMs 0).Count | Should -Be 0
        }

        It 'Does not insert a null element into the empty result' {
            # An explicit 'return $null' would pass the previous test with a count of 1 but could also, according
# to the writing, produce a collection of a single null element. The two defects are distinct.
            $empty = @(Get-EpmPolicyHygieneReport -SetId $script:Servers -MinIntervalMs 0)
            @($empty | Where-Object { $null -eq $_ }).Count | Should -Be 0
        }
    }

    Context 'Filtering by severity' {

        It 'Only retains lines of severity at least High' {
            $severe = @(Get-EpmPolicyHygieneReport -SetId $script:Production -MinIntervalMs 0 -MinimumSeverity 'High')
            $severe.Count | Should -Be 3
        }

        It 'Excludes the Medium line from the High filtering' {
            $severe = @(Get-EpmPolicyHygieneReport -SetId $script:Production -MinIntervalMs 0 -MinimumSeverity 'High')
            @($severe.Severity) | Should -Not -Contain 'Medium'
        }
    }
}
