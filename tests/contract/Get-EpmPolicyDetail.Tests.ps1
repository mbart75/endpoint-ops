BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port

    $script:Production = '11111111-1111-1111-1111-111111111111'

    $identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))

    Connect-EpmTenant -DispatcherUri "http://localhost:$($script:Port)" -Credential $identifiers | Out-Null
}

AfterAll {
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmPolicyDetail' {

    Context 'Description' {
        # All calls from this file pass -MinIntervalMs explicitly. The default interval is 2100 ms:
# relying on it would make this file last for several minutes, and lowering it to fix the tests
# would mean expediting a module that no longer respects the limit.

        It 'Provides the detailed description of the first policy' {
            $detail = Get-EpmPolicyDetail -SetId $script:Production `
                -PolicyId '00000000-0000-0000-0000-000000000001' -MinIntervalMs 0
            $detail.Description | Should -BeExactly 'Request RITM0012345, dev tools'
        }

        It 'Returns an empty Description as a string' {
            $detail = Get-EpmPolicyDetail -SetId $script:Production `
                -PolicyId '00000000-0000-0000-0000-000000000002' -MinIntervalMs 0
            $detail.Description | Should -BeOfType [string]
        }

        It 'Returns an empty Description unchanged' {
            $detail = Get-EpmPolicyDetail -SetId $script:Production `
                -PolicyId '00000000-0000-0000-0000-000000000002' -MinIntervalMs 0
            $detail.Description | Should -BeExactly ''
        }

        It 'Preserves verbatim a description containing three spaces' {
            # The module does not cut off whites, and this is not an omission: a description of three spaces IS
# NOT an absence of description, it is someone who has filled in the field so that it is no longer
# empty. Making it "here" would make the information disappear at the same time it is needed. The
# judgment belongs to the report, not the reader.
            $detail = Get-EpmPolicyDetail -SetId $script:Production `
                -PolicyId '00000000-0000-0000-0000-000000000006' -MinIntervalMs 0
            $detail.Description | Should -BeExactly '   '
        }
    }

    Context 'Entry by pipeline' {

        It 'Reads the details of each policy retrieved from Get-EpmPolicy' {
            $details = @(Get-EpmPolicy -SetId $script:Production |
                Get-EpmPolicyDetail -SetId $script:Production -MinIntervalMs 0)
            @($details.PolicyId) | Should -Be @(
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002',
                '00000000-0000-0000-0000-000000000003',
                '00000000-0000-0000-0000-000000000004',
                '00000000-0000-0000-0000-000000000005',
                '00000000-0000-0000-0000-000000000006')
        }
    }

    Context 'Enforced request rate' {

        It 'Spaces two consecutive reads by at least the requested interval' {
            # The policy APIs are capped at 30 calls per minute and NO timing header is documented: the limit
# cannot be exceeded and then recovered, it must be respected upstream. 600 ms instead of 2100 so
# that the test takes one second.
            $chrono = [System.Diagnostics.Stopwatch]::StartNew()
            @('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002') |
                Get-EpmPolicyDetail -SetId $script:Production -MinIntervalMs 600 | Out-Null
            $chrono.Stop()

            $chrono.ElapsedMilliseconds | Should -BeGreaterOrEqual 600
        }

        It 'Keeps 2100 ms as the default interval' {
            # The default is verified from the declaration rather than by timing: measuring would take two seconds for
# each execution of the sequence. 2100 ms makes 28 calls per minute, under the limit of 30.
            $parameters = (Get-Command Get-EpmPolicyDetail).ScriptBlock.Ast.Body.ParamBlock.Parameters
            $interval = $parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MinIntervalMs' }
            $interval.DefaultValue.Extent.Text | Should -Be '2100'
        }
    }

    Context 'Unknown policy' {

        It 'Throws for an unknown policy identifier' {
            { Get-EpmPolicyDetail -SetId $script:Production `
                    -PolicyId '00000000-0000-0000-0000-000000000099' -MinIntervalMs 0 } |
                Should -Throw -ExpectedMessage '*404*'
        }

        It 'Explains that a 404 can also indicate insufficient permissions' {
            # The only ambiguous return code by design of the entire module: the documentation gives the same
# 404 for "resource not found", "wrong SetId" and "the user does not have the permissions". A
# message stating "policy not found" would conclude to an absence where there is only a missing
# right, and a falsely reassuring report is worse than no report.
            $message = ''
            try {
                Get-EpmPolicyDetail -SetId $script:Production `
                    -PolicyId '00000000-0000-0000-0000-000000000099' -MinIntervalMs 0
            }
            catch { $message = $_.Exception.Message }

            $message | Should -BeLike '*permission*'
        }
    }
}
