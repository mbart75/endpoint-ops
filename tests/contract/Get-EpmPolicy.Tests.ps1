BeforeAll {
    Set-StrictMode -Version 3.0

    function Get-EpmRequestLog {
        <#
        .SYNOPSIS
            Reads the EPM introspection log of the mock server, from a rank.
        .DESCRIPTION
            Each test raises the current rank BEFORE its call, then only reads what it itself
            produced. Without this, a test would also read the calls of previous tests, and its
            result would depend on the order of execution.
        #>
        [CmdletBinding()]
        param([int]$Since = 0)

        $log = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/EPM/API/_test/requests").requests)
        if ($Since -ge $log.Count) { return @() }
        return @($log[$Since..($log.Count - 1)])
    }

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port

    $script:Production = '11111111-1111-1111-1111-111111111111'
    $script:Servers   = '22222222-2222-2222-2222-222222222222'
    $script:SearchPath  = "/EPM/API/Sets/$($script:Production)/Policies/Server/Search"

    $identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))

    Connect-EpmTenant -DispatcherUri "http://localhost:$($script:Port)" -Credential $identifiers | Out-Null
}

AfterAll {
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmPolicy' {

    Context 'Content of the list' {

        It 'Returns the six policies of the Production group' {
            @(Get-EpmPolicy -SetId $script:Production).Count | Should -Be 6
        }

        It 'Exposes the identifiers in the order served' {
            @((Get-EpmPolicy -SetId $script:Production).PolicyId) | Should -Be @(
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002',
                '00000000-0000-0000-0000-000000000003',
                '00000000-0000-0000-0000-000000000004',
                '00000000-0000-0000-0000-000000000005',
                '00000000-0000-0000-0000-000000000006')
        }

        It 'Returns no policies on a set that has none' {
            # Case essential to the report: an empty set is not an error, and it must neither raise, nor return
# $null.
            @(Get-EpmPolicy -SetId $script:Servers).Count | Should -Be 0
        }

        It 'Sets IsActive to false on the disabled policy' {
            $old = @(Get-EpmPolicy -SetId $script:Production) |
                Where-Object { $_.PolicyId -eq '00000000-0000-0000-0000-000000000005' }
            $old.IsActive | Should -BeFalse
        }

        It 'Sets IsAppliedToAllComputers to true on the universal policy' {
            # It is the field that distinguishes a targeted policy from a policy applied to the entire fleet: the
# scope, therefore the risk.
            $temp = @(Get-EpmPolicy -SetId $script:Production) |
                Where-Object { $_.PolicyId -eq '00000000-0000-0000-0000-000000000002' }
            $temp.IsAppliedToAllComputers | Should -BeTrue
        }
    }

    Context 'Shape of objects' {

        It 'Exposes the ten fields that the list actually covers' {
            $names = @((Get-EpmPolicy -SetId $script:Production)[0].PSObject.Properties.Name)
            foreach ($expected in @('PolicyId', 'PolicyName', 'IsActive', 'Action', 'PolicyType',
                    'Order', 'IsAppliedToAllComputers', 'OsType', 'CreatedDate', 'ModifiedDate')) {
                $names | Should -Contain $expected
            }
        }

        It 'Does not expose a Description field' {
            # This is the central point of the test: the list does not include Description; only the detail
            # endpoint does. Adding a blank description here would make the object indistinguishable from a
            # genuinely undocumented policy, and the report would incorrectly flag all six policies without
            # reading their details.
            $names = @((Get-EpmPolicy -SetId $script:Production)[0].PSObject.Properties.Name)
            $names | Should -Not -Contain 'Description'
        }
    }

    Context 'Method and transport' {

        It 'Sends a POST on the search route' {
            # The list is a POST while it is a read: it is counterintuitive, so it is exactly what is lost in
# the first rewrite if nothing holds it.
            $index = @(Get-EpmRequestLog).Count
            Get-EpmPolicy -SetId $script:Production | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq $script:SearchPath })
            @($calls | ForEach-Object { $_.method }) | Should -Be @('POST')
        }

        It 'Rejects GET on the same route' {
            # Verify the configuration of the mock server as well as the module: if the route also responded in
# GET, the previous test would still pass with an implementation that had chosen the wrong method,
# and nothing would tell you that.
            { & (Get-Module EndpointOps) { param($p) Invoke-EpmRequest -Path $p -Method 'Get' } $script:SearchPath } |
                Should -Throw -ExpectedMessage '*405*'
        }
    }

    Context 'Filter' {

        It 'Places the filter in the body of the query' {
            # The log of the mock server only retains the NAMES of the keys received, never their values: the
# proof cannot therefore become itself the place of a leak.
            $index = @(Get-EpmRequestLog).Count
            Get-EpmPolicy -SetId $script:Production -Filter 'PolicyName CONTAINS Elevate' | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq $script:SearchPath })
            @($calls[0].bodyKeys) | Should -Contain 'filter'
        }

        It 'Transmits the filter value in the body rather than the URL' {
            # The key name alone would not prove that the value has arrived. The mock server, on the other
# hand, only reads the filter in the body: a filter that goes into the request string would leave the
# search unfiltered and bring back the six policies. The result is therefore proof, without any
# value being logged.
            @((Get-EpmPolicy -SetId $script:Production -Filter 'PolicyName CONTAINS Elevate').PolicyName) |
                Should -Be @('Elevate Dev Tools', 'Elevate Legacy App', 'Elevate Installers')
        }
    }
}
