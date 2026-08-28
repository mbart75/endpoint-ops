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

    $identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))

    # The session is opened by the PUBLIC path: the ManagerURL used by Get-EpmSet is therefore the one
# that the dispatcher actually sent back, not a value held in hand within the scope of the module.
    Connect-EpmTenant -DispatcherUri "http://localhost:$($script:Port)" -Credential $identifiers | Out-Null
}

AfterAll {
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmSet' {

    Context 'Content of the sets' {

        It 'Returns both sets of the tenant' {
            @(Get-EpmSet).Count | Should -Be 2
        }

        It 'Exposes the identifiers in the order served' {
            @((Get-EpmSet).Id) | Should -Be @(
                '11111111-1111-1111-1111-111111111111',
                '22222222-2222-2222-2222-222222222222')
        }

        It 'Exposes the names in the order served' {
            @((Get-EpmSet).Name) | Should -Be @('Production', 'Servers')
        }

        It 'Normalizes each item with ConvertTo-EpmSet' {
            # The type name is imposed by ConvertTo-EpmSet and by it alone: an implementation that would
# reconstruct the object by hand would lose this mark. This is proof that shared normalization is
# well implemented, rather than reimplemented on site.
            @(Get-EpmSet)[0].PSObject.TypeNames | Should -Contain 'EndpointOps.Epm.Set'
        }

        It 'Provides the detailed description of Production' {
            $production = @(Get-EpmSet) | Where-Object { $_.Name -eq 'Production' }
            $production.Description | Should -BeExactly 'Production endpoints'
        }

        It 'Returns the Servers description as a string rather than null' {
            # Test BEFORE the value: $null would fail here with a message naming the real cause. A -BeExactly ''
# alone would only say "n is not equal", without distinguishing the absence of the void.
            $servers = @(Get-EpmSet) | Where-Object { $_.Name -eq 'Servers' }
            $servers.Description | Should -BeOfType [string]
        }

        It 'Returns an empty description for Servers' {
            $servers = @(Get-EpmSet) | Where-Object { $_.Name -eq 'Servers' }
            $servers.Description | Should -BeExactly ''
        }
    }

    Context 'Pagination by offset' {

        It 'Returns both sets even when each page contains only one item' {
            # With -Limit 1, each set is on its own page. An implementation that would only read the first page
# would only return Production, and the report would announce a single tenant set without raising
# any errors.
            @((Get-EpmSet -Limit 1).Name) | Should -Be @('Production', 'Servers')
        }

        It 'Sends multiple requests when the limit is 1' {
            # The request log does not expose query values outside test routes; this test verifies
# the number of calls. Two full pages plus the empty page end pagination because set responses do not
# include TotalCount.
            $index = @(Get-EpmRequestLog).Count
            Get-EpmSet -Limit 1 | Out-Null

            $calls = @(Get-EpmRequestLog -Since $index | Where-Object { $_.path -eq '/EPM/API/Sets' })
            $calls.Count | Should -Be 3
        }
    }
}
