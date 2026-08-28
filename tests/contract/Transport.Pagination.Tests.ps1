BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-EndpointOpsRequest - pagination' {
    It 'Returns only the first page without -Paginate' {
        $summary = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/agents"
        $summary.data.Count | Should -Be 2
    }

    It 'Follows the cursor and returns all items with -Paginate' {
        $items = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/agents" -Paginate
        $items.Count | Should -Be 3
        $items.computerName | Should -Contain 'MOCK-PC-03'
    }

    It 'Does not loop indefinitely when the pagination key is absent' {
        # The last page omits the pagination key. Under Set-StrictMode, accessing it with dot notation
# would raise: reading must be defensive.
        #
        # What the test proves: pagination stops on the last page, after exactly two requests, because
        # the mock server only exposes two pages. A loop that would not recognize the end would send
        # a third one.
        #
        # The old ten-second timing guard assumed that an endless loop would be slow. That assumption was
        # unreliable: Invoke-EndpointOpsRequest already interrupts a repeated cursor by throwing, while a
        # loaded machine may take ten seconds despite correct behavior. The number of pages requested is
        # the exact contract this test needs to verify.
        #
        # Front/back offset: the mock server is shared by the entire file, and the two previous
        # tests already call /agents.
        $before = Get-MockApiServerHitCount -Server $script:Server -Path '/agents'
        Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/agents" -Paginate | Out-Null
        $after = Get-MockApiServerHitCount -Server $script:Server -Path '/agents'

        ($after - $before) | Should -Be 2 -Because 'The mock server only displays two pages'
    }
}
