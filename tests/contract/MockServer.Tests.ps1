BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Mock server' {
    It 'Responds on /health' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/health"
        $r.status | Should -Be 'ok'
    }

    It 'Returns 500 on /always-fails' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/always-fails" -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 500
    }

    It 'Returns received headers on /echo-headers' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/echo-headers" -Headers @{ 'X-Test' = 'abc' }
        $r.'X-Test' | Should -Be 'abc'
    }

    It 'The first page of /agents has a cursor' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/agents"
        $r.data.Count | Should -Be 2
        $r.pagination.nextCursor | Should -Be 'Page 2'
    }

    It 'Omits the pagination key from the last page instead of setting it to null' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/agents?cursor=page2"
        $r.data.Count | Should -Be 1
        # This is the heart of the contract: a real API omits the key. A module under Set-StrictMode that
# would read $r.pagination.nextCursor here would raise an error.
        $r.PSObject.Properties.Name | Should -Not -Contain 'pagination'
    }

    It 'Rejects a SentinelOne route without an Authorization header' {
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 401
    }

    It 'Accepts a SentinelOne route whose token has the correct casing' {
        # This control case isolates the next failure to token casing rather than a missing route or an
        # overly broad guard.
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" `
            -Headers @{ Authorization = 'ApiToken MOCK-S1-TOKEN' } -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 200
    }

    It 'Rejects a SentinelOne route whose token casing is altered' {
        # A token is sensitive to case everywhere. Comparing it with -ne, which ignores case, would
# make the mock server validate a mock secret incorrectly: contract tests would stop verifying
# the constraint they claim to verify.
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" `
            -Headers @{ Authorization = 'ApiToken mock-s1-token' } -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 401 -Because 'A token is sensitive to case'
    }

    It 'Accepts the SentinelOne authentication scheme regardless of casing' {
        # The authentication scheme is case-insensitive (RFC 7235). Hardening the token should not harden
# the scheme in the process.
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/api/v2.1/exclusions" `
            -Headers @{ Authorization = 'apitoken MOCK-S1-TOKEN' } -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 200 -Because 'The scheme is case-insensitive, but the token is not'
    }

    It 'Rejects a SentinelOne route whose path casing differs from the guard' {
        # The router that follows is a PowerShell switch, whose comparison is case-insensitive.
# A case-sensitive guard could therefore be bypassed by changing only one letter of the
# path: the request would avoid the guard and would still reach its route.
        $r = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/web/API/v2.1/exclusions" -SkipHttpErrorCheck
        $r.StatusCode | Should -Be 401 -Because 'The guard must cover exactly what the router accepts'
    }

    It 'Binds the listener only to the loopback interface' {
        $source = Get-Content (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1') -Raw
        $source | Should -Not -Match 'http://\+' -Because 'A prefix + would expose the server on all interfaces'
        $source | Should -Not -Match 'http://\*' -Because 'A prefix * would expose the server on all interfaces'
        $source | Should -Match 'http://localhost:'
    }

    It 'Counts the requests received by route' {
        # The counter is what transport tests now rely on to prove no reattempt for a certain period of
# time. If it counted wrong, these tests would become unable to fail without anything saying so.
        $before = Get-MockApiServerHitCount -Server $script:Server -Path '/health'
        Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/health" | Out-Null
        Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/health" | Out-Null
        $after = Get-MockApiServerHitCount -Server $script:Server -Path '/health'

        ($after - $before) | Should -Be 2
    }

    It 'Also counts an unknown path served with a 404 response' {
        # Counting takes place before routing: a request that reaches the default case is counted
# anyway. This is exactly what the 404 no-retry test reads.
        $before = Get-MockApiServerHitCount -Server $script:Server -Path '/never-routed-path'
        Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/never-routed-path" -SkipHttpErrorCheck | Out-Null
        $after = Get-MockApiServerHitCount -Server $script:Server -Path '/never-routed-path'

        ($after - $before) | Should -Be 1
    }

    It 'Does not count the counter endpoint itself' {
        Get-MockApiServerHitCount -Server $script:Server -Path '/_test/hits' | Out-Null
        Get-MockApiServerHitCount -Server $script:Server -Path '/_test/hits' |
            Should -Be 0 -Because 'Reading the counter must not modify it'
    }

    It 'Releases the port when stopped' {
        $s = Start-MockApiServer
        $port = $s.Port
        Stop-MockApiServer -Server $s

        # If the port is returned, we must be able to take it back.
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        { $listener.Start() } | Should -Not -Throw
        $listener.Stop()
    }
}
