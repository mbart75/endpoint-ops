BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'CANARY - the test harness can detect failures' {
    It 'Confirms that the mock server responds so later tests cannot pass vacuously' {
        $r = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/health"
        $r.status | Should -Be 'ok'
    }

    It 'A deliberately broken call correctly reports an error' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/always-fails" -SkipHttpErrorCheck
        $response.StatusCode | Should -Be 500
    }

    It 'Returns 404 for an unknown route, proving that routing is active' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/route-qui-nexiste-pas" -SkipHttpErrorCheck
        $response.StatusCode | Should -Be 404
    }
}
