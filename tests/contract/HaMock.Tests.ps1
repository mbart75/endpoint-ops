#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:HaKey = 'MOCK-HA-KEY'
    $script:KnownHash = ('B' * 38) + '02'
    $script:UnknownHash = ('E' * 38) + '05'
    $script:HaPath = '/api/v2/search/hash'
    $script:OpaqueQuota = '{"opaque_mock_quota":"fixture-only-do-not-parse"}'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Mock server - Hybrid Analysis route' {
    It 'Requires an exact api-key and the GET method' {
        $withoutKey = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:HaPath)?hash=$($script:KnownHash)" `
            -SkipHttpErrorCheck
        $wrongCase = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:HaPath)?hash=$($script:KnownHash)" `
            -Headers @{ 'api-key' = 'mock-ha-key' } -SkipHttpErrorCheck
        $wrongMethod = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:HaPath)?hash=$($script:KnownHash)" `
            -Method Post -Headers @{ 'api-key' = $script:HaKey } -SkipHttpErrorCheck

        $withoutKey.StatusCode | Should -Be 401
        $wrongCase.StatusCode | Should -Be 401
        $wrongMethod.StatusCode | Should -Be 405
    }

    It 'Serves SearchByHash reports and an opaque quota without logging secrets' {
        $pathWithDifferentCase = '/API/V2/SEARCH/HASH'
        $response = Invoke-WebRequest `
            -Uri "$($script:Server.BaseUrl)${pathWithDifferentCase}?hash=$($script:KnownHash)" `
            -Headers @{ 'api-key' = $script:HaKey }

        $response.StatusCode | Should -Be 200
        [string]$response.Headers['Api-Limits'] | Should -BeExactly $script:OpaqueQuota
        $body = $response.Content | ConvertFrom-Json
        @($body.sha256s).Count | Should -Be 1
        @($body.reports).Count | Should -Be 1
        $body.reports[0].id | Should -BeExactly 'mock-ha-report-b02'
        $body.reports[0].environment_id | Should -Be 160
        $body.reports[0].environment_description | Should -BeExactly 'Windows 10 64 bit'
        $body.reports[0].state | Should -BeExactly 'SUCCESS'
        $body.reports[0].verdict | Should -BeExactly 'malicious'

        $requestLog = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation"
        $entry = @($requestLog.requests | Where-Object path -eq $pathWithDifferentCase)[-1]
        @($entry.PSObject.Properties.Name).Count | Should -Be 3
        $entry.PSObject.Properties.Name | Should -Contain 'path'
        $entry.PSObject.Properties.Name | Should -Contain 'method'
        $entry.PSObject.Properties.Name | Should -Contain 'authExact'
        $entry.path | Should -BeExactly $pathWithDifferentCase
        $entry.method | Should -BeExactly 'GET'
        $entry.authExact | Should -BeTrue
        ($requestLog | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match [regex]::Escape($script:HaKey)
        ($requestLog | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match [regex]::Escape($script:KnownHash)
    }

    It 'Serves an empty result without reports or an Api-Limits header' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:HaPath)?hash=$($script:UnknownHash)" `
            -Headers @{ 'api-key' = $script:HaKey }
        $body = $response.Content | ConvertFrom-Json

        @($body.sha256s).Count | Should -Be 0
        @($body.reports).Count | Should -Be 0
        $response.Headers.Keys | Should -Not -Contain 'Api-Limits'
    }
}
