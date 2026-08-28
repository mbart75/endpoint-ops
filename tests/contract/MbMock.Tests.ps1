#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:MbKey = 'MOCK-MB-KEY'
    $script:KnownHash = ('B' * 38) + '02'
    $script:UnknownHash = ('E' * 38) + '05'
    $script:MbPath = '/mb/api/v1/'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Mock server - MalwareBazaar routes' {
    It 'Rejects a request without an Auth-Key header' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:MbPath)" `
            -Method Post -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401
    }

    It 'Rejects a request with an incorrect Auth-Key' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:MbPath)" `
            -Method Post -Headers @{ 'Auth-Key' = 'WRONG-MB-KEY' } `
            -Body "query=get_info&hash=$($script:KnownHash)" `
            -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401
    }

    It 'Serves data for an exact Auth-Key and valid form body' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:MbPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:MbKey } `
            -Body "query=get_info&hash=$($script:KnownHash)" `
            -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $body = $response.Content | ConvertFrom-Json
        $body.query_status | Should -BeExactly 'ok'
        @($body.data).Count | Should -BeGreaterThan 0
    }

    It 'Returns 200 and hash_not_found for an unknown hash' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:MbPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:MbKey } `
            -Body "query=get_info&hash=$($script:UnknownHash)" `
            -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        ($response.Content | ConvertFrom-Json).query_status | Should -BeExactly 'hash_not_found'
    }

    It 'Rejects a JSON body even with a valid key' {
        $json = @{ query = 'get_info'; hash = $script:KnownHash } | ConvertTo-Json -Compress
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:MbPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:MbKey } -Body $json `
            -ContentType 'application/json' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 400
    }

    It 'Logs the observable contract without retaining the key' {
        $requestLog = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation"
        $entries = @($requestLog.requests | Where-Object {
                [string]::Equals([string]$_.path, $script:MbPath, [StringComparison]::OrdinalIgnoreCase)
            })

        $entries.Count | Should -BeGreaterThan 0
        $json = $requestLog | ConvertTo-Json -Depth 10 -Compress
        $json | Should -Not -Match [regex]::Escape($script:MbKey)

        if ($entries.Count -gt 0) {
            foreach ($entry in $entries) {
                @($entry.PSObject.Properties.Name).Count | Should -Be 3
                $entry.PSObject.Properties.Name | Should -Contain 'path'
                $entry.PSObject.Properties.Name | Should -Contain 'method'
                $entry.PSObject.Properties.Name | Should -Contain 'authExact'
                [string]::Equals([string]$entry.path, $script:MbPath, [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
                $entry.method | Should -BeExactly 'POST'
                $entry.authExact.GetType().Name | Should -BeExactly 'Boolean'
            }

            @($entries | Where-Object { $_.authExact -eq $true }).Count | Should -BeGreaterThan 0
        }
    }
}
