#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:VtKey = 'MOCK-VT-KEY'
    $script:KnownHash = ('A' * 38) + '01'
    $script:UnknownHash = ('B' * 38) + '02'
    $script:MaliciousHash = ('C' * 38) + '03'
    $script:SingleEngineHash = ('D' * 38) + '04'
    $script:RateLimitedHash = ('F' * 38) + '06'
    $script:BadRequestHash = ('0' * 38) + '07'
    $script:FailingHash = ('1' * 38) + '08'
    $script:MaliciousUrlId = 'aHR0cHM6Ly9tYWx3YXJlLmV4YW1wbGUuaW52YWxpZC9-cGF5bG9hZD94PTE'
    $script:UnknownUrlId = 'aHR0cHM6Ly91bmtub3duLmV4YW1wbGUuaW52YWxpZC8_YWE'
    $script:CleanUrlId = 'aHR0cHM6Ly9jbGVhbi5leGFtcGxlLmludmFsaWQvfmRvd25sb2FkP2FhPTE'
    $script:RateLimitedUrlId = 'aHR0cHM6Ly9xdW90YS5leGFtcGxlLmludmFsaWQvP2Fh'
    $script:FailingUrlId = 'aHR0cHM6Ly9mYWlsdXJlLmV4YW1wbGUuaW52YWxpZC9-eA'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'VirusTotal routes of the mock server' {
    It 'Rejects a file report without an x-apikey header' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:KnownHash)" -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401
    }

    It 'Rejects a file report with an incorrect x-apikey key' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:KnownHash)" `
            -Headers @{ 'x-apikey' = 'WRONG-VT-KEY' } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401
    }

    It 'Uses the analysis statistics for an exact x-apikey key' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:KnownHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $body = $response.Content | ConvertFrom-Json
        $body.data.attributes.last_analysis_stats | Should -Not -BeNullOrEmpty
        $body.data.attributes.md5 | Should -Be (('A' * 30) + '01')
        $body.data.attributes.sha1 | Should -Be $script:KnownHash
        $body.data.attributes.sha256 | Should -Be (('A' * 62) + '01')
    }

    It 'Uses malicious statistics from the CCCC fixture' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:MaliciousHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $stats = ($response.Content | ConvertFrom-Json).data.attributes.last_analysis_stats
        $stats.malicious | Should -Be 8
        $stats.harmless | Should -Be 40
        $stats.suspicious | Should -Be 2
    }

    It 'Accepts a hexadecimal hash in lowercase' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:KnownHash.ToLowerInvariant())" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $stats = ($response.Content | ConvertFrom-Json).data.attributes.last_analysis_stats
        $stats.malicious | Should -Be 0
        $stats.harmless | Should -Be 60
        $stats.undetected | Should -Be 12
    }

    It 'Uses the DDDD fixture with a single malicious engine' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:SingleEngineHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $stats = ($response.Content | ConvertFrom-Json).data.attributes.last_analysis_stats
        $stats.malicious | Should -Be 1
        $stats.harmless | Should -Be 68
        $stats.undetected | Should -Be 5
    }

    It 'Returns 404 for a never submitted hash' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:UnknownHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 404
    }

    It 'Returns 429 for the hash reserved for quota exhaustion' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:RateLimitedHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 429
    }

    It 'Returns 400 for the alternate unknown-hash fixture' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:BadRequestHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 400
    }

    It 'Returns 500 systematically for the failure fixture' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/files/$($script:FailingHash)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 500
    }

    It 'Uses malicious statistics from a URL indexed by its identifier' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/urls/$($script:MaliciousUrlId)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $body = $response.Content | ConvertFrom-Json
        $body.data.id | Should -BeExactly $script:MaliciousUrlId
        $body.data.attributes.last_analysis_stats.malicious | Should -Be 6
    }

    It 'Returns 404 for the identifier of a URL never submitted' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/urls/$($script:UnknownUrlId)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 404
    }

    It 'Uses the statistics specific to a URL indexed by its identifier' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/urls/$($script:CleanUrlId)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
        $stats = ($response.Content | ConvertFrom-Json).data.attributes.last_analysis_stats
        $stats.malicious | Should -Be 0
        $stats.harmless | Should -Be 60
        $stats.undetected | Should -Be 12
    }

    It 'Returns 429 for the URL identifier reserved for quota exhaustion' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/urls/$($script:RateLimitedUrlId)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 429
    }

    It 'Returns 500 for the URL identifier reserved for failure' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/api/v3/urls/$($script:FailingUrlId)" `
            -Headers @{ 'x-apikey' = $script:VtKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 500
    }

    It 'Records only the path, method, and key validity' {
        $path = "/api/v3/files/$($script:KnownHash)"
        Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$path" -Headers @{ 'x-apikey' = $script:VtKey } | Out-Null

        $log = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation"
        $entry = @($log.requests | Where-Object path -eq $path)[-1]

        @($entry.PSObject.Properties.Name).Count | Should -Be 3
        $entry.PSObject.Properties.Name | Should -Contain 'path'
        $entry.PSObject.Properties.Name | Should -Contain 'method'
        $entry.PSObject.Properties.Name | Should -Contain 'authExact'
        $entry.path | Should -Be $path
        $entry.method | Should -Be 'GET'
        $entry.authExact | Should -BeTrue
        ($log | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match [regex]::Escape($script:VtKey)
    }
}
