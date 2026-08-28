#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer
    $script:TfKey = 'MOCK-MB-KEY'
    $script:KnownHash = ('C' * 62) + '03'
    $script:UnknownHash = ('E' * 62) + '05'
    $script:Sha1 = ('C' * 38) + '03'
    $script:TfPath = '/tf/api/v1/'
    $script:JournalUri = "$($script:Server.BaseUrl)/_test/reputation"
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'Mock server - ThreatFox route' {
    It 'Rejects missing or inexact authentication' {
        $body = @{ query = 'search_hash'; hash = $script:KnownHash } | ConvertTo-Json -Compress
        $withoutKey = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Body $body -ContentType 'application/json' -SkipHttpErrorCheck
        $wrongCase = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = 'mock-mb-key' } -Body $body `
            -ContentType 'application/json' -SkipHttpErrorCheck

        $withoutKey.StatusCode | Should -Be 401
        $wrongCase.StatusCode | Should -Be 401
    }

    It 'Rejects methods other than POST' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Headers @{ 'Auth-Key' = $script:TfKey } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 405
    }

    It 'Rejects a content type or payload that violates the official JSON contract' {
        $validBody = @{ query = 'search_hash'; hash = $script:KnownHash } | ConvertTo-Json -Compress
        $wrongContentType = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body $validBody `
            -ContentType 'text/plain' -SkipHttpErrorCheck
        $malformedJson = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body '{' `
            -ContentType 'application/json' -SkipHttpErrorCheck
        $wrongQueryBody = @{ query = 'get_info'; hash = $script:KnownHash } | ConvertTo-Json -Compress
        $wrongQuery = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body $wrongQueryBody `
            -ContentType 'application/json' -SkipHttpErrorCheck
        $wrongHashBody = @{ query = 'search_hash'; hash = 'not-a-hash' } | ConvertTo-Json -Compress
        $wrongHash = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body $wrongHashBody `
            -ContentType 'application/json' -SkipHttpErrorCheck

        $wrongContentType.StatusCode | Should -Be 400
        $malformedJson.StatusCode | Should -Be 400
        $wrongQuery.StatusCode | Should -Be 400
        $wrongHash.StatusCode | Should -Be 400
    }

    It 'Serves a realistic ok response for a known SHA-256 on a case-insensitive route' {
        $pathWithDifferentCase = '/TF/API/V1/'
        $body = @{ query = 'search_hash'; hash = $script:KnownHash } | ConvertTo-Json -Compress
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$pathWithDifferentCase" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body $body `
            -ContentType 'application/json'

        $response.StatusCode | Should -Be 200
        $payload = $response.Content | ConvertFrom-Json
        $payload.query_status | Should -BeExactly 'ok'
        @($payload.data).Count | Should -Be 1
        @($payload.data[0].PSObject.Properties.Name | Sort-Object) | Should -Be (@(
            'id', 'ioc', 'threat_type', 'threat_type_desc', 'ioc_type',
            'ioc_type_desc', 'malware', 'malware_printable', 'malware_alias',
            'malware_malpedia', 'confidence_level', 'first_seen', 'last_seen',
            'reference', 'reporter', 'tags') | Sort-Object)
        $payload.data[0].malware_printable | Should -BeExactly 'AgentTesla'
        $payload.data[0].malware_alias.GetType().FullName | Should -BeExactly 'System.String'
        $payload.data[0].malware_alias | Should -BeExactly 'Agent Tesla,Negasteal'
        @($payload.data[0].tags) | Should -Contain 'TA505'
        $payload.data[0].ioc | Should -Match '\.invalid/'
        $payload.data[0].reference | Should -Match '\.invalid/'
    }

    It 'Serves ok with empty data for an unknown SHA-256' {
        $body = @{ query = 'search_hash'; hash = $script:UnknownHash } | ConvertTo-Json -Compress
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body $body `
            -ContentType 'application/json'
        $payload = $response.Content | ConvertFrom-Json

        $response.StatusCode | Should -Be 200
        $payload.query_status | Should -BeExactly 'ok'
        @($payload.data).Count | Should -Be 0
    }

    It 'Rejects a SHA-1 while logging the request so the guard remains observable' {
        $before = Get-MockApiServerHitCount -Server $script:Server -Path $script:TfPath
        $body = @{ query = 'search_hash'; hash = $script:Sha1 } | ConvertTo-Json -Compress

        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)$($script:TfPath)" `
            -Method Post -Headers @{ 'Auth-Key' = $script:TfKey } -Body $body `
            -ContentType 'application/json' -SkipHttpErrorCheck

        $after = Get-MockApiServerHitCount -Server $script:Server -Path $script:TfPath
        ($after - $before) | Should -Be 1
        $response.StatusCode | Should -Be 200
        ($response.Content | ConvertFrom-Json).query_status | Should -BeExactly 'illegal_hash'
    }

    It 'Logs only path, method, and authExact without key, hash, body, or query values' {
        $requestLog = Invoke-RestMethod -Uri $script:JournalUri
        $entries = @($requestLog.requests | Where-Object {
                [string]::Equals([string]$_.path, $script:TfPath, [StringComparison]::OrdinalIgnoreCase)
            })

        $entries.Count | Should -BeGreaterThan 0
        foreach ($entry in $entries) {
            @($entry.PSObject.Properties.Name).Count | Should -Be 3
            $entry.PSObject.Properties.Name | Should -Contain 'path'
            $entry.PSObject.Properties.Name | Should -Contain 'method'
            $entry.PSObject.Properties.Name | Should -Contain 'authExact'
            $entry.authExact.GetType().Name | Should -BeExactly 'Boolean'
        }

        $requestLogJson = $requestLog | ConvertTo-Json -Depth 10 -Compress
        $requestLogJson | Should -Not -Match [regex]::Escape($script:TfKey)
        $requestLogJson | Should -Not -Match [regex]::Escape($script:KnownHash)
        $requestLogJson | Should -Not -Match [regex]::Escape($script:UnknownHash)
        $requestLogJson | Should -Not -Match [regex]::Escape($script:Sha1)
        $requestLogJson | Should -Not -Match 'search_hash'
    }
}
