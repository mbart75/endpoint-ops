#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    $functionPath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-HttpStatusFromError.ps1'
    if (Test-Path -LiteralPath $functionPath) {
        . $functionPath
    }
}

Describe 'Get-HttpStatusFromError' {
    It 'Extracts the 404 status after the transport anchor' {
        Get-HttpStatusFromError -Message 'EndpointOps: GET https://example.test/a returned 404 after 1 attempt(s)' |
            Should -Be 404
    }

    It 'Extracts the status 429 after the transport marker' {
        Get-HttpStatusFromError -Message 'EndpointOps: GET https://example.test/a returned 429 after 1 attempt(s)' |
            Should -Be 429
    }

    It 'Extracts the status 500 after several attempts' {
        Get-HttpStatusFromError -Message 'EndpointOps: GET https://example.test/a returned 500 after 4 attempt(s)' |
            Should -Be 500
    }

    It 'Returns $null without throwing when the message has no status' {
        { Get-HttpStatusFromError -Message 'EndpointOps: call interrupted by the network' } |
            Should -Not -Throw
        Get-HttpStatusFromError -Message 'EndpointOps: call interrupted by the network' |
            Should -BeNullOrEmpty
    }

    It 'Ignores a 404 URL fragment and returns the actual status 200' {
        Get-HttpStatusFromError -Message 'EndpointOps: GET https://example.test/api/404/file returned 200 after 1 attempt(s)' |
            Should -Be 200
    }
}
