BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Token = ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN'
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Connect-S1Tenant' {
    AfterEach {
        Disconnect-S1Tenant
    }

    It 'Accepts an HTTPS console' {
        $r = Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $script:Token -SkipValidation
        $r.BaseUri | Should -Be 'https://example.sentinelone.net'
    }

    It 'Removes the trailing slash' {
        $r = Connect-S1Tenant -BaseUri 'https://example.sentinelone.net/' -ApiToken $script:Token -SkipValidation
        $r.BaseUri | Should -Be 'https://example.sentinelone.net'
    }

    It 'Rejects an HTTP console that is not local' {
        { Connect-S1Tenant -BaseUri 'http://example.sentinelone.net' -ApiToken $script:Token -SkipValidation } |
            Should -Throw -ExpectedMessage '*HTTPS*'
    }

    It 'Accepts HTTP on loopback so that the test harness can run' {
        $r = Connect-S1Tenant -BaseUri 'http://localhost:9999' -ApiToken $script:Token -SkipValidation
        $r.BaseUri | Should -Be 'http://localhost:9999'
    }

    It 'Never returns the token' {
        $r = Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $script:Token -SkipValidation
        ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-S1-TOKEN'
        $r.PSObject.Properties.Name | Should -Not -Contain 'ApiToken'
    }

    It 'Indicates that the connection has not been validated' {
        $r = Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $script:Token -SkipValidation
        $r.Validated | Should -BeFalse
    }
}

Describe 'Disconnect-S1Tenant' {
    # These tests verify the directly observable disconnect contract: idempotency and the ability to
    # establish a new connection after clearing the previous session state.

    It 'Can be called without active connection' {
        { Disconnect-S1Tenant } | Should -Not -Throw
    }

    It 'May be called twice in a row' {
        Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $script:Token -SkipValidation | Out-Null
        { Disconnect-S1Tenant; Disconnect-S1Tenant } | Should -Not -Throw
    }

    It 'Allows the connection to be reopened after disconnection' {
        Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $script:Token -SkipValidation | Out-Null
        Disconnect-S1Tenant
        $r = Connect-S1Tenant -BaseUri 'https://other.example.invalid' -ApiToken $script:Token -SkipValidation
        $r.BaseUri | Should -Be 'https://other.example.invalid'
    }
}

Describe 'Connect-S1Tenant - validation against a real server' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
        $script:Server = Start-MockApiServer
    }

    AfterAll {
        Stop-MockApiServer -Server $script:Server
    }

    AfterEach {
        Disconnect-S1Tenant
    }

    It 'Validates the connection and reports it' {
        $r = Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken $script:Token
        $r.Validated | Should -BeTrue
    }

    It 'Rejects a bad token' {
        $bad = ConvertTo-TestSecureString -PlainText 'BAD TOKEN'

        { Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken $bad } |
            Should -Throw -ExpectedMessage '*refused*'
    }

    It 'Allows a normal reconnection after a failure' {
        # Voluntarily modest name: this test verifies reconnection, NOT resetting the state. Measurement
# made by removing the line $script:S1Connection = $null from the catch block: it remains green,
# because the next connection overwrites the state regardless. The assertion that proves the
# reset lives in S1Agent.Tests.ps1, or Get-S1Agent can read the state without rewriting it.
        $bad = ConvertTo-TestSecureString -PlainText 'BAD TOKEN'
        try { Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken $bad } catch { Write-Verbose 'Expected failure' }

        $r = Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken $script:Token
        $r.Validated | Should -BeTrue
    }

    It 'Does not make any network calls with -SkipValidation' {
        $bad = ConvertTo-TestSecureString -PlainText 'BAD TOKEN'
        # The token is a mock value, but no request is sent: the connection opens.
        $r = Connect-S1Tenant -BaseUri $script:Server.BaseUrl -ApiToken $bad -SkipValidation
        $r.Validated | Should -BeFalse
    }
}
