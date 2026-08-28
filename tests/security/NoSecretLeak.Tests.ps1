BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
    $script:Token  = 'ApiToken TOKEN-WHO-NEVER-SHOULD-APPEAR'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Non-disclosure of the token' {
    It 'Does not expose the token in the verbose stream' {
        $verbose = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/health" `
            -Headers @{ Authorization = $script:Token } -Verbose 4>&1 | Out-String

        $verbose | Should -Not -Match 'TOKEN-THAT-NEVER-SHOULD-APPEAR'
    }

    It 'Logs the header name rather than its value' {
        $verbose = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/health" `
            -Headers @{ Authorization = $script:Token } -Verbose 4>&1 | Out-String

        $verbose | Should -Match 'Authorization'
    }

    It 'Does not expose the token in a failed request error' {
        $message = try {
            Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/always-fails" `
                -Headers @{ Authorization = $script:Token } -MaxAttempts 1
        }
        catch { $_.Exception.Message }

        $message | Should -Not -Match 'TOKEN-THAT-NEVER-SHOULD-APPEAR'
    }

    It 'Finds no hardcoded token in source files' {
        $sources = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..' 'src') -Filter '*.ps1' -Recurse
        foreach ($file in $sources) {
            (Get-Content $file.FullName -Raw) | Should -Not -Match 'ApiToken\s+[A-Za-z0-9]{20,}'
        }
    }
}

Describe 'Non-disclosure of the token - SentinelOne surface' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
        $script:S1Token = ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN'
    }

    AfterEach {
        Disconnect-S1Tenant
    }

    It 'Does not return the token from Connect-S1Tenant' {
        $r = Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $script:S1Token -SkipValidation
        ($r | Format-List | Out-String) | Should -Not -Match 'MOCK-S1-TOKEN'
        ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-S1-TOKEN'
    }

    It 'Does not expose the token in the Connect-S1Tenant verbose stream' {
        $verbose = Connect-S1Tenant -BaseUri "$($script:Server.BaseUrl)" -ApiToken $script:S1Token -Verbose 4>&1 | Out-String
        $verbose | Should -Not -Match 'MOCK-S1-TOKEN'
    }

    It 'Does not expose the token in a rejected connection error' {
        $bad = ConvertTo-TestSecureString -PlainText 'SECRET TOKEN-DO-NOT-FLIGHT'
        $message = try {
            Connect-S1Tenant -BaseUri "$($script:Server.BaseUrl)" -ApiToken $bad
        }
        catch { $_.Exception.Message }

        $message | Should -Not -Match 'SECRET TOKEN-DO-NOT-FLIGHT'
    }

    It 'Does not expose the token in an authenticated request verbose stream' {
        Connect-S1Tenant -BaseUri "$($script:Server.BaseUrl)" -ApiToken $script:S1Token | Out-Null
        $verbose = Get-S1Agent -Verbose 4>&1 | Out-String
        $verbose | Should -Not -Match 'MOCK-S1-TOKEN'
        # The name of the header must remain visible: it is useful for diagnosis.
        $verbose | Should -Match 'Authorization'
    }

    It 'Does not expose the token in an authenticated request debug stream' {
        # Under -Debug, Invoke-WebRequest may emit a "WebRequest Detail" block containing request
        # headers. The adjacent -Verbose test cannot detect that separate stream, so this regression
        # check verifies that the transport explicitly suppresses HTTP debug output.
        Connect-S1Tenant -BaseUri "$($script:Server.BaseUrl)" -ApiToken $script:S1Token | Out-Null
        $debugOutput = Get-S1Agent -Debug 5>&1 | Out-String

        $debugOutput | Should -Not -Match 'MOCK-S1-TOKEN'
    }

    It 'Objects returned by the Get-S1 functions do not contain the token' {
        Connect-S1Tenant -BaseUri "$($script:Server.BaseUrl)" -ApiToken $script:S1Token | Out-Null
        $whole = @(Get-S1Agent) + @(Get-S1Exclusion) + @(Get-S1DeviceControlRule)
        ($whole | ConvertTo-Json -Depth 6) | Should -Not -Match 'MOCK-S1-TOKEN'
    }

    It 'Finds no hardcoded token in source files' {
        # Line by line, and not on the full raw text: a pattern applied to -Raw allows \s+ to cross line
# breaks and triggers a false positive between "ApiToken = $ApiToken" and the following property
# (e.g.: ConnectedAt) in a multi-line object literal.
        #
        # The first character after the space must be alphanumeric. This is what distinguishes a
        # hard token from a legitimate code: '$state.ApiToken -AsPlainText' starts with an
        # underscore, 'ApiToken = $ApiToken' with an equals sign, and a subexpression call with a
        # dollar sign. Underscores and hyphens remain allowed within the token, which
        # real tokens often contain.
        #
        # Pattern verifies on six cases before being retained: three forms of hard token, all
        # detected, and three forms of legitimate repository code, all ignored. An earlier version
        # required a quotation mark just after 'ApiToken' and no longer detected ANYTHING, not even
        # a real leak, because in a header the quotation mark precedes 'ApiToken' instead of
        # following it.
        $hardcodedTokenPattern = 'ApiToken\s+[A-Za-z0-9][A-Za-z0-9_-]{7,}'
        $sources = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..' 'src') -Filter '*.ps1' -Recurse
        foreach ($file in $sources) {
            foreach ($line in Get-Content $file.FullName) {
                $line | Should -Not -Match $hardcodedTokenPattern
            }
        }
    }
}
