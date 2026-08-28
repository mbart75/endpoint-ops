BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    $script:Server = Start-MockApiServer

    # Fixed identifiers of the mock server. They are deliberately written in plain text here: no real
# secrets exist in this repository, and a test that would guess these values would prove nothing.
    $script:EpmUser  = 'mock-epm-user'
    $script:EpmPass  = 'MOCK-EPM-PASSWORD'
    $script:EpmAppId = 'EndpointOps'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
}

Describe 'EPM authentication routes of the mock server' {

    It 'Exposes the version of the dispatcher without authorization header' {
        # This is the reachability control: it must respond BEFORE a password has circulated, otherwise we
# cannot distinguish an unreachable dispatcher from rejected credentials.
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Server/Version" -SkipHttpErrorCheck
        $response.StatusCode | Should -Be 200

        $body = $response.Content | ConvertFrom-Json
        $body.PSObject.Properties.Name | Should -Contain 'Version'
        $body.Version | Should -Not -BeNullOrEmpty
    }

    It 'Returns a token, a ManagerURL and the status of the password on a valid logon' {
        $requestBody = @{
            Username      = $script:EpmUser
            Password      = $script:EpmPass
            ApplicationID = $script:EpmAppId
        } | ConvertTo-Json

        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Auth/EPM/Logon" `
            -Method Post -Body $requestBody -ContentType 'application/json' -SkipHttpErrorCheck
        $response.StatusCode | Should -Be 200

        $body = $response.Content | ConvertFrom-Json
        $names = $body.PSObject.Properties.Name
        $names | Should -Contain 'EPMAuthenticationResult'
        $names | Should -Contain 'ManagerURL'
        $names | Should -Contain 'IsPasswordExpired'
        $body.EPMAuthenticationResult | Should -Not -BeNullOrEmpty
        $body.IsPasswordExpired | Should -BeFalse
    }

    It 'Returns a ManagerURL that points to the mock server' {
        # Without this, the dispatcher -> ManagerURL model would not be executable offline: the rest of the
# pagination would start in the void.
        $requestBody = @{
            Username      = $script:EpmUser
            Password      = $script:EpmPass
            ApplicationID = $script:EpmAppId
        } | ConvertTo-Json

        $body = Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/EPM/API/Auth/EPM/Logon" `
            -Method Post -Body $requestBody -ContentType 'application/json'

        $body.ManagerURL | Should -Be $script:Server.BaseUrl
    }

    It 'Rejects an incorrect password with a 401' {
        $requestBody = @{
            Username      = $script:EpmUser
            Password      = 'BAD PASSWORD'
            ApplicationID = $script:EpmAppId
        } | ConvertTo-Json

        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Auth/EPM/Logon" `
            -Method Post -Body $requestBody -ContentType 'application/json' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401
    }

    It 'Rejects a body without an ApplicationID with a 400' {
        # ApplicationID is mandatory according to the doc: it is an improperly formatted request, not a
# refusal of identifiers. The return code must say so.
        $requestBody = @{
            Username = $script:EpmUser
            Password = $script:EpmPass
        } | ConvertTo-Json

        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Auth/EPM/Logon" `
            -Method Post -Body $requestBody -ContentType 'application/json' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 400
    }

    It 'Rejects a protected EPM route called without an Authorization header' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Sets" -SkipHttpErrorCheck
        $response.StatusCode | Should -Be 401
    }

    It 'Rejects a protected EPM route with a bad token' {
        # The trap here is: an HTTP client that would build a standard authentication from a PSCredential
# would send a user/password pair encoded in base64 where EPM expects the RAW TOKEN. Therefore, it
# is not the schema case that fails this call: the schema is accepted regardless of its
# case, a lower test verifies it. It is indeed the transmitted value that is rejected, because
# it is not the token.
        #
        # The formulation deliberately avoids the "Basic" sequence followed by a word: the hard
        # credential scan of tests/security looks for exactly this form, and prose that contains it
        # would be a false positive. Correcting the sentence is better than weakening the pattern.
        $falseValue = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$($script:EpmUser):$($script:EpmPass)"))
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Sets" `
            -Headers @{ Authorization = "Basic $falseValue" } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401
    }

    It 'Accepts a protected EPM route whose token has the correct casing' {
        # This control case ensures that a 401 in the next test is caused by altered token casing rather than
        # a missing route, an overly broad guard, or incorrect server startup.
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Sets" `
            -Headers @{ Authorization = 'basic MOCK-EPM-TOKEN' } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200
    }

    It 'Rejects a protected EPM route whose token casing is altered' {
        # A path with altered casing is harmless; accepting a TOKEN with altered casing would mean the mock server validates an invalid
# secret. Tokens are sensitive to case everywhere, so the guard must be. The schema, however,
# remains insensitive to case: see the following test.
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Sets" `
            -Headers @{ Authorization = 'basic mock-epm-token' } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 401 -Because 'A token is sensitive to case'
    }

    It 'Accepts the authentication scheme regardless of casing' {
        # RFC 7235: the authentication schema is case-insensitive. Hardening the token should not harden the
# scheme in the process, otherwise one defect would merely replace another.
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Sets" `
            -Headers @{ Authorization = 'BASIC MOCK-EPM-TOKEN' } -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 200 -Because 'The scheme is case-insensitive, but the token is not'
    }

    It 'Rejects a protected EPM route whose path casing differs from the guard' {
        # The same trap applies as for SentinelOne: the switch-based router ignores casing. If the EPM guard
        # treated casing differently, /epm/api/Sets could bypass the guard and still reach the route.
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/epm/api/Sets" -SkipHttpErrorCheck
        $response.StatusCode | Should -Be 401 -Because 'The guard must cover exactly what the router accepts'
    }

    # The two tests that follow are deliberately in LAST: if the server dies, everything that follows
# would fail in a cascade and mask the cause.
    #
    # They are deliberately SEPARATE rather than combined in a single two-assertion test. Combined,
    # the -Be 400 fails first and interrupts the test: the survival assertion would never be
    # evaluated, so never proven capable of failing. Observe by injecting the fault, not assuming.
    It 'Returns 400 for an unreadable JSON body sent without authentication' {
        $response = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Auth/EPM/Logon" `
            -Method Post -Body '{ not json' -ContentType 'application/json' -SkipHttpErrorCheck

        $response.StatusCode | Should -Be 400
    }

    It 'Remains reachable after an unreadable JSON body sent without authentication' {
        # The body is read BEFORE the authentication guard. Without try/catch around the JSON analysis, the
# exception goes up to the finally of the listening loop, which closes the listener: an
# unauthenticated caller would stop the server in the middle of a test suite.
        Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/EPM/API/Auth/EPM/Logon" `
            -Method Post -Body '{ still not json' -ContentType 'application/json' `
            -SkipHttpErrorCheck | Out-Null

        $health = Invoke-WebRequest -Uri "$($script:Server.BaseUrl)/health" -TimeoutSec 5 -SkipHttpErrorCheck
        $health.StatusCode | Should -Be 200 -Because 'A malformed body should not stop the mock server'
    }
}
