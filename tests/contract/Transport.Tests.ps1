BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
    $script:Server = Start-MockApiServer
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-EndpointOpsRequest - simple request' {
    It 'Transmits the authentication header' {
        $summary = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/echo-headers" -Headers @{ Authorization = 'ApiToken SECRET123' }
        $summary.Authorization | Should -Be 'ApiToken SECRET123'
    }

    It 'Returns the deserialized object' {
        $summary = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/health"
        $summary.status | Should -Be 'ok'
    }
}

Describe 'Invoke-EndpointOpsRequest - server errors' {
    It 'Retries a transient 500 response and eventually succeeds' {
        $summary = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/flaky" -MaxAttempts 4 -BackoffBaseSec 0.1
        $summary.ok | Should -BeTrue
        $summary.attempts | Should -Be 3
    }

    It 'Gives up after MaxAttempts and reports it in the message' {
        { Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/always-fails" -MaxAttempts 3 -BackoffBaseSec 0.1 } |
            Should -Throw -ExpectedMessage '*3 attempt(s)*'
    }

    It 'Does not retry a 404 response' {
        # What the test proves: the server has received ONLY ONE request for this path. A 404 does not fix
# itself, trying again would only add unnecessary calls.
        #
        # The subtraction is performed before and after, and it is the difference that is asserted:
        # the mock server is shared by the entire file, an absolute value would depend on the order
        # of execution.
        #
        # BackoffBaseSec is 0.1 rather than 2: the high value only existed to widen the
        # time difference that the old time limit measured. The decrement does not depend on the
        # waiting time, and a regression now fails in a fraction of a second instead of waiting for
        # the next step during the three successive decrements.
        $before = Get-MockApiServerHitCount -Server $script:Server -Path '/inexistant'
        try { Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/inexistant" -MaxAttempts 4 -BackoffBaseSec 0.1 }
        catch {
            # Expected: 404 n cannot be retried. Only the number of calls received interests us here, not the
# error itself.
            Write-Verbose "Error 404 expected and ignored: $($_.Exception.Message)"
        }
        $after = Get-MockApiServerHitCount -Server $script:Server -Path '/inexistant'

        ($after - $before) | Should -Be 1 -Because 'A 404 should not be tried again'
    }
}
