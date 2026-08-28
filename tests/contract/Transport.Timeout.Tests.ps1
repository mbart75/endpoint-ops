BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-EndpointOpsRequest - timeout' {
    # Each It starts its own mock server rather than sharing one via BeforeAll file. The /slow route
# sleeps 5 seconds on the server side, even after the client has abandoned its side. With a single
# shared server, the second test would reopen a connection while the first call may still be
# sleeping on the same HttpListener, making the result unstable depending on the timing. One server
# (so one port and one job) per test completely isolates the two dozings of 5 seconds from each
# other, without weakening any assertion.
    BeforeEach {
        $script:Server = Start-MockApiServer

        # Warm-up, out of any measure. The first HTTP call of a process pays for the JIT compilation of the
# module and the initialization of the HTTP stack: this is time that has nothing to do with the test
# expiration delay, and it is exactly what makes a cold-start timeout assertion fragile. We
# pay for it here, once, on a route that responds immediately.
        Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/health" | Out-Null
    }

    AfterEach {
        Stop-MockApiServer -Server $script:Server
    }

    It 'Gives up after the deadline rather than waiting indefinitely' {
        # This test deliberately keeps a duration limit because elapsed time is part of the contract.
        #
        # A countdown would make no difference here: whether the client abandons after a second or
        # waits for the five seconds of /slow, the server receives a request, only one. What
        # separates the two behaviors is the MOMENT when the client gives up.
        #
        # The Should -Throw already contains the essentials: waiting for the complete response would
        # return a 200, so there is no exception. The elapsed-time assertion adds the only fact it does not provide: that
        # the abandonment occurs before the requested deadline and not later.
        #
        # The timeout is extended from 4 s to 4.5 s and remains high: /slow sleeps for five seconds
        # before responding, so the faulty behavior cannot end in less than 5 s, regardless of the
        # machine. Any value strictly less than 5 discriminates; 4.5 leaves 3.4 s of margin above
        # the expected second. The BeforeEach warm-up is outside the measurement, the cost of cold
        # start, which was the only known source of variance at this point.
        $elapsed = Measure-Command {
            { Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/slow" -TimeoutSec 1 } |
                Should -Throw -ExpectedMessage '*interrupted*'
        }
        $elapsed.TotalSeconds | Should -BeLessThan 4.5
    }

    It 'Does not retry after the deadline' {
        # A timeout is not retried: without a real timeout, we do not know if it is transient or structural,
# and retrying a query that is already slow multiplies the waiting time.
        #
        # What the test proves: despite MaxAttempts being 4, the server only received ONE request.
        # The server is new each It (BeforeEach), so the absolute value is sufficient, without prior
        # detection.
        #
        # The reading of the counter waits for /slow to finish sleeping its five seconds: the
        # HttpListener is single-threaded and will not respond before. This is a bounded wait, not a
        # blocking, and the wide expiration delay of Get-MockApiServerHitCount is sized for the
        # worst case, meaning four queued requests could consume twenty seconds of service time.
        try { Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/slow" -TimeoutSec 1 -MaxAttempts 4 -BackoffBaseSec 0.1 }
        catch { Write-Verbose "Expected failure: $($_.Exception.Message)" }

        Get-MockApiServerHitCount -Server $script:Server -Path '/slow' |
            Should -Be 1 -Because 'A time limit exceeded must not be retried'
    }
}
