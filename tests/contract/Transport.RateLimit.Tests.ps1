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

Describe 'Invoke-EndpointOpsRequest - rate limiting' {
    It 'Retries after a 429, respects Retry-After, and eventually succeeds' {
        # The /throttled route returns a 429 with Retry-After: 1 on the first call only. With a base backoff
# of 0.1 s, a total duration greater than a second proves that it is indeed the server header that
# was followed, and not our own calculation. A Stopwatch replaces Measure-Command: PSScriptAnalyzer
# (PSUseDeclaredVarsMoreThanAssignment) does not follow assignments across the boundary of the
# Measure-Command scriptblock and signals $summary as unused, while it is actually read further down.
# Same limit observation of the tool as that already documented in MockApiServer.ps1 for Start-Job
# runspaces.
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $summary = Invoke-EndpointOpsRequest -Uri "$($script:Server.BaseUrl)/throttled" -BackoffBaseSec 0.1
        $stopwatch.Stop()
        $elapsed = $stopwatch.Elapsed

        $summary.ok | Should -BeTrue
        $summary.attempts | Should -Be 2
        $elapsed.TotalSeconds | Should -BeGreaterThan 0.9
    }
}
