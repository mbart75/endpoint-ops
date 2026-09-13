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

    Context 'Bounded retry delays' {
        It 'Rejects hostile Retry-After value <Header>' -TestCases @(
            @{ Header = 'NaN';       Max = 60; Message = '*invalid Retry-After*' }
            @{ Header = 'Infinity';  Max = 60; Message = '*invalid Retry-After*' }
            @{ Header = '-Infinity'; Max = 60; Message = '*invalid Retry-After*' }
            @{ Header = '-1';        Max = 60; Message = '*invalid Retry-After*' }
            @{ Header = '1.5';       Max = 60; Message = '*invalid Retry-After*' }
            @{ Header = '999999';    Max = 60; Message = '*exceeds*60*' }
            @{ Header = 'later';     Max = 60; Message = '*invalid Retry-After*' }
        ) {
            param($Header, $Max, $Message)

            InModuleScope EndpointOps -Parameters @{ Header = $Header; Max = $Max; Message = $Message } {
                Mock Invoke-WebRequest {
                    [pscustomobject]@{ StatusCode = 429; Headers = @{ 'Retry-After' = $Header } }
                }
                Mock Start-Sleep

                {
                    Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                        -MaxAttempts 2 -MaxRetryAfterSec $Max
                } | Should -Throw -ExpectedMessage $Message

                Should -Invoke Start-Sleep -Times 0 -Exactly
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly
            }
        }

        It 'Honors an integer delta-seconds value within policy' {
            InModuleScope EndpointOps {
                $script:RetryCall = 0
                Mock Invoke-WebRequest {
                    $script:RetryCall++
                    if ($script:RetryCall -eq 1) {
                        return [pscustomobject]@{ StatusCode = 429; Headers = @{ 'Retry-After' = '1' } }
                    }
                    [pscustomobject]@{ StatusCode = 200; Headers = @{} }
                }
                Mock Start-Sleep

                Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                    -MaxAttempts 2 -MaxRetryAfterSec 60 | Out-Null

                Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 1 }
                Should -Invoke Invoke-WebRequest -Times 2 -Exactly
            }
        }

        It 'Honors a future HTTP date within policy' {
            InModuleScope EndpointOps {
                $script:RetryCall = 0
                do {
                    $phase = [DateTimeOffset]::UtcNow
                    if ($phase.Millisecond -lt 600 -or $phase.Millisecond -gt 650) {
                        [System.Threading.Thread]::Sleep(5)
                    }
                } until ($phase.Millisecond -ge 600 -and $phase.Millisecond -le 650)
                $script:FutureRetryDate = $phase.AddSeconds(20).ToString('R')
                Mock Invoke-WebRequest {
                    $script:RetryCall++
                    if ($script:RetryCall -eq 1) {
                        return [pscustomobject]@{
                            StatusCode = 429
                            Headers = @{ 'Retry-After' = $script:FutureRetryDate }
                        }
                    }
                    [pscustomobject]@{ StatusCode = 200; Headers = @{} }
                }
                Mock Start-Sleep

                Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                    -MaxAttempts 2 -MaxRetryAfterSec 60 | Out-Null

                Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter {
                    $Seconds -is [double] -and $Seconds -gt 19 -and $Seconds -le 20
                }
                Should -Invoke Invoke-WebRequest -Times 2 -Exactly
            }
        }

        It 'Treats a valid far-past HTTP date as a zero-second wait' {
            InModuleScope EndpointOps {
                $script:RetryCall = 0
                $script:FarPastRetryDate = [DateTimeOffset]::new(
                    1900, 11, 6, 8, 49, 37, [TimeSpan]::Zero).ToString('R')
                Mock Invoke-WebRequest {
                    $script:RetryCall++
                    if ($script:RetryCall -eq 1) {
                        return [pscustomobject]@{
                            StatusCode = 429
                            Headers = @{ 'Retry-After' = $script:FarPastRetryDate }
                        }
                    }
                    [pscustomobject]@{ StatusCode = 200; Headers = @{} }
                }
                Mock Start-Sleep

                Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                    -MaxAttempts 2 -MaxRetryAfterSec 60 | Out-Null

                Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter {
                    $Seconds -is [double] -and $Seconds -eq 0
                }
                Should -Invoke Invoke-WebRequest -Times 2 -Exactly
            }
        }

        It 'Rejects a valid far-future HTTP date without exposing it' {
            InModuleScope EndpointOps {
                $script:FarFutureRetryDate = [DateTimeOffset]::new(
                    2200, 11, 6, 8, 49, 37, [TimeSpan]::Zero).ToString('R')
                Mock Invoke-WebRequest {
                    [pscustomobject]@{
                        StatusCode = 429
                        Headers = @{ 'Retry-After' = $script:FarFutureRetryDate }
                    }
                }
                Mock Start-Sleep

                $errorMessage = ''
                try {
                    Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                        -MaxAttempts 2 -MaxRetryAfterSec 60 | Out-Null
                }
                catch { $errorMessage = $_.Exception.Message }

                $errorMessage | Should -BeLike '*exceeds*60*'
                $errorMessage | Should -Not -BeLike "*$script:FarFutureRetryDate*"
                Should -Invoke Start-Sleep -Times 0 -Exactly
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly
            }
        }

        It 'Does not round a fractional HTTP-date delay below the policy limit' {
            InModuleScope EndpointOps {
                do {
                    $phase = [DateTimeOffset]::UtcNow
                    if ($phase.Millisecond -lt 550 -or $phase.Millisecond -gt 650) {
                        [System.Threading.Thread]::Sleep(5)
                    }
                } until ($phase.Millisecond -ge 550 -and $phase.Millisecond -le 650)

                $script:NearLimitRetryDate = $phase.AddSeconds(61).ToString('R')
                Mock Invoke-WebRequest {
                    [pscustomobject]@{
                        StatusCode = 429
                        Headers = @{ 'Retry-After' = $script:NearLimitRetryDate }
                    }
                }
                Mock Start-Sleep

                {
                    Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                        -MaxAttempts 2 -MaxRetryAfterSec 60
                } | Should -Throw -ExpectedMessage '*exceeds*60*'

                Should -Invoke Start-Sleep -Times 0 -Exactly
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly
            }
        }

        It 'Treats a past HTTP date as a zero-second wait' {
            InModuleScope EndpointOps {
                $script:RetryCall = 0
                $script:PastRetryDate = [DateTimeOffset]::UtcNow.AddMinutes(-5).ToString('R')
                Mock Invoke-WebRequest {
                    $script:RetryCall++
                    if ($script:RetryCall -eq 1) {
                        return [pscustomobject]@{
                            StatusCode = 429
                            Headers = @{ 'Retry-After' = $script:PastRetryDate }
                        }
                    }
                    [pscustomobject]@{ StatusCode = 200; Headers = @{} }
                }
                Mock Start-Sleep

                Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/throttled' `
                    -MaxAttempts 2 -MaxRetryAfterSec 60 | Out-Null

                Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 0 }
                Should -Invoke Invoke-WebRequest -Times 2 -Exactly
            }
        }

        It 'Rejects exponential backoff above the retry-delay policy' {
            InModuleScope EndpointOps {
                Mock Invoke-WebRequest {
                    [pscustomobject]@{ StatusCode = 500; Headers = @{} }
                }
                Mock Start-Sleep

                {
                    Invoke-EndpointOpsHttpRequest -Uri 'https://tenant.example.invalid/failure' `
                        -MaxAttempts 2 -BackoffBaseSec 2 -MaxRetryAfterSec 1
                } | Should -Throw -ExpectedMessage '*exceeds*1*'

                Should -Invoke Start-Sleep -Times 0 -Exactly
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly
            }
        }
    }
}
