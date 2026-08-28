#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:VtKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
    $script:KnownPath = "/api/v3/files/$(('A' * 38) + '01')"
    $script:RateLimitedPath = "/api/v3/files/$(('F' * 38) + '06')"
    $script:FailingPath = "/api/v3/files/$(('1' * 38) + '08')"
    $script:InvokeVtRequestPath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Invoke-VtRequest.ps1'
}

AfterAll {
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'VirusTotal connection' {
    AfterEach {
        if (Get-Command Disconnect-VirusTotal -ErrorAction SilentlyContinue) {
            Disconnect-VirusTotal
        }
    }

    It 'Sets up the connection without exposing the key in the returned object' {
        $connection = Connect-VirusTotal -ApiKey $script:VtKey

        $connection.BaseUri | Should -Be 'https://www.virustotal.com'
        $connection.PSObject.Properties.Name | Should -Not -Contain 'ApiKey'
        ($connection | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Closes the connection and remains idempotent' {
        Connect-VirusTotal -ApiKey $script:VtKey | Out-Null

        { Disconnect-VirusTotal; Disconnect-VirusTotal } | Should -Not -Throw
    }
}

Describe 'VirusTotal call authenticates and terminates' {
    BeforeEach {
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
    }

    AfterEach {
        Disconnect-VirusTotal
    }

    It 'Emits the exact key without disclosing it in the Debug stream' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        $debugOutput = InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -Debug 5>&1 | Out-String
        }

        $log = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $entry = $log[$before]
        $entry.authExact | Should -BeTrue
        $debugOutput | Should -Not -Match 'MOCK-VT-KEY'
        ($entry | ConvertTo-Json -Compress) | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Names Connect-VirusTotal when the connection has been closed' {
        Disconnect-VirusTotal

        $message = InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            try {
                Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 | Out-Null
                ''
            }
            catch { $_.Exception.Message }
        }

        $message | Should -Match 'Connect-VirusTotal'
    }

    It 'Spaces two consecutive calls by at least the requested interval' {
        $chrono = [System.Diagnostics.Stopwatch]::StartNew()
        InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 400 | Out-Null
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 400 | Out-Null
        }
        $chrono.Stop()

        $chrono.ElapsedMilliseconds | Should -BeGreaterOrEqual 400
    }

    It 'Blocks a daily quota excess without issuing a third call' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        $message = InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -DailyQuota 2 | Out-Null
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -DailyQuota 2 | Out-Null
            try {
                Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -DailyQuota 2 | Out-Null
                ''
            }
            catch { $_.Exception.Message }
        }

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $message | Should -Match 'daily VirusTotal quota.*2'
        ($after - $before) | Should -Be 2
    }

    It 'Does not reset the quota to zero during a reconnection without disconnection' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        $message = InModuleScope EndpointOps -Parameters @{
            RequestPath = $script:KnownPath
            VtKey       = $script:VtKey
            BaseUri     = $script:Server.BaseUrl
        } {
            param($RequestPath, $VtKey, $BaseUri)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -DailyQuota 1 | Out-Null
            Connect-VirusTotal -ApiKey $VtKey -BaseUri $BaseUri | Out-Null
            try {
                Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -DailyQuota 1 | Out-Null
                ''
            }
            catch { $_.Exception.Message }
        }

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $message | Should -Match 'daily VirusTotal quota.*1'
        ($after - $before) | Should -Be 1
    }

    It 'Counts in the new day a request whose waiting time crosses midnight UTC' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $beforePacing = ([datetimeoffset]'2030-01-01T23:59:59.950Z').UtcDateTime
        $afterPacing = ([datetimeoffset]'2030-01-02T00:00:00.050Z').UtcDateTime

        $state = InModuleScope EndpointOps -Parameters @{
            RequestPath = $script:KnownPath
            BeforePacing = $beforePacing
            AfterPacing = $afterPacing
        } {
            param($RequestPath, $BeforePacing, $AfterPacing)
            $script:VtUtcTimes = [System.Collections.Generic.Queue[datetime]]::new()
            $script:VtUtcTimes.Enqueue($BeforePacing)
            $script:VtUtcTimes.Enqueue($AfterPacing)
            Mock Get-VtUtcNow { $script:VtUtcTimes.Dequeue() }

            $state = Get-VtConnectionState
            $state.LastRequestAtUtc = $BeforePacing.AddMilliseconds(-50)
            $state.DailyRequestDateUtc = $BeforePacing.Date
            $state.DailyRequestCount = 5

            try {
                Invoke-VtRequest -Path $RequestPath -MinIntervalMs 100 -DailyQuota 10 | Out-Null
                [pscustomobject]@{
                    Date = $state.DailyRequestDateUtc
                    Count = $state.DailyRequestCount
                }
            }
            finally {
                Remove-Variable -Name VtUtcTimes -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $state.Date | Should -Be $afterPacing.Date
        $state.Count | Should -Be 1
        ($after - $before) | Should -Be 1
    }

    It 'Keeps the counter when the waiting time remains in the same UTC day' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $beforePacing = ([datetimeoffset]'2030-01-01T12:00:00.000Z').UtcDateTime
        $afterPacing = ([datetimeoffset]'2030-01-01T12:00:00.050Z').UtcDateTime

        $state = InModuleScope EndpointOps -Parameters @{
            RequestPath = $script:KnownPath
            BeforePacing = $beforePacing
            AfterPacing = $afterPacing
        } {
            param($RequestPath, $BeforePacing, $AfterPacing)
            $script:VtUtcTimes = [System.Collections.Generic.Queue[datetime]]::new()
            $script:VtUtcTimes.Enqueue($BeforePacing)
            $script:VtUtcTimes.Enqueue($AfterPacing)
            Mock Get-VtUtcNow { $script:VtUtcTimes.Dequeue() }

            $state = Get-VtConnectionState
            $state.LastRequestAtUtc = $BeforePacing.AddMilliseconds(-50)
            $state.DailyRequestDateUtc = $BeforePacing.Date
            $state.DailyRequestCount = 5

            try {
                Invoke-VtRequest -Path $RequestPath -MinIntervalMs 100 -DailyQuota 10 | Out-Null
                [pscustomobject]@{
                    Date = $state.DailyRequestDateUtc
                    Count = $state.DailyRequestCount
                }
            }
            finally {
                Remove-Variable -Name VtUtcTimes -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $state.Date | Should -Be $afterPacing.Date
        $state.Count | Should -Be 6
        ($after - $before) | Should -Be 1
    }

    It 'Does not disclose the key or retry status 429' {
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -eq $script:RateLimitedPath).Count

        $capture = InModuleScope EndpointOps -Parameters @{ RequestPath = $script:RateLimitedPath } {
            param($RequestPath)
            $null = $RequestPath
            & {
                try { Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -Debug | Out-Null }
                catch { $_ | Out-String }
            } 5>&1 | Out-String
        }

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($logAfter | Where-Object path -eq $script:RateLimitedPath).Count
        $capture | Should -Match '\b429\b'
        $capture | Should -Not -Match 'MOCK-VT-KEY'
        ($logAfter | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match 'MOCK-VT-KEY'
        ($after - $before) | Should -Be 1
    }

    It 'Does not disclose the key and sends exactly two requests on status 500' {
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -eq $script:FailingPath).Count

        $capture = InModuleScope EndpointOps -Parameters @{ RequestPath = $script:FailingPath } {
            param($RequestPath)
            $null = $RequestPath
            & {
                try { Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -Debug | Out-Null }
                catch { $_ | Out-String }
            } 5>&1 | Out-String
        }

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($logAfter | Where-Object path -eq $script:FailingPath).Count
        $capture | Should -Match '\b500\b'
        $capture | Should -Not -Match 'MOCK-VT-KEY'
        ($logAfter | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match 'MOCK-VT-KEY'
        ($after - $before) | Should -Be 2
    }
}

Describe 'VirusTotal rate defaults' {
    It 'Keeps 15000 ms as the default interval on the private function' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:InvokeVtRequestPath, [ref]$tokens, [ref]$errors)

        @($errors).Count | Should -Be 0
        $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Invoke-VtRequest'
            }, $false)
        $interval = $functionAst.Body.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -eq 'MinIntervalMs' }

        $interval.DefaultValue.Extent.Text | Should -Be '15000'
    }
}
