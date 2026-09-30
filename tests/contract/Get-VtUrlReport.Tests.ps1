#Requires -Version 7.6

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:VtKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
    $script:MaliciousUrl = 'https://malware.example.invalid/~payload?x=1'
    $script:MaliciousUrlId = 'aHR0cHM6Ly9tYWx3YXJlLmV4YW1wbGUuaW52YWxpZC9-cGF5bG9hZD94PTE'
    $script:UnknownUrl = 'https://unknown.example.invalid/?aa'
    $script:UnknownUrlId = 'aHR0cHM6Ly91bmtub3duLmV4YW1wbGUuaW52YWxpZC8_YWE'
    $script:CleanUrl = 'https://clean.example.invalid/~download?aa=1'
    $script:CleanUrlId = 'aHR0cHM6Ly9jbGVhbi5leGFtcGxlLmludmFsaWQvfmRvd25sb2FkP2FhPTE'
    $script:RateLimitedUrl = 'https://quota.example.invalid/?aa'
    $script:RateLimitedUrlId = 'aHR0cHM6Ly9xdW90YS5leGFtcGxlLmludmFsaWQvP2Fh'
    $script:FailingUrl = 'https://failure.example.invalid/~x'
    $script:FailingUrlId = 'aHR0cHM6Ly9mYWlsdXJlLmV4YW1wbGUuaW52YWxpZC9-eA'
    $script:KnownHash = ('A' * 38) + '01'
}

AfterAll {
    Disconnect-VirusTotal
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-VtUrlReport' {
    BeforeEach {
        Disconnect-VirusTotal
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
    }

    AfterEach {
        Disconnect-VirusTotal
    }

    It 'Exports the expected public command' {
        Get-Command Get-VtUrlReport -Module EndpointOps -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'Classifies a URL known as Malicious' {
        $report = Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0

        $report.Verdict | Should -BeExactly 'Malicious'
        $report.MaliciousCount | Should -Be 6
        $report.TotalEngines | Should -Be 50
    }

    It 'Classifies a URL that was never submitted as Unknown' {
        { $script:UnknownReport = Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 } | Should -Not -Throw

        $script:UnknownReport.Verdict | Should -BeExactly 'Unknown'
        $script:UnknownReport.UrlId | Should -BeExactly $script:UnknownUrlId
    }

    It 'Rejects an empty or null URL before any network call' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        foreach ($candidateValue in @('', $null)) {
            $caughtError = try {
                Get-VtUrlReport -Url $candidateValue -MinIntervalMs 0 | Out-Null
                $null
            }
            catch { $_ }

            $caughtError | Should -Not -BeNullOrEmpty
            $caughtError.Exception | Should -BeOfType ([System.Management.Automation.ParameterBindingException])
            $caughtError.FullyQualifiedErrorId | Should -Match '^ParameterArgumentValidationError'
        }

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($after - $before) | Should -Be 0
    }

    It 'Sends a single request for two identical lookups' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0 | Out-Null
        Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0 | Out-Null

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($after - $before) | Should -Be 1
    }

    It 'Emits exactly the base64url identifier expected in the path' {
        $path = "/api/v3/urls/$($script:MaliciousUrlId)"
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -ceq $path).Count

        Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0 | Out-Null

        $log = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($log | Where-Object path -ceq $path).Count
        ($after - $before) | Should -Be 1
    }

    It 'Accepts multiple URLs per pipeline' {
        $reports = @($script:MaliciousUrl, $script:UnknownUrl |
                Get-VtUrlReport -MinIntervalMs 0)

        @($reports.Url) | Should -Be @($script:MaliciousUrl, $script:UnknownUrl)
    }

    It 'Caches Unknown and clears this cache on disconnection' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 | Out-Null
        Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 | Out-Null
        Disconnect-VirusTotal
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
        Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 | Out-Null

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($after - $before) | Should -Be 2
    }

    # Production break caught: serving a Clean URL verdict after its seven-day lifetime.
    It 'Keeps Clean through seven days and requeries after the boundary' {
        $url = $script:CleanUrl
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url; Now = $now } {
            param($TestUrl, $Now)
            $testNow = $Now
            $script:VtUrlReportCache.Clear()
            $script:VtUrlFreshnessCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtUrlFreshnessCalls++
                $malicious = if ($script:VtUrlFreshnessCalls -eq 1) { 0 } else { 6 }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = $malicious; harmless = 10
                            }
                        }
                    }
                }
            }

            try {
                $first = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(7) }
                $atBoundary = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(8) }
                $expired = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Clean'
                $atBoundary.Verdict | Should -BeExactly 'Clean'
                $expired.Verdict | Should -BeExactly 'Malicious'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUrlFreshnessCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: losing the quota-saving Unknown entry or retaining it beyond seven days.
    It 'Keeps Unknown through seven days and requeries after the boundary' {
        $url = $script:UnknownUrl
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url; Now = $now } {
            param($TestUrl, $Now)
            $testNow = $Now
            $script:VtUrlReportCache.Clear()
            $script:VtUrlUnknownCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtUrlUnknownCalls++
                if ($script:VtUrlUnknownCalls -eq 1) {
                    throw 'EndpointOps: mock VirusTotal provider returned 404.'
                }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                        }
                    }
                }
            }

            try {
                $first = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(7) }
                $atBoundary = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(8) }
                $expired = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Unknown'
                $atBoundary.Verdict | Should -BeExactly 'Unknown'
                $expired.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUrlUnknownCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: serving a Malicious URL verdict after its ninety-day lifetime.
    It 'Keeps Malicious through ninety days and requeries after the boundary' {
        $url = $script:MaliciousUrl
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url; Now = $now } {
            param($TestUrl, $Now)
            $testNow = $Now
            $script:VtUrlReportCache.Clear()
            $script:VtUrlMaliciousCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtUrlMaliciousCalls++
                $malicious = if ($script:VtUrlMaliciousCalls -eq 1) { 6 } else { 0 }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = $malicious; harmless = 10
                            }
                        }
                    }
                }
            }

            try {
                $first = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(90) }
                $atBoundary = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(91) }
                $expired = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Malicious'
                $atBoundary.Verdict | Should -BeExactly 'Malicious'
                $expired.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUrlMaliciousCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: trusting an entry whose acquisition time is in the future.
    It 'Evicts a future URL cache timestamp and requeries the provider' {
        $url = $script:CleanUrl
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url; Now = $now } {
            param($TestUrl, $Now)
            $testNow = $Now
            $script:VtUrlReportCache.Clear()
            $script:VtUrlRollbackCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtUrlRollbackCalls++
                $malicious = if ($script:VtUrlRollbackCalls -eq 1) { 0 } else { 6 }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = $malicious; harmless = 10
                            }
                        }
                    }
                }
            }

            try {
                $first = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddSeconds(-1) }
                $second = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Clean'
                $second.Verdict | Should -BeExactly 'Malicious'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUrlRollbackCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: caching a transient provider outage for the entire session.
    It 'Retries after a transient Unavailable URL transport result' {
        $url = $script:RateLimitedUrl

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url } {
            param($TestUrl)
            $script:VtUrlReportCache.Clear()
            $script:VtUrlTransportCalls = 0
            Mock Invoke-VtRequest {
                $script:VtUrlTransportCalls++
                if ($script:VtUrlTransportCalls -eq 1) {
                    throw 'EndpointOps: HTTP 503 from mock VirusTotal provider.'
                }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                        }
                    }
                }
            }

            try {
                $first = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                $second = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Unavailable'
                $second.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUrlTransportCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: caching an Unavailable report from malformed provider data.
    It 'Retries after a malformed Unavailable URL response' {
        $url = 'https://malformed.example.invalid/recovery'

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url } {
            param($TestUrl)
            $script:VtUrlReportCache.Clear()
            $script:VtUrlMalformedCalls = 0
            Mock Invoke-VtRequest {
                $script:VtUrlMalformedCalls++
                $malicious = if ($script:VtUrlMalformedCalls -eq 1) { 'many' } else { 0 }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = $malicious; harmless = 10
                            }
                        }
                    }
                }
            }

            try {
                $first = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
                $second = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Unavailable'
                $second.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUrlMalformedCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: leaking private cache metadata through the public report.
    It 'Stores a timestamped private envelope without changing the public report' {
        $url = $script:CleanUrl
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ TestUrl = $url; Now = $now } {
            param($TestUrl, $Now)
            $script:VtUrlReportCache.Clear()
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest {
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                        }
                    }
                }
            }

            $report = Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
            $entry = $script:VtUrlReportCache[$TestUrl]

            @($entry.PSObject.Properties.Name) | Should -Be @('Report', 'CachedAtUtc')
            $entry.CachedAtUtc | Should -BeOfType ([datetime])
            $entry.CachedAtUtc | Should -BeExactly $Now
            $report.PSObject.TypeNames[0] | Should -BeExactly 'EndpointOps.VirusTotal.UrlReport'
            @($report.PSObject.Properties.Name) | Should -Be @(
                'Url', 'UrlId', 'verdict', 'MaliciousCount', 'TotalEngines',
                'LastAnalysisDate', 'Permalink')
            @($report.PSObject.Properties.Name) | Should -Not -Contain 'Report'
            @($report.PSObject.Properties.Name) | Should -Not -Contain 'CachedAtUtc'
        }
    }

    It 'Isolates cached results from caller mutations' {
        $path = "/api/v3/urls/$($script:MaliciousUrlId)"
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -ceq $path).Count

        $first = Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0
        $first.Verdict = 'Clean'
        $first.MaliciousCount = 0
        $second = Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0
        $second.Verdict = 'Unknown'
        $second.MaliciousCount = 1
        $third = Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($logAfter | Where-Object path -ceq $path).Count
        [object]::ReferenceEquals($first, $second) | Should -BeFalse
        [object]::ReferenceEquals($second, $third) | Should -BeFalse
        $third.PSObject.TypeNames[0] | Should -BeExactly 'EndpointOps.VirusTotal.UrlReport'
        @($third.PSObject.Properties.Name) | Should -Be @(
            'Url', 'UrlId', 'verdict', 'MaliciousCount', 'TotalEngines',
            'LastAnalysisDate', 'Permalink')
        $third.Url | Should -BeExactly $script:MaliciousUrl
        $third.UrlId | Should -BeExactly $script:MaliciousUrlId
        $third.Verdict | Should -BeExactly 'Malicious'
        $third.MaliciousCount | Should -Be 6
        $third.TotalEngines | Should -Be 50
        $third.LastAnalysisDate | Should -BeNullOrEmpty
        $third.Permalink | Should -BeExactly "https://www.virustotal.com/gui/url/$($script:MaliciousUrlId)"
        ($after - $before) | Should -Be 1
    }

    It 'Shares the quota counter with the file reports' {
        $before = InModuleScope EndpointOps { (Get-VtConnectionState).DailyRequestCount }

        Get-VtFileReport -Hash $script:KnownHash -MinIntervalMs 0 | Out-Null
        Get-VtUrlReport -Url $script:MaliciousUrl -MinIntervalMs 0 | Out-Null

        $after = InModuleScope EndpointOps { (Get-VtConnectionState).DailyRequestCount }
        ($after - $before) | Should -Be 2
    }

    It 'Classifies a known healthy URL as Clean' {
        $report = Get-VtUrlReport -Url $script:CleanUrl -MinIntervalMs 0

        $report.Verdict | Should -BeExactly 'Clean'
        $report.MaliciousCount | Should -Be 0
        $report.TotalEngines | Should -Be 72
    }

    It 'Returns Unavailable for a 429 response without throwing' {
        { $script:RateLimitedReport = Get-VtUrlReport -Url $script:RateLimitedUrl -MinIntervalMs 0 } |
            Should -Not -Throw

        $script:RateLimitedReport.Verdict | Should -BeExactly 'Unavailable'
    }

    It 'Returns Unavailable for a persistent 500 response after exactly two calls' {
        $path = "/api/v3/urls/$($script:FailingUrlId)"
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -ceq $path).Count

        { $script:FailedReport = Get-VtUrlReport -Url $script:FailingUrl -MinIntervalMs 0 } |
            Should -Not -Throw

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($logAfter | Where-Object path -ceq $path).Count
        $script:FailedReport.Verdict | Should -BeExactly 'Unavailable'
        ($after - $before) | Should -Be 2
    }

    It 'Returns Unavailable for malformed statistics without throwing' {
        $url = 'https://malformed.example.invalid/stats'
        $response = [pscustomobject]@{
            data = [pscustomobject]@{
                attributes = [pscustomobject]@{
                    last_analysis_stats = [pscustomobject]@{
                        malicious = 'many'
                        harmless = 60
                    }
                }
            }
        }

        $report = InModuleScope EndpointOps -Parameters @{ RawResponse = $response; TestUrl = $url } {
            param($RawResponse, $TestUrl)
            $script:VtMalformedUrlResponse = $RawResponse
            Mock Invoke-VtRequest { $script:VtMalformedUrlResponse }

            try {
                Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
            }
            finally {
                Remove-Variable -Name VtMalformedUrlResponse -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $report.Verdict | Should -BeExactly 'Unavailable'
        $report.MaliciousCount | Should -BeNullOrEmpty
        $report.Permalink | Should -BeNullOrEmpty
    }

    It 'Degrades a malformed date to Unavailable without throwing' {
        $url = 'https://malformed.example.invalid/date'
        $response = [pscustomobject]@{
            data = [pscustomobject]@{
                attributes = [pscustomobject]@{
                    last_analysis_date = 'yesterday'
                    last_analysis_stats = [pscustomobject]@{
                        malicious = 0
                        harmless = 60
                    }
                }
            }
        }

        $report = InModuleScope EndpointOps -Parameters @{ RawResponse = $response; TestUrl = $url } {
            param($RawResponse, $TestUrl)
            $script:VtMalformedUrlResponse = $RawResponse
            Mock Invoke-VtRequest { $script:VtMalformedUrlResponse }

            try {
                Get-VtUrlReport -Url $TestUrl -MinIntervalMs 0
            }
            finally {
                Remove-Variable -Name VtMalformedUrlResponse -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $report.Verdict | Should -BeExactly 'Unavailable'
        $report.LastAnalysisDate | Should -BeNullOrEmpty
        $report.Permalink | Should -BeNullOrEmpty
    }
}
