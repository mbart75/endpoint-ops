#Requires -Version 7.2

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

    It 'Also caches errors and clears this cache on disconnection' {
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 | Out-Null
        Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 | Out-Null
        Disconnect-VirusTotal
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
        Get-VtUrlReport -Url $script:UnknownUrl -MinIntervalMs 0 | Out-Null

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($after - $before) | Should -Be 2
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
