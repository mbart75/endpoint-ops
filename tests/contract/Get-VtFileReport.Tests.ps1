#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:VtKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
    $script:KnownHash = ('A' * 38) + '01'
    $script:UnknownHash = ('B' * 38) + '02'
    $script:MaliciousHash = ('C' * 38) + '03'
    $script:RateLimitedHash = ('F' * 38) + '06'
    $script:BadRequestHash = ('0' * 38) + '07'
    $script:FailingHash = ('1' * 38) + '08'
}

AfterAll {
    Disconnect-VirusTotal
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-VtFileReport' {
    BeforeEach {
        Disconnect-VirusTotal
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
    }

    AfterEach {
        Disconnect-VirusTotal
    }

    It 'Classifies CCC as Malicious with eight engines out of fifty' {
        $report = Get-VtFileReport -Hash $script:MaliciousHash -MinIntervalMs 0

        $report.Verdict | Should -BeExactly 'Malicious'
        $report.MaliciousCount | Should -Be 8
        $report.TotalEngines | Should -Be 50
    }

    It 'Classifies AAA as Clean' {
        $report = Get-VtFileReport -Hash $script:KnownHash -MinIntervalMs 0

        $report.Verdict | Should -BeExactly 'Clean'
        $report.MaliciousCount | Should -Be 0
        $report.TotalEngines | Should -Be 72
    }

    It 'Returns Unknown for a 404 response without derived metadata' {
        { $script:NotFoundReport = Get-VtFileReport -Hash $script:UnknownHash -MinIntervalMs 0 } | Should -Not -Throw

        $script:NotFoundReport.Verdict | Should -BeExactly 'Unknown'
        $script:NotFoundReport.Sha256 | Should -BeNullOrEmpty
    }

    It 'Returns Unknown for a 400 response' {
        { $script:BadRequestReport = Get-VtFileReport -Hash $script:BadRequestHash -MinIntervalMs 0 } | Should -Not -Throw

        $script:BadRequestReport.Verdict | Should -BeExactly 'Unknown'
    }

    It 'Returns Unavailable for a 429 response' {
        { $script:RateLimitedReport = Get-VtFileReport -Hash $script:RateLimitedHash -MinIntervalMs 0 } | Should -Not -Throw

        $script:RateLimitedReport.Verdict | Should -BeExactly 'Unavailable'
    }

    It 'Returns Unavailable for a persistent 500 response after exactly two calls' {
        $path = "/api/v3/files/$($script:FailingHash)"
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -eq $path).Count

        { $script:FailedReport = Get-VtFileReport -Hash $script:FailingHash -MinIntervalMs 0 } | Should -Not -Throw

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($logAfter | Where-Object path -eq $path).Count
        $script:FailedReport.Verdict | Should -BeExactly 'Unavailable'
        ($after - $before) | Should -Be 2
    }

    It 'Exposes the complete contract and the three hashes of a known file' {
        $report = Get-VtFileReport -Hash $script:KnownHash -MinIntervalMs 0

        @($report.PSObject.Properties.Name) | Should -Be @(
            'Hash', 'verdict', 'MaliciousCount', 'TotalEngines', 'LastAnalysisDate',
            'Permalink', 'Sha1', 'Sha256', 'Md5')
        $report.Hash | Should -BeExactly $script:KnownHash
        $report.Sha1 | Should -BeExactly $script:KnownHash
        $report.Sha256 | Should -BeExactly (('A' * 62) + '01')
        $report.Md5 | Should -BeExactly (('A' * 30) + '01')
        $report.LastAnalysisDate | Should -BeNullOrEmpty
        $report.Permalink | Should -BeExactly "https://www.virustotal.com/gui/file/$(('A' * 62) + '01')"
    }

    It 'Caches results and clears the cache on disconnection' {
        $path = "/api/v3/files/$($script:KnownHash)"
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -eq $path).Count

        Get-VtFileReport -Hash $script:KnownHash -MinIntervalMs 0 | Out-Null
        Get-VtFileReport -Hash $script:KnownHash.ToLowerInvariant() -MinIntervalMs 0 | Out-Null

        $cacheLog = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $afterCache = @($cacheLog | Where-Object path -eq $path).Count
        ($afterCache - $before) | Should -Be 1

        Disconnect-VirusTotal
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
        Get-VtFileReport -Hash $script:KnownHash -MinIntervalMs 0 | Out-Null

        $purgeLog = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $afterPurge = @($purgeLog | Where-Object path -eq $path).Count
        ($afterPurge - $before) | Should -Be 2
    }

    It 'Isolates cached results from caller mutations' {
        $path = "/api/v3/files/$($script:MaliciousHash)"
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $before = @($logBefore | Where-Object path -eq $path).Count

        $first = Get-VtFileReport -Hash $script:MaliciousHash -MinIntervalMs 0
        $first.Verdict = 'Clean'
        $first.MaliciousCount = 0
        $second = Get-VtFileReport -Hash $script:MaliciousHash -MinIntervalMs 0
        $second.Verdict = 'Unknown'
        $second.MaliciousCount = 1
        $third = Get-VtFileReport -Hash $script:MaliciousHash -MinIntervalMs 0

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $after = @($logAfter | Where-Object path -eq $path).Count
        [object]::ReferenceEquals($first, $second) | Should -BeFalse
        [object]::ReferenceEquals($second, $third) | Should -BeFalse
        $third.PSObject.TypeNames[0] | Should -BeExactly 'EndpointOps.VirusTotal.FileReport'
        @($third.PSObject.Properties.Name) | Should -Be @(
            'Hash', 'verdict', 'MaliciousCount', 'TotalEngines', 'LastAnalysisDate',
            'Permalink', 'Sha1', 'Sha256', 'Md5')
        $third.Hash | Should -BeExactly $script:MaliciousHash
        $third.Verdict | Should -BeExactly 'Malicious'
        $third.MaliciousCount | Should -Be 8
        $third.TotalEngines | Should -Be 50
        $third.LastAnalysisDate | Should -BeNullOrEmpty
        $third.Permalink | Should -BeExactly "https://www.virustotal.com/gui/file/$(('C' * 62) + '03')"
        $third.Sha1 | Should -BeExactly $script:MaliciousHash
        $third.Sha256 | Should -BeExactly (('C' * 62) + '03')
        $third.Md5 | Should -BeExactly (('C' * 30) + '03')
        ($after - $before) | Should -Be 1
    }

    It 'Accepts multiple hashes from the pipeline' {
        $reports = @($script:KnownHash, $script:MaliciousHash |
                Get-VtFileReport -MinIntervalMs 0)

        @($reports.Hash) | Should -Be @($script:KnownHash, $script:MaliciousHash)
        @($reports.Verdict) | Should -Be @('Clean', 'Malicious')
    }

    It 'Locally rejects a thirty-nine character hash' {
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        $caughtError = try {
            Get-VtFileReport -Hash ('A' * 39) -MinIntervalMs 0 | Out-Null
            $null
        }
        catch { $_ }

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($logAfter - $logBefore) | Should -Be 0
        $caughtError.Exception | Should -BeOfType ([System.Management.Automation.ParameterBindingException])
        $caughtError.FullyQualifiedErrorId | Should -Match '^ParameterArgumentValidationError'
    }

    It 'Locally rejects a non-hexadecimal character in a SHA-1 hash' {
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        $caughtError = try {
            Get-VtFileReport -Hash (('A' * 39) + 'G') -MinIntervalMs 0 | Out-Null
            $null
        }
        catch { $_ }

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($logAfter - $logBefore) | Should -Be 0
        $caughtError.Exception | Should -BeOfType ([System.Management.Automation.ParameterBindingException])
        $caughtError.FullyQualifiedErrorId | Should -Match '^ParameterArgumentValidationError'
    }

    It 'Returns Unavailable for explicitly malformed statistics' {
        $hash = ('2' * 38) + '09'
        $response = [pscustomobject]@{
            data = [pscustomobject]@{
                attributes = [pscustomobject]@{
                    md5 = ('2' * 32)
                    sha1 = $hash
                    sha256 = ('2' * 64)
                    last_analysis_stats = [pscustomobject]@{
                        malicious = 'many'
                        harmless = 60
                        undetected = 12
                    }
                }
            }
        }

        $report = InModuleScope EndpointOps -Parameters @{ RawResponse = $response; TestHash = $hash } {
            param($RawResponse, $TestHash)
            $script:VtMalformedResponse = $RawResponse
            Mock Invoke-VtRequest { $script:VtMalformedResponse }

            try {
                Get-VtFileReport -Hash $TestHash -MinIntervalMs 0
            }
            finally {
                Remove-Variable -Name VtMalformedResponse -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $report.Verdict | Should -BeExactly 'Unavailable'
        $report.MaliciousCount | Should -BeNullOrEmpty
        $report.Sha256 | Should -BeNullOrEmpty
    }

    It 'Returns Unavailable for an explicitly malformed analysis date' {
        $hash = ('3' * 38) + '10'
        $response = [pscustomobject]@{
            data = [pscustomobject]@{
                attributes = [pscustomobject]@{
                    md5 = ('3' * 32)
                    sha1 = $hash
                    sha256 = ('3' * 64)
                    last_analysis_date = 'yesterday'
                    last_analysis_stats = [pscustomobject]@{
                        malicious = 0
                        harmless = 60
                        undetected = 12
                    }
                }
            }
        }

        $report = InModuleScope EndpointOps -Parameters @{ RawResponse = $response; TestHash = $hash } {
            param($RawResponse, $TestHash)
            $script:VtMalformedResponse = $RawResponse
            Mock Invoke-VtRequest { $script:VtMalformedResponse }

            try {
                Get-VtFileReport -Hash $TestHash -MinIntervalMs 0
            }
            finally {
                Remove-Variable -Name VtMalformedResponse -Scope Script -ErrorAction SilentlyContinue
            }
        }

        $report.Verdict | Should -BeExactly 'Unavailable'
        $report.LastAnalysisDate | Should -BeNullOrEmpty
        $report.Sha256 | Should -BeNullOrEmpty
    }
}
