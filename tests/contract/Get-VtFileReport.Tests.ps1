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

    function ConvertTo-TestVtSessionReport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Hash,
            [Parameter(Mandatory)][ValidateSet('Malicious', 'Clean', 'Unknown')][string]$Verdict
        )

        $maliciousCount = if ($Verdict -eq 'Malicious') { 8 } elseif ($Verdict -eq 'Clean') { 0 } else { $null }
        $totalEngines = if ($Verdict -in @('Malicious', 'Clean')) { 50 } else { $null }
        return [pscustomobject]@{
            PSTypeName       = 'EndpointOps.VirusTotal.FileReport'
            Hash             = $Hash
            Verdict          = $Verdict
            MaliciousCount   = $maliciousCount
            TotalEngines     = $totalEngines
            LastAnalysisDate = $null
            Permalink        = $null
            Sha1             = $Hash
            Sha256           = ('D' * 64)
            Md5              = ('D' * 32)
        }
    }
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

    # Production break caught: serving clean session evidence after its seven-day lifetime.
    It 'Requeries a Clean session entry after seven days' {
        $hash = $script:KnownHash
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now } {
            param($Hash, $Now)
            $testNow = $Now
            $script:VtFileReportCache.Clear()
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('A' * 64)
                            md5 = ('A' * 32)
                        }
                    }
                }
            }

            $first = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
            Mock Get-VtUtcNow { $testNow.AddDays(8) }
            $second = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

            $first.Verdict | Should -BeExactly 'Clean'
            $second.Verdict | Should -BeExactly 'Clean'
            Should -Invoke Invoke-VtRequest -Times 2 -Exactly
        }
    }

    # Production break caught: expiring non-malicious evidence at its inclusive seven-day boundary.
    It 'Serves a Clean session entry at exactly seven days' {
        $hash = $script:KnownHash
        $now = [datetime]'2026-09-07T12:00:00Z'
        $seedReport = ConvertTo-TestVtSessionReport -Hash $hash -Verdict 'Clean'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now; SeedReport = $seedReport } {
            param($Hash, $Now, $SeedReport)
            $script:VtFileReportCache.Clear()
            $script:VtFileReportCache[$Hash] = [pscustomobject]@{
                Report = $SeedReport.PSObject.Copy(); CachedAtUtc = $Now.AddDays(-7)
            }
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest { throw 'The provider must not be queried for fresh evidence.' }

            $report = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

            $report.Verdict | Should -BeExactly 'Clean'
            Should -Invoke Invoke-VtRequest -Times 0 -Exactly
        }
    }

    # Production break caught: either not caching provider absence or retaining it beyond seven days.
    It 'Caches Unknown through seven days and requeries it after seven days' {
        $hash = ('6' * 38) + '13'
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now } {
            param($Hash, $Now)
            $testNow = $Now
            $script:VtFileReportCache.Clear()
            $script:VtUnknownCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtUnknownCalls++
                if ($script:VtUnknownCalls -eq 1) {
                    throw 'EndpointOps: mock VirusTotal provider returned 404.'
                }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('6' * 64)
                            md5 = ('6' * 32)
                        }
                    }
                }
            }

            try {
                $first = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(7) }
                $atBoundary = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
                Mock Get-VtUtcNow { $testNow.AddDays(8) }
                $expired = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Unknown'
                $atBoundary.Verdict | Should -BeExactly 'Unknown'
                $expired.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtUnknownCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: caching a transient provider failure for the process lifetime.
    It 'Recovers from a transient Unavailable result on the next call' {
        $hash = ('4' * 38) + '11'
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now } {
            param($Hash, $Now)
            $testNow = $Now
            $script:VtFileReportCache.Clear()
            $script:VtTransientFailureCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtTransientFailureCalls++
                if ($script:VtTransientFailureCalls -eq 1) {
                    throw 'EndpointOps: HTTP 503 from mock VirusTotal provider.'
                }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('4' * 64)
                            md5 = ('4' * 32)
                        }
                    }
                }
            }

            try {
                $first = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
                $second = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Unavailable'
                $second.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtTransientFailureCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: caching an Unavailable report created by response validation.
    It 'Recovers from a malformed Unavailable response on the next call' {
        $hash = ('7' * 38) + '14'
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now } {
            param($Hash, $Now)
            $testNow = $Now
            $script:VtFileReportCache.Clear()
            $script:VtMalformedRecoveryCalls = 0
            Mock Get-VtUtcNow { $testNow }
            Mock Invoke-VtRequest {
                $script:VtMalformedRecoveryCalls++
                $malicious = if ($script:VtMalformedRecoveryCalls -eq 1) { 'many' } else { 0 }
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = $malicious; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('7' * 64)
                            md5 = ('7' * 32)
                        }
                    }
                }
            }

            try {
                $first = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
                $second = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

                $first.Verdict | Should -BeExactly 'Unavailable'
                $second.Verdict | Should -BeExactly 'Clean'
                Should -Invoke Invoke-VtRequest -Times 2 -Exactly
            }
            finally {
                Remove-Variable -Name VtMalformedRecoveryCalls -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    # Production break caught: changing the private envelope or leaking it through the public API.
    It 'Stores the exact private cache envelope while returning the public report shape' {
        $hash = ('5' * 38) + '12'
        $now = [datetime]'2026-09-07T12:00:00Z'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now } {
            param($Hash, $Now)
            $script:VtFileReportCache.Clear()
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest {
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('5' * 64)
                            md5 = ('5' * 32)
                        }
                    }
                }
            }

            $report = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
            $entry = $script:VtFileReportCache[$Hash]

            @($entry.PSObject.Properties.Name) | Should -Be @('Report', 'CachedAtUtc')
            $entry.Report | Should -BeOfType ([pscustomobject])
            $entry.CachedAtUtc | Should -BeOfType ([datetime])
            $entry.CachedAtUtc | Should -BeExactly $Now
            $entry.Report.PSObject.TypeNames[0] | Should -BeExactly 'EndpointOps.VirusTotal.FileReport'
            $report.PSObject.TypeNames[0] | Should -BeExactly 'EndpointOps.VirusTotal.FileReport'
            @($report.PSObject.Properties.Name) | Should -Be @(
                'Hash', 'verdict', 'MaliciousCount', 'TotalEngines', 'LastAnalysisDate',
                'Permalink', 'Sha1', 'Sha256', 'Md5')
            @($report.PSObject.Properties.Name) | Should -Not -Contain 'Report'
            @($report.PSObject.Properties.Name) | Should -Not -Contain 'CachedAtUtc'
        }
    }

    # Production break caught: expiring malicious evidence at its inclusive ninety-day boundary.
    It 'Serves a Malicious session entry at exactly ninety days' {
        $hash = $script:MaliciousHash
        $now = [datetime]'2026-09-07T12:00:00Z'
        $seedReport = ConvertTo-TestVtSessionReport -Hash $hash -Verdict 'Malicious'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now; SeedReport = $seedReport } {
            param($Hash, $Now, $SeedReport)
            $script:VtFileReportCache.Clear()
            $script:VtFileReportCache[$Hash] = [pscustomobject]@{
                Report = $SeedReport.PSObject.Copy(); CachedAtUtc = $Now.AddDays(-90)
            }
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest { throw 'The provider must not be queried for fresh evidence.' }

            $report = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

            $report.Verdict | Should -BeExactly 'Malicious'
            Should -Invoke Invoke-VtRequest -Times 0 -Exactly
        }
    }

    # Production break caught: serving malicious evidence beyond its ninety-day lifetime.
    It 'Requeries a Malicious session entry older than ninety days' {
        $hash = $script:MaliciousHash
        $now = [datetime]'2026-09-07T12:00:00Z'
        $seedReport = ConvertTo-TestVtSessionReport -Hash $hash -Verdict 'Malicious'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now; SeedReport = $seedReport } {
            param($Hash, $Now, $SeedReport)
            $script:VtFileReportCache.Clear()
            $script:VtFileReportCache[$Hash] = [pscustomobject]@{
                Report = $SeedReport.PSObject.Copy(); CachedAtUtc = $Now.AddDays(-91)
            }
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest {
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('C' * 64)
                            md5 = ('C' * 32)
                        }
                    }
                }
            }

            $report = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

            $report.Verdict | Should -BeExactly 'Clean'
            Should -Invoke Invoke-VtRequest -Times 1 -Exactly
        }
    }

    # Production break caught: accepting a future cache timestamp after clock rollback or corruption.
    It 'Evicts a future session timestamp and requeries the provider' {
        $hash = $script:KnownHash
        $now = [datetime]'2026-09-07T12:00:00Z'
        $seedReport = ConvertTo-TestVtSessionReport -Hash $hash -Verdict 'Clean'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now; SeedReport = $seedReport } {
            param($Hash, $Now, $SeedReport)
            $script:VtFileReportCache.Clear()
            $script:VtFileReportCache[$Hash] = [pscustomobject]@{
                Report = $SeedReport.PSObject.Copy(); CachedAtUtc = $Now.AddSeconds(1)
            }
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest {
                [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                            sha1 = $Hash
                            sha256 = ('A' * 64)
                            md5 = ('A' * 32)
                        }
                    }
                }
            }

            $report = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

            $report.Verdict | Should -BeExactly 'Clean'
            Should -Invoke Invoke-VtRequest -Times 1 -Exactly
        }
    }

    # Production break caught: replacing the dictionary's case-insensitive hash identity.
    It 'Shares one valid session envelope across uppercase and lowercase SHA-1 lookups' {
        $hash = $script:KnownHash
        $now = [datetime]'2026-09-07T12:00:00Z'
        $seedReport = ConvertTo-TestVtSessionReport -Hash $hash -Verdict 'Clean'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now; SeedReport = $seedReport } {
            param($Hash, $Now, $SeedReport)
            $script:VtFileReportCache.Clear()
            $script:VtFileReportCache[$Hash] = [pscustomobject]@{
                Report = $SeedReport.PSObject.Copy(); CachedAtUtc = $Now.AddDays(-1)
            }
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest { throw 'The provider must not be queried for fresh evidence.' }

            $report = Get-VtFileReport -Hash $Hash.ToLowerInvariant() -MinIntervalMs 0

            $script:VtFileReportCache.Count | Should -Be 1
            $report.Hash | Should -BeExactly $Hash
            $report.Verdict | Should -BeExactly 'Clean'
            Should -Invoke Invoke-VtRequest -Times 0 -Exactly
        }
    }

    # Production break caught: returning the cache-owned report object to a caller.
    It 'Defensively copies a seeded session report on every retrieval' {
        $hash = $script:MaliciousHash
        $now = [datetime]'2026-09-07T12:00:00Z'
        $seedReport = ConvertTo-TestVtSessionReport -Hash $hash -Verdict 'Malicious'

        InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now; SeedReport = $seedReport } {
            param($Hash, $Now, $SeedReport)
            $script:VtFileReportCache.Clear()
            $script:VtFileReportCache[$Hash] = [pscustomobject]@{
                Report = $SeedReport.PSObject.Copy(); CachedAtUtc = $Now.AddDays(-1)
            }
            Mock Get-VtUtcNow { $Now }
            Mock Invoke-VtRequest { throw 'The provider must not be queried for fresh evidence.' }

            $first = Get-VtFileReport -Hash $Hash -MinIntervalMs 0
            $first.Verdict = 'Clean'
            $first.MaliciousCount = 0
            $second = Get-VtFileReport -Hash $Hash -MinIntervalMs 0

            [object]::ReferenceEquals($first, $second) | Should -BeFalse
            $second.Verdict | Should -BeExactly 'Malicious'
            $second.MaliciousCount | Should -Be 8
            Should -Invoke Invoke-VtRequest -Times 0 -Exactly
        }
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

    It 'Locally rejects a <Length>-character hash followed by LF before provider access' -ForEach @(
        @{ Length = 32 }
        @{ Length = 40 }
        @{ Length = 64 }
    ) {
        $logBefore = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        $malformedHash = ('A' * $Length) + "`n"

        $caughtError = try {
            Get-VtFileReport -Hash $malformedHash -MinIntervalMs 0 | Out-Null
            $null
        }
        catch { $_ }

        $logAfter = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count
        ($logAfter - $logBefore) | Should -Be 0
        $caughtError.Exception | Should -BeOfType ([System.Management.Automation.ParameterBindingException])
        $caughtError.FullyQualifiedErrorId | Should -Match '^ParameterArgumentValidationError'
    }

    It 'Retains direct VirusTotal support for a valid <Kind> identifier' -ForEach @(
        @{ Kind = 'MD5'; Length = 32 }
        @{ Kind = 'SHA-1'; Length = 40 }
        @{ Kind = 'SHA-256'; Length = 64 }
    ) {
        $hash = 'A' * $Length
        $path = "/api/v3/files/$hash"
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests |
                Where-Object path -eq $path).Count

        $report = Get-VtFileReport -Hash $hash -MinIntervalMs 0

        $after = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests |
                Where-Object path -eq $path).Count
        ($after - $before) | Should -Be 1
        $report.Hash | Should -BeExactly $hash
        $report.Verdict | Should -BeExactly 'Unknown'
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
