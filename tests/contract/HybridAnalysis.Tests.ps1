#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:HaKey = ConvertTo-TestSecureString -PlainText 'MOCK-HA-KEY'
    $script:KnownHash = ('B' * 38) + '02'
    $script:UnknownHash = ('E' * 38) + '05'
    $script:HaPath = '/api/v2/search/hash'
    $script:OpaqueQuota = '{"opaque_mock_quota":"fixture-only-do-not-parse"}'
}

AfterAll {
    if (Get-Command Disconnect-HybridAnalysis -ErrorAction SilentlyContinue) {
        Disconnect-HybridAnalysis
    }
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Hybrid Analysis connection' {
    AfterEach {
        if (Get-Command Disconnect-HybridAnalysis -ErrorAction SilentlyContinue) {
            Disconnect-HybridAnalysis
        }
    }

    It 'Keeps the key out of metadata, uses the official service, and rejects non-loopback HTTP' {
        $connection = Connect-HybridAnalysis -ApiKey $script:HaKey
        $message = try {
            Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri 'http://example.invalid' | Out-Null
            ''
        }
        catch { $_.Exception.Message }

        $connection.PSTypeNames[0] | Should -BeExactly 'EndpointOps.HybridAnalysis.Connection'
        $connection.BaseUri | Should -BeExactly 'https://www.hybrid-analysis.com'
        $connection.PSObject.Properties.Name | Should -Not -Contain 'ApiKey'
        ($connection | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-HA-KEY'
        $message | Should -Match 'BaseUri must use HTTPS'
        $message | Should -Not -Match 'MOCK-HA-KEY'
        { Disconnect-HybridAnalysis; Disconnect-HybridAnalysis } | Should -Not -Throw
    }
}

Describe 'Hybrid Analysis transport and verdicts' {
    AfterEach {
        if (Get-Command Disconnect-HybridAnalysis -ErrorAction SilentlyContinue) {
            Disconnect-HybridAnalysis
        }
    }

    It 'Returns Malicious with the sandbox verdict and environment actually provided' {
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownHash } {
            param($Hash)
            Get-HaFileVerdict -Hash $Hash
        }

        $result.PSTypeNames[0] | Should -BeExactly 'EndpointOps.Reputation.Verdict'
        @($result.PSObject.Properties.Name) | Should -Be @(
            'Source', 'Verdict', 'Detail', 'HashUsed', 'HashSource', 'QueryDate')
        $result.Source | Should -BeExactly 'HybridAnalysis'
        $result.Verdict | Should -BeExactly 'Malicious'
        $result.Detail | Should -Match 'malicious'
        $result.Detail | Should -Match 'Windows 10 64 bit'
        $result.Detail | Should -Not -Match 'process|behavior|indicator'
        $result.HashUsed | Should -BeExactly $script:KnownHash
        $result.HashSource | Should -BeExactly 'EPM'
        $result.QueryDate.Kind | Should -BeExactly ([DateTimeKind]::Utc)
    }

    It 'Returns Unknown without presenting missing reports as Clean' {
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:UnknownHash } {
            param($Hash)
            Get-HaFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unknown'
        $result.Verdict | Should -Not -BeExactly 'Clean'
        $result.Detail | Should -BeOfType [string]
        $result.Detail | Should -Match 'no report'
    }

    It 'Returns Unavailable without throwing when disconnected' {
        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownHash } {
            param($Hash)
            Get-HaFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unavailable'
        $result.Detail | Should -BeOfType [string]
        $result.Detail | Should -Not -BeNullOrEmpty
    }

    It 'Exposes the Api-Limits header without parsing it' {
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
        $before = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests).Count

        $capture = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownHash } {
            param($Hash)
            $verbose = Invoke-HaRequest -Hash $Hash -Verbose 4>&1
            [pscustomobject]@{
                Response = @($verbose | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] })[-1]
                Verbose = $verbose | Out-String
            }
        }

        @($capture.Response.PSObject.Properties.Name) | Should -Be @('Data', 'ApiLimits', 'QuotaKnown')
        $capture.Response.ApiLimits | Should -BeExactly $script:OpaqueQuota
        $capture.Response.QuotaKnown | Should -BeTrue
        @($capture.Response.Data.reports).Count | Should -Be 1
        $entries = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/_test/reputation").requests)
        $entry = $entries[$before]
        $entry.path | Should -BeExactly $script:HaPath
        $entry.method | Should -BeExactly 'GET'
        $entry.authExact | Should -BeTrue
        $capture.Verbose | Should -Not -Match 'MOCK-HA-KEY'
        ($entry | ConvertTo-Json -Compress) | Should -Not -Match 'MOCK-HA-KEY'
    }

    It 'Exposes an unknown quota without throwing when Api-Limits is absent' {
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null

        $response = InModuleScope EndpointOps -Parameters @{ Hash = $script:UnknownHash } {
            param($Hash)
            Invoke-HaRequest -Hash $Hash
        }

        $response.ApiLimits | Should -BeNullOrEmpty
        $response.QuotaKnown | Should -BeFalse
        @($response.Data.reports).Count | Should -Be 0
    }

    It 'Remains Unavailable when the SearchByHash response is malformed' {
        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownHash } {
            param($Hash)
            Mock Invoke-HaRequest {
                [pscustomobject]@{
                    Data = [pscustomobject]@{ sha256s = @() }
                    ApiLimits = $null
                    QuotaKnown = $false
                }
            }
            Get-HaFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unavailable'
        $result.Detail | Should -BeOfType [string]
    }

    It 'Keeps Unknown for no specific threat and cites the sandbox verdict and environment' {
        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownHash } {
            param($Hash)
            Mock Invoke-HaRequest {
                [pscustomobject]@{
                    Data = [pscustomobject]@{
                        sha256s = @((('B' * 62) + '02'))
                        reports = @([pscustomobject]@{
                            id = 'mock-ha-no-specific-threat'
                            environment_id = 160
                            environment_description = 'Windows 10 64 bit'
                            state = 'SUCCESS'
                            error_type = $null
                            error_origin = $null
                            error = $null
                            verdict = 'no specific threat'
                        })
                    }
                    ApiLimits = $null
                    QuotaKnown = $false
                }
            }
            Get-HaFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unknown'
        $result.Verdict | Should -Not -BeExactly 'Clean'
        $result.Detail | Should -Match 'no specific threat'
        $result.Detail | Should -Match 'Windows 10 64 bit'
    }
}
