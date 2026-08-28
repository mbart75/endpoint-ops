#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:MbKey = ConvertTo-TestSecureString -PlainText 'MOCK-MB-KEY'
    $script:KnownSha256 = ('C' * 62) + '03'
    $script:UnknownSha256 = ('E' * 62) + '05'
    $script:Sha1 = ('C' * 38) + '03'
    $script:MbBaseUri = "$($script:Server.BaseUrl)/mb"
    $script:TfBaseUri = "$($script:Server.BaseUrl)/tf"
    $script:TfPath = '/tf/api/v1/'
    $script:JournalUri = "$($script:Server.BaseUrl)/_test/reputation"

    function Get-TfRequestCount {
        $requests = @((Invoke-RestMethod -Uri $script:JournalUri).requests)
        return @($requests | Where-Object path -eq $script:TfPath).Count
    }
}

AfterAll {
    if (Get-Command Disconnect-MalwareBazaar -ErrorAction SilentlyContinue) {
        Disconnect-MalwareBazaar
    }
    Stop-MockApiServer -Server $script:Server
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
}

Describe 'Shared abuse.ch state for ThreatFox' {
    AfterEach {
        if (Get-Command Disconnect-MalwareBazaar -ErrorAction SilentlyContinue) {
            Disconnect-MalwareBazaar
        }
    }

    It 'Retains both URIs and the same SecureString without exposing the key' {
        $connection = Connect-MalwareBazaar -AuthKey $script:MbKey `
            -BaseUri $script:MbBaseUri -ThreatFoxBaseUri $script:TfBaseUri
        $stateFacts = InModuleScope EndpointOps -Parameters @{ ExpectedKey = $script:MbKey } {
            param($ExpectedKey)
            $state = Get-MbConnectionState
            [pscustomobject]@{
                BaseUri = $state.BaseUri
                ThreatFoxBaseUri = $state.ThreatFoxBaseUri
                SameKey = [object]::ReferenceEquals($state.AuthKey, $ExpectedKey)
                Serialized = $state | ConvertTo-Json -Depth 5
            }
        }

        $connection.BaseUri | Should -BeExactly $script:MbBaseUri
        $connection.ThreatFoxBaseUri | Should -BeExactly $script:TfBaseUri
        $connection.PSObject.Properties.Name | Should -Not -Contain 'AuthKey'
        $stateFacts.BaseUri | Should -BeExactly $script:MbBaseUri
        $stateFacts.ThreatFoxBaseUri | Should -BeExactly $script:TfBaseUri
        $stateFacts.SameKey | Should -BeTrue
        $stateFacts.Serialized | Should -Not -Match 'MOCK-MB-KEY'
    }

    It 'Uses the official ThreatFox URI by default and validates both URIs independently' {
        $connection = Connect-MalwareBazaar -AuthKey $script:MbKey
        $tfMessage = try {
            Connect-MalwareBazaar -AuthKey $script:MbKey `
                -BaseUri $script:MbBaseUri -ThreatFoxBaseUri 'http://example.invalid' | Out-Null
            ''
        }
        catch { $_.Exception.Message }
        $mbMessage = try {
            Connect-MalwareBazaar -AuthKey $script:MbKey `
                -BaseUri 'http://example.invalid' -ThreatFoxBaseUri $script:TfBaseUri | Out-Null
            ''
        }
        catch { $_.Exception.Message }

        $connection.ThreatFoxBaseUri | Should -BeExactly 'https://threatfox-api.abuse.ch'
        $tfMessage | Should -Match 'ThreatFoxBaseUri must use HTTPS'
        $mbMessage | Should -Match 'BaseUri must use HTTPS'
    }
}

Describe 'ThreatFox transport and verdicts' {
    AfterEach {
        if (Get-Command Disconnect-MalwareBazaar -ErrorAction SilentlyContinue) {
            Disconnect-MalwareBazaar
        }
    }

    It 'Returns Malicious with the family and tags actually provided' {
        Connect-MalwareBazaar -AuthKey $script:MbKey `
            -BaseUri $script:MbBaseUri -ThreatFoxBaseUri $script:TfBaseUri | Out-Null
        $before = Get-TfRequestCount

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownSha256 } {
            param($Hash)
            Get-TfFileVerdict -Hash $Hash
        }

        $after = Get-TfRequestCount
        ($after - $before) | Should -Be 1
        $result.PSTypeNames[0] | Should -BeExactly 'EndpointOps.Reputation.Verdict'
        @($result.PSObject.Properties.Name) | Should -Be @(
            'Source', 'Verdict', 'Detail', 'HashUsed', 'HashSource', 'QueryDate')
        $result.Source | Should -BeExactly 'ThreatFox'
        $result.Verdict | Should -BeExactly 'Malicious'
        $result.Detail | Should -Match 'AgentTesla'
        $result.Detail | Should -Match 'TA505'
        $result.Detail | Should -Not -Match 'campaign'
        $result.HashUsed | Should -BeExactly $script:KnownSha256
        $result.HashSource | Should -BeExactly 'VirusTotal'
        $result.QueryDate.Kind | Should -BeExactly ([DateTimeKind]::Utc)

        $requestLog = Invoke-RestMethod -Uri $script:JournalUri
        $entry = @($requestLog.requests | Where-Object path -eq $script:TfPath)[-1]
        $entry.path | Should -BeExactly $script:TfPath
        $entry.method | Should -BeExactly 'POST'
        $entry.authExact | Should -BeTrue
    }

    It 'Returns Unknown for ok with empty data without presenting absence as Clean' {
        Connect-MalwareBazaar -AuthKey $script:MbKey `
            -BaseUri $script:MbBaseUri -ThreatFoxBaseUri $script:TfBaseUri | Out-Null

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:UnknownSha256 } {
            param($Hash)
            Get-TfFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unknown'
        $result.Verdict | Should -Not -BeExactly 'Clean'
        $result.Detail | Should -BeOfType [string]
        $result.Detail | Should -Match 'no indicator'
    }

    It 'Returns Unavailable for a SHA-1 without sending a ThreatFox request' {
        Connect-MalwareBazaar -AuthKey $script:MbKey `
            -BaseUri $script:MbBaseUri -ThreatFoxBaseUri $script:TfBaseUri | Out-Null
        $before = Get-TfRequestCount

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:Sha1 } {
            param($Hash)
            Get-TfFileVerdict -Hash $Hash
        }

        $after = Get-TfRequestCount
        $result.Verdict | Should -BeExactly 'Unavailable'
        ($after - $before) | Should -Be 0
    }

    It 'Returns Unavailable without throwing when disconnected' {
        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownSha256 } {
            param($Hash)
            Get-TfFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unavailable'
        $result.Detail | Should -BeOfType [string]
        $result.Detail | Should -Not -BeNullOrEmpty
    }

    It 'Returns Unavailable when authentication is rejected' {
        $wrongKey = ConvertTo-TestSecureString -PlainText 'WRONG-MB-KEY'
        Connect-MalwareBazaar -AuthKey $wrongKey `
            -BaseUri $script:MbBaseUri -ThreatFoxBaseUri $script:TfBaseUri | Out-Null

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownSha256 } {
            param($Hash)
            Get-TfFileVerdict -Hash $Hash
        }

        $result.Verdict | Should -BeExactly 'Unavailable'
    }

    It 'Returns Unavailable for a malformed response' {
        Connect-MalwareBazaar -AuthKey $script:MbKey `
            -BaseUri $script:MbBaseUri -ThreatFoxBaseUri $script:TfBaseUri | Out-Null

        $result = InModuleScope EndpointOps -Parameters @{ Hash = $script:KnownSha256 } {
            param($Hash)
            Mock Invoke-EndpointOpsRequest { [pscustomobject]@{ unexpected = $true } }
            $verdict = Get-TfFileVerdict -Hash $Hash
            Should -Invoke Invoke-EndpointOpsRequest -Times 1 -Exactly
            $verdict
        }

        $result.Verdict | Should -BeExactly 'Unavailable'
    }
}
