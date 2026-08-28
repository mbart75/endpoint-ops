#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:VtKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
    $script:MbKey = ConvertTo-TestSecureString -PlainText 'MOCK-MB-KEY'
    $script:HaKey = ConvertTo-TestSecureString -PlainText 'MOCK-HA-KEY'
    $script:MbBaseUri = "$($script:Server.BaseUrl)/mb"
    $script:TfBaseUri = "$($script:Server.BaseUrl)/tf"
    $script:JournalUri = "$($script:Server.BaseUrl)/_test/reputation"
    $script:MbPath = '/mb/api/v1/'
    $script:HaPath = '/api/v2/search/hash'
    $script:TfPath = '/tf/api/v1/'

    $script:CleanHash = ('A' * 38) + '01'
    $script:VtUnknownMbKnownHash = ('B' * 38) + '02'
    $script:MaliciousMbKnownHash = ('C' * 38) + '03'
    $script:SkipHash = ('E' * 38) + '05'
    $script:UnavailableHash = ('F' * 38) + '06'
    $script:NoReliefHash = ('2' * 38) + '09'

    function Get-ReputationRequestCount {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$Path)

        $requests = @((Invoke-RestMethod -Uri $script:JournalUri).requests)
        return @($requests | Where-Object path -eq $Path).Count
    }
}

AfterAll {
    Disconnect-VirusTotal
    Disconnect-MalwareBazaar
    if (Get-Command Disconnect-HybridAnalysis -ErrorAction SilentlyContinue) {
        Disconnect-HybridAnalysis
    }
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-FileReputation' {
    BeforeEach {
        Disconnect-VirusTotal
        Disconnect-MalwareBazaar
        if (Get-Command Disconnect-HybridAnalysis -ErrorAction SilentlyContinue) {
            Disconnect-HybridAnalysis
        }
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
        Connect-MalwareBazaar -AuthKey $script:MbKey -BaseUri $script:MbBaseUri `
            -ThreatFoxBaseUri $script:TfBaseUri | Out-Null
    }

    AfterEach {
        Disconnect-VirusTotal
        Disconnect-MalwareBazaar
        if (Get-Command Disconnect-HybridAnalysis -ErrorAction SilentlyContinue) {
            Disconnect-HybridAnalysis
        }
    }

    It 'Stops the cascade after a Clean VirusTotal verdict' {
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $vtBefore = Get-ReputationRequestCount -Path $vtPath
        $mbBefore = Get-ReputationRequestCount -Path $script:MbPath

        $results = @(Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0)

        $vtAfter = Get-ReputationRequestCount -Path $vtPath
        $mbAfter = Get-ReputationRequestCount -Path $script:MbPath
        $results.Count | Should -Be 1
        ($vtAfter - $vtBefore) | Should -Be 1
        ($mbAfter - $mbBefore) | Should -Be 0
        @($results[0].Sources).Source | Should -Be @('VirusTotal')
    }

    It 'Queries MalwareBazaar when VirusTotal does not know the file' {
        $mbBefore = Get-ReputationRequestCount -Path $script:MbPath

        $result = Get-FileReputation -Hash $script:VtUnknownMbKnownHash -MinIntervalMs 0

        $mbAfter = Get-ReputationRequestCount -Path $script:MbPath
        ($mbAfter - $mbBefore) | Should -Be 1
        @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis')
        @($result.Sources).Verdict | Should -Be @('Unknown', 'Malicious', 'Unavailable')
        $result.Verdict | Should -BeExactly 'Malicious'
    }

    It 'Queries MalwareBazaar when VirusTotal is Unavailable' {
        $mbBefore = Get-ReputationRequestCount -Path $script:MbPath

        Get-FileReputation -Hash $script:UnavailableHash -MinIntervalMs 0 | Out-Null

        $mbAfter = Get-ReputationRequestCount -Path $script:MbPath
        ($mbAfter - $mbBefore) | Should -Be 1
    }

    It 'Emits one result per pipeline input with per-source verdicts and no score' {
        $hashes = @($script:MaliciousMbKnownHash, $script:NoReliefHash)

        $results = @($hashes | Get-FileReputation -MinIntervalMs 0)

        $results.Count | Should -Be 2
        $results.Hash | Should -Be $hashes
        foreach ($result in $results) {
            $result.PSTypeNames[0] | Should -BeExactly 'EndpointOps.Reputation.FileResult'
            @($result.PSObject.Properties.Name) | Should -Be @('Hash', 'Verdict', 'Sources')
            $result.PSObject.Properties.Name | Should -Not -Contain 'Score'
            @($result.Sources).Count | Should -Be 4
            @($result.Sources).Source | Should -Be @(
                'VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox')

            foreach ($source in @($result.Sources)) {
                $source.PSTypeNames[0] | Should -BeExactly 'EndpointOps.Reputation.Verdict'
                @($source.PSObject.Properties.Name) | Should -Be @(
                    'Source', 'Verdict', 'Detail', 'HashUsed', 'HashSource', 'QueryDate')
                $source.Detail | Should -BeOfType [string]
                $source.Detail | Should -Not -BeNullOrEmpty
                if ($source.Source -eq 'ThreatFox') {
                    $source.HashUsed | Should -Match '^[0-9A-Fa-f]{64}$'
                    $source.HashSource | Should -BeExactly 'VirusTotal'
                }
                else {
                    $source.HashUsed | Should -BeExactly $result.Hash
                    $source.HashSource | Should -BeExactly 'EPM'
                }
                $source.QueryDate.Kind | Should -BeExactly ([DateTimeKind]::Utc)
            }
        }
    }

    It 'Does not downgrade a Malicious VirusTotal verdict absent from MalwareBazaar' {
        $result = Get-FileReputation -Hash $script:NoReliefHash -MinIntervalMs 0

        @($result.Sources).Verdict | Should -Be @(
            'Malicious', 'Unknown', 'Unavailable', 'Malicious')
        $result.Verdict | Should -BeExactly 'Malicious'
    }

    It 'Still emits both verdicts when every source is Unavailable' {
        $results = @(Get-FileReputation -Hash $script:UnavailableHash -MinIntervalMs 0)

        $results.Count | Should -Be 1
        $results[0].Verdict | Should -BeExactly 'Unavailable'
        @($results[0].Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
        @($results[0].Sources).Verdict | Should -Be @('Unavailable', 'Unavailable')
    }

    It 'SkipCascade queries only VirusTotal for an otherwise eligible hash' {
        $vtPath = "/api/v3/files/$($script:SkipHash)"
        $vtBefore = Get-ReputationRequestCount -Path $vtPath
        $mbBefore = Get-ReputationRequestCount -Path $script:MbPath

        $result = Get-FileReputation -Hash $script:SkipHash -MinIntervalMs 0 -SkipCascade

        $vtAfter = Get-ReputationRequestCount -Path $vtPath
        $mbAfter = Get-ReputationRequestCount -Path $script:MbPath
        ($vtAfter - $vtBefore) | Should -Be 1
        ($mbAfter - $mbBefore) | Should -Be 0
        @($result.Sources).Source | Should -Be @('VirusTotal')
        $result.Verdict | Should -BeExactly 'Unknown'
    }

    Context 'Third-stage cascade behavior' {
        It 'Queries Hybrid Analysis exactly once after Unknown VT and Malicious MB verdicts for B...02' {
            Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
            $haBefore = Get-ReputationRequestCount -Path $script:HaPath

            $result = Get-FileReputation -Hash $script:VtUnknownMbKnownHash -MinIntervalMs 0

            $haAfter = Get-ReputationRequestCount -Path $script:HaPath
            ($haAfter - $haBefore) | Should -Be 1
            @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis')
            @($result.Sources).Verdict | Should -Be @('Unknown', 'Malicious', 'Malicious')
            $result.Verdict | Should -BeExactly 'Malicious'
        }

        It 'Does not reach the third stage after Unknown VT and hash_not_found MB results for E...05' {
            Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
            $haBefore = Get-ReputationRequestCount -Path $script:HaPath
            $tfBefore = Get-ReputationRequestCount -Path $script:TfPath

            $result = Get-FileReputation -Hash $script:SkipHash -MinIntervalMs 0

            $haAfter = Get-ReputationRequestCount -Path $script:HaPath
            $tfAfter = Get-ReputationRequestCount -Path $script:TfPath
            ($haAfter - $haBefore) | Should -Be 0
            ($tfAfter - $tfBefore) | Should -Be 0
            @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
            @($result.Sources).Verdict | Should -Be @('Unknown', 'Unknown')
            $result.Verdict | Should -BeExactly 'Unknown'
        }

        It 'Queries MB, Hybrid Analysis, and ThreatFox once each after a Malicious VT verdict for C...03' {
            Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
            $mbBefore = Get-ReputationRequestCount -Path $script:MbPath
            $haBefore = Get-ReputationRequestCount -Path $script:HaPath
            $tfBefore = Get-ReputationRequestCount -Path $script:TfPath

            $result = Get-FileReputation -Hash $script:MaliciousMbKnownHash -MinIntervalMs 0

            $mbAfter = Get-ReputationRequestCount -Path $script:MbPath
            $haAfter = Get-ReputationRequestCount -Path $script:HaPath
            $tfAfter = Get-ReputationRequestCount -Path $script:TfPath
            ($mbAfter - $mbBefore) | Should -Be 1
            ($haAfter - $haBefore) | Should -Be 1
            ($tfAfter - $tfBefore) | Should -Be 1
            @($result.Sources).Source | Should -Be @(
                'VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox')
            @($result.Sources).Verdict | Should -Be @(
                'Malicious', 'Malicious', 'Malicious', 'Malicious')
            $result.Verdict | Should -BeExactly 'Malicious'
        }

        It 'Does not trigger the third stage when VT and MB are Unavailable for F...06' {
            Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
            $haBefore = Get-ReputationRequestCount -Path $script:HaPath
            $tfBefore = Get-ReputationRequestCount -Path $script:TfPath

            $result = Get-FileReputation -Hash $script:UnavailableHash -MinIntervalMs 0

            $haAfter = Get-ReputationRequestCount -Path $script:HaPath
            $tfAfter = Get-ReputationRequestCount -Path $script:TfPath
            ($haAfter - $haBefore) | Should -Be 0
            ($tfAfter - $tfBefore) | Should -Be 0
            @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
            @($result.Sources).Verdict | Should -Be @('Unavailable', 'Unavailable')
            $result.Verdict | Should -BeExactly 'Unavailable'
        }

        It 'Queries Hybrid Analysis but not ThreatFox when VT provides no SHA-256 for B...02' {
            Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
            $haBefore = Get-ReputationRequestCount -Path $script:HaPath
            $tfBefore = Get-ReputationRequestCount -Path $script:TfPath

            $result = Get-FileReputation -Hash $script:VtUnknownMbKnownHash -MinIntervalMs 0

            $haAfter = Get-ReputationRequestCount -Path $script:HaPath
            $tfAfter = Get-ReputationRequestCount -Path $script:TfPath
            ($haAfter - $haBefore) | Should -Be 1
            ($tfAfter - $tfBefore) | Should -Be 0
            @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis')
            @($result.Sources).Source | Should -Not -Contain 'ThreatFox'
        }
    }

    It 'Identifies VirusTotal as the source of the ThreatFox pivot hash' {
        $result = Get-FileReputation -Hash $script:NoReliefHash -MinIntervalMs 0

        $tf = @($result.Sources | Where-Object Source -eq 'ThreatFox')
        $tf.Count | Should -Be 1
        $tf[0].HashUsed | Should -BeExactly (('2' * 62) + '09')
        $tf[0].HashSource | Should -BeExactly 'VirusTotal'
        $tf[0].HashUsed | Should -Not -BeExactly $result.Hash
    }
}
