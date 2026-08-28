#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port = ([uri]$script:Server.BaseUrl).Port
    $script:Production = '11111111-1111-1111-1111-111111111111'
    $script:HContoso = ('A' * 38) + '01'
    $script:HUnknown = ('B' * 38) + '02'
    $script:HFabrikam = ('C' * 38) + '03'
    $script:HMicrosoft = ('D' * 38) + '04'
    $script:HNorthwind = ('F' * 38) + '06'
    $script:EpmLog = "http://localhost:$($script:Port)/EPM/API/_test/requests"
    $script:VtLog = "http://localhost:$($script:Port)/_test/reputation"
    $script:VtKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'

    function Measure-EpmRequestLog {
        @((Invoke-RestMethod -Uri $script:EpmLog).requests).Count
    }

    function Measure-VtRequestLog {
        @((Invoke-RestMethod -Uri $script:VtLog).requests).Count
    }

    function Get-GroupedSummary {
        param($Summary, [string]$Hash)
        @($Summary | Where-Object { $_.Hash -eq $Hash })[0]
    }

    $identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))
    Connect-EpmTenant -DispatcherUri "http://localhost:$($script:Port)" -Credential $identifiers | Out-Null
}

AfterAll {
    Disconnect-VirusTotal
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmElevationSummary with reputation' {
    BeforeEach {
        Disconnect-VirusTotal
        Connect-VirusTotal -BaseUri $script:Server.BaseUrl -ApiKey $script:VtKey | Out-Null
    }

    It 'Preserves the base contract and does not call VirusTotal without IncludeReputation' {
        $before = Measure-VtRequestLog
        $summary = @(Get-EpmElevationSummary -SetId $script:Production -MinIntervalMs 0)

        @($summary).Count | Should -Be 5
        @($summary[0].PSObject.Properties.Name) | Should -Be @(
            'Publisher', 'Hash', 'FileName', 'DistinctUserCount', 'EventCount',
            'ComputerCount', 'FirstSeen', 'LastSeen', 'IsSigned', 'SourceTypes',
            'FromRemovableDrive', 'ProposalLevel', 'ProposalRank', 'Rationale'
        )
        @($summary | ForEach-Object { "$($_.Hash)|$($_.ProposalLevel)" }) | Should -Be @(
            "$($script:HContoso)|Strong",
            "$($script:HFabrikam)|Moderate",
            "$($script:HMicrosoft)|Weak",
            "$($script:HNorthwind)|Weak",
            "$($script:HUnknown)|None"
        )
        (Measure-VtRequestLog) | Should -Be $before
    }

    It 'Adds Reputation and ReputationDetail to each request grouping' {
        $summary = @(Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0)

        @($summary | Where-Object {
                $_.PSObject.Properties.Name -notcontains 'Reputation' -or
                $_.PSObject.Properties.Name -notcontains 'ReputationDetail' -or
                $null -eq $_.ReputationDetail
            }).Count | Should -Be 0
    }

    It 'Downgrades a malicious signed binary from Moderate to None with a valid reason' {
        $group = Get-GroupedSummary -Summary @(
            Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0
        ) -Hash $script:HFabrikam

        $group.IsSigned | Should -BeTrue
        $group.Reputation | Should -BeExactly 'Malicious'
        $group.ProposalLevel | Should -BeExactly 'None'
        $group.ProposalRank | Should -Be 0
        $group.Rationale | Should -BeLike '*Signed binary*flagged by 8 engines*'
        $group.Rationale | Should -Not -BeLike '*UNSIGNED BINARY*'
    }

    It 'Ignores a hostile mutation of the malicious report already cached' {
        $path = "/api/v3/files/$($script:HFabrikam)"
        $logBefore = @((Invoke-RestMethod -Uri $script:VtLog).requests)
        $before = @($logBefore | Where-Object path -eq $path).Count
        $exposedReport = Get-VtFileReport -Hash $script:HFabrikam -MinIntervalMs 0
        $exposedReport.Verdict = 'Clean'
        $exposedReport.MaliciousCount = 0

        $group = Get-GroupedSummary -Summary @(
            Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0
        ) -Hash $script:HFabrikam

        $logAfter = @((Invoke-RestMethod -Uri $script:VtLog).requests)
        $after = @($logAfter | Where-Object path -eq $path).Count
        $group.Reputation | Should -BeExactly 'Malicious'
        $group.ProposalLevel | Should -BeExactly 'None'
        $group.ReputationDetail.MaliciousCount | Should -Be 8
        ($after - $before) | Should -Be 1
    }

    It 'Never promotes a Clean verdict' {
        $group = Get-GroupedSummary -Summary @(
            Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0
        ) -Hash $script:HMicrosoft

        $group.Reputation | Should -BeExactly 'Clean'
        $group.ProposalLevel | Should -BeExactly 'Weak'
        $group.Rationale | Should -BeLike '*no engine*does not promote*'
    }

    It 'Does not change the level for an Unknown verdict' {
        $withoutReputation = Get-GroupedSummary -Summary @(
            Get-EpmElevationSummary -SetId $script:Production
        ) -Hash $script:HUnknown
        $withReputation = Get-GroupedSummary -Summary @(
            Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0
        ) -Hash $script:HUnknown

        $withReputation.Reputation | Should -BeExactly 'Unknown'
        $withReputation.ProposalLevel | Should -BeExactly $withoutReputation.ProposalLevel
        $withReputation.Rationale | Should -BeLike '*Unknown reputation*level remains unchanged*'
    }

    It 'Does not change the unavailable level and explains the absence of reputation' {
        $group = Get-GroupedSummary -Summary @(
            Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0
        ) -Hash $script:HNorthwind

        $group.Reputation | Should -BeExactly 'Unavailable'
        $group.ProposalLevel | Should -BeExactly 'Weak'
        $group.Rationale | Should -BeLike '*reputation could not be obtained*'
    }

    It 'Rejects IncludeReputation with GroupBy User before any connection or query' {
        Disconnect-VirusTotal
        $epmBefore = Measure-EpmRequestLog
        $vtBefore = Measure-VtRequestLog

        try {
            { Get-EpmElevationSummary -SetId $script:Production -GroupBy User -IncludeReputation } |
                Should -Throw '*IncludeReputation requires -GroupBy Binary*'
            (Measure-EpmRequestLog) | Should -Be $epmBefore
            (Measure-VtRequestLog) | Should -Be $vtBefore
        }
        finally {
            Connect-VirusTotal -BaseUri $script:Server.BaseUrl -ApiKey $script:VtKey | Out-Null
        }
    }

    It 'Throws before querying EPM when VirusTotal is disconnected and identifies the required action' {
        Disconnect-VirusTotal
        $before = Measure-EpmRequestLog

        try {
            { Get-EpmElevationSummary -SetId $script:Production -IncludeReputation -MinIntervalMs 0 } |
                Should -Throw '*Connect-VirusTotal*'
            (Measure-EpmRequestLog) | Should -Be $before
        }
        finally {
            Connect-VirusTotal -BaseUri $script:Server.BaseUrl -ApiKey $script:VtKey | Out-Null
        }
    }

    It 'Returns all groupings when VirusTotal fails along the way' {
        $summary = @(InModuleScope EndpointOps -Parameters @{ Production = $script:Production } {
                param($Production)
                $script:VtCallsForSummary = 0
                Mock Get-VtFileReport {
                    $script:VtCallsForSummary++
                    if ($script:VtCallsForSummary -eq 1) {
                        return [pscustomobject]@{
                            Verdict = 'Clean'; MaliciousCount = 0; Hash = ('A' * 38) + '01'
                        }
                    }
                    throw 'VirusTotal failure injected after the first grouping'
                }

                try {
                    Get-EpmElevationSummary -SetId $Production -IncludeReputation -MinIntervalMs 0
                }
                finally {
                    Remove-Variable -Name VtCallsForSummary -Scope Script -ErrorAction SilentlyContinue
                }
            })

        $summary.Count | Should -Be 5
        (Get-GroupedSummary -Summary $summary -Hash $script:HContoso).Reputation | Should -BeExactly 'Clean'
        (Get-GroupedSummary -Summary $summary -Hash $script:HFabrikam).Reputation | Should -BeExactly 'Unavailable'
        (Get-GroupedSummary -Summary $summary -Hash $script:HMicrosoft).Reputation | Should -BeExactly 'Unavailable'
        (Get-GroupedSummary -Summary $summary -Hash $script:HNorthwind).Reputation | Should -BeExactly 'Unavailable'
        (Get-GroupedSummary -Summary $summary -Hash $script:HUnknown).Reputation | Should -BeExactly 'Unavailable'
    }
}
