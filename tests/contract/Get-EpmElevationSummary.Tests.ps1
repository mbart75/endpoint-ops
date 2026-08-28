BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port

    $script:Production = '11111111-1111-1111-1111-111111111111'
    $script:Servers   = '22222222-2222-2222-2222-222222222222'
    # Set dedicated to ranking by user. The nine Production events give ONE event per user: a ranking by
# number of requests would be flat, therefore unmanageable, therefore a sorting test incapable of
# failing. This set has different counts.
    $script:Ranking = '33333333-3333-3333-3333-333333333333'

    $script:Log = "http://localhost:$($script:Port)/EPM/API/_test/requests"

    $script:SummarySource = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Public' 'Get-EpmElevationSummary.ps1'

    $script:HContoso   = ('A' * 38) + '01'
    $script:HUnknown   = ('B' * 38) + '02'
    $script:HFabrikam  = ('C' * 38) + '03'
    $script:HMicrosoft = ('D' * 38) + '04'

    # The log only retains the NAMES of the keys received, never their values, and it is cumulative
# throughout the entire duration of the server: it is therefore read by difference.
    function Measure-EpmRequestLog {
        @((Invoke-RestMethod -Uri $script:Log).requests).Count
    }

    function Get-EpmLogSince {
        param([int]$Index)
        @(@((Invoke-RestMethod -Uri $script:Log).requests) | Select-Object -Skip $Index)
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
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Get-EpmElevationSummary' {

    Context 'Grouping' {

        It 'Reduces nine events to five groupings' {
            @(Get-EpmElevationSummary -SetId $script:Production).Count | Should -Be 5
        }

        It 'Keeps the PAIR publisher + hash as the key' {
            # The five pairs expected, in full letters. A grouping on the sole hash, or on the sole
# publisher would produce the same count here: only the exact pair distinguishes it.
            $pairs = @(Get-EpmElevationSummary -SetId $script:Production |
                    ForEach-Object { "$($_.Publisher)|$($_.Hash)" } | Sort-Object)

            $pairs | Should -Be @(
                "|$($script:HUnknown)",
                "Contoso Software|$($script:HContoso)",
                "Fabrikam Inc|$($script:HFabrikam)",
                "Microsoft Windows|$($script:HMicrosoft)",
                'Northwind Traders|FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF06'
            )
        }

        It 'Has four distinct users on the Contoso group' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).DistinctUserCount |
                Should -Be 4
        }

        It 'Has four events on the Contoso group' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).EventCount |
                Should -Be 4
        }

        It 'Returns an empty collection on a set without events' {
            @(Get-EpmElevationSummary -SetId $script:Servers).Count | Should -Be 0
        }
    }

    Context 'Fields exposed by each grouping' {

        It 'Exposes <_>' -ForEach @(
            'Publisher', 'Hash', 'FileName', 'DistinctUserCount', 'EventCount',
            'ComputerCount', 'FirstSeen', 'LastSeen', 'IsSigned', 'SourceTypes',
            'FromRemovableDrive', 'ProposalLevel', 'ProposalRank', 'Rationale') {

            $first = @(Get-EpmElevationSummary -SetId $script:Production)[0]
            $first.PSObject.Properties.Name | Should -Contain $_
        }

        It 'Has four distinct endpoints on the Contoso group' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).ComputerCount |
                Should -Be 4
        }

        It 'Returns FirstSeen as DateTime rather than a string' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).FirstSeen |
                Should -BeOfType [datetime]
        }

        It 'Returns LastSeen as DateTime, not as a string' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).LastSeen |
                Should -BeOfType [datetime]
        }

        It 'Uses the earliest start date as FirstSeen' {
            # The first Contoso event starts on 07/09 at 08:00Z, the last one on 07/13. Taking the date of the
# last event seen, or the first match in pagination order, would give something else.
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).FirstSeen |
                Should -Be ([datetime]::new(2026, 7, 9, 8, 0, 0, [System.DateTimeKind]::Utc))
        }

        It 'Uses the latest end date as LastSeen' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).LastSeen |
                Should -Be ([datetime]::new(2026, 7, 14, 11, 0, 0, [System.DateTimeKind]::Utc))
        }
    }

    Context 'Proposal level' {

        It 'Proposes Strong on a signed binary seen by four users' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).ProposalLevel |
                Should -Be 'Strong'
        }

        It 'Proposes Moderate on a signed binary seen by two users' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HFabrikam).ProposalLevel |
                Should -Be 'Moderate'
        }

        It 'Proposes Weak on a signed binary seen by only one user' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HMicrosoft).ProposalLevel |
                Should -Be 'Weak'
        }
    }

    Context 'Unsigned binary' {

        It 'Does not propose a rule for an unsigned binary' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HUnknown).ProposalLevel |
                Should -Be 'None'
        }

        It 'Marks the unsigned group as unsigned' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HUnknown).IsSigned |
                Should -BeFalse
        }

        It 'Never proposes an unsigned binary regardless of request volume' {
            # The heart of the rule. Frequency measures diffusion, not confidence: an undesirable software
# widely deployed is more widespread, not more legitimate. The test simulates diffusion by lowering
# the thresholds of the module instead of creating events, and verifies that the level does NOT
# move.
            InModuleScope EndpointOps {
                $script:EpmStrongUserThreshold   = 1
                $script:EpmModerateUserThreshold = 1
            }
            try {
                $hUnknown = ('B' * 38) + '02'
                $summary = @(Get-EpmElevationSummary -SetId $script:Production)
                @($summary | Where-Object { $_.Hash -eq $hUnknown })[0].ProposalLevel |
                    Should -Be 'None'
            }
            finally {
                InModuleScope EndpointOps {
                    $script:EpmStrongUserThreshold   = 3
                    $script:EpmModerateUserThreshold = 2
                }
            }
        }

        It 'Explains in Rationale why no rule is proposed' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HUnknown).Rationale |
                Should -BeLike '*UNSIGNED BINARY*'
        }
    }

    Context 'Removable source' {

        It 'Explicitly identifies a removable source' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HFabrikam).FromRemovableDrive |
                Should -BeTrue
        }

        It 'Reports a removable source even for a signed binary' {
            # The Fabrikam group is a sign and remains available in Moderate: reporting is an ADDITIONAL signal,
# not a silent degradation of the level. The two must coexist.
            $g = Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HFabrikam
            $g.IsSigned | Should -BeTrue
        }

        It 'Names the removable source in Rationale' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HFabrikam).Rationale |
                Should -BeLike '*REMOVABLE SOURCE*'
        }

        It 'Does not report a removable source for a local group' {
            # Without this test, a FromRemovableDrive cable with $true everywhere would pass the previous test.
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).FromRemovableDrive |
                Should -BeFalse
        }
    }

    Context 'Plain-language rationale' {

        It 'Includes a non-empty rationale on each of the five groupings' {
            $emptyItems = @(Get-EpmElevationSummary -SetId $script:Production |
                    Where-Object { [string]::IsNullOrWhiteSpace($_.Rationale) })
            $emptyItems.Count | Should -Be 0
        }

        It 'Includes a written rationale rather than only a keyword' {
            # A rationale that copied the ProposalLevel would justify nothing. We require a sentence: several
# words, and a length that excludes etiquette.
            $shortItems = @(Get-EpmElevationSummary -SetId $script:Production |
                    Where-Object { $_.Rationale.Length -lt 40 -or -not $_.Rationale.Contains(' ') })
            $shortItems.Count | Should -Be 0
        }

        It 'Names the distinct-user count in a signed group rationale' {
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production) -Hash $script:HContoso).Rationale |
                Should -BeLike '*4 distinct users*'
        }
    }

    Context 'Ranking by user' {

        It 'Returns two users on the entire ranking set' {
            @(Get-EpmElevationSummary -SetId $script:Ranking -GroupBy User).Count | Should -Be 2
        }

        It 'Ranks users by request count in descending order' {
            # Zoe has three requests and Aaron has only one. Alphabetical and ascending order would both place
            # Aaron first, so this test distinguishes all three orderings.
            @(Get-EpmElevationSummary -SetId $script:Ranking -GroupBy User |
                    ForEach-Object { $_.UserName }) | Should -Be @('zoe', 'aaron')
        }

        It 'Counts the requests of each user' {
            @(Get-EpmElevationSummary -SetId $script:Ranking -GroupBy User |
                    ForEach-Object { $_.RequestCount }) | Should -Be @(3, 1)
        }

        It 'Counts the distinct binaries per user' {
            # Zoe asked FOR TWO different binaries in three requests: confusing requests and binaries would give
# 3.
            @(Get-EpmElevationSummary -SetId $script:Ranking -GroupBy User)[0].DistinctBinaryCount |
                Should -Be 2
        }

        It 'Counts the distinct endpoints per user' {
            @(Get-EpmElevationSummary -SetId $script:Ranking -GroupBy User)[0].ComputerCount |
                Should -Be 2
        }

        It 'Exposes <_> on a user line' -ForEach @(
            'UserName', 'RequestCount', 'DistinctBinaryCount', 'ComputerCount',
            'FirstSeen', 'LastSeen') {

            $first = @(Get-EpmElevationSummary -SetId $script:Ranking -GroupBy User)[0]
            $first.PSObject.Properties.Name | Should -Contain $_
        }

        It 'Returns all nine user entries of the production set' {
            @(Get-EpmElevationSummary -SetId $script:Production -GroupBy User).Count | Should -Be 9
        }
    }

    Context 'Forwarded time boundaries' {

        It 'Transmits -Since to the event query' {
            # The summary must not read the entire period ignoring the boundaries: 08:30Z removes Alice's event,
# so the Contoso group reduces to three users.
            $fromDate = [datetime]::new(2026, 7, 10, 8, 30, 0, [System.DateTimeKind]::Utc)
            (Get-GroupedSummary -Summary (Get-EpmElevationSummary -SetId $script:Production -Since $fromDate) -Hash $script:HContoso).DistinctUserCount |
                Should -Be 3
        }

        It 'Transmits -Until to the event query' {
            $untilDate = [datetime]::new(2026, 7, 22, 14, 30, 0, [System.DateTimeKind]::Utc)
            @(Get-EpmElevationSummary -SetId $script:Production -Until $untilDate).Count | Should -Be 4
        }

        It 'Transmits -EventType to the event query' {
            # Only two ManualRequest: the unsigned binary and mmc.exe.
            @(Get-EpmElevationSummary -SetId $script:Production -EventType 'ManualRequest').Count |
                Should -Be 2
        }
    }

    Context 'Read-only behavior' {
        # This function proposes actions. The guard prevents a future change from turning a proposal into an
        # actual modification.

        It 'Does not issue any write request while querying events' {
            $index = Measure-EpmRequestLog
            Get-EpmElevationSummary -SetId $script:Production | Out-Null
            Get-EpmElevationSummary -SetId $script:Production -GroupBy User | Out-Null

            $newItems = @(Get-EpmLogSince -Index $index)
            $writes = @($newItems | Where-Object { $_.method -ne 'GET' })

            # Any observed writing must be a search for events, and nothing else.
            @($writes | Where-Object { $_.path -notmatch '/Events/Search$' }).Count |
                Should -Be 0
        }

        It 'Sends the expected queries so the preceding no-write test cannot pass vacuously' {
            # A test that counts zero write requests would also pass if no call occurred. This assertion
            # excludes that vacuous result.
            $index = Measure-EpmRequestLog
            Get-EpmElevationSummary -SetId $script:Production | Out-Null

            $newItems = @(Get-EpmLogSince -Index $index)
            @($newItems | Where-Object { $_.method -eq 'POST' -and $_.path -match '/Events/Search$' }).Count |
                Should -Be 3
        }

        It 'Reads the source file it claims to analyze' {
            # Without this test, the two text controls that follow would be EMPTY. Get-Content on a missing file
# writes an unblocking error and makes $null, and '$null | Should -Not -Match' PASS: the two
# controls would remain green in n having read nothing. They therefore use -ErrorAction Stop, and
# this also excludes the present but empty file.
            $source = Get-Content -Raw -ErrorAction Stop -Path $script:SummarySource
            $source.Length | Should -BeGreaterThan 500
        }

        It 'Does not mention any policy write operation in its source code' {
            # The test log proves current behavior on the current fixtures. This check concerns the text: an
# additional writing route added behind a condition never taken by the fixtures would escape the
# log, not the user.
            $source = Get-Content -Raw -ErrorAction Stop -Path $script:SummarySource
            $source | Should -Not -Match "Method\s*=?\s*'(Post|Put|Delete|Patch)'"
        }

        It 'Does not cite any policy route in its source code' {
            $source = Get-Content -Raw -ErrorAction Stop -Path $script:SummarySource
            $source | Should -Not -Match '/Policies'
        }
    }
}
