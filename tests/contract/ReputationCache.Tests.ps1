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
    $script:KnownHash = ('B' * 38) + '02'
    $script:MaliciousHash = ('C' * 38) + '03'
    $script:UnavailableHash = ('F' * 38) + '06'

    function Initialize-ReputationCacheTestModule {
        Disconnect-VirusTotal -ErrorAction SilentlyContinue
        Disconnect-MalwareBazaar -ErrorAction SilentlyContinue
        Disconnect-HybridAnalysis -ErrorAction SilentlyContinue
        Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop
        Connect-VirusTotal -ApiKey $script:VtKey -BaseUri $script:Server.BaseUrl | Out-Null
        Connect-MalwareBazaar -AuthKey $script:MbKey -BaseUri $script:MbBaseUri `
            -ThreatFoxBaseUri $script:TfBaseUri | Out-Null
    }

    function Get-ReputationRequestCount {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$Path)

        $requests = @((Invoke-RestMethod -Uri $script:JournalUri).requests)
        return @($requests | Where-Object path -eq $Path).Count
    }

    function ConvertTo-TestReputationCacheEntry {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Hash,
            [Parameter(Mandatory)][string]$Source,
            [Parameter(Mandatory)][string]$Verdict,
            [Parameter(Mandatory)][datetime]$QueryDate
        )

        return [pscustomobject][ordered]@{
            Hash      = $Hash
            Source    = $Source
            Verdict   = $Verdict
            QueryDate = $QueryDate.ToUniversalTime().ToString('o')
        }
    }

    function ConvertTo-TestReputationCacheFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$CachePath,
            [Parameter(Mandatory)][object[]]$Entries
        )

        $directory = Split-Path -Path $CachePath -Parent
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
        $entriesList = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $Entries) {
            $entriesList.Add($entry)
        }
        ConvertTo-Json -InputObject $entriesList -Depth 4 | Set-Content -Path $CachePath -Encoding utf8NoBOM
    }
}

AfterAll {
    Disconnect-VirusTotal -ErrorAction SilentlyContinue
    Disconnect-MalwareBazaar -ErrorAction SilentlyContinue
    Disconnect-HybridAnalysis -ErrorAction SilentlyContinue
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Persistent cache mutation integrity' {
    BeforeEach {
        $script:cachePath = Join-Path $TestDrive "$([guid]::NewGuid().ToString('N')).json"
        $script:lookup = 'A' * 40
        $script:canonical = 'B' * 64
    }

    BeforeAll {
        function Write-IntegrityCandidate {
            param($Path, $Lookup, $Canonical, $Verdict = 'Clean', $Source = 'VirusTotal')
            & (Get-Module EndpointOps) {
                param($Path, $Lookup, $Canonical, $Verdict, $Source)
                $candidate = [pscustomobject]@{
                    HashUsed = $Lookup; HashSource = 'EPM'; Source = $Source
                    Verdict = $Verdict; QueryDate = [datetime]::UtcNow
                }
                Write-ReputationCacheEntry -CachePath $Path -LookupHash $Lookup -CanonicalSha256 $Canonical -SourceResult $candidate
            } $Path $Lookup $Canonical $Verdict $Source
        }
        function Initialize-IntegritySeed {
            param(
                $Path,
                $Lookup,
                [AllowNull()]$Canonical,
                $Date = [datetime]::UtcNow,
                $Source = 'VirusTotal'
            )
            $seed = [pscustomobject][ordered]@{
                Version = 2; LookupHash = $Lookup; CanonicalSha256 = $Canonical
                Hash = $Lookup; HashSource = 'EPM'; Source = $Source
                Verdict = 'Malicious'; QueryDate = $Date.ToString('o')
            }
            [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject @($seed)))
        }
        function Wait-IntegritySignal {
            param($Path)
            $timer = [Diagnostics.Stopwatch]::StartNew()
            while (-not [IO.File]::Exists($Path) -and $timer.ElapsedMilliseconds -lt 5000) {
                Start-Sleep -Milliseconds 20
            }
            [IO.File]::Exists($Path) | Should -BeTrue
        }
    }

    It 'preserves parseable unrelated JSON bytes instead of replacing another application file' {
        [IO.File]::WriteAllText($cachePath, '[{"project":"not-endpoint-ops"}]')
        $before = [IO.File]::ReadAllBytes($cachePath)
        { Write-IntegrityCandidate $cachePath $lookup $canonical } | Should -Not -Throw
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($cachePath)) | Should -BeExactly ([Convert]::ToBase64String($before))
    }

    It 'runs the entire persistent mutation under the cache lock' {
        Mock Invoke-WithReputationCacheLock -ModuleName EndpointOps { & $ScriptBlock }
        Write-IntegrityCandidate $cachePath $lookup $canonical
        Should -Invoke Invoke-WithReputationCacheLock -ModuleName EndpointOps -Times 1 -Exactly
        @((Get-Content $cachePath -Raw) | ConvertFrom-Json).Count | Should -Be 1
    }

    It 'retains fresh malicious evidence instead of a same-binding <Weaker> verdict' -ForEach @(
        @{ Weaker = 'Clean' }; @{ Weaker = 'Unknown' }
    ) {
        Initialize-IntegritySeed $cachePath $lookup $canonical
        Write-IntegrityCandidate $cachePath $lookup $canonical $Weaker
        $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
        $entries.Count | Should -Be 1
        $entries[0].Verdict | Should -Be 'Malicious'
    }

    It 'preserves bytes when an established binding receives a <Binding> update' -ForEach @(
        @{ Binding = 'different'; Candidate = ('C' * 64) }
        @{ Binding = 'null'; Candidate = $null }
    ) {
        Initialize-IntegritySeed $cachePath $lookup $canonical
        $before = [IO.File]::ReadAllBytes($cachePath)
        Write-IntegrityCandidate $cachePath $lookup $Candidate
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($cachePath)) | Should -BeExactly ([Convert]::ToBase64String($before))
    }

    It 'does not let <Age> malicious evidence suppress a current replacement' -ForEach @(
        @{ Age = 'expired'; Days = -91 }; @{ Age = 'future'; Days = 1 }
    ) {
        Initialize-IntegritySeed $cachePath $lookup $canonical ([datetime]::UtcNow.AddDays($Days))
        Write-IntegrityCandidate $cachePath $lookup $canonical
        $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
        $entries.Count | Should -Be 1
        $entries[0].Verdict | Should -Be 'Clean'
    }

    It 'retains both sources from concurrent processes writing the same identity' {
        $modulePath = Join-Path $PSScriptRoot '../../src/EndpointOps/EndpointOps.psd1'
        $jobs = @()
        try {
            foreach ($source in @('VirusTotal', 'MalwareBazaar')) {
                $worker = {
                    param($ModulePath, $Path, $Lookup, $Canonical, $Source)
                    $ErrorActionPreference = 'Stop'
                    Import-Module $ModulePath -Force
                    & (Get-Module EndpointOps) {
                        param($Path, $Lookup, $Canonical, $Source)
                        $candidate = [pscustomobject]@{
                            HashUsed = $Lookup; HashSource = 'EPM'; Source = $Source
                            Verdict = $(if ($Source -eq 'VirusTotal') { 'Clean' } else { 'Malicious' })
                            QueryDate = [datetime]::UtcNow
                        }
                        Write-ReputationCacheEntry -CachePath $Path -LookupHash $Lookup -CanonicalSha256 $Canonical -SourceResult $candidate
                    } $Path $Lookup $Canonical $Source
                }
                $jobs += Start-Job -ArgumentList $modulePath, $cachePath, $lookup, $canonical, $source -ScriptBlock $worker
            }
            $jobs | Wait-Job -Timeout 10 | Out-Null
            $jobs.State | Should -Be @('Completed', 'Completed')
            $jobs | Receive-Job -ErrorAction Stop
            $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
            @($entries | Where-Object Source -eq 'VirusTotal').Count | Should -Be 1
            @($entries | Where-Object Source -eq 'MalwareBazaar').Count | Should -Be 1
        }
        finally { $jobs | Stop-Job; $jobs | Remove-Job -Force }
    }

    It 'retains same-source fresh malicious evidence while learning its canonical binding' {
        Initialize-IntegritySeed $cachePath $lookup $null
        Write-IntegrityCandidate $cachePath $lookup $canonical 'Clean' 'VirusTotal'

        $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
        $entries.Count | Should -Be 1
        $entries[0].Source | Should -BeExactly 'VirusTotal'
        $entries[0].Verdict | Should -BeExactly 'Malicious'
        $entries[0].CanonicalSha256 | Should -BeExactly $canonical
    }

    It 'retains cross-source fresh malicious evidence while learning a canonical binding' {
        Initialize-IntegritySeed $cachePath $lookup $null ([datetime]::UtcNow) 'MalwareBazaar'
        Write-IntegrityCandidate $cachePath $lookup $canonical 'Clean' 'VirusTotal'

        $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
        $entries.Count | Should -Be 2
        @($entries | Where-Object Source -eq 'MalwareBazaar').Verdict | Should -BeExactly 'Malicious'
        @($entries).CanonicalSha256 | Should -Be @($canonical, $canonical)
    }

    # Production break caught: carrying one entry's null-to-bound transition into the next
    # unrelated version-2 entry, or reading that per-entry state before it is initialized.
    It 'isolates canonical learning when the target entry is <Position>' -ForEach @(
        @{ Position = 'first'; TargetFirst = $true }
        @{ Position = 'last'; TargetFirst = $false }
    ) {
        $unrelatedLookup = 'D' * 40
        $unrelatedDate = [datetime]::UtcNow.AddMinutes(-5).ToString('o')
        $target = [pscustomobject][ordered]@{
            Version = 2; LookupHash = $lookup; CanonicalSha256 = $null
            Hash = $lookup; HashSource = 'EPM'; Source = 'VirusTotal'
            Verdict = 'Malicious'; QueryDate = [datetime]::UtcNow.ToString('o')
        }
        $unrelated = [pscustomobject][ordered]@{
            Version = 2; LookupHash = $unrelatedLookup; CanonicalSha256 = $null
            Hash = $unrelatedLookup; HashSource = 'EPM'; Source = 'MalwareBazaar'
            Verdict = 'Unknown'; QueryDate = $unrelatedDate
        }
        $seedEntries = if ($TargetFirst) { @($target, $unrelated) } else { @($unrelated, $target) }
        [IO.File]::WriteAllText($cachePath, (ConvertTo-Json -InputObject $seedEntries))

        Write-IntegrityCandidate $cachePath $lookup $canonical 'Clean' 'VirusTotal'

        $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
        $entries.Count | Should -Be 2
        $retainedTarget = @($entries | Where-Object LookupHash -eq $lookup)
        $retainedTarget.Count | Should -Be 1
        $retainedTarget[0].Verdict | Should -BeExactly 'Malicious'
        $retainedTarget[0].CanonicalSha256 | Should -BeExactly $canonical
        $retainedUnrelated = @($entries | Where-Object LookupHash -eq $unrelatedLookup)
        $retainedUnrelated.Count | Should -Be 1
        $retainedUnrelated[0].CanonicalSha256 | Should -BeNullOrEmpty
        $retainedUnrelated[0].Hash | Should -BeExactly $unrelatedLookup
        $retainedUnrelated[0].HashSource | Should -BeExactly 'EPM'
        $retainedUnrelated[0].Source | Should -BeExactly 'MalwareBazaar'
        $retainedUnrelated[0].Verdict | Should -BeExactly 'Unknown'
        ([datetime]$retainedUnrelated[0].QueryDate).ToUniversalTime() |
            Should -Be ([datetime]$unrelatedDate).ToUniversalTime()
    }

    It 'retains malicious evidence from deterministic concurrent null-to-bound writers with <Order> first' -ForEach @(
        @{ Order = 'unbound'; CleanDelayMs = 250; MaliciousDelayMs = 0 }
        @{ Order = 'bound'; CleanDelayMs = 0; MaliciousDelayMs = 250 }
    ) {
        $modulePath = Join-Path $PSScriptRoot '../../src/EndpointOps/EndpointOps.psd1'
        $start = Join-Path $TestDrive "$Order-start"
        $cleanReady = Join-Path $TestDrive "$Order-clean-ready"
        $maliciousReady = Join-Path $TestDrive "$Order-malicious-ready"
        $worker = {
            param($ModulePath, $Path, $Lookup, $Canonical, $Source, $Verdict, $Ready, $Start, $DelayMs)
            $ErrorActionPreference = 'Stop'
            Import-Module $ModulePath -Force
            [IO.File]::WriteAllText($Ready, '')
            $timer = [Diagnostics.Stopwatch]::StartNew()
            while (-not [IO.File]::Exists($Start)) {
                if ($timer.ElapsedMilliseconds -ge 5000) { throw 'Start signal timed out' }
                Start-Sleep -Milliseconds 20
            }
            if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
            & (Get-Module EndpointOps) {
                param($Path, $Lookup, $Canonical, $Source, $Verdict)
                $candidate = [pscustomobject]@{
                    HashUsed = $Lookup; HashSource = 'EPM'; Source = $Source
                    Verdict = $Verdict; QueryDate = [datetime]::UtcNow
                }
                Write-ReputationCacheEntry -CachePath $Path -LookupHash $Lookup `
                    -CanonicalSha256 $Canonical -SourceResult $candidate
            } $Path $Lookup $Canonical $Source $Verdict
        }
        $jobs = @()
        try {
            $jobs += Start-Job -ScriptBlock $worker -ArgumentList $modulePath, $cachePath, $lookup, `
                $canonical, 'VirusTotal', 'Clean', $cleanReady, $start, $CleanDelayMs
            $jobs += Start-Job -ScriptBlock $worker -ArgumentList $modulePath, $cachePath, $lookup, `
                $null, 'MalwareBazaar', 'Malicious', $maliciousReady, $start, $MaliciousDelayMs
            Wait-IntegritySignal $cleanReady
            Wait-IntegritySignal $maliciousReady
            [IO.File]::WriteAllText($start, '')
            $jobs | Wait-Job -Timeout 10 | Out-Null
            $jobs.State | Should -Be @('Completed', 'Completed')
            $jobs | Receive-Job -ErrorAction Stop

            $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
            $entries.Count | Should -Be 2
            @($entries | Where-Object Source -eq 'MalwareBazaar').Verdict |
                Should -BeExactly 'Malicious'
            @($entries).CanonicalSha256 | Should -Be @($canonical, $canonical)
        }
        finally { $jobs | Stop-Job; $jobs | Remove-Job -Force }
    }
}

Describe 'Recognizable ShouldProcess cache clearing' {
    BeforeEach {
        $script:cachePath = Join-Path $TestDrive "$([guid]::NewGuid().ToString('N')).json"
    }

    It 'leaves both cache bytes and the directory unchanged with WhatIf' {
        [IO.File]::WriteAllText($cachePath, '[]')
        Clear-ReputationCache -CachePath $cachePath -WhatIf
        (Get-Content $cachePath -Raw) | Should -BeExactly '[]'
        (Test-Path -LiteralPath "$cachePath.lock") | Should -BeFalse
    }

    It 'rejects unrelated valid JSON and preserves the selected file' {
        [IO.File]::WriteAllText($cachePath, '[{"project":"not-endpoint-ops"}]')
        { Clear-ReputationCache -CachePath $cachePath } | Should -Throw '*not a recognized reputation cache*'
        (Get-Content $cachePath -Raw) | Should -BeExactly '[{"project":"not-endpoint-ops"}]'
    }

    It 'allows explicit forced recovery of a corrupt cache' {
        [IO.File]::WriteAllText($cachePath, '[corrupt')
        Clear-ReputationCache -CachePath $cachePath -Force -Confirm:$false
        (Test-Path $cachePath) | Should -BeFalse
    }

    It 'creates no directory or lock when the cache is absent' {
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $absent = Join-Path $directory 'cache.json'
        Clear-ReputationCache -CachePath $absent
        Clear-ReputationCache -CachePath $absent -WhatIf
        (Test-Path $directory) | Should -BeFalse
        (Test-Path "$absent.lock") | Should -BeFalse
    }
}

Describe 'Get-FileReputation reputation cache' {
    BeforeEach {
        Initialize-ReputationCacheTestModule
        $script:ReferenceDate = [datetime]::SpecifyKind([datetime]'2026-08-25T12:00:00', [DateTimeKind]::Utc)
    }

    AfterEach {
        Disconnect-VirusTotal -ErrorAction SilentlyContinue
        Disconnect-MalwareBazaar -ErrorAction SilentlyContinue
        Disconnect-HybridAnalysis -ErrorAction SilentlyContinue
    }

    # Production break caught: reading or writing the cache when UseCache is absent.
    It '1. leaves the supplied file untouched and queries normally without UseCache' {
        $cachePath = Join-Path $TestDrive 'disabled/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate
        )
        $contentBefore = Get-Content -Path $cachePath -Raw
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        $result.Verdict | Should -BeExactly 'Clean'
        ($after - $before) | Should -Be 1
        (Test-Path -LiteralPath $cachePath) | Should -BeTrue
        (Get-Content -Path $cachePath -Raw) | Should -BeExactly $contentBefore
    }

    # Production break caught: ignoring a valid persisted entry after a process restart.
    It '2. serves the second pipeline query from cache without a network call when UseCache is set' {
        $cachePath = Join-Path $TestDrive 'hit/reputation-cache.json'
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $queryReference = [datetime]::UtcNow

        @($script:CleanHash | Get-FileReputation -MinIntervalMs 0 -SkipCascade -UseCache `
                -CachePath $cachePath -ReferenceDate $queryReference).Count | Should -Be 1
        Initialize-ReputationCacheTestModule
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = @($script:CleanHash | Get-FileReputation -MinIntervalMs 0 -SkipCascade -UseCache `
                -CachePath $cachePath -ReferenceDate $queryReference.AddMinutes(1))

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 0
        $result.Count | Should -Be 1
        $result[0].Verdict | Should -BeExactly 'Clean'
        $result[0].PSTypeNames[0] | Should -BeExactly 'EndpointOps.Reputation.FileResult'
        @($result[0].PSObject.Properties.Name) | Should -Be @('Hash', 'Verdict', 'Sources')
        @($result[0].Sources).Source | Should -Be @('VirusTotal')
        $source = @($result[0].Sources)[0]
        $source.PSTypeNames[0] | Should -BeExactly 'EndpointOps.Reputation.Verdict'
        @($source.PSObject.Properties.Name) | Should -Be @(
            'Source', 'Verdict', 'Detail', 'HashUsed', 'HashSource', 'QueryDate')
        $source.Detail | Should -BeLike '*persistent cache*'
        $source.HashUsed | Should -BeExactly $script:CleanHash
        $source.HashSource | Should -BeExactly 'EPM'
        $source.QueryDate.Kind | Should -BeExactly ([DateTimeKind]::Utc)
    }

    # Production break caught: treating an eight-day Clean entry as valid.
    It '3. ignores an eight-day Clean entry and queries the provider again' {
        $cachePath = Join-Path $TestDrive 'clean-expired/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate.AddDays(-8)
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
    }

    # Production break caught: expiring Clean entries at or before their seven-day boundary.
    It '4. serves a six-day Clean entry and one at the exact seven-day boundary' {
        $cachePath = Join-Path $TestDrive 'clean-fresh/reputation-cache.json'
        foreach ($age in @(6, 7)) {
            ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
                ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                    -Verdict 'Clean' -QueryDate $script:ReferenceDate.AddDays(-$age)
            )
            $vtPath = "/api/v3/files/$($script:CleanHash)"
            $before = Get-ReputationRequestCount -Path $vtPath

            $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
                -CachePath $cachePath -ReferenceDate $script:ReferenceDate

            $after = Get-ReputationRequestCount -Path $vtPath
            $result.Verdict | Should -BeExactly 'Clean'
            ($after - $before) | Should -Be 0
        }
    }

    # Production break caught: expiring a Malicious entry before its ninety-day boundary.
    It '5. serves an eighty-day Malicious entry and one at the exact ninety-day boundary' {
        $cachePath = Join-Path $TestDrive 'malicious-fresh/reputation-cache.json'
        foreach ($age in @(80, 90)) {
            ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
                ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'VirusTotal' `
                    -Verdict 'Malicious' -QueryDate $script:ReferenceDate.AddDays(-$age)
            )
            $vtPath = "/api/v3/files/$($script:MaliciousHash)"
            $before = Get-ReputationRequestCount -Path $vtPath

            $result = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -SkipCascade -UseCache `
                -CachePath $cachePath -ReferenceDate $script:ReferenceDate

            $after = Get-ReputationRequestCount -Path $vtPath
            $result.Verdict | Should -BeExactly 'Malicious'
            ($after - $before) | Should -Be 0
        }
    }

    # Production break caught: treating a one-hundred-day Malicious entry as valid.
    It '6. ignores a one-hundred-day Malicious entry and queries the provider again' {
        $cachePath = Join-Path $TestDrive 'malicious-expired/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'VirusTotal' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate.AddDays(-100)
        )
        $vtPath = "/api/v3/files/$($script:MaliciousHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Malicious'
    }

    # Production break caught: serializing a service outage as a reusable cache result.
    It '7. never writes an Unavailable verdict to the cache' {
        $cachePath = Join-Path $TestDrive 'unavailable/reputation-cache.json'

        $result = Get-FileReputation -Hash $script:UnavailableHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $result.Verdict | Should -BeExactly 'Unavailable'
        if (Test-Path -LiteralPath $cachePath) {
            @((Get-Content -Path $cachePath -Raw | ConvertFrom-Json)).Verdict | Should -Not -Contain 'Unavailable'
        }
    }

    # Production break caught: omitting the explicit lookup-to-evidence binding or persisting
    # operational data beyond the versioned cache contract.
    It "8. persists only the versioned identity binding and each source's actual HashUsed value" {
        $cachePath = Join-Path $TestDrive 'privacy/reputation-cache.json'
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null

        $result = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $entries = @((Get-Content -Path $cachePath -Raw | ConvertFrom-Json))
        $result.Sources.Count | Should -Be 4
        $entries.Count | Should -Be 4
        foreach ($entry in $entries) {
            @($entry.PSObject.Properties.Name) | Should -Be @(
                'Version', 'LookupHash', 'CanonicalSha256', 'Hash', 'HashSource',
                'Source', 'Verdict', 'QueryDate')
            $entry.Version | Should -Be 2
            $entry.LookupHash | Should -BeExactly $script:MaliciousHash
            $entry.PSObject.Properties.Name | Should -Not -Contain 'Detail'
            $entry.PSObject.Properties.Name | Should -Not -Contain 'Machine'
            $entry.PSObject.Properties.Name | Should -Not -Contain 'User'
            $entry.PSObject.Properties.Name | Should -Not -Contain 'Key'
        }
        $threatFox = @($entries | Where-Object Source -eq 'ThreatFox')
        $threatFox.Count | Should -Be 1
        $threatFox[0].Hash | Should -Match '^[0-9A-Fa-f]{64}$'
        $threatFox[0].Hash | Should -Not -BeExactly $script:MaliciousHash
        $threatFox[0].CanonicalSha256 | Should -BeExactly $threatFox[0].Hash
        $threatFox[0].HashSource | Should -BeExactly 'VirusTotal'
    }

    # Production break caught: resolving the default cache location inside the repository or outside ApplicationData.
    It '9. resolves the default path outside the repository under ApplicationData without writing' {
        $expected = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json'

        InModuleScope EndpointOps {
            $expected = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json'
            Mock Test-Path { return $false }

            Clear-ReputationCache

            Should -Invoke Test-Path -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $Expected }
        }
        $expected.StartsWith((Get-Location).Path, [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse
    }

    # Production break caught: allowing a corrupt cache to escape instead of falling back to the normal query.
    It '10. ignores a corrupt cache file and queries normally' {
        $cachePath = Join-Path $TestDrive 'corrupt/reputation-cache.json'
        New-Item -Path (Split-Path -Path $cachePath -Parent) -ItemType Directory -Force | Out-Null
        Set-Content -Path $cachePath -Value '[ not json' -Encoding utf8NoBOM
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        $result.Verdict | Should -BeExactly 'Clean'
        ($after - $before) | Should -Be 1
    }

    # Production break caught: leaving an existing cache file behind or throwing when it is already absent.
    It '11. Clear-ReputationCache removes only the selected file and does not throw when it is absent' {
        $cachePath = Join-Path $TestDrive 'clear/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate
        )

        { Clear-ReputationCache -CachePath $cachePath } | Should -Not -Throw
        (Test-Path -LiteralPath $cachePath) | Should -BeFalse
        { Clear-ReputationCache -CachePath $cachePath } | Should -Not -Throw
    }

    # Production break caught: emitting an earlier valid entry before rejecting a later invalid entry.
    It '12. ignores the entire cache when an invalid entry follows a valid hit' {
        $cachePath = Join-Path $TestDrive 'partial-invalid/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'InvalidSource' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate
            )
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
        $result.Sources[0].Detail | Should -Not -BeLike '*persistent cache*'
    }

    # Production break caught: refusing a relative CachePath because it has no parent component.
    It '13. writes a relative CachePath in the current TestDrive directory' {
        $sourceResult = [pscustomobject]@{
            Source    = 'VirusTotal'
            Verdict   = 'Clean'
            HashUsed  = $script:CleanHash
            QueryDate = $script:ReferenceDate
        }
        $relativePath = 'relative-cache.json'
        InModuleScope EndpointOps -Parameters @{
            SourceResult = $sourceResult
            CachePath = $relativePath
            TestDirectory = $TestDrive
        } {
            param($SourceResult, $CachePath, $TestDirectory)
            Push-Location -LiteralPath $TestDirectory
            try {
                Write-ReputationCacheEntry -SourceResult $SourceResult -CachePath $CachePath
            }
            finally {
                Pop-Location
            }
        }
        $cachePath = Join-Path $TestDrive $relativePath
        (Test-Path -LiteralPath $cachePath -PathType Leaf) | Should -BeTrue
        $entries = @(Get-Content -LiteralPath $cachePath -Raw | ConvertFrom-Json)
        $entries.Count | Should -Be 1
        @($entries[0].PSObject.Properties.Name) | Should -Be @('Hash', 'Source', 'Verdict', 'QueryDate')
    }

    # Production break caught: abandoning a write when the previous list-shaped JSON is malformed.
    It '14. repairs corrupt JSON cache content that begins as a list' {
        $cachePath = Join-Path $TestDrive 'corrupt-writer/reputation-cache.json'
        New-Item -Path (Split-Path -Path $cachePath -Parent) -ItemType Directory -Force | Out-Null
        Set-Content -Path $cachePath -Value '[ not json' -Encoding utf8NoBOM
        $sourceResult = [pscustomobject]@{
            Source    = 'VirusTotal'
            Verdict   = 'Clean'
            HashUsed  = $script:CleanHash
            QueryDate = $script:ReferenceDate
        }

        InModuleScope EndpointOps -Parameters @{ SourceResult = $sourceResult; CachePath = $cachePath } {
            param($SourceResult, $CachePath)
            Write-ReputationCacheEntry -SourceResult $SourceResult -CachePath $CachePath
        }

        $entries = @(Get-Content -LiteralPath $cachePath -Raw | ConvertFrom-Json -ErrorAction Stop)
        $entries.Count | Should -Be 1
        @($entries[0].PSObject.Properties.Name) | Should -Be @('Hash', 'Source', 'Verdict', 'QueryDate')
        $entries[0].Hash | Should -BeExactly $script:CleanHash
    }

    # Production break caught: accepting a VirusTotal-only SkipCascade cache as a complete cascade.
    It '15. does not serve a VirusTotal-only SkipCascade cache as a complete cascade' {
        $cachePath = Join-Path $TestDrive 'partial-cascade/reputation-cache.json'
        $queryReference = [datetime]::UtcNow

        $seed = Get-FileReputation -Hash $script:KnownHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference
        $persistedAfterSeed = @((Get-Content -LiteralPath $cachePath -Raw | ConvertFrom-Json)).Count
        $before = Get-ReputationRequestCount -Path $script:MbPath

        $full = Get-FileReputation -Hash $script:KnownHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference.AddMinutes(1)

        $after = Get-ReputationRequestCount -Path $script:MbPath
        $seed.Verdict | Should -BeExactly 'Unknown'
        @($seed.Sources).Source | Should -Be @('VirusTotal')
        $persistedAfterSeed | Should -Be 1
        ($after - $before) | Should -Be 1
        $full.Verdict | Should -BeExactly 'Malicious'
        @($full.Sources).Source | Should -Contain 'MalwareBazaar'
    }

    # Production break caught: returning complementary cached sources despite an explicit SkipCascade.
    It '16. serves only the VirusTotal entry from a multi-source cache with SkipCascade' {
        $cachePath = Join-Path $TestDrive 'skip-multi-source/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'VirusTotal' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'HybridAnalysis' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'ThreatFox' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
        )
        $vtPath = "/api/v3/files/$($script:MaliciousHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Malicious'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    # Security invariant: missing enrichment cannot suppress or re-query decisive malicious evidence.
    It '17. serves available fresh Malicious evidence without requiring every third-stage source' {
        $cachePath = Join-Path $TestDrive 'partial-malicious/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'VirusTotal' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'MalwareBazaar' `
                -Verdict 'Unknown' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:MaliciousHash -Source 'HybridAnalysis' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
        )
        $vtPath = "/api/v3/files/$($script:MaliciousHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Malicious'
        @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis')
    }

    # Production break caught: requiring complementary cache entries when VirusTotal is already clean.
    It '18. serves a standalone Clean VirusTotal entry for a full query' {
        $cachePath = Join-Path $TestDrive 'complete-clean/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    # Production break caught: rejecting a complete two-stage non-malicious cache as incomplete.
    It '19. serves VirusTotal and MalwareBazaar when the cascade stops without a Malicious verdict' {
        $cachePath = Join-Path $TestDrive 'complete-two-stage/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:KnownHash -Source 'VirusTotal' `
                -Verdict 'Unknown' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:KnownHash -Source 'MalwareBazaar' `
                -Verdict 'Unknown' -QueryDate $script:ReferenceDate)
        )
        $vtPath = "/api/v3/files/$($script:KnownHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:KnownHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Unknown'
        @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
    }

    # Security regression: a reassuring provider result must never hide fresh malicious evidence
    # already present for the same file.
    It '20. makes fresh cached Malicious evidence dominate a fresh VirusTotal Clean result' {
        $cachePath = Join-Path $TestDrive 'mixed-fresh/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Malicious'
        @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
        @($result.Sources | Where-Object Verdict -eq 'Malicious').Source |
            Should -Be @('MalwareBazaar')
    }

    It '21. ignores expired cached Malicious evidence beside a fresh VirusTotal Clean result' {
        $cachePath = Join-Path $TestDrive 'mixed-expired-malicious/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate.AddDays(-91))
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    It '22. preserves fresh cached Malicious evidence when the VirusTotal entry is expired' {
        $cachePath = Join-Path $TestDrive 'expired-vt-fresh-malicious/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate.AddDays(-8))
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Malicious'
        @($result.Sources).Source | Should -Be @('MalwareBazaar')
    }

    It '23. keeps SkipCascade VirusTotal-only when complementary cached evidence is Malicious' {
        $cachePath = Join-Path $TestDrive 'mixed-skip-cascade/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    It '24. never lets cached Clean evidence promote an Unknown VirusTotal result' {
        $cachePath = Join-Path $TestDrive 'unknown-plus-clean/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:KnownHash -Source 'VirusTotal' `
                -Verdict 'Unknown' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:KnownHash -Source 'MalwareBazaar' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:KnownHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Unknown'
        @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
    }

    It '25. deduplicates fresh same-source Malicious evidence without falling back to live Clean' {
        $cachePath = Join-Path $TestDrive 'duplicate-malicious-source/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate.AddMinutes(-1))
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'MalwareBazaar' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate)
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Malicious'
        @($result.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
        @($result.Sources | Where-Object Source -eq 'MalwareBazaar').Count | Should -Be 1
    }

    # Security regression: SkipCascade must reduce contradictory VirusTotal cache entries before
    # deciding whether the cache is usable. A newer Clean result cannot hide fresh Malicious evidence.
    It '26. makes cached VirusTotal Malicious dominate duplicate Clean evidence with SkipCascade' {
        $cachePath = Join-Path $TestDrive 'duplicate-vt-skip-cascade/cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Malicious' -QueryDate $script:ReferenceDate.AddMinutes(-1))
            (ConvertTo-TestReputationCacheEntry -Hash $script:CleanHash -Source 'VirusTotal' `
                -Verdict 'Clean' -QueryDate $script:ReferenceDate)
        )
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $result.Verdict | Should -BeExactly 'Malicious'
        @($result.Sources).Source | Should -Be @('VirusTotal')
        @($result.Sources).Count | Should -Be 1
    }

    # Security regression: canonical SHA-256 evidence must remain explicitly bound to the original
    # SHA-1 lookup across a module reload. A loose cross-hash cache search is never acceptable.
    It '27. reuses complete canonical malicious evidence with provenance after a module reload' {
        $cachePath = Join-Path $TestDrive 'canonical-reload/reputation-cache.json'
        $vtPath = "/api/v3/files/$($script:MaliciousHash)"
        $canonicalSha256 = ('C' * 62) + '03'
        $queryReference = [datetime]::UtcNow
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null

        $first = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference
        @($first.Sources).Source | Should -Be @(
            'VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox')

        Initialize-ReputationCacheTestModule
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $second = Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference.AddMinutes(1)

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $second.Verdict | Should -BeExactly 'Malicious'
        @($second.Sources).Source | Should -Be @(
            'VirusTotal', 'MalwareBazaar', 'HybridAnalysis', 'ThreatFox')
        $threatFox = @($second.Sources | Where-Object Source -eq 'ThreatFox')
        $threatFox.Count | Should -Be 1
        $threatFox[0].HashUsed | Should -BeExactly $canonicalSha256
        $threatFox[0].HashSource | Should -BeExactly 'VirusTotal'
        (Get-ReputationRequestCount -Path $vtPath) | Should -BeGreaterThan 0
    }

    It '28. rejects a contradictory canonical cache relationship and queries normally' {
        $cachePath = Join-Path $TestDrive 'canonical-mismatch/reputation-cache.json'
        $wrongCanonicalSha256 = ('B' * 62) + '02'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            [pscustomobject][ordered]@{
                Version          = 2
                LookupHash       = $script:CleanHash
                CanonicalSha256  = $wrongCanonicalSha256
                Hash             = (('C' * 62) + '03')
                HashSource       = 'VirusTotal'
                Source           = 'ThreatFox'
                Verdict          = 'Malicious'
                QueryDate        = $script:ReferenceDate.ToString('o')
            }
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    It '29. never reuses a valid canonical cache group for an unrelated lookup hash' {
        $cachePath = Join-Path $TestDrive 'canonical-unrelated/reputation-cache.json'
        $queryReference = [datetime]::UtcNow
        Connect-HybridAnalysis -ApiKey $script:HaKey -BaseUri $script:Server.BaseUrl | Out-Null
        Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference | Out-Null
        Initialize-ReputationCacheTestModule
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference.AddMinutes(1)

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    It '30. rejects a ThreatFox canonical hash that conflicts with its VirusTotal binding' {
        $cachePath = Join-Path $TestDrive 'canonical-group-conflict/reputation-cache.json'
        $vtCanonicalSha256 = ('A' * 62) + '01'
        $tfCanonicalSha256 = ('C' * 62) + '03'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ([pscustomobject][ordered]@{
                    Version = 2; LookupHash = $script:CleanHash; CanonicalSha256 = $vtCanonicalSha256
                    Hash = $script:CleanHash; HashSource = 'EPM'; Source = 'VirusTotal'
                    Verdict = 'Unknown'; QueryDate = $script:ReferenceDate.ToString('o')
                })
            ([pscustomobject][ordered]@{
                    Version = 2; LookupHash = $script:CleanHash; CanonicalSha256 = $tfCanonicalSha256
                    Hash = $tfCanonicalSha256; HashSource = 'VirusTotal'; Source = 'ThreatFox'
                    Verdict = 'Malicious'; QueryDate = $script:ReferenceDate.ToString('o')
                })
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    It '31. rejects canonical evidence after its VirusTotal binding expires' {
        $cachePath = Join-Path $TestDrive 'canonical-expired-authority/reputation-cache.json'
        $canonicalSha256 = ('A' * 62) + '01'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            ([pscustomobject][ordered]@{
                    Version = 2; LookupHash = $script:CleanHash; CanonicalSha256 = $canonicalSha256
                    Hash = $script:CleanHash; HashSource = 'EPM'; Source = 'VirusTotal'
                    Verdict = 'Unknown'; QueryDate = $script:ReferenceDate.AddDays(-8).ToString('o')
                })
            ([pscustomobject][ordered]@{
                    Version = 2; LookupHash = $script:CleanHash; CanonicalSha256 = $canonicalSha256
                    Hash = $canonicalSha256; HashSource = 'VirusTotal'; Source = 'ThreatFox'
                    Verdict = 'Malicious'; QueryDate = $script:ReferenceDate.ToString('o')
                })
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
        @($result.Sources).Source | Should -Be @('VirusTotal')
    }

    It '32. rejects a string cache schema version instead of coercing it to an integer' {
        $cachePath = Join-Path $TestDrive 'canonical-string-version/reputation-cache.json'
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            [pscustomobject][ordered]@{
                Version          = '2'
                LookupHash       = $script:CleanHash
                CanonicalSha256  = (('A' * 62) + '01')
                Hash             = $script:CleanHash
                HashSource       = 'EPM'
                Source           = 'VirusTotal'
                Verdict          = 'Clean'
                QueryDate        = $script:ReferenceDate.ToString('o')
            }
        )
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $result = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade -UseCache `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate

        $after = Get-ReputationRequestCount -Path $vtPath
        ($after - $before) | Should -Be 1
        $result.Verdict | Should -BeExactly 'Clean'
    }

    # Production break caught: persisting the process session cache without the explicit UseCache switch.
    It '33. keeps the default session cache memory-only and clears it on disconnection' {
        $cachePath = Join-Path $TestDrive 'session-only/reputation-cache.json'
        $vtPath = "/api/v3/files/$($script:CleanHash)"
        $before = Get-ReputationRequestCount -Path $vtPath

        $first = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate
        $second = Get-FileReputation -Hash $script:CleanHash.ToLowerInvariant() -MinIntervalMs 0 `
            -SkipCascade -CachePath $cachePath -ReferenceDate $script:ReferenceDate
        $afterSessionHit = Get-ReputationRequestCount -Path $vtPath

        Initialize-ReputationCacheTestModule
        $third = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade `
            -CachePath $cachePath -ReferenceDate $script:ReferenceDate
        $afterReconnect = Get-ReputationRequestCount -Path $vtPath

        $first.Verdict | Should -BeExactly 'Clean'
        $second.Verdict | Should -BeExactly 'Clean'
        $third.Verdict | Should -BeExactly 'Clean'
        ($afterSessionHit - $before) | Should -Be 1
        ($afterReconnect - $before) | Should -Be 2
        (Test-Path -LiteralPath $cachePath) | Should -BeFalse
    }

    It '34. preserves unbound cached malicious evidence across a bound public refresh' {
        $cachePath = Join-Path $TestDrive 'public-null-to-bound/reputation-cache.json'
        $canonicalSha256 = ('A' * 62) + '01'
        $queryReference = [datetime]::UtcNow
        ConvertTo-TestReputationCacheFile -CachePath $cachePath -Entries @(
            [pscustomobject][ordered]@{
                Version = 2; LookupHash = $script:CleanHash; CanonicalSha256 = $null
                Hash = $script:CleanHash; HashSource = 'EPM'; Source = 'MalwareBazaar'
                Verdict = 'Malicious'; QueryDate = $queryReference.ToString('o')
            }
        )

        $refresh = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -SkipCascade `
            -UseCache -CachePath $cachePath -ReferenceDate $queryReference
        $refresh.Verdict | Should -BeExactly 'Clean'
        Initialize-ReputationCacheTestModule
        $before = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count

        $cached = Get-FileReputation -Hash $script:CleanHash -MinIntervalMs 0 -UseCache `
            -CachePath $cachePath -ReferenceDate $queryReference.AddMinutes(1)

        $after = @((Invoke-RestMethod -Uri $script:JournalUri).requests).Count
        ($after - $before) | Should -Be 0
        $cached.Verdict | Should -BeExactly 'Malicious'
        @($cached.Sources).Source | Should -Be @('VirusTotal', 'MalwareBazaar')
        $entries = @((Get-Content $cachePath -Raw) | ConvertFrom-Json)
        @($entries).CanonicalSha256 | Should -Be @($canonicalSha256, $canonicalSha256)
    }
}
