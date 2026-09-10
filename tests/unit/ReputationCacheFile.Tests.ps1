#Requires -Version 7.2
Set-StrictMode -Version 3.0

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../src/EndpointOps/EndpointOps.psd1'
    Import-Module $script:ModulePath -Force
    function Wait-CacheSignal {
        param([string]$Path)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not [IO.File]::Exists($Path) -and $timer.ElapsedMilliseconds -lt 5000) {
            Start-Sleep -Milliseconds 20
        }
        [IO.File]::Exists($Path) | Should -BeTrue -Because "worker must signal $Path within five seconds"
    }
    $script:LockWorker = {
        param($ModulePath, $Path, $EnteredPath, $ReleasePath, $ReadyPath)
        $ErrorActionPreference = 'Stop'
        Import-Module $ModulePath -Force
        if ($ReadyPath) { [IO.File]::WriteAllText($ReadyPath, '') }
        & (Get-Module EndpointOps) {
            param($Path, $EnteredPath, $ReleasePath)
            $enteredSignal = $EnteredPath
            $releaseSignal = $ReleasePath
            Invoke-WithReputationCacheLock -CachePath $Path -ScriptBlock {
                [IO.File]::WriteAllText($enteredSignal, '')
                if ($releaseSignal) {
                    $timer = [Diagnostics.Stopwatch]::StartNew()
                    while (-not [IO.File]::Exists($releaseSignal)) {
                        if ($timer.ElapsedMilliseconds -ge 5000) { throw 'Release signal timed out' }
                        Start-Sleep -Milliseconds 20
                    }
                }
            }
        } $Path $EnteredPath $ReleasePath
    }
}

Describe 'Persistent cache atomic file replacement' {
    It 'preserves the live file and removes its temporary file when replacement fails' {
        $cachePath = Join-Path $TestDrive 'interrupted.json'
        $originalContent = '[{"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Source":"VirusTotal","Verdict":"Malicious","QueryDate":"2026-09-01T00:00:00Z"}]'
        [IO.File]::WriteAllText($cachePath, $originalContent)
        Mock Move-ReputationCacheFile -ModuleName EndpointOps { throw 'injected move failure' }
        { & (Get-Module EndpointOps) {
            param($Path)
            Write-ReputationCacheFile -CachePath $Path -Entries @([pscustomobject]@{ Value = 'replacement' })
        } $cachePath } | Should -Throw '*injected move failure*'
        (Get-Content -LiteralPath $cachePath -Raw) | Should -BeExactly $originalContent
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp.*').Count | Should -Be 0
    }

    It 'replaces complete JSON using UTF-8 without a byte order mark' {
        $cachePath = Join-Path $TestDrive 'success.json'
        & (Get-Module EndpointOps) {
            param($Path)
            Write-ReputationCacheFile -CachePath $Path -Entries @([pscustomobject]@{ Value = 'replacement' })
        } $cachePath
        @((Get-Content -LiteralPath $cachePath -Raw) | ConvertFrom-Json)[0].Value | Should -Be 'replacement'
        $bytes = [IO.File]::ReadAllBytes($cachePath)
        $bytes[0] | Should -Be 91
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp.*').Count | Should -Be 0
    }

    It 'creates the content-bearing temporary file with owner-only Unix permissions' -Skip:$IsWindows {
        $cachePath = Join-Path $TestDrive 'private-temporary.json'
        [IO.File]::WriteAllText($cachePath, '[]')
        [IO.File]::SetUnixFileMode($cachePath,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)

        Mock Move-ReputationCacheFile -ModuleName EndpointOps {
            $mode = [IO.File]::GetUnixFileMode($SourcePath)
            $publicBits = [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupWrite -bor `
                [IO.UnixFileMode]::GroupExecute -bor [IO.UnixFileMode]::OtherRead -bor `
                [IO.UnixFileMode]::OtherWrite -bor [IO.UnixFileMode]::OtherExecute
            ($mode -band $publicBits) | Should -Be ([IO.UnixFileMode]::None)
            [IO.File]::Move($SourcePath, $DestinationPath, $true)
        }

        & (Get-Module EndpointOps) {
            param($Path)
            Write-ReputationCacheFile -CachePath $Path -Entries @([pscustomobject]@{ Value = 'private' })
        } $cachePath

        [IO.File]::GetUnixFileMode($cachePath) | Should -Be (
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
    }

    It 'creates a new Unix cache with owner-only permissions' -Skip:$IsWindows {
        $cachePath = Join-Path $TestDrive 'new-private-cache.json'

        & (Get-Module EndpointOps) {
            param($Path)
            Write-ReputationCacheFile -CachePath $Path -Entries @([pscustomobject]@{ Value = 'private' })
        } $cachePath

        [IO.File]::GetUnixFileMode($cachePath) | Should -Be (
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
    }

    It 'preserves an existing Windows cache ACL during atomic replacement' -Skip:(-not $IsWindows) {
        $cachePath = Join-Path $TestDrive 'preserved-acl.json'
        [IO.File]::WriteAllText($cachePath, '[]')
        $before = (Get-Acl -LiteralPath $cachePath).Sddl

        & (Get-Module EndpointOps) {
            param($Path)
            Write-ReputationCacheFile -CachePath $Path -Entries @([pscustomobject]@{ Value = 'private' })
        } $cachePath

        (Get-Acl -LiteralPath $cachePath).Sddl | Should -BeExactly $before
    }
}

Describe 'Strict cache file recognition' {
    It 'recognizes an absent file without creating anything' {
        $path = Join-Path $TestDrive 'absent/cache.json'
        $result = & (Get-Module EndpointOps) { param($Path) Test-ReputationCacheFile -CachePath $Path } $path
        $result.Exists | Should -BeFalse
        $result.IsValid | Should -BeTrue
        @($result.Entries).Count | Should -Be 0
        (Test-Path (Split-Path $path -Parent)) | Should -BeFalse
    }

    It 'recognizes <Kind> cache envelopes' -ForEach @(
        @{ Kind = 'empty'; Json = '[]'; Count = 0 }
        @{ Kind = 'legacy'; Json = '[{"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Source":"VirusTotal","Verdict":"Clean","QueryDate":"2026-01-01T00:00:00Z"}]'; Count = 1 }
        @{ Kind = 'version two'; Json = '[{"Version":2,"LookupHash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","CanonicalSha256":null,"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","HashSource":"EPM","Source":"VirusTotal","Verdict":"Unknown","QueryDate":"2026-01-01T00:00:00Z"}]'; Count = 1 }
    ) {
        $path = Join-Path $TestDrive 'recognize.json'
        [IO.File]::WriteAllText($path, $Json)
        $result = & (Get-Module EndpointOps) { param($Path) Test-ReputationCacheFile -CachePath $Path } $path
        $result.Exists | Should -BeTrue
        $result.IsValid | Should -BeTrue
        @($result.Entries).Count | Should -Be $Count
    }

    It 'rejects <Kind> without returning partial entries' -ForEach @(
        @{ Kind = 'object root'; Json = '{}' }
        @{ Kind = 'corrupt array'; Json = '[broken' }
        @{ Kind = 'null element'; Json = '[null]' }
        @{ Kind = 'nested array'; Json = '[[]]' }
        @{ Kind = 'unrelated object'; Json = '[{"project":"unrelated"}]' }
        @{ Kind = 'extra property'; Json = '[{"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Source":"VirusTotal","Verdict":"Clean","QueryDate":"2026-01-01","Other":0}]' }
        @{ Kind = 'bad hash'; Json = '[{"Hash":"bad","Source":"VirusTotal","Verdict":"Clean","QueryDate":"2026-01-01"}]' }
        @{ Kind = 'bad source'; Json = '[{"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Source":"Other","Verdict":"Clean","QueryDate":"2026-01-01"}]' }
        @{ Kind = 'unavailable verdict'; Json = '[{"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Source":"VirusTotal","Verdict":"Unavailable","QueryDate":"2026-01-01"}]' }
        @{ Kind = 'bad date'; Json = '[{"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Source":"VirusTotal","Verdict":"Clean","QueryDate":"bad"}]' }
        @{ Kind = 'string version'; Json = '[{"Version":"2","LookupHash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","CanonicalSha256":null,"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","HashSource":"EPM","Source":"VirusTotal","Verdict":"Unknown","QueryDate":"2026-01-01"}]' }
        @{ Kind = 'unbound ThreatFox'; Json = '[{"Version":2,"LookupHash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","CanonicalSha256":null,"Hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","HashSource":"EPM","Source":"ThreatFox","Verdict":"Unknown","QueryDate":"2026-01-01"}]' }
    ) {
        $path = Join-Path $TestDrive 'invalid.json'
        [IO.File]::WriteAllText($path, $Json)
        $result = & (Get-Module EndpointOps) { param($Path) Test-ReputationCacheFile -CachePath $Path } $path
        $result.Exists | Should -BeTrue
        $result.IsValid | Should -BeFalse
        @($result.Entries).Count | Should -Be 0
        (Get-Content $path -Raw) | Should -BeExactly $Json
    }
}

Describe 'Persistent cache cross-process lock' {
    It 'serializes <Kind> while allowing independent cache paths' -ForEach @(
        @{ Kind = 'same path'; Independent = $false; Alias = $false }
        @{ Kind = 'dot-dot alias'; Independent = $false; Alias = $true }
        @{ Kind = 'different paths'; Independent = $true; Alias = $false }
    ) {
        $caseDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item $caseDirectory -ItemType Directory | Out-Null
        $cache = Join-Path $caseDirectory 'cache.json'
        $other = if ($Independent) { Join-Path $caseDirectory 'other.json' } else { $cache }
        if ($Alias) {
            New-Item (Join-Path $caseDirectory 'child') -ItemType Directory -Force | Out-Null
            $other = Join-Path $caseDirectory 'child/../cache.json'
        }
        $a = Join-Path $caseDirectory 'entered-a'
        $b = Join-Path $caseDirectory 'entered-b'
        $release = Join-Path $caseDirectory 'release-a'
        $ready = Join-Path $caseDirectory 'ready-b'
        $jobs = @()
        try {
            $jobs += Start-Job -ScriptBlock $script:LockWorker -ArgumentList $script:ModulePath, $cache, $a, $release, $null
            Wait-CacheSignal $a
            $jobs += Start-Job -ScriptBlock $script:LockWorker -ArgumentList $script:ModulePath, $other, $b, $null, $ready
            Wait-CacheSignal $ready
            if ($Independent) { Wait-CacheSignal $b }
            else {
                Start-Sleep -Milliseconds 250
                [IO.File]::Exists($b) | Should -BeFalse
            }
            [IO.File]::WriteAllText($release, '')
            $jobs | Wait-Job -Timeout 5 | Out-Null
            $jobs.State | Should -Be @('Completed', 'Completed')
            $jobs | Receive-Job -ErrorAction Stop
            Wait-CacheSignal $b
        }
        finally { $jobs | Stop-Job; $jobs | Remove-Job -Force }
    }

    It 'exposes a bounded lock helper' {
        & (Get-Module EndpointOps) {
            Invoke-WithReputationCacheLock -CachePath (Join-Path $TestDrive 'bound.json') -ScriptBlock { 'entered' }
        } | Should -Be 'entered'
    }
}
