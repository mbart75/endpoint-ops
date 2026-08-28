BeforeAll {
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-PropertyOrDefault.ps1')
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Measure-ExclusionBreadth.ps1')

    function Get-TestExclusion {
        param($Type = 'path', $Value = 'C:\App\', $ScopeLevel = 'group', $Description = 'ticket INC-1')
        [pscustomobject]@{
            Id = '9000'; Type = $Type; Value = $Value; OsType = 'windows'; Mode = 'suppress'
            ScopeLevel = $ScopeLevel; ScopeName = 'Workstations'; Description = $Description
            CreatedBy = 'test@mock.invalid'; CreatedAt = '2026-01-01T00:00:00Z'
            UpdatedBy = 'test@mock.invalid'; UpdatedAt = '2026-01-01T00:00:00Z'
        }
    }
}

Describe 'Measure-ExclusionBreadth' {
    It 'Reports no issue for a justified hash exclusion with group scope' {
        $e = Get-TestExclusion -Type 'white_hash' -Value 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
        @(Measure-ExclusionBreadth -Exclusion $e).Count | Should -Be 0
    }

    It 'Classifies a disk root as Critical' {
        $patterns = @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Value 'C:\'))
        ($patterns | Where-Object Severity -eq 'Critical') | Should -Not -BeNullOrEmpty
        ($patterns | Where-Object { $_.Reason -match 'Disk root' }) | Should -Not -BeNullOrEmpty
    }

    It 'Accepts the root with or without a final slash' {
        @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Value 'D:')).Severity  | Should -Contain 'Critical'
        @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Value 'D:\')).Severity | Should -Contain 'Critical'
    }

    It 'Classifies a high-level wildcard as High' {
        $patterns = @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Value 'C:\Users\*\AppData\'))
        ($patterns | Where-Object { $_.Reason -match 'High-level wildcard' }).Severity | Should -Be 'High'
    }

    It 'Classifies a deep wildcard as Medium, less serious than a high-level wildcard' {
        $patterns = @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Value 'C:\Program Files\App\logs\*.tmp'))
        ($patterns | Where-Object { $_.Reason -match 'Wildcard' }).Severity | Should -Be 'Medium'
    }

    It 'Reports a path exclusion as Low severity' {
        $patterns = @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Value 'C:\App\'))
        ($patterns | Where-Object { $_.Reason -match 'hash' }).Severity | Should -Be 'Low'
    }

    It 'Reports site-wide scope' {
        $patterns = @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -ScopeLevel 'site'))
        ($patterns | Where-Object { $_.Reason -match 'Site scope' }).Severity | Should -Be 'High'
    }

    It 'Indicates an empty description' {
        foreach ($empty in @('', $null)) {
            $patterns = @(Measure-ExclusionBreadth -Exclusion (Get-TestExclusion -Description $empty))
            ($patterns | Where-Object { $_.Reason -match 'justification' }).Severity | Should -Be 'Medium'
        }
    }

    It 'Accumulates the causes when several problems combine' {
        $e = Get-TestExclusion -Value 'C:\' -ScopeLevel 'site' -Description ''
        $patterns = @(Measure-ExclusionBreadth -Exclusion $e)
        $patterns.Count | Should -BeGreaterOrEqual 4
    }

    It 'Returns a usable array even when empty, without throwing' {
        # Under StrictMode, an empty array that flattens to $null would cause any caller that reads .Count
# to throw an error. This is the trap that cost an iteration.
        $e = Get-TestExclusion -Type 'white_hash' -Value 'abc123'
        { @(Measure-ExclusionBreadth -Exclusion $e).Count } | Should -Not -Throw
    }
}
