BeforeAll {
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Test-OsBuildStatus.ps1')

    $script:Targets = @{
        '22631' = 4890   # Windows 11 23H2
        '19045' = 4046   # Windows 10 22H2
        '17763' = 6414   # Windows Server 2019
    }
}

Describe 'Test-OsBuildStatus' {
    It 'Recognizes an up-to-date build' {
        Test-OsBuildStatus -OsRevision '22631.4890' -SupportedBuilds $script:Targets | Should -Be 'UpToDate'
    }

    It 'Recognizes an advanced build as up to date' {
        Test-OsBuildStatus -OsRevision '22631.5011' -SupportedBuilds $script:Targets | Should -Be 'UpToDate'
    }

    It 'Recognizes a late revision on a supported branch' {
        Test-OsBuildStatus -OsRevision '22631.3007' -SupportedBuilds $script:Targets | Should -Be 'OutdatedRevision'
    }

    It 'Recognizes a branch that is no longer supported' {
        # 19044 is Windows 10 21H2: this is not a patch delay, it is an entire branch that no longer has any
# patches at all.
        Test-OsBuildStatus -OsRevision '19044.1288' -SupportedBuilds $script:Targets | Should -Be 'UnsupportedBranch'
    }

    It 'Compares revisions numerically rather than alphabetically' {
        # 999 < 4890 in number, but '999' > '4890' in text.
        Test-OsBuildStatus -OsRevision '22631.999' -SupportedBuilds $script:Targets | Should -Be 'OutdatedRevision'
        Test-OsBuildStatus -OsRevision '22631.10000' -SupportedBuilds $script:Targets | Should -Be 'UpToDate'
    }

    It 'Returns Unknown for a blank or malformed value without throwing' {
        foreach ($bad in @('', $null, 'not-a-build', '22631')) {
            { Test-OsBuildStatus -OsRevision $bad -SupportedBuilds $script:Targets } | Should -Not -Throw
            Test-OsBuildStatus -OsRevision $bad -SupportedBuilds $script:Targets | Should -Be 'Unknown'
        }
    }

    It 'Returns Unknown when no reference is provided' {
        # Without a reference point, we do not know: above all, we must not conclude that everything is
# fine.
        Test-OsBuildStatus -OsRevision '22631.4890' -SupportedBuilds @{} | Should -Be 'Unknown'
    }
}
