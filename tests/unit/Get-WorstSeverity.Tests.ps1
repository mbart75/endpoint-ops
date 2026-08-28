BeforeAll {
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-PropertyOrDefault.ps1')
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-WorstSeverity.ps1')
}

Describe 'Get-WorstSeverity' {
    It 'Returns None on an empty list' {
        Get-WorstSeverity -Findings @() | Should -Be 'None'
    }

    It 'Returns the unique severity when there is only one' {
        $f = @([pscustomobject]@{ Severity = 'Medium'; Reason = 'irrelevant' })
        Get-WorstSeverity -Findings $f | Should -Be 'Medium'
    }

    It 'Returns the worst severity, regardless of the order' {
        $f = @(
            [pscustomobject]@{ Severity = 'Low';      Reason = 'a' }
            [pscustomobject]@{ Severity = 'Critical'; Reason = 'b' }
            [pscustomobject]@{ Severity = 'Medium';   Reason = 'c' }
        )
        Get-WorstSeverity -Findings $f | Should -Be 'Critical'

        $reversed = @(
            [pscustomobject]@{ Severity = 'Critical'; Reason = 'b' }
            [pscustomobject]@{ Severity = 'Low';      Reason = 'a' }
        )
        Get-WorstSeverity -Findings $reversed | Should -Be 'Critical'
    }

    It 'Orders all five severity levels correctly' {
        $pairs = @(
            @{ Basse = 'None';   Haute = 'Low' }
            @{ Basse = 'Low';    Haute = 'Medium' }
            @{ Basse = 'Medium'; Haute = 'High' }
            @{ Basse = 'High';   Haute = 'Critical' }
        )
        foreach ($p in $pairs) {
            $f = @(
                [pscustomobject]@{ Severity = $p.Basse; Reason = 'x' }
                [pscustomobject]@{ Severity = $p.Haute; Reason = 'y' }
            )
            Get-WorstSeverity -Findings $f | Should -Be $p.Haute -Because "$($p.Haute) must take precedence over $($p.Basse)"
        }
    }

    It 'Ignores an unknown severity rather than raising it' {
        $f = @(
            [pscustomobject]@{ Severity = 'Nonexistent'; Reason = 'a' }
            [pscustomobject]@{ Severity = 'Low';         Reason = 'b' }
        )
        Get-WorstSeverity -Findings $f | Should -Be 'Low'
    }

    It 'Tolerates $null as input' {
        { Get-WorstSeverity -Findings $null } | Should -Not -Throw
        Get-WorstSeverity -Findings $null | Should -Be 'None'
    }
}
