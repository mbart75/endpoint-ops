BeforeAll {
    Set-StrictMode -Version 3.0
    $functionPath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Test-ObservationWindow.ps1'
    if (Test-Path -LiteralPath $functionPath) {
        . $functionPath
    }
}

Describe 'Test-ObservationWindow' {
    It 'Determines whether a window can establish an absence of use' -TestCases @(
        @{ WindowDays = 30; RetentionDays = 60; Expected = 'Usable' }
        @{ WindowDays = 59; RetentionDays = 60; Expected = 'Usable' }
        @{ WindowDays = 60; RetentionDays = 60; Expected = 'Indeterminate' }
        @{ WindowDays = 90; RetentionDays = 60; Expected = 'Indeterminate' }
        @{ WindowDays = 30; RetentionDays = 30; Expected = 'Indeterminate' }
    ) {
        param($WindowDays, $RetentionDays, $Expected)

        Test-ObservationWindow -WindowDays $WindowDays -RetentionDays $RetentionDays | Should -Be $Expected
    }

    It 'Rejects a null window' {
        { Test-ObservationWindow -WindowDays 0 -RetentionDays 60 } | Should -Throw
    }

    It 'Rejects a negative window' {
        { Test-ObservationWindow -WindowDays -1 -RetentionDays 60 } | Should -Throw
    }

    It 'Rejects a zero retention' {
        { Test-ObservationWindow -WindowDays 30 -RetentionDays 0 } | Should -Throw
    }

    It 'Rejects a negative retention' {
        { Test-ObservationWindow -WindowDays 30 -RetentionDays -1 } | Should -Throw
    }
}
