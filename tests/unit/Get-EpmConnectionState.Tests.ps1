BeforeAll {
    # StrictMode reproduces here the real conditions of the module: without it, the test would pass even
# with a naive implementation, and would prove nothing.
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-EpmConnectionState.ps1')
}

Describe 'Get-EpmConnectionState' {
    Context 'Without an open connection' {
        BeforeEach {
            $script:EpmConnection = $null
        }

        It 'Throws rather than returning $null' {
            { Get-EpmConnectionState } | Should -Throw
        }

        It 'Names Connect-EpmTenant in the message to identify the required action' {
            # A "missing property" three calls away would cost much more to diagnose than an explicit message.
            { Get-EpmConnectionState } | Should -Throw -ExpectedMessage '*Connect-EpmTenant*'
        }
    }

    Context 'With an active connection' {
        BeforeEach {
            $script:EpmConnection = [pscustomobject]@{
                DispatcherUri = 'https://login.epm.cyberark.com/login'
                ManagerUri    = 'https://eu123.epm.cyberark.com'
                Token         = ConvertTo-TestSecureString -PlainText 'MOCK-EPM-TOKEN'
                ConnectedAt   = [datetime]'2026-07-27T10:00:00Z'
            }
        }

        AfterEach {
            $script:EpmConnection = $null
        }

        It 'Does not throw' {
            { Get-EpmConnectionState } | Should -Not -Throw
        }

        It 'Keeps the dispatcher used for authentication' {
            (Get-EpmConnectionState).DispatcherUri | Should -Be 'https://login.epm.cyberark.com/login'
        }

        It 'Keeps the ManagerUri used by subsequent calls' {
            # This distinction is easy to miss: the two URLs differ and only the second
# is used for business calls.
            (Get-EpmConnectionState).ManagerUri | Should -Be 'https://eu123.epm.cyberark.com'
        }

        It 'Keeps the token in the form of a SecureString' {
            (Get-EpmConnectionState).Token | Should -BeOfType [securestring]
        }

        It 'Saves the login date' {
            (Get-EpmConnectionState).ConnectedAt | Should -Be ([datetime]'2026-07-27T10:00:00Z')
        }

        It 'Returns the status object itself, without a copy' {
            [object]::ReferenceEquals((Get-EpmConnectionState), $script:EpmConnection) | Should -BeTrue
        }
    }
}
