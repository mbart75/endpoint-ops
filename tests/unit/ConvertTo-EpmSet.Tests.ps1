BeforeAll {
    # StrictMode reproduces here the real conditions of the module: without it, the test would pass even
# with a naive implementation, and would prove nothing.
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-PropertyOrDefault.ps1')
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'ConvertTo-EpmSet.ps1')
}

Describe 'ConvertTo-EpmSet' {
    Context 'Shape used by the documentation JSON example' {
        BeforeEach {
            $script:Raw = [pscustomobject]@{
                Id          = 'set-001'
                Name        = 'Workstations'
                Description = 'Office furniture'
                IsNPVDI     = $true
            }
        }

        It 'Maps Id' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Id | Should -Be 'set-001'
        }

        It 'Maps Name' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Name | Should -Be 'Workstations'
        }

        It 'Maps Description' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Description | Should -Be 'Office furniture'
        }

        It 'Maps IsNPVDI' {
            (ConvertTo-EpmSet -InputObject $script:Raw).IsNPVDI | Should -BeTrue
        }
    }

    Context 'Shape used by the documentation table' {
        BeforeEach {
            $script:Raw = [pscustomobject]@{
                SetId          = 'set-002'
                SetName        = 'Servers'
                SetDescription = 'Server fleet'
            }
        }

        # Each field has its own It block: if combined, the first failing assertion would mask the remaining
        # assertions and would not identify which mapping is broken.
        It 'Maps SetId to Id' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Id | Should -Be 'set-002'
        }

        It 'Maps SetName to Name' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Name | Should -Be 'Servers'
        }

        It 'Maps SetDescription to Description' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Description | Should -Be 'Server fleet'
        }
    }

    Context 'Mixed shape containing both conventions' {
        BeforeEach {
            $script:Raw = [pscustomobject]@{
                Id      = 'set-003'
                SetName = 'Mixed'
            }
        }

        It 'Maps the example-shape ID' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Id | Should -Be 'set-003'
        }

        It 'Maps the table-shape SetName' {
            (ConvertTo-EpmSet -InputObject $script:Raw).Name | Should -Be 'Mixed'
        }
    }

    Context 'Missing fields' {
        It 'Returns an empty string and not $null when the response has no description' {
            $raw = [pscustomobject]@{ Id = 'set-004'; Name = 'Without description' }
            $result = ConvertTo-EpmSet -InputObject $raw
            # The consumer must never have to distinguish between absent and empty.
            $result.Description | Should -Be ''
        }

        It 'Returns a description of type string, not $null' {
            $raw = [pscustomobject]@{ Id = 'set-004'; Name = 'Without description' }
            (ConvertTo-EpmSet -InputObject $raw).Description | Should -BeOfType [string]
        }

        It 'Sets IsNPVDI to false when the field is absent' {
            $raw = [pscustomobject]@{ Id = 'set-004'; Name = 'Without description' }
            (ConvertTo-EpmSet -InputObject $raw).IsNPVDI | Should -BeFalse
        }

        It 'Does not throw under StrictMode on an object without any known fields' {
            $raw = [pscustomobject]@{ AutreChose = 1 }
            { ConvertTo-EpmSet -InputObject $raw } | Should -Not -Throw
        }
    }

    Context 'Null input' {
        It 'Does not throw' {
            { ConvertTo-EpmSet -InputObject $null } | Should -Not -Throw
        }

        It 'Returns $null' {
            ConvertTo-EpmSet -InputObject $null | Should -BeNullOrEmpty
        }
    }

    It 'Uses the EndpointOps.Epm.Set PSTypeName' {
        $raw = [pscustomobject]@{ Id = 'set-005'; Name = 'Type' }
        (ConvertTo-EpmSet -InputObject $raw).PSObject.TypeNames | Should -Contain 'EndpointOps.Epm.Set'
    }
}
