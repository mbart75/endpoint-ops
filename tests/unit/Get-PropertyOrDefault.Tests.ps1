BeforeAll {
    # StrictMode reproduces here the real conditions of the module: without it, the test would pass even
# with a naive implementation, and would prove nothing.
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-PropertyOrDefault.ps1')
}

Describe 'Get-PropertyOrDefault' {
    It 'Returns the value when the property exists' {
        $obj = [pscustomobject]@{ computerName = 'MOCK-WKS-01' }
        Get-PropertyOrDefault -InputObject $obj -Name 'computerName' | Should -Be 'MOCK-WKS-01'
    }

    It 'Returns $null without throwing when the input object is absent' {
        $obj = [pscustomobject]@{ computerName = 'MOCK-WKS-01' }
        { Get-PropertyOrDefault -InputObject $obj -Name 'agentVersion' } | Should -Not -Throw
        Get-PropertyOrDefault -InputObject $obj -Name 'agentVersion' | Should -BeNullOrEmpty
    }

    It 'Returns the default value provided when the property is absent' {
        $obj = [pscustomobject]@{ computerName = 'MOCK-WKS-01' }
        Get-PropertyOrDefault -InputObject $obj -Name 'isDecommissioned' -Default $false | Should -BeFalse
    }

    It 'Tolerates a null input object' {
        { Get-PropertyOrDefault -InputObject $null -Name 'irrelevant' } | Should -Not -Throw
        Get-PropertyOrDefault -InputObject $null -Name 'irrelevant' -Default 'Fallback' | Should -Be 'Fallback'
    }

    It 'Distinguishes an absent property from a present property whose value is $null' {
        $obj = [pscustomobject]@{ lastActiveDate = $null }
        # Present but null: we return $null, not the default value.
        Get-PropertyOrDefault -InputObject $obj -Name 'lastActiveDate' -Default 'NEVER' | Should -BeNullOrEmpty
    }

    It 'Reads a property from ConvertFrom-Json output' {
        $obj = '{"data":[{"id":"1001"}]}' | ConvertFrom-Json
        $first = (Get-PropertyOrDefault -InputObject $obj -Name 'data')[0]
        Get-PropertyOrDefault -InputObject $first -Name 'id' | Should -Be '1001'
        Get-PropertyOrDefault -InputObject $first -Name 'absent' -Default 'void' | Should -Be 'void'
    }
}
