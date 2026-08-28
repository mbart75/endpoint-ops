BeforeAll {
    # StrictMode reproduces here the real conditions of the module: without it, the test would pass even
# with a naive implementation, and would prove nothing.
    Set-StrictMode -Version 3.0
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-PropertyOrDefault.ps1')
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-EpmNextCursor.ps1')
}

Describe 'Get-EpmNextCursor' {
    It 'Returns the cursor when it is present' {
        $page = [pscustomobject]@{ nextCursor = 'abc123'; events = @() }
        Get-EpmNextCursor -Page $page | Should -Be 'abc123'
    }

    It 'Returns $null for an empty string, as documented' {
        $page = [pscustomobject]@{ nextCursor = ''; events = @() }
        Get-EpmNextCursor -Page $page | Should -BeNullOrEmpty
    }

    It 'Returns $null for a null value, as shown in the documentation example' {
        $page = [pscustomobject]@{ nextCursor = $null; events = @() }
        Get-EpmNextCursor -Page $page | Should -BeNullOrEmpty
    }

    # The two "missing key" cases are separate: combined in a single It, the Should -Not -Throw would
# short-circuit the value assertion if the function raised, and the second assertion would never be
# evaluated.
    It 'Does not throw under StrictMode when the key is absent' {
        $page = [pscustomobject]@{ events = @() }
        { Get-EpmNextCursor -Page $page } | Should -Not -Throw
    }

    It 'Returns $null when the key is absent' {
        $page = [pscustomobject]@{ events = @() }
        Get-EpmNextCursor -Page $page | Should -BeNullOrEmpty
    }

    It 'Returns $null for a null page' {
        Get-EpmNextCursor -Page $null | Should -BeNullOrEmpty
    }

    It 'Does not confuse the start cursor with a next cursor' {
        # 'start' is an input value, never an output value. Returning it would loop the pagination to the
# first page.
        $page = [pscustomobject]@{ nextCursor = 'start'; events = @() }
        Get-EpmNextCursor -Page $page | Should -BeNullOrEmpty
    }
}
