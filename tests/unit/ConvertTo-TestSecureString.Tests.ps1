BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')
}

Describe 'ConvertTo-TestSecureString' {
    It 'Returns a SecureString correctly' {
        $secure = ConvertTo-TestSecureString -PlainText 'ABC123'
        $secure | Should -BeOfType [System.Security.SecureString]
    }

    It 'Returns exactly the supplied text' {
        $secure = ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN'
        (ConvertFrom-SecureString -SecureString $secure -AsPlainText) | Should -Be 'MOCK-S1-TOKEN'
    }

    It 'Produces a SecureString for read-only access' {
        $secure = ConvertTo-TestSecureString -PlainText 'ABC'
        $secure.IsReadOnly() | Should -BeTrue
    }
}
