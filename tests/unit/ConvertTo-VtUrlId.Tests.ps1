BeforeAll {
    Set-StrictMode -Version 3.0
    $functionPath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'ConvertTo-VtUrlId.ps1'
    if (Test-Path -LiteralPath $functionPath) {
        . $functionPath
    }
}

Describe 'ConvertTo-VtUrlId' {
    It 'Encodes a reference URL with the expected fixed value' {
        ConvertTo-VtUrlId -Url 'https://example.com/a' | Should -BeExactly 'aHR0cHM6Ly9leGFtcGxlLmNvbS9h'
    }

    It 'Replaces the plus character from base64 with a dash' {
        $summary = ConvertTo-VtUrlId -Url 'https://example.com/~x'

        $summary | Should -Match '-'
        $summary | Should -Not -Match '\+'
    }

    It 'Replaces base64 slashes with an underscore' {
        $summary = ConvertTo-VtUrlId -Url 'https://example.com/?aa'

        $summary | Should -Match '_'
        $summary | Should -Not -Match '/'
    }

    It 'Removes all padding characters' {
        ConvertTo-VtUrlId -Url 'https://example.com/~x' | Should -Not -Match '='
        ConvertTo-VtUrlId -Url 'https://example.com/?aa' | Should -Not -Match '='
    }

    It 'Throws for an empty URL' {
        { ConvertTo-VtUrlId -Url '' } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException]) -ErrorId 'ParameterArgumentValidationError,ConvertTo-VtUrlId'
    }

    It 'Throws for a null URL' {
        { ConvertTo-VtUrlId -Url $null } | Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException]) -ErrorId 'ParameterArgumentValidationError,ConvertTo-VtUrlId'
    }
}
