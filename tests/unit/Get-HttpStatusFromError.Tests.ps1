#Requires -Version 7.6

Set-StrictMode -Version 3.0

BeforeAll {
    $functionPath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'Get-HttpStatusFromError.ps1'
    . $functionPath
}

Describe 'Get-HttpStatusFromError' {
    It 'Uses native status <Status>, not the misleading message' -ForEach @(
        @{ Status = 400 }; @{ Status = 401 }; @{ Status = 404 }; @{ Status = 429 }; @{ Status = 500 }
    ) {
        $errorException = [System.Net.Http.HttpRequestException]::new(
            'Misleading text: returned 503 on /401/', $null, [System.Net.HttpStatusCode]$Status)
        Get-HttpStatusFromError -Exception $errorException | Should -Be $Status
    }

    It 'Unwraps a generic exception to the first native HTTP exception' {
        $httpError = [System.Net.Http.HttpRequestException]::new('No status in text', $null, [System.Net.HttpStatusCode]::NotFound)
        $wrapper = [System.Exception]::new('returned 500', $httpError)
        Get-HttpStatusFromError -Exception $wrapper | Should -Be 404
    }

    It 'Keeps the outer native status rather than a conflicting inner status' {
        $inner = [System.Net.Http.HttpRequestException]::new('inner', $null, [System.Net.HttpStatusCode]::NotFound)
        $outer = [System.Net.Http.HttpRequestException]::new('outer', $inner, [System.Net.HttpStatusCode]::InternalServerError)
        Get-HttpStatusFromError -Exception $outer | Should -Be 500
    }

    It 'Does not infer a status from text, null input or a null native status' {
        $inner = [System.Net.Http.HttpRequestException]::new('inner', $null, [System.Net.HttpStatusCode]::NotFound)
        $outer = [System.Net.Http.HttpRequestException]::new('returned 401', $inner, $null)
        Get-HttpStatusFromError -Exception $outer | Should -BeNullOrEmpty
        Get-HttpStatusFromError -Exception ([System.Exception]::new('returned 404')) | Should -BeNullOrEmpty
        Get-HttpStatusFromError -Exception $null | Should -BeNullOrEmpty
    }
}
