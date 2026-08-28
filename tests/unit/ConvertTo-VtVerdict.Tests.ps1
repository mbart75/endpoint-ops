BeforeAll {
    Set-StrictMode -Version 3.0
    $functionPath = Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'Private' 'ConvertTo-VtVerdict.ps1'
    if (Test-Path -LiteralPath $functionPath) {
        . $functionPath
    }
}

Describe 'ConvertTo-VtVerdict' {
    It 'Returns Malicious when at least two engines report the file' {
        ConvertTo-VtVerdict -Statistics ([pscustomobject]@{ malicious = 8; harmless = 40 }) | Should -Be 'Malicious'
    }

    It 'Returns Clean when only one engine flags the file' {
        ConvertTo-VtVerdict -Statistics ([pscustomobject]@{ malicious = 1; harmless = 68 }) | Should -Be 'Clean'
    }

    It 'Returns Clean when no engine flags an analyzed file' {
        ConvertTo-VtVerdict -Statistics ([pscustomobject]@{ malicious = 0; harmless = 60 }) | Should -Be 'Clean'
    }

    It 'Returns Unknown when the file has never been submitted' {
        ConvertTo-VtVerdict -Statistics $null | Should -Be 'Unknown'
    }

    It 'Returns Unknown when all statistics are zero' {
        ConvertTo-VtVerdict -Statistics ([pscustomobject]@{ malicious = 0; harmless = 0; suspicious = 0; undetected = 0 }) | Should -Be 'Unknown'
    }

    It 'Returns Unknown without throwing when statistics are absent' {
        $statistics = [pscustomobject]@{}
        { ConvertTo-VtVerdict -Statistics $statistics } | Should -Not -Throw
        ConvertTo-VtVerdict -Statistics $statistics | Should -Be 'Unknown'
    }

    It 'Uses the provided MinimumDetection threshold' {
        ConvertTo-VtVerdict -Statistics ([pscustomobject]@{ malicious = 1; harmless = 68 }) -MinimumDetection 1 | Should -Be 'Malicious'
    }
}
