#Requires -Version 7.2

Set-StrictMode -Version 3.0

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:RedirectOrigin = Start-MockApiServer
    $script:TargetOrigin = Start-MockApiServer
    $script:TargetPath = '/echo-headers'
    $script:SyntheticHeaderValue = 'SYNTHETIC-REDIRECT-HEADER-SECRET'
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:RedirectOrigin
    Stop-MockApiServer -Server $script:TargetOrigin
}

Describe 'Transport does not transmit a secret from one origin to another' {
    It 'Blocks the redirect before the second origin receives x-apikey' {
        $targetUri = "$($script:TargetOrigin.BaseUrl)$($script:TargetPath)"
        $redirectUri = "$($script:RedirectOrigin.BaseUrl)/_test/redirect?target=$([uri]::EscapeDataString($targetUri))"
        $before = Get-MockApiServerHitCount -Server $script:TargetOrigin -Path $script:TargetPath

        $rendered = try {
            Invoke-EndpointOpsRequest -Uri $redirectUri `
                -Headers @{ 'x-apikey' = $script:SyntheticHeaderValue } -MaxAttempts 1 |
                ConvertTo-Json -Depth 5
        }
        catch { $_ | Out-String }

        $after = Get-MockApiServerHitCount -Server $script:TargetOrigin -Path $script:TargetPath

        ($after - $before) | Should -Be 0 -Because 'Another origin must never receive the authenticated request'
        $rendered | Should -Match 'HTTP redirection blocked' -Because 'The redirection must be reported without being followed'
        $rendered | Should -Not -Match [regex]::Escape($script:SyntheticHeaderValue)
    }
}
