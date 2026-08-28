BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:ApiKey = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
    $script:KnownPath = "/api/v3/files/$(('A' * 38) + '01')"
    $script:LogUri = "$($script:Server.BaseUrl)/_test/reputation"
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'The VirusTotal state does not disclose the key' {

    AfterEach { Disconnect-VirusTotal }

    It 'Does not show the key value anywhere in the serialized state' {
        Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl | Out-Null

        $state = InModuleScope EndpointOps { Get-VtConnectionState | ConvertTo-Json -Depth 5 }

        $state | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Retains non-empty state so the disclosure check is meaningful' {
        Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl | Out-Null

        $state = InModuleScope EndpointOps { Get-VtConnectionState | ConvertTo-Json -Depth 5 }

        $state | Should -Match 'BaseUri'
    }
}

Describe 'A rejected VirusTotal connection does not disclose the key' {

    AfterEach { Disconnect-VirusTotal }

    It 'Does not show the key in any part of the ErrorRecord' {
        $rendered = try {
            Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri 'http://example.invalid' | Out-Null
            ''
        }
        catch { $_ | Out-String }

        $rendered | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Produces a connection error to inspect' {
        $rendered = try {
            Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri 'http://example.invalid' | Out-Null
            ''
        }
        catch { $_ | Out-String }

        $rendered | Should -Match 'BaseUri must use HTTPS'
    }
}

Describe 'The VirusTotal verbose stream does not disclose the key' {

    AfterEach { Disconnect-VirusTotal }

    It 'Does not show the key in any verbose message of a real request' {
        Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl | Out-Null
        $before = @((Invoke-RestMethod -Uri $script:LogUri).requests).Count

        $verboseOutput = InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 -Verbose 4>&1 | Out-String
        }

        $after = @((Invoke-RestMethod -Uri $script:LogUri).requests).Count

        ($after - $before) | Should -Be 1
        $verboseOutput | Should -Match 'headers: x-apikey'
        $verboseOutput | Should -Not -Match 'MOCK-VT-KEY'
    }
}

Describe 'The VirusTotal debugging flow does not disclose the key' {

    AfterEach { Disconnect-VirusTotal }

    It 'Does not display the key in any debugging object or message' {
        $debugOutput = Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl -Debug 5>&1 | Out-String

        $debugOutput | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Produces an output to inspect under -Debug' {
        $debugOutput = Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl -Debug 5>&1 | Out-String

        $debugOutput | Should -Match 'BaseUri'
    }
}

Describe 'The VirusTotal request log does not expose secrets' {

    AfterEach { Disconnect-VirusTotal }

    It 'Does not expose any value in the log' {
        Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl | Out-Null
        InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 | Out-Null
        }

        $log = Invoke-RestMethod -Uri $script:LogUri
        ($log | ConvertTo-Json -Depth 10) | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Logs a VirusTotal query and authExact remains a boolean' {
        Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl | Out-Null
        $before = @((Invoke-RestMethod -Uri $script:LogUri).requests).Count
        InModuleScope EndpointOps -Parameters @{ RequestPath = $script:KnownPath } {
            param($RequestPath)
            Invoke-VtRequest -Path $RequestPath -MinIntervalMs 0 | Out-Null
        }

        $inputs = @((Invoke-RestMethod -Uri $script:LogUri).requests)
        $after = $inputs.Count

        ($after - $before) | Should -Be 1
        $newEntry = $inputs[$before]
        $newEntry.path | Should -Be $script:KnownPath
        $newEntry.authExact | Should -BeOfType [bool]
        ($newEntry | ConvertTo-Json -Depth 10) | Should -Not -Match 'MOCK-VT-KEY'
    }
}

Describe 'No hardcoded VirusTotal key in the repository' {

    BeforeAll {
        $script:VtKeyPattern = '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])'
        $script:PowerShellFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..') -Filter '*.ps1' -Recurse -File)
    }

    It 'Analyzes a non-empty collection of PowerShell files' {
        $script:PowerShellFiles.Count | Should -BeGreaterThan 0
    }

    It 'Recognizes a VirusTotal hexadecimal key built without contiguous literal' {
        $key = ('a' * 63) + 'b'

        $key | Should -Match $script:VtKeyPattern
    }

    It 'Ignores values that are not hexadecimal VirusTotal keys' -ForEach @(
        ('a' * 63),
        (('a' * 63) + 'g'),
        (('a' * 64) + 'b'),
        'MOCK-VT-KEY'
    ) {
        $_ | Should -Not -Match $script:VtKeyPattern
    }

    It 'Does not find any hardcoded hexadecimal VirusTotal key in PowerShell files' {
        $offenders = [System.Collections.Generic.List[string]]::new()

        foreach ($file in $script:PowerShellFiles) {
            $n = 0
            foreach ($row in Get-Content -Path $file.FullName -ErrorAction Stop) {
                $n++
                if ($row -match $script:VtKeyPattern) {
                    $offenders.Add("$($file.FullName):$n")
                }
            }
        }

        $offenders | Should -Be @()
    }
}

Describe 'Connect-VirusTotal never returns the key' {

    AfterEach { Disconnect-VirusTotal }

    It 'Does not show the key in any property of the returned object' {
        $connection = Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl

        ($connection | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'Returns an object with properties to inspect' {
        $connection = Connect-VirusTotal -ApiKey $script:ApiKey -BaseUri $script:Server.BaseUrl

        @($connection.PSObject.Properties.Name).Count | Should -BeGreaterThan 0
        $connection.PSObject.Properties.Name | Should -Contain 'BaseUri'
    }
}
