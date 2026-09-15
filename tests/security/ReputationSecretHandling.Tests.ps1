#Requires -Version 7.2

Set-StrictMode -Version 3.0

$script:ProviderNames = @('VirusTotal', 'MalwareBazaar', 'HybridAnalysis')

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:JournalUri = "$($script:Server.BaseUrl)/_test/reputation"
    $script:KnownHash = ('B' * 38) + '02'
    $script:MaliciousHash = ('C' * 38) + '03'
    $script:VtPath = "/api/v3/files/$(('A' * 38) + '01')"
    $script:MbBaseUri = "$($script:Server.BaseUrl)/mb"
    $script:TfBaseUri = "$($script:Server.BaseUrl)/tf"

    $script:Keys = @{
        VirusTotal = ConvertTo-TestSecureString -PlainText 'MOCK-VT-KEY'
        MalwareBazaar = ConvertTo-TestSecureString -PlainText 'MOCK-MB-KEY'
        HybridAnalysis = ConvertTo-TestSecureString -PlainText 'MOCK-HA-KEY'
    }
    $script:KeyTexts = @{
        VirusTotal = 'MOCK-VT-KEY'
        MalwareBazaar = 'MOCK-MB-KEY'
        HybridAnalysis = 'MOCK-HA-KEY'
    }
    $script:DistinctiveFragments = @{
        VirusTotal = 'VT-KEY'
        MalwareBazaar = 'MB-KEY'
        HybridAnalysis = 'HA-KEY'
    }
    $script:Providers = @(
        [pscustomobject]@{ Name = 'VirusTotal'; StateProperty = 'BaseUri'; Path = $script:VtPath; Method = 'GET' }
        [pscustomobject]@{ Name = 'MalwareBazaar'; StateProperty = 'BaseUri'; Path = '/mb/api/v1/'; Method = 'POST' }
        [pscustomobject]@{ Name = 'HybridAnalysis'; StateProperty = 'BaseUri'; Path = '/api/v2/search/hash'; Method = 'GET' }
    )
    $script:Ps1Files = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..') -Filter '*.ps1' -Recurse -File)

    function Get-ReputationProviderStateReset {
        Disconnect-VirusTotal -ErrorAction SilentlyContinue
        Disconnect-MalwareBazaar -ErrorAction SilentlyContinue
        Disconnect-HybridAnalysis -ErrorAction SilentlyContinue
    }

    function Connect-ReputationProvider {
        param([Parameter(Mandatory)][string]$Name)

        switch ($Name) {
            'VirusTotal' {
                return Connect-VirusTotal -ApiKey $script:Keys[$Name] -BaseUri $script:Server.BaseUrl
            }
            'MalwareBazaar' {
                return Connect-MalwareBazaar -AuthKey $script:Keys[$Name] -BaseUri $script:MbBaseUri `
                    -ThreatFoxBaseUri $script:TfBaseUri
            }
            'HybridAnalysis' {
                return Connect-HybridAnalysis -ApiKey $script:Keys[$Name] -BaseUri $script:Server.BaseUrl
            }
            default { throw "Unknown reputation provider: $Name" }
        }
    }

    function Get-ReputationConnectionStateJson {
        param([Parameter(Mandatory)][string]$Name)

        return InModuleScope EndpointOps -Parameters @{ ProviderName = $Name } {
            param($ProviderName)
            switch ($ProviderName) {
                'VirusTotal' { Get-VtConnectionState | ConvertTo-Json -Depth 5 }
                'MalwareBazaar' { Get-MbConnectionState | ConvertTo-Json -Depth 5 }
                'HybridAnalysis' { Get-HaConnectionState | ConvertTo-Json -Depth 5 }
                default { throw "Unknown reputation provider: $ProviderName" }
            }
        }
    }

    function Invoke-ReputationProviderRequest {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][ValidateSet('Normal', 'Verbose', 'Debug')][string]$Channel
        )

        return @(InModuleScope EndpointOps -Parameters @{
                ProviderName = $Name
                VtPath = $script:VtPath
                KnownHash = $script:KnownHash
                Channel = $Channel
            } {
                param($ProviderName, $VtPath, $KnownHash, $Channel)
                switch ($ProviderName) {
                    'VirusTotal' {
                        switch ($Channel) {
                            'Normal' { Invoke-VtRequest -Path $VtPath -MinIntervalMs 0 }
                            'Verbose' { Invoke-VtRequest -Path $VtPath -MinIntervalMs 0 -Verbose 4>&1 }
                            'Debug' { Invoke-VtRequest -Path $VtPath -MinIntervalMs 0 -Debug 5>&1 }
                        }
                    }
                    'MalwareBazaar' {
                        switch ($Channel) {
                            'Normal' { Invoke-MbRequest -Hash $KnownHash }
                            'Verbose' { Invoke-MbRequest -Hash $KnownHash -Verbose 4>&1 }
                            'Debug' { Invoke-MbRequest -Hash $KnownHash -Debug 5>&1 }
                        }
                    }
                    'HybridAnalysis' {
                        switch ($Channel) {
                            'Normal' { Invoke-HaRequest -Hash $KnownHash }
                            'Verbose' { Invoke-HaRequest -Hash $KnownHash -Verbose 4>&1 }
                            'Debug' { Invoke-HaRequest -Hash $KnownHash -Debug 5>&1 }
                        }
                    }
                    default { throw "Unknown reputation provider: $ProviderName" }
                }
            })
    }

    function Get-ReputationJournalEntry {
        return @((Invoke-RestMethod -Uri $script:JournalUri).requests)
    }
}

AfterAll {
    Get-ReputationProviderStateReset
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe '1. Reputation connection states do not disclose keys' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> does not contain its key after serialization' -ForEach $script:ProviderNames {
        $providerName = $_
        Connect-ReputationProvider -Name $providerName | Out-Null

        $stateJson = Get-ReputationConnectionStateJson -Name $providerName

        $stateJson | Should -Match 'BaseUri'
        $stateJson | Should -Not -Match $script:KeyTexts[$providerName]
    }
}

Describe '2. Reputation connection failures do not disclose keys' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> does not disclose its key in the complete ErrorRecord' -ForEach $script:ProviderNames {
        $providerName = $_
        $record = try {
            switch ($providerName) {
                'VirusTotal' {
                    Connect-VirusTotal -ApiKey $script:Keys[$providerName] -BaseUri 'http://example.invalid' | Out-Null
                }
                'MalwareBazaar' {
                    Connect-MalwareBazaar -AuthKey $script:Keys[$providerName] -BaseUri 'http://example.invalid' | Out-Null
                }
                'HybridAnalysis' {
                    Connect-HybridAnalysis -ApiKey $script:Keys[$providerName] -BaseUri 'http://example.invalid' | Out-Null
                }
            }
            $null
        }
        catch { $_ }

        $record | Should -Not -BeNullOrEmpty
        $record.Exception.Message | Should -Match 'BaseUri must use HTTPS'
        $record.Exception.Message | Should -Not -Match $script:KeyTexts[$providerName]
        $recordText = $record | Out-String
        $recordText | Should -Match 'BaseUri must use HTTPS'
        $recordText | Should -Not -Match $script:KeyTexts[$providerName]
    }
}

Describe '3. Reputation verbose streams do not disclose keys' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> sends a real request without exposing its key' -ForEach $script:ProviderNames {
        $providerName = $_
        Connect-ReputationProvider -Name $providerName | Out-Null
        $before = (Get-ReputationJournalEntry).Count

        $records = Invoke-ReputationProviderRequest -Name $providerName -Channel Verbose
        $after = (Get-ReputationJournalEntry).Count
        $verboseText = $records | Out-String

        ($after - $before) | Should -Be 1
        $records.Count | Should -BeGreaterThan 0
        $verboseText | Should -Not -Match $script:KeyTexts[$providerName]
    }
}

Describe '4. Reputation debug streams do not disclose keys' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> sends a real request without exposing its key' -ForEach $script:ProviderNames {
        $providerName = $_
        Connect-ReputationProvider -Name $providerName | Out-Null
        $before = (Get-ReputationJournalEntry).Count

        $records = Invoke-ReputationProviderRequest -Name $providerName -Channel Debug
        $after = (Get-ReputationJournalEntry).Count
        $debugText = $records | Out-String

        ($after - $before) | Should -Be 1
        $records.Count | Should -BeGreaterThan 0
        $debugText | Should -Not -Match $script:KeyTexts[$providerName]
    }
}

Describe '5. The reputation journal never retains headers' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> records only the path, method, and Boolean authExact value' -ForEach $script:ProviderNames {
        $providerName = $_
        Connect-ReputationProvider -Name $providerName | Out-Null
        $before = (Get-ReputationJournalEntry).Count

        Invoke-ReputationProviderRequest -Name $providerName -Channel Normal | Out-Null
        $entries = Get-ReputationJournalEntry
        $entry = $entries[$before]
        $entryJson = $entry | ConvertTo-Json -Depth 5

        ($entries.Count - $before) | Should -Be 1
        @($entry.PSObject.Properties.Name).Count | Should -Be 3
        $entry.PSObject.Properties.Name | Should -Contain 'path'
        $entry.PSObject.Properties.Name | Should -Contain 'method'
        $entry.PSObject.Properties.Name | Should -Contain 'authExact'
        $providerContract = @($script:Providers | Where-Object Name -eq $providerName)[0]
        $entry.path | Should -BeExactly $providerContract.Path
        $entry.method | Should -BeExactly $providerContract.Method
        $entry.authExact | Should -BeOfType [bool]
        $entry.authExact | Should -BeTrue
        $entryJson | Should -Not -Match $script:KeyTexts[$providerName]
    }
}

Describe '6. Reputation Connect commands do not return keys' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> returns an inspectable object without its key' -ForEach $script:ProviderNames {
        $providerName = $_
        $connection = Connect-ReputationProvider -Name $providerName
        $connectionJson = $connection | ConvertTo-Json -Depth 5

        @($connection.PSObject.Properties.Name).Count | Should -BeGreaterThan 0
        $connection.PSObject.Properties.Name | Should -Contain 'BaseUri'
        $connectionJson | Should -Not -Match $script:KeyTexts[$providerName]
    }
}

Describe '7. The reputation cache never discloses keys' {
    AfterEach { Get-ReputationProviderStateReset }

    It '<_> leaves neither its key nor its distinctive fragment in TestDrive' -ForEach $script:ProviderNames {
        $providerName = $_
        $cachePath = Join-Path $TestDrive "$providerName/reputation-cache.json"
        Connect-ReputationProvider -Name 'VirusTotal' | Out-Null
        Connect-ReputationProvider -Name 'MalwareBazaar' | Out-Null
        Connect-ReputationProvider -Name 'HybridAnalysis' | Out-Null

        Get-FileReputation -Hash $script:MaliciousHash -MinIntervalMs 0 -UseCache -CachePath $cachePath | Out-Null
        $cacheContent = Get-Content -LiteralPath $cachePath -Raw -ErrorAction Stop

        $cacheContent | Should -Match 'VirusTotal|MalwareBazaar|HybridAnalysis'
        $cacheContent | Should -Not -Match $script:KeyTexts[$providerName]
        $cacheContent | Should -Not -Match $script:DistinctiveFragments[$providerName]
    }
}

Describe '8. PowerShell files contain no hardcoded reputation secrets' {
    BeforeAll {
        $script:VtKeyPattern = '(?i)["'']x-apikey["'']\s*=\s*["''](?<value>[A-Za-z0-9_-]+)["'']'
        $script:MbKeyPattern = '(?i)["'']Auth-Key["'']\s*=\s*["''](?<value>[A-Za-z0-9_-]+)["'']'
        $script:HaKeyPattern = '(?i)["'']api-key["'']\s*=\s*["''](?<value>[A-Za-z0-9_-]+)["'']'
        $script:ConnectSecretParameters = @{
            'Connect-VirusTotal'      = 'ApiKey'
            'Connect-MalwareBazaar'   = 'AuthKey'
            'Connect-HybridAnalysis'  = 'ApiKey'
        }
        $script:AllowedTestLiterals = @(
            'MOCK-VT-KEY', 'MOCK-MB-KEY', 'MOCK-HA-KEY', 'WRONG-MB-KEY', 'WRONG-VT-KEY')

        function Find-ReputationHardcodedSecret {
            param([Parameter(Mandatory)][System.IO.FileInfo[]]$Files)

            $findings = [System.Collections.Generic.List[string]]::new()
            foreach ($file in $Files) {
                $isTest = $file.FullName -match '[\\/]tests[\\/]'
                $lineNumber = 0
                foreach ($line in Get-Content -LiteralPath $file.FullName -ErrorAction Stop) {
                    $lineNumber++
                    foreach ($pattern in @(
                            $script:VtKeyPattern,
                            $script:MbKeyPattern,
                            $script:HaKeyPattern)) {
                        foreach ($match in [regex]::Matches($line, $pattern)) {
                            $value = $match.Groups['value'].Value
                            if (-not $isTest -or $value -cnotin $script:AllowedTestLiterals) {
                                $findings.Add("$($file.FullName):${lineNumber}:ProviderKeyPattern")
                            }
                        }
                    }
                }

                $tokens = $null
                $parseErrors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName, [ref]$tokens, [ref]$parseErrors)
                $commands = @($ast.FindAll({
                            param($node)
                            $node -is [System.Management.Automation.Language.CommandAst]
                        }, $true))
                foreach ($command in $commands) {
                    $commandName = $command.GetCommandName()
                    if ([string]::IsNullOrWhiteSpace($commandName) -and
                        $command.CommandElements.Count -gt 0 -and
                        $command.CommandElements[0] -is
                            [System.Management.Automation.Language.ParenExpressionAst]) {
                        $pipelineElements = @($command.CommandElements[0].Pipeline.PipelineElements)
                        if ($pipelineElements.Count -eq 1 -and
                            $pipelineElements[0] -is
                                [System.Management.Automation.Language.CommandExpressionAst]) {
                            $commandExpression = $pipelineElements[0].Expression
                            if ($commandExpression -is
                                [System.Management.Automation.Language.StringConstantExpressionAst]) {
                                $commandName = [string]$commandExpression.Value
                            }
                            elseif ($commandExpression -is
                                [System.Management.Automation.Language.ExpandableStringExpressionAst] -and
                                @($commandExpression.NestedExpressions).Count -eq 0) {
                                $commandName = [string]$commandExpression.Value
                            }
                        }
                    }

                    $isDynamicInvocation = [string]::IsNullOrWhiteSpace($commandName) -and
                        $command.InvocationOperator -eq
                            [System.Management.Automation.Language.TokenKind]::Ampersand
                    $parameterNames = if ($isDynamicInvocation) {
                        @('ApiKey', 'AuthKey')
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($commandName)) {
                        $terminalCommandName = $commandName.Substring($commandName.LastIndexOf([char]92) + 1)
                        if ($script:ConnectSecretParameters.ContainsKey($terminalCommandName)) {
                            @($script:ConnectSecretParameters[$terminalCommandName])
                        }
                        else {
                            @()
                        }
                    }
                    else {
                        @()
                    }

                    foreach ($parameterName in $parameterNames) {
                        for ($index = 1; $index -lt $command.CommandElements.Count; $index++) {
                            $element = $command.CommandElements[$index]
                            if ($element -isnot [System.Management.Automation.Language.CommandParameterAst] -or
                                $element.ParameterName -ne $parameterName) {
                                continue
                            }

                            $argument = $element.Argument
                            if ($null -eq $argument -and $index + 1 -lt $command.CommandElements.Count) {
                                $argument = $command.CommandElements[$index + 1]
                            }

                            $value = $null
                            if ($argument -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                                $value = [string]$argument.Value
                            }
                            elseif ($argument -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and
                                @($argument.NestedExpressions).Count -eq 0) {
                                $value = [string]$argument.Value
                            }

                            if (-not [string]::IsNullOrWhiteSpace($value) -and
                                (-not $isTest -or $value -cnotin $script:AllowedTestLiterals)) {
                                $findings.Add(
                                    "$($file.FullName):$($argument.Extent.StartLineNumber):$($parameterName)Literal")
                            }
                        }
                    }
                }
            }
            return @($findings)
        }
    }

    It 'scans a non-empty collection of PowerShell files' {
        $script:Ps1Files.Count | Should -BeGreaterThan 30
    }

    It 'recognizes all three constructed secret headers without a dangerous literal' {
        $vtCandidate = ("'x-apikey'|=|'" + ('V' * 8) + "'") -replace '\|', ' '
        $mbCandidate = ("'Auth-Key'|=|'" + ('M' * 8) + "'") -replace '\|', ' '
        $haCandidate = ("'api-key'|=|'" + ('H' * 8) + "'") -replace '\|', ' '

        $vtCandidate | Should -Match $script:VtKeyPattern
        $mbCandidate | Should -Match $script:MbKeyPattern
        $haCandidate | Should -Match $script:HaKeyPattern
    }

    It 'recognizes header suffixes without mistaking a SHA-256 hash for a key' {
        $mbSuffix = ("'Auth-Key'|=|'WRONG-MB-KEY-LEAK'") -replace '\|', ' '
        $vtSuffix = ("'x-apikey'|=|'WRONG-VT-KEY-LEAK'") -replace '\|', ' '
        $sha256OutsideSink = ('a' * 63) + 'b'

        $mbSuffix | Should -Match $script:MbKeyPattern
        $vtSuffix | Should -Match $script:VtKeyPattern
        $sha256OutsideSink | Should -Not -Match $script:VtKeyPattern
    }

    It 'ignores legitimate constructed forms for all three providers' {
        $vtCandidates = @((('a' * 63)), (('a' * 63) + 'g'), 'MOCK-VT-KEY')
        $mbCandidate = ("'Auth-Key'|=|ConvertFrom-SecureString|$state.AuthKey") -replace '\|', ' '
        $haCandidate = ("'api-key'|=|ConvertFrom-SecureString|$state.ApiKey") -replace '\|', ' '
        $mbFixture = ("'Auth-Key'|=|'MOCK-MB-KEY'") -replace '\|', ' '
        $mbRejectedFixture = ("'Auth-Key'|=|'WRONG-MB-KEY'") -replace '\|', ' '
        $haFixture = ("'api-key'|=|'MOCK-HA-KEY'") -replace '\|', ' '

        foreach ($candidate in $vtCandidates) {
            $candidate | Should -Not -Match $script:VtKeyPattern
        }
        $mbCandidate | Should -Not -Match $script:MbKeyPattern
        $haCandidate | Should -Not -Match $script:HaKeyPattern
        $mbFixture | Should -Match $script:MbKeyPattern
        $mbRejectedFixture | Should -Match $script:MbKeyPattern
        $haFixture | Should -Match $script:HaKeyPattern
        $script:AllowedTestLiterals | Should -Contain 'MOCK-MB-KEY'
        $script:AllowedTestLiterals | Should -Contain 'WRONG-MB-KEY'
        $script:AllowedTestLiterals | Should -Contain 'MOCK-HA-KEY'
    }

    It 'flags non-fixtures and suffixes under tests without exempting src or a SHA-256 outside a sink' {
        $testDirectory = Join-Path $TestDrive 'tests'
        $testPath = Join-Path $testDirectory 'scanner-fixtures.ps1'
        $sourceDirectory = Join-Path $TestDrive 'src'
        $sourcePath = Join-Path $sourceDirectory 'scanner-source.ps1'
        $outsideTestsPath = Join-Path $TestDrive 'scanner-outside-tests.ps1'
        New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
        New-Item -ItemType Directory -Path $sourceDirectory -Force | Out-Null

        $testLines = @(
            (("@{|'Auth-Key'|=|'NON-FIXTURE-KEY'|}") -replace '\|', ' '),
            (("@{|'Auth-Key'|=|'WRONG-MB-KEY-LEAK'|}") -replace '\|', ' '),
            (("@{|'x-apikey'|=|'UNAPPROVED-VT-KEY'|}") -replace '\|', ' '),
            (("@{|'x-apikey'|=|'WRONG-VT-KEY-LEAK'|}") -replace '\|', ' '),
            (("@{|'Auth-Key'|=|'MOCK-MB-KEY'|}") -replace '\|', ' '),
            (("@{|'x-apikey'|=|'MOCK-VT-KEY'|}") -replace '\|', ' '),
            (("@{|'x-apikey'|=|'WRONG-VT-KEY'|}") -replace '\|', ' '),
            (("@{|'api-key'|=|'MOCK-HA-KEY'|}") -replace '\|', ' '),
            (("Connect-VirusTotal|-ApiKey|'MOCK-VT-KEY'") -replace '\|', ' '),
            (("Connect-MalwareBazaar|-AuthKey|'WRONG-MB-KEY'") -replace '\|', ' '),
            (('a' * 63) + 'b')
        )
        Set-Content -LiteralPath $testPath -Value $testLines -Encoding utf8NoBOM
        Set-Content -LiteralPath $sourcePath -Value @(
            (("@{|'Auth-Key'|=|'MOCK-MB-KEY'|}") -replace '\|', ' '),
            (("@{|'x-apikey'|=|'WRONG-VT-KEY'|}") -replace '\|', ' ')
        ) -Encoding utf8NoBOM
        Set-Content -LiteralPath $outsideTestsPath -Value `
            (("@{|'api-key'|=|'MOCK-HA-KEY'|}") -replace '\|', ' ') -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @(
            [System.IO.FileInfo]$testPath,
            [System.IO.FileInfo]$sourcePath,
            [System.IO.FileInfo]$outsideTestsPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 7
        $findingText | Should -Match 'scanner-fixtures.ps1:1:ProviderKeyPattern'
        $findingText | Should -Match 'scanner-fixtures.ps1:2:ProviderKeyPattern'
        $findingText | Should -Match 'scanner-fixtures.ps1:3:ProviderKeyPattern'
        $findingText | Should -Match 'scanner-fixtures.ps1:4:ProviderKeyPattern'
        $findingText | Should -Match 'scanner-source.ps1:1:ProviderKeyPattern'
        $findingText | Should -Match 'scanner-source.ps1:2:ProviderKeyPattern'
        $findingText | Should -Match 'scanner-outside-tests.ps1:1:ProviderKeyPattern'
        foreach ($literal in @(
                'NON-FIXTURE-KEY',
                'WRONG-MB-KEY-LEAK',
                'UNAPPROVED-VT-KEY',
                'WRONG-VT-KEY-LEAK',
                'MOCK-MB-KEY',
                'MOCK-VT-KEY',
                'WRONG-MB-KEY',
                'WRONG-VT-KEY',
                'MOCK-HA-KEY')) {
            $findingText | Should -Not -Match ([regex]::Escape($literal))
        }
        $findingText | Should -Not -Match (('a' * 63) + 'b')
    }

    It 'redacts a source-tree text-pattern finding' {
        $sourceDirectory = Join-Path $TestDrive 'src'
        $testPath = Join-Path $sourceDirectory 'scanner-text-redaction.ps1'
        New-Item -ItemType Directory -Path $sourceDirectory -Force | Out-Null
        Set-Content -LiteralPath $testPath -Value `
            (("@{|'Auth-Key'|=|'TEXT-REDACTION-SYNTHETIC'|}") -replace '\|', ' ') `
            -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-text-redaction.ps1:1:ProviderKeyPattern'
        $findingText | Should -Not -Match 'TEXT-REDACTION-SYNTHETIC'
    }

    It 'redacts a resolved-command AST finding' {
        $sourceDirectory = Join-Path $TestDrive 'src'
        $testPath = Join-Path $sourceDirectory 'scanner-ast-redaction.ps1'
        New-Item -ItemType Directory -Path $sourceDirectory -Force | Out-Null
        Set-Content -LiteralPath $testPath -Value `
            "EndpointOps\Connect-VirusTotal -ApiKey 'AST-REDACTION-SYNTHETIC'" `
            -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-ast-redaction.ps1:1:ApiKeyLiteral'
        $findingText | Should -Not -Match 'AST-REDACTION-SYNTHETIC'
    }

    It 'flags a case-variant textual fixture under tests' {
        $testDirectory = Join-Path $TestDrive 'tests'
        $testPath = Join-Path $testDirectory 'scanner-case-variant-text.ps1'
        New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
        Set-Content -LiteralPath $testPath -Value `
            (("@{|'x-apikey'|=|'mock-vt-key'|}") -replace '\|', ' ') -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-case-variant-text.ps1:1:ProviderKeyPattern'
        $findingText | Should -Not -Match 'mock-vt-key'
    }

    It 'flags a case-variant AST fixture under tests' {
        $testDirectory = Join-Path $TestDrive 'tests'
        $testPath = Join-Path $testDirectory 'scanner-case-variant-ast.ps1'
        New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
        Set-Content -LiteralPath $testPath -Value `
            "EndpointOps\Connect-VirusTotal -ApiKey 'mock-vt-key'" -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-case-variant-ast.ps1:1:ApiKeyLiteral'
        $findingText | Should -Not -Match 'mock-vt-key'
    }

    It 'flags all three multiline Connect sinks with a literal argument' {
        $testPath = Join-Path $TestDrive 'scanner-multiline.ps1'
        $continuation = [char]96
        Set-Content -LiteralPath $testPath -Value @(
            'function Invoke-MultilineSecretProbe {'
            ('    Connect-VirusTotal ' + $continuation)
            "        -ApiKey 'MULTILINE-VT-SECRET'"
            ('    Connect-MalwareBazaar ' + $continuation)
            "        -AuthKey 'MULTILINE-MB-SECRET'"
            ('    Connect-HybridAnalysis ' + $continuation)
            "        -ApiKey 'MULTILINE-HA-SECRET'"
            '}'
        ) -Encoding utf8NoBOM

        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $testPath, [ref]$null, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 3
        $findingText | Should -Match 'scanner-multiline.ps1:3:ApiKeyLiteral'
        $findingText | Should -Match 'scanner-multiline.ps1:5:AuthKeyLiteral'
        $findingText | Should -Match 'scanner-multiline.ps1:7:ApiKeyLiteral'
        $findingText | Should -Not -Match 'MULTILINE-VT-SECRET'
        $findingText | Should -Not -Match 'MULTILINE-MB-SECRET'
        $findingText | Should -Not -Match 'MULTILINE-HA-SECRET'
    }

    It 'flags module-qualified literal Connect secrets for all three providers' {
        $testPath = Join-Path $TestDrive 'scanner-module-qualified.ps1'
        Set-Content -LiteralPath $testPath -Value @(
            "EndpointOps\Connect-VirusTotal -ApiKey 'MODULE-VT-SECRET'"
            "EndpointOps\Connect-MalwareBazaar -AuthKey 'MODULE-MB-SECRET'"
            "EndpointOps\Connect-HybridAnalysis -ApiKey 'MODULE-HA-SECRET'"
        ) -Encoding utf8NoBOM

        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $testPath, [ref]$null, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 3
        $findingText | Should -Match 'scanner-module-qualified.ps1:1:ApiKeyLiteral'
        $findingText | Should -Match 'scanner-module-qualified.ps1:2:AuthKeyLiteral'
        $findingText | Should -Match 'scanner-module-qualified.ps1:3:ApiKeyLiteral'
        $findingText | Should -Not -Match 'MODULE-VT-SECRET'
        $findingText | Should -Not -Match 'MODULE-MB-SECRET'
        $findingText | Should -Not -Match 'MODULE-HA-SECRET'
    }

    It 'keeps the fixture exception inside tests for module-qualified sinks' {
        $testDirectory = Join-Path $TestDrive 'tests'
        $sourceDirectory = Join-Path $TestDrive 'src'
        $testPath = Join-Path $testDirectory 'scanner-module-fixtures.ps1'
        $sourcePath = Join-Path $sourceDirectory 'scanner-module-source.ps1'
        New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
        New-Item -ItemType Directory -Path $sourceDirectory -Force | Out-Null

        Set-Content -LiteralPath $testPath -Value @(
            "EndpointOps\Connect-VirusTotal -ApiKey 'MOCK-VT-KEY'"
            "EndpointOps\Connect-MalwareBazaar -AuthKey 'WRONG-MB-KEY-LEAK'"
        ) -Encoding utf8NoBOM
        Set-Content -LiteralPath $sourcePath -Value `
            "EndpointOps\Connect-HybridAnalysis -ApiKey 'MOCK-HA-KEY'" -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @(
            [System.IO.FileInfo]$testPath,
            [System.IO.FileInfo]$sourcePath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 2
        $findingText | Should -Match 'scanner-module-fixtures.ps1:2:AuthKeyLiteral'
        $findingText | Should -Match 'scanner-module-source.ps1:1:ApiKeyLiteral'
        $findingText | Should -Not -Match 'WRONG-MB-KEY-LEAK'
        $findingText | Should -Not -Match 'MOCK-HA-KEY'
        $findingText | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'flags a parenthesized static module-qualified command expression' {
        $testPath = Join-Path $TestDrive 'scanner-parenthesized-static.ps1'
        Set-Content -LiteralPath $testPath -Value `
            "& ('EndpointOps\Connect-HybridAnalysis') -ApiKey 'PARENTHESIZED-HA-SECRET'" `
            -Encoding utf8NoBOM

        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $testPath, [ref]$null, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-parenthesized-static.ps1:1:ApiKeyLiteral'
        $findingText | Should -Not -Match 'PARENTHESIZED-HA-SECRET'
    }

    It 'flags an ApiKey literal passed through a dynamic invocation' {
        $testPath = Join-Path $TestDrive 'scanner-dynamic-apikey.ps1'
        Set-Content -LiteralPath $testPath -Value @(
            '$commandName = "EndpointOps\Connect-VirusTotal"'
            "& `$commandName -ApiKey 'DYNAMIC-VT-LITERAL'"
        ) -Encoding utf8NoBOM

        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $testPath, [ref]$null, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-dynamic-apikey.ps1:2:ApiKeyLiteral'
        $findingText | Should -Not -Match 'DYNAMIC-VT-LITERAL'
    }

    It 'flags an AuthKey literal passed through a dynamic invocation' {
        $testPath = Join-Path $TestDrive 'scanner-dynamic-authkey.ps1'
        Set-Content -LiteralPath $testPath -Value @(
            '$commandName = "EndpointOps\Connect-MalwareBazaar"'
            "& `$commandName -AuthKey 'DYNAMIC-MB-LITERAL'"
        ) -Encoding utf8NoBOM

        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $testPath, [ref]$null, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 1
        $findingText | Should -Match 'scanner-dynamic-authkey.ps1:2:AuthKeyLiteral'
        $findingText | Should -Not -Match 'DYNAMIC-MB-LITERAL'
    }

    It 'does not flag a variable ApiKey argument at a dynamic invocation' {
        $testPath = Join-Path $TestDrive 'scanner-dynamic-variable.ps1'
        Set-Content -LiteralPath $testPath -Value @(
            '$commandName = "EndpointOps\Connect-VirusTotal"'
            '$apiKey = Read-Host -AsSecureString'
            '& $commandName -ApiKey $apiKey'
        ) -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)

        $findings | Should -Be @()
    }

    It 'does not flag a runtime expression AuthKey argument at a dynamic invocation' {
        $testPath = Join-Path $TestDrive 'scanner-dynamic-expression.ps1'
        Set-Content -LiteralPath $testPath -Value @(
            '$commandName = "EndpointOps\Connect-MalwareBazaar"'
            '& $commandName -AuthKey (Get-SecretFromApprovedRuntimeSource)'
        ) -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)

        $findings | Should -Be @()
    }

    It 'does not flag a literal ApiKey argument on an unrelated resolved command' {
        $testPath = Join-Path $TestDrive 'scanner-unrelated-command.ps1'
        Set-Content -LiteralPath $testPath -Value `
            "Invoke-UnrelatedTool -ApiKey 'NOT-A-CONNECTION-SECRET'" -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)

        $findings | Should -Be @()
    }

    It 'limits exact dynamic fixture exemptions to files under tests' {
        $testDirectory = Join-Path $TestDrive 'tests'
        $sourceDirectory = Join-Path $TestDrive 'src'
        $allowedTestPath = Join-Path $testDirectory 'scanner-dynamic-allowed.ps1'
        $variantTestPath = Join-Path $testDirectory 'scanner-dynamic-variant.ps1'
        $sourcePath = Join-Path $sourceDirectory 'scanner-dynamic-source.ps1'
        New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
        New-Item -ItemType Directory -Path $sourceDirectory -Force | Out-Null

        Set-Content -LiteralPath $allowedTestPath -Value @(
            '$commandName = "EndpointOps\Connect-VirusTotal"'
            "& `$commandName -ApiKey 'MOCK-VT-KEY'"
        ) -Encoding utf8NoBOM
        Set-Content -LiteralPath $variantTestPath -Value @(
            '$commandName = "EndpointOps\Connect-VirusTotal"'
            "& `$commandName -ApiKey 'MOCK-VT-KEY-LEAK'"
        ) -Encoding utf8NoBOM
        Set-Content -LiteralPath $sourcePath -Value @(
            '$commandName = "EndpointOps\Connect-VirusTotal"'
            "& `$commandName -ApiKey 'MOCK-VT-KEY'"
        ) -Encoding utf8NoBOM

        $findings = Find-ReputationHardcodedSecret -Files @(
            [System.IO.FileInfo]$allowedTestPath,
            [System.IO.FileInfo]$variantTestPath,
            [System.IO.FileInfo]$sourcePath)
        $findingText = $findings -join "`n"

        $findings.Count | Should -Be 2
        $findingText | Should -Match 'scanner-dynamic-variant.ps1:2:ApiKeyLiteral'
        $findingText | Should -Match 'scanner-dynamic-source.ps1:2:ApiKeyLiteral'
        $findingText | Should -Not -Match 'MOCK-VT-KEY-LEAK'
        $findingText | Should -Not -Match 'MOCK-VT-KEY'
    }

    It 'finds no hardcoded reputation key in PowerShell files' {
        $findings = Find-ReputationHardcodedSecret -Files $script:Ps1Files

        $findings | Should -Be @()
    }
}
