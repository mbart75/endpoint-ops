BeforeAll {
    Set-StrictMode -Version 3.0

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port
    $script:Base   = "http://localhost:$($script:Port)"

    # The three values that nothing should disclose. The password is the subject of this file: unlike
# SentinelOne sends its secret only in an HTTP header, whereas EPM sends the password in a JSON body,
# which is more likely to be copied into an error message, verbose trace, or retry log.
    $script:Password = 'MOCK-EPM-PASSWORD'
    $script:Token      = 'MOCK-EPM-TOKEN'
    $script:User = 'mock-epm-user'

    $script:Log = "$($script:Base)/EPM/API/_test/requests"

    # Identifiers are built ONCE, in a variable. This is optional: if the password had been written
# literally on the call line, the rendering of an ErrorRecord ($_ | Out-String) would display this
# source line, and test 2 would catch its own staging instead of the module's behavior.
    $script:ValidCases = [pscredential]::new(
        $script:User, (ConvertTo-TestSecureString -PlainText $script:Password))

    $script:InvalidCases = [pscredential]::new(
        $script:User, (ConvertTo-TestSecureString -PlainText ($script:Password + 'X')))
}

AfterAll {
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'The connection status does not retain the password' {

    AfterEach { Disconnect-EpmTenant }

    It 'Does not display the password anywhere in the login status' {
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        # Get-EpmConnectionState is PRIVATE: it is read within the scope of the module. It is this object
# that we want to inspect, and not the one returned by Connect-EpmTenant: the state is what SURVIVES
# the call.
        $state = InModuleScope EndpointOps { Get-EpmConnectionState | ConvertTo-Json -Depth 5 }

        $state | Should -Not -Match 'MOCK-EPM-PASSWORD'
    }

    It 'Does not retain the password in any state property' {
        # The control on the TEXT would not see a password stored in a SecureString: the JSON rendering does
# not show anything. The name, however, is visible.
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $names = InModuleScope EndpointOps { @((Get-EpmConnectionState).PSObject.Properties.Name) }

        @($names | Where-Object { $_ -match 'Password|Password|Secret|Pwd' }).Count | Should -Be 0
    }

    It 'Retains non-empty state so the preceding checks cannot pass vacuously' {
        # An empty state would pass both of the above tests without proving anything.
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $names = InModuleScope EndpointOps { @((Get-EpmConnectionState).PSObject.Properties.Name) }

        $names | Should -Contain 'ManagerUri'
    }
}

Describe 'A rejected connection does not disclose secrets' {

    It 'Does not display the password in any part of the ErrorRecord' {
        # Out-String on the ErrorRecord complete, and not just $_.Exception.Message: the rendering of a
# PowerShell error includes the source line, the stack and the details of the invocation. This is
# precisely where a copy of a query body would slide in.
        $rendered = try {
            Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:InvalidCases | Out-Null
            ''
        }
        catch { $_ | Out-String }

        $rendered | Should -Not -Match 'MOCK-EPM-PASSWORD'
    }

    It 'Does not display any token in the ErrorRecord of a rejected connection' {
        $rendered = try {
            Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:InvalidCases | Out-Null
            ''
        }
        catch { $_ | Out-String }

        $rendered | Should -Not -Match 'MOCK-EPM-TOKEN'
    }

    It 'Produces a failure record to inspect' {
        # Without this guard, a connection that SUCCEEDED would make the string empty, and the above two
# tests would pass without having examined anything.
        $rendered = try {
            Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:InvalidCases | Out-Null
            ''
        }
        catch { $_ | Out-String }

        $rendered | Should -Match 'CyberArk EPM authentication refused'
    }
}

Describe 'The verbose stream does not disclose the password' {

    AfterEach { Disconnect-EpmTenant }

    It 'Does not display the password in any verbose messages' {
        $verboseOutput = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases -Verbose 4>&1 | Out-String

        $verboseOutput | Should -Not -Match 'MOCK-EPM-PASSWORD'
    }

    It 'Produces verbose output to inspect' {
        # An empty stream would pass the previous test without proving anything. We require the trace of the
# authentication request itself.
        $verboseOutput = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases -Verbose 4>&1 | Out-String

        $verboseOutput | Should -Match 'Auth/EPM/Logon'
    }
}

Describe 'The debug stream does not disclose the password' {

    AfterEach { Disconnect-EpmTenant }

    It 'Does not display the password in any debugging messages' {
        # 5>&1 redirects the Debug stream. -Debug is enough to make it observable without an invitation in
# non-interactive execution: verifies, and does not assumes.
        $debugOutput = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases -Debug 5>&1 | Out-String

        $debugOutput | Should -Not -Match 'MOCK-EPM-PASSWORD'
    }

    It 'Does not display the password either in Debug or in Verbose combinations' {
        # The two flows at once: a trace may only exist when both switches are placed together.
        $whole = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases -Debug -Verbose 5>&1 4>&1 | Out-String

        $whole | Should -Not -Match 'MOCK-EPM-PASSWORD'
    }

    It 'Produces valid output to inspect under -Debug' {
        $whole = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases -Debug -Verbose 5>&1 4>&1 | Out-String

        $whole | Should -Match 'Auth/EPM/Logon'
    }
}

Describe 'The EPM request log does not expose secrets' {

    AfterEach { Disconnect-EpmTenant }

    It 'Does not display the password in any entry of the log' {
        # The mock server logs EPM calls so that the tests can prove what went wrong. A log that would
# retain the VALUES would be exactly the leak it is used to exclude.
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $log = (Invoke-RestMethod -Uri $script:Log) | ConvertTo-Json -Depth 10

        $log | Should -Not -Match 'MOCK-EPM-PASSWORD'
    }

    It 'Does not display any token in the log' {
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $log = (Invoke-RestMethod -Uri $script:Log) | ConvertTo-Json -Depth 10

        $log | Should -Not -Match 'MOCK-EPM-TOKEN'
    }

    It 'Does not display any user names in the log' {
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $log = (Invoke-RestMethod -Uri $script:Log) | ConvertTo-Json -Depth 10

        $log | Should -Not -Match 'mock-epm-user'
    }

    It 'Logs the Password key name, proving that the request body was inspected' {
        # Without this assertion, an empty request log would pass every disclosure check above. The
        # key name Password must be present while its value remains absent: names, never values.
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $inputs = @((Invoke-RestMethod -Uri $script:Log).requests |
                Where-Object { $_.path -eq '/EPM/API/Auth/EPM/Logon' })

        @($inputs)[-1].bodyKeys | Should -Contain 'Password'
    }

    It 'Logs authentication presence as a boolean rather than a value' {
        # authExact says "the received value is the expected one" without ever writing the token. A log that
# would store the raw header would be more informative and much more dangerous.
        Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases | Out-Null

        $inputs = @((Invoke-RestMethod -Uri $script:Log).requests |
                Where-Object { $_.path -eq '/EPM/API/Sets' })

        @($inputs)[-1].authExact | Should -BeOfType [bool]
    }
}

Describe 'No hardcoded identifier in the repository' {

    BeforeAll {
        # The MANDATE pattern, taken from the SentinelOne test and adapted to the EPM header. The first
# character after the space must be alphanumeric: this is what distinguishes a hard token from a
# legitimate code. "basic $(ConvertFrom-SecureString ...)" starts with a dollar sign and is
# therefore ignored, correctly. Underscores and hyphens remain allowed within the token,
# which real tokens often contain.
        $script:TokenPattern = 'basic\s+[A-Za-z0-9][A-Za-z0-9_-]{7,}'

        # A hard password does not look like anything special: we cannot recognize it by its form. What can
# be recognized is its ASSIGNMENT to a field that bears its name, with a literal for value. The
# dollar excluded after the quotation marks allows "Password =
# $Credential.GetNetworkCredential().Password" to pass through.
        #
        # The variable is called MotifMdp and not MotifMotDePasse: under the latter name, the line
        # declaration of the pattern could match itself and be reported as a hardcoded
        # password. A pattern that matches itself is a permanent false positive, so this test
        # eventually end up deactivating.
        $script:PasswordPattern = '(?i)(password|pwd|secret|motdepasse)\s*=\s*[''"][^''"$]'

        $script:Files = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..') -Filter '*.ps1' -Recurse -File)
    }

    It 'Scans a non-empty file set so the checks cannot pass vacuously' {
        # A renamed path would make the collection empty and every control in this Describe block pass
        # without reading anything. A wrong file count would expose that regression.
        $script:Files.Count | Should -BeGreaterThan 30
    }

    It 'Detects a hardcoded token: <_>' -ForEach @(
        "Authorization = 'basic|AbCdEf0123456789'",
        'Authorization = "basic|MOCK-EPM-TOKEN"',
        '$auth -ne ''basic|a1b2c3d4-e5f6-7890''',
        '@{ Authorization = "basic|TOKEN_AVEC_UNDERSCORE" }',
        'basic|Zx9Kq2Lm7Pw4'
    ) {
        # The samples have a vertical bar where the space goes, and it is replaced HERE. Without this
# precaution, this test file would also contain strings of the form "basic <token>" and would fail
# its own scan of the repository.
        ($_ -replace '\|', ' ') | Should -Match $script:TokenPattern
    }

    It 'Ignores legitimate token-handling code: <_>' -ForEach @(
        'Authorization = "basic|$(ConvertFrom-SecureString -SecureString $state.Token -AsPlainText)"',
        'Authorization = "basic|$jeton"',
        '# ce n est pas de l authentification HTTP Basic|(avec majuscule)',
        '$enTete = ''basic|'' + $valeur',
        'basic|court'
    ) {
        # The French samples are intentional multilingual scanner coverage, not public-facing prose.
        # Cases 1 and 2 read a variable rather than a literal. Case 3 is prose, case 4 uses
        # concatenation, and case 5 is shorter than the minimum token length.
        #
        # This is the meaning of this list: the previous version of the SentinelOne control required
        # an APOSTROPHE AFTER the schema name and no longer caught ANYTHING, not even a real leak,
        # because in a header the APOSTROPHE PRECEDES the schema. A pattern is not validated by
        # reading it.
        ($_ -replace '\|', ' ') | Should -Not -Match $script:TokenPattern
    }

    It 'Detects a hardcoded password assignment: <_>' -ForEach @(
        'Password = |MonMotDePasse123|',
        'Password=|p4ssw0rd|',
        'Secret = |abcdef|',
        'Pwd = |quelquechose|'
    ) {
        # Same masking as for the token samples, this time for the quotation mark: written as they are, these four
# samples would be real hardcoded password assignments in the repository scan, and this file would
# fail its own control.
        ($_ -replace '\|', "'") | Should -Match $script:PasswordPattern
    }

    It 'Ignores legitimate password-handling code: <_>' -ForEach @(
        'Password      = $Credential.GetNetworkCredential().Password',
        'Password = $motDePasse',
        '$motDePasse  = [string]$epmBody.Password'
    ) {
        $_ | Should -Not -Match $script:PasswordPattern
    }

    It 'Finds no hardcoded token in ./src' {
        # Zero tolerance in production code. The mock server must know the token it expects because it is a
        # fixture rather than a secret. The following control enforces that distinction.
        $src = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..' 'src') -Filter '*.ps1' -Recurse -File)
        $offenders = [System.Collections.Generic.List[string]]::new()

        foreach ($file in $src) {
            $n = 0
            foreach ($row in Get-Content -Path $file.FullName -ErrorAction Stop) {
                $n++
                if ($row -match $script:TokenPattern) { $offenders.Add("$($file.Name):$n") }
            }
        }

        $offenders | Should -Be @()
    }

    It 'Finds no hardcoded password in ./src' {
        $src = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..' 'src') -Filter '*.ps1' -Recurse -File)
        $offenders = [System.Collections.Generic.List[string]]::new()

        foreach ($file in $src) {
            $n = 0
            foreach ($row in Get-Content -Path $file.FullName -ErrorAction Stop) {
                $n++
                if ($row -match $script:PasswordPattern) { $offenders.Add("$($file.Name):$n") }
            }
        }

        $offenders | Should -Be @()
    }

    It 'Finds no undocumented token value in repository PowerShell files' {
        # The entire repository, including tests. The rule is not "zero occurrence" (the mock server must know
# the token it is waiting for) but "no UNKNOWN identifier": a real token sticking in a test file is
# exactly the escape method that this control must catch and exclude. /tests from the scan would let
# it pass.
        $allowed = @('basic MOCK-EPM-TOKEN')
        $offenders   = [System.Collections.Generic.List[string]]::new()

        foreach ($file in $script:Files) {
            $n = 0
            foreach ($row in Get-Content -Path $file.FullName -ErrorAction Stop) {
                $n++
                if ($row -match $script:TokenPattern -and $allowed -notcontains $Matches[0]) {
                    $offenders.Add("$($file.Name):$n [$($Matches[0])]")
                }
            }
        }

        $offenders | Should -Be @()
    }

    It 'Finds no undocumented password value in repository PowerShell files' {
        # The only values tolerated are documented FIXTURES from the mock server. BAD-PASSWORD is actually
# part of it: it is the deliberately false password with which EpmMockAuth.Tests.ps1 causes a 401.
# The list is short and explicitly named so that a new value fails the test instead of blending in
# with the background.
        $allowed = @('MOCK-EPM-PASSWORD', 'MOCK-S1-TOKEN', 'MOCK-EPM-TOKEN', 'BAD PASSWORD')
        $offenders   = [System.Collections.Generic.List[string]]::new()

        foreach ($file in $script:Files) {
            $n = 0
            foreach ($row in Get-Content -Path $file.FullName -ErrorAction Stop) {
                $n++
                if ($row -match $script:PasswordPattern) {
                    $candidateValue = ''
                    if ($row -match '(?i)(?:password|pwd|secret|motdepasse)\s*=\s*[''"]([^''"]*)') {
                        $candidateValue = $Matches[1]
                    }
                    if ($allowed -notcontains $candidateValue) {
                        $offenders.Add("$($file.Name):$n [$candidateValue]")
                    }
                }
            }
        }

        $offenders | Should -Be @()
    }
}

Describe 'The object returned by Connect-EpmTenant does not carry the token' {

    AfterEach { Disconnect-EpmTenant }

    It 'Does not display the token in any value of the returned object' {
        $returnValue = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases

        ($returnValue | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-EPM-TOKEN'
    }

    It 'Does not display the token in any list rendering of the returned object' {
        # Format-List and ConvertTo-Json do not do the same things: the first calls type converters, the
# second serializes properties. A secret can come out from one without coming out from the other.
        $returnValue = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases

        ($returnValue | Format-List | Out-String) | Should -Not -Match 'MOCK-EPM-TOKEN'
    }

    It 'Does not return any property whose name refers to a token or secret' {
        # A token stored in a SecureString would not be output in JSON or Format-List: both controls above
# would completely miss it. The NAME of the property, however, remains visible. A Token property on
# a returned object has no reason to exist: the token lives in the private state of the module, not
# in a return value that the caller can log.
        $returnValue = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases

        @($returnValue.PSObject.Properties.Name |
                Where-Object { $_ -match 'Token|Secret|Password|Credential|Token' }).Count |
            Should -Be 0
    }

    It 'Returns an object so the preceding checks are meaningful' {
        # An object without ownership would pass all three controls above.
        $returnValue = Connect-EpmTenant -DispatcherUri $script:Base -Credential $script:ValidCases

        @($returnValue.PSObject.Properties.Name) | Should -Contain 'ManagerUri'
    }
}
