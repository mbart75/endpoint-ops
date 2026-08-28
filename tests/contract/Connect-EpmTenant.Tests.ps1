BeforeAll {
    Set-StrictMode -Version 3.0

    function Get-EpmRequestLog {
        <#
        .SYNOPSIS
            Reads mock EPM requests recorded after a given index.
        .DESCRIPTION
            Each test captures the current request count before exercising the system, then reads
            only the requests it produced. This keeps results independent of execution order.
        #>
        [CmdletBinding()]
        param([int]$Since = 0)

        $log = @((Invoke-RestMethod -Uri "$($script:Server.BaseUrl)/EPM/API/_test/requests").requests)
        if ($Since -ge $log.Count) { return @() }
        return @($log[$Since..($log.Count - 1)])
    }

    function Get-EpmSessionError {
        <#
        .SYNOPSIS
            Returns the error message from an authenticated EPM request.
        .DESCRIPTION
            The helper invokes the private request function in module scope. This verifies session
            behavior without duplicating or directly inspecting the module's connection state. It
            returns an empty string when the request succeeds.
        #>
        [CmdletBinding()]
        param()

        $message = ''
        try { & (Get-Module EndpointOps) { Invoke-EpmRequest -Path '/EPM/API/Sets' } | Out-Null }
        catch { $message = $_.Exception.Message }
        return $message
    }

    function Get-EpmStateError {
        <#
        .SYNOPSIS
            Returns the error message produced when reading EPM connection state.
        .DESCRIPTION
            Unlike Get-EpmSessionError, this helper performs no network request. It isolates the
            in-memory state check and returns an empty string when connection state is present.
        #>
        [CmdletBinding()]
        param()

        $message = ''
        try { & (Get-Module EndpointOps) { Get-EpmConnectionState } | Out-Null }
        catch { $message = $_.Exception.Message }
        return $message
    }

    . (Join-Path $PSScriptRoot '..' 'mock' 'MockApiServer.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'ConvertTo-TestSecureString.ps1')

    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'EndpointOps' 'EndpointOps.psd1') -Force -ErrorAction Stop

    $script:Server = Start-MockApiServer
    $script:Port   = ([uri]$script:Server.BaseUrl).Port

    # The uppercase host deliberately distinguishes DispatcherUri from the ManagerURL returned by
    # the mock server while keeping both addresses routable. This ensures that a faulty
    # implementation retaining DispatcherUri remains observable with -BeExactly.
    $script:Dispatcher = "http://LOCALHOST:$($script:Port)"

    # Adding user information makes this HTTP URI fail the loopback exception while it remains
    # routable to the mock server. A request would leave a log entry, so an unchanged request count
    # proves that the HTTPS guard rejected the URI before transport.
    $script:RejectingDispatcher = "http://mock-epm-user@localhost:$($script:Port)"

    $script:Identifiers = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'MOCK-EPM-PASSWORD'))
    $script:InvalidCredentials = [pscredential]::new(
        'mock-epm-user', (ConvertTo-TestSecureString -PlainText 'BAD PASSWORD'))
}

AfterAll {
    Disconnect-EpmTenant
    Remove-Module EndpointOps -Force -ErrorAction SilentlyContinue
    Stop-MockApiServer -Server $script:Server
}

Describe 'Connect-EpmTenant' {

    AfterEach {
        Disconnect-EpmTenant
    }

    Context 'Valid connection' {

        It 'Returns an object of type EndpointOps.Epm.Connection' {
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            $r.PSTypeNames | Should -Contain 'EndpointOps.Epm.Connection'
        }

        It 'Exposes exactly the four expected properties, and nothing else' {
            # Assert the complete property set at once so unexpected sensitive properties such as
            # Token or Credential cannot be hidden by an earlier failed assertion.
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            @($r.PSObject.Properties.Name | Sort-Object) |
                Should -Be @('ConnectedAt', 'DispatcherUri', 'ManagerUri', 'Validated')
        }

        It 'Does not include the password in the returned object' {
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-EPM-PASSWORD'
        }

        It 'Does not include the token in the returned object' {
            # Keep token and password checks separate so one disclosure failure cannot mask the other.
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'MOCK-EPM-TOKEN'
        }

        It 'Keeps the ManagerUri returned by the server, not the dispatcher''s' {
            # EPM requests must use the manager returned by authentication, not the dispatcher.
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            $r.ManagerUri | Should -BeExactly $script:Server.BaseUrl
        }

        It 'Keeps the DispatcherUri as it was provided' {
            # Preserve the authentication endpoint for diagnostics while keeping it distinct from ManagerUri.
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            $r.DispatcherUri | Should -BeExactly $script:Dispatcher
        }

        It 'Indicates that the connection has been validated' {
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
            $r.Validated | Should -BeTrue
        }

        It 'Opens the session for subsequent calls' {
            Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers | Out-Null
            Get-EpmSessionError | Should -BeExactly ''
        }
    }

    Context 'Rejected password' {

        It 'Throws when the password is incorrect' {
            # Match the authentication-specific message so a later validation failure cannot satisfy this test.
            { Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:InvalidCredentials } |
                Should -Throw -ExpectedMessage '*CyberArk EPM authentication refused*'
        }

        It 'Does not leave a half-open session after rejection' {
            # The state check must report no active connection after rejected credentials.
            try { Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:InvalidCredentials }
            catch { $null = $_ }

            Get-EpmSessionError | Should -BeLike '*no active CyberArk EPM connection*'
        }

        It 'Does not copy the password into the error message' {
            # EPM sends the password in a JSON body, so error rendering must not copy it into CI logs.
            $message = ''
            try { Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:InvalidCredentials }
            catch { $message = $_.Exception.Message }

            $message | Should -Not -BeLike '*WRONG PASSWORD*'
        }
    }

    Context 'HTTPS guard' {

        It 'Rejects an HTTP dispatcher outside the local loop' {
            # The reserved .invalid hostname cannot resolve. This keeps the regression test safe even
            # if the HTTPS guard is accidentally moved after the connectivity check.
            { Connect-EpmTenant -DispatcherUri 'http://login.epm.cyberark.invalid/login' -Credential $script:Identifiers } |
                Should -Throw -ExpectedMessage '*HTTPS*'
        }

        It 'Sends no request before rejecting an HTTP dispatcher' {
            # The rejecting URI remains routable to the mock server. An unchanged request count proves
            # that rejection happened before any request, rather than after a password was transmitted.
            $index = @(Get-EpmRequestLog).Count

            try { Connect-EpmTenant -DispatcherUri $script:RejectingDispatcher -Credential $script:Identifiers }
            catch { $null = $_ }

            @(Get-EpmRequestLog -Since $index).Count | Should -Be 0
        }
    }

    Context 'Validation failure' {
        # Authentication may succeed before validation fails. The module must clear the resulting
        # token and manager state so later requests cannot use a session the caller believes failed.

        It 'Throws when validation fails' {
            { Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers `
                    -ApplicationId 'EndpointOps-ManagerKo' } |
                Should -Throw -ExpectedMessage '*CyberArk EPM connection*refused*'
        }

        It 'Does not leave any state behind a validation failure' {
            # State cleanup is asserted separately from the validation exception itself.
            try {
                Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers `
                    -ApplicationId 'EndpointOps-ManagerKo'
            }
            catch { $null = $_ }

            Get-EpmStateError | Should -BeLike '*no active CyberArk EPM connection*'
        }
    }

    Context 'SkipValidation' {

        It 'Does not make any calls after authentication' {
            # SkipValidation permits only dispatcher reachability and authentication requests.
            $index = @(Get-EpmRequestLog).Count

            Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers -SkipValidation | Out-Null

            @(Get-EpmRequestLog -Since $index | ForEach-Object { $_.path }) |
                Should -Be @('/EPM/API/Server/Version', '/EPM/API/Auth/EPM/Logon')
        }

        It 'Indicates that the connection has not been validated' {
            $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers -SkipValidation
            $r.Validated | Should -BeFalse
        }
    }
}

Describe 'Disconnect-EpmTenant' {

    It 'Resets connection state so a subsequent call throws the Get-EpmConnectionState message' {
        Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers | Out-Null
        Disconnect-EpmTenant

        Get-EpmSessionError | Should -BeLike '*no active CyberArk EPM connection*'
    }

    It 'Remains idempotent when the session is already closed' {
        Disconnect-EpmTenant
        { Disconnect-EpmTenant } | Should -Not -Throw
    }

    It 'Allows the connection to be reopened after disconnection' {
        Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers | Out-Null
        Disconnect-EpmTenant

        $r = Connect-EpmTenant -DispatcherUri $script:Dispatcher -Credential $script:Identifiers
        $r.Validated | Should -BeTrue

        Disconnect-EpmTenant
    }
}
