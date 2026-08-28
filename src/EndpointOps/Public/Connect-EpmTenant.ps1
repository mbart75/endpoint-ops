function Connect-EpmTenant {
    <#
    .SYNOPSIS
        Opens a CyberArk EPM session for the module.
    .DESCRIPTION
        Authentication is sent to the dispatcher, which returns both a token and a ManagerURL.
        Subsequent API calls use that ManagerURL, so the connection retains both endpoints.

        The credentials are stored in a PSCredential rather than two parameters: a password passed in
        a string would end up in the session history, and in a file on disk.

        HTTPS is required except for loopback addresses, which allows mock server tests to run
        without a certificate while preventing clear-text password transmission over a network.

        By default, the connection is immediately validated by a single-item request.
        -SkipValidation bypasses this check.

        The module does not reconnect automatically after a 401 response. CyberArk allows only one
        connection per user per minute, so an immediate retry would hide the cause and likely fail.
    .EXAMPLE
        $credential = Get-Credential
        Connect-EpmTenant -DispatcherUri 'https://login.epm.cyberark.com/login' -Credential $credential
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DispatcherUri,
        [Parameter(Mandatory)][ValidateNotNull()][pscredential]$Credential,
        [string]$ApplicationId = 'EndpointOps',
        [switch]$SkipValidation
    )

    $normalized = $DispatcherUri.TrimEnd('/')
    $isLoopback = $normalized -match '^http://(localhost|127\.0\.0\.1)(:\d+)?$'

    # Perform this check BEFORE any network call. Performing it later would raise the same error only
    # after the password had already been sent in clear text.
    if (-not $isLoopback -and $normalized -notmatch '^https://') {
        throw "EndpointOps: DispatcherUri must use HTTPS ('$DispatcherUri'). A password must not be sent in clear text."
    }

    # Check dispatcher availability without authentication so credentials are never sent to an
    # unreachable or unexpected host.
    try {
        $null = Invoke-EndpointOpsRequest -Uri "$normalized/EPM/API/Server/Version"
    }
    catch {
        throw "EndpointOps: CyberArk EPM dispatcher unreachable at $normalized ($($_.Exception.Message)). No credentials were sent."
    }

    # Keep the password only for the duration of this call. Unlike a SentinelOne token, it travels
    # in a JSON body and is therefore more likely to be copied into an error or verbose trace.
    $payload = @{
        Username      = $Credential.UserName
        Password      = $Credential.GetNetworkCredential().Password
        ApplicationID = $ApplicationId
    } | ConvertTo-Json -Compress

    try {
        $response = Invoke-EndpointOpsRequest -Uri "$normalized/EPM/API/Auth/EPM/Logon" -Method 'Post' -Body $payload -Headers @{ 'Content-Type' = 'application/json' }
    }
    catch {
        # Rephrase the original message without including the submitted body; the transport layer reports
        # only the method, URL, and status.
        throw "EndpointOps: CyberArk EPM authentication refused on $normalized ($($_.Exception.Message)). CyberArk only allows one connection per minute and per user: wait a minute before trying again."
    }
    finally {
        $payload = $null
        [System.GC]::Collect()
    }

    # Read defensively: under Set-StrictMode, accessing a missing property raises an error that does not
    # identify the missing property. An incomplete authentication response is a realistic failure case.
    $managerUrl = Get-PropertyOrDefault -InputObject $response -Name 'ManagerURL'
    $tokenText      = Get-PropertyOrDefault -InputObject $response -Name 'EPMAuthenticationResult'

    if (-not $managerUrl) {
        throw "EndpointOps: EPM authentication response is incomplete: ManagerURL is missing or empty, so subsequent requests cannot be sent."
    }
    if (-not $tokenText) {
        throw "EndpointOps: EPM authentication response is incomplete: EPMAuthenticationResult is missing or empty, so no token was returned."
    }

    # Continuing with an expired password would produce unclear 401 errors on subsequent calls.
    if (Get-PropertyOrDefault -InputObject $response -Name 'IsPasswordExpired' -Default $false) {
        throw "EndpointOps: the password for the $($Credential.UserName) account has expired on CyberArk EPM. Change it before trying again."
    }

    # Build the SecureString one character at a time. This avoids suppressing the analyzer rule that
    # correctly flags ConvertTo-SecureString -AsPlainText -Force.
    $secureToken = [System.Security.SecureString]::new()
    foreach ($character in ([string]$tokenText).ToCharArray()) {
        $secureToken.AppendChar($character)
    }
    $secureToken.MakeReadOnly()

    $managerUri  = ([string]$managerUrl).TrimEnd('/')
    $connectionTimestamp  = Get-Date

    $script:EpmConnection = [pscustomobject]@{
        DispatcherUri = $normalized
        ManagerUri    = $managerUri
        Token         = $secureToken
        ConnectedAt   = $connectionTimestamp
    }

    if (-not $SkipValidation) {
        try {
            # Validate with a single-item request to the endpoint confirmed in docs/api-notes-epm.md
            # instead of inventing a health endpoint.
            $null = Invoke-EpmRequest -Path '/EPM/API/Sets' -Query @{ offset = 0; limit = 1 }
        }
        catch {
            # Do not leave a connection half open behind a failure.
            $script:EpmConnection = $null
            throw "EndpointOps: CyberArk EPM connection to $managerUri refused ($($_.Exception.Message))"
        }
    }

    return [pscustomobject]@{
        PSTypeName    = 'EndpointOps.Epm.Connection'
        DispatcherUri = $normalized
        ManagerUri    = $managerUri
        ConnectedAt   = $connectionTimestamp
        Validated     = -not $SkipValidation
    }
}
