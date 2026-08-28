#Requires -Version 7.2

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }
}

function Start-MockApiServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Test utility: asking for confirmation to start a mock server would block the rest of the tests.')]
    [CmdletBinding()]
    param([int]$Port = (Get-FreeTcpPort))

    # PSUseUsingScopeModifierInNewRunspaces (PSScriptAnalyzer 1.25.0) reports a false positive for
    # a Start-Job param() block. Reading the ArgumentList value from $args avoids that diagnostic.
    #
    # The analyzer rule does not detect payload values captured through either form, so it is not a
    # security boundary. Secret-disclosure tests provide the relevant protection.
    $job = Start-Job -ArgumentList $Port -ScriptBlock {
        $Port = $args[0]

        function Send-Json {
            $Context      = $args[0]
            $Object       = $args[1]
            $Status       = if ($args.Count -gt 2) { $args[2] } else { 200 }
            $ExtraHeaders = if ($args.Count -gt 3) { $args[3] } else { @{} }

            $json  = $Object | ConvertTo-Json -Depth 10 -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $Context.Response.StatusCode  = $Status
            $Context.Response.ContentType = 'application/json'
            foreach ($key in $ExtraHeaders.Keys) {
                $Context.Response.Headers.Add($key, $ExtraHeaders[$key])
            }
            $Context.Response.ContentLength64 = $bytes.Length
            try {
                $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            }
            finally {
                $Context.Response.OutputStream.Close()
            }
        }

        function Test-MockAuthHeader {
            # Authentication schemes are case-insensitive, while token values are case-sensitive.
            #
            # Comparing the entire header with -ne accepted 'basic
            # mock-epm-token': a mock server that validates a mock secret no longer verifies the
            # constraint that contract tests believe to verify. Comparing the entire header with
            # -cne would have refused 'Basic MOCK-EPM-TOKEN', while RFC 7235 explicitly states that
            # the schema is case insensitive.
            #
            # Split at the first space, then compare the scheme with -ne and the token with -cne.
            $Header = $args[0]
            $Scheme = $args[1]
            $Token  = $args[2]

            if ([string]::IsNullOrEmpty($Header)) { return $false }

            $cutoff = $Header.IndexOf(' ')
            if ($cutoff -lt 1) { return $false }

            $receivedScheme = $Header.Substring(0, $cutoff)
            $receivedToken  = $Header.Substring($cutoff + 1)

            return ($receivedScheme -eq $Scheme) -and ($receivedToken -ceq $Token)
        }

        $listener = [System.Net.HttpListener]::new()
        # Local loop only. Never replace with + or *: the server would listen on all interfaces.
        $listener.Prefixes.Add("http://localhost:$Port/")
        $listener.Start()

        # Call counters: this is what allows a route to fail the first times and then succeed.
        $counters = @{ throttled = 0; flaky = 0 }

        # Count requests by path. Direct counts are stable across machine load, cold starts, and CI variance.
        #
        # Retain only path and count, never headers, bodies, or query strings.
        $hits = @{}

        # Record movement requests so tests can distinguish real execution from -WhatIf.
        $moves = [System.Collections.Generic.List[object]]::new()

        # The EPM log retains received key names, never values, so disclosure checks do not create a leak.
        $epmRequests = [System.Collections.Generic.List[object]]::new()

        # Reputation requests retain only an observable route contract. The
        # API key is never retained: authExact is enough for tests to prove
        # that the client emitted the expected value without creating a leak.
        $reputationRequests = [System.Collections.Generic.List[object]]::new()

        try {
            while ($listener.IsListening) {
                $context = $listener.GetContext()
                $path    = $context.Request.Url.AbsolutePath

                # Count before routing so rejected and unknown requests remain observable.
                #
                # The route of introspection itself is excluded: reading it should not change what it
                # reports.
                if ($path -ne '/_test/hits') {
                    if (-not $hits.ContainsKey($path)) { $hits[$path] = 0 }
                    $hits[$path]++
                }

                # SentinelOne routes require authentication; generic transport routes remain open to
                # keep retry and pagination failures independent. Match route prefixes without case
                # sensitivity so the guard covers the same surface as the router.
                $isS1Route = $path.StartsWith('/web/api/v2.1/', [StringComparison]::OrdinalIgnoreCase)
                $authValue = $context.Request.Headers['Authorization']

                if ($isS1Route -and -not (Test-MockAuthHeader $authValue 'ApiToken' 'MOCK-S1-TOKEN')) {
                    Send-Json $context @{
                        errors = @(@{ code = 4010010; detail = 'Authentication required'; title = 'Unauthorized' })
                    } 401
                    continue
                }

                # VirusTotal uses a distinct guard: its path does not overlap
                # either product API and its key is sent in x-apikey.
                $isVtRoute = $path.StartsWith('/api/v3/', [StringComparison]::OrdinalIgnoreCase)
                if ($isVtRoute) {
                    $vtApiKey = $context.Request.Headers['x-apikey']
                    $reputationRequests.Add(@{
                        path      = $path
                        method    = $context.Request.HttpMethod
                        authExact = ($vtApiKey -ceq 'MOCK-VT-KEY')
                    })

                    if (-not ($vtApiKey -ceq 'MOCK-VT-KEY')) {
                        Send-Json $context @{ error = @{ code = 'AuthenticationRequiredError' } } 401
                        continue
                    }

                    if ($path.StartsWith('/api/v3/files/', [StringComparison]::OrdinalIgnoreCase)) {
                        $hash = $path.Substring('/api/v3/files/'.Length)
                        switch ($hash) {
                            { $_ -ieq (('A' * 38) + '01') } {
                                Send-Json $context @{ data = @{ attributes = @{
                                    md5 = (('A' * 30) + '01'); sha1 = $hash; sha256 = (('A' * 62) + '01')
                                    last_analysis_stats = @{ malicious = 0; harmless = 60; undetected = 12 }
                                } } }
                            }
                            { $_ -ieq (('B' * 38) + '02') } { Send-Json $context @{ error = @{ code = 'NotFoundError' } } 404 }
                            { $_ -ieq (('C' * 38) + '03') } {
                                Send-Json $context @{ data = @{ attributes = @{
                                    md5 = (('C' * 30) + '03'); sha1 = $hash; sha256 = (('C' * 62) + '03')
                                    last_analysis_stats = @{ malicious = 8; harmless = 40; suspicious = 2 }
                                } } }
                            }
                            { $_ -ieq (('D' * 38) + '04') } {
                                Send-Json $context @{ data = @{ attributes = @{
                                    md5 = (('D' * 30) + '04'); sha1 = $hash; sha256 = (('D' * 62) + '04')
                                    last_analysis_stats = @{ malicious = 1; harmless = 68; undetected = 5 }
                                } } }
                            }
                            { $_ -ieq (('F' * 38) + '06') } { Send-Json $context @{ error = @{ code = 'QuotaExceededError' } } 429 }
                            { $_ -ieq (('0' * 38) + '07') } { Send-Json $context @{ error = @{ code = 'BadRequestError' } } 400 }
                            { $_ -ieq (('1' * 38) + '08') } { Send-Json $context @{ error = @{ code = 'InternalServerError' } } 500 }
                            default { Send-Json $context @{ error = @{ code = 'NotFoundError' } } 404 }
                        }
                        continue
                    }

                    if ($path.StartsWith('/api/v3/urls/', [StringComparison]::Ordinal)) {
                        $urlId = $path.Substring('/api/v3/urls/'.Length)
                        switch -CaseSensitive ($urlId) {
                            'aHR0cHM6Ly9tYWx3YXJlLmV4YW1wbGUuaW52YWxpZC9-cGF5bG9hZD94PTE' {
                                Send-Json $context @{ data = @{ id = $urlId; attributes = @{
                                    last_analysis_stats = @{ malicious = 6; harmless = 42; suspicious = 2 }
                                } } }
                            }
                            'aHR0cHM6Ly91bmtub3duLmV4YW1wbGUuaW52YWxpZC8_YWE' {
                                Send-Json $context @{ error = @{ code = 'NotFoundError' } } 404
                            }
                            'aHR0cHM6Ly9jbGVhbi5leGFtcGxlLmludmFsaWQvfmRvd25sb2FkP2FhPTE' {
                                Send-Json $context @{ data = @{ id = $urlId; attributes = @{
                                    last_analysis_stats = @{ malicious = 0; harmless = 60; undetected = 12 }
                                } } }
                            }
                            'aHR0cHM6Ly9xdW90YS5leGFtcGxlLmludmFsaWQvP2Fh' {
                                Send-Json $context @{ error = @{ code = 'QuotaExceededError' } } 429
                            }
                            'aHR0cHM6Ly9mYWlsdXJlLmV4YW1wbGUuaW52YWxpZC9-eA' {
                                Send-Json $context @{ error = @{ code = 'InternalServerError' } } 500
                            }
                            default { Send-Json $context @{ error = @{ code = 'NotFoundError' } } 404 }
                        }
                        continue
                    }
                }

                # EPM routes have their own guard, distinct from that of SentinelOne: the expected header is not the
# same, and the dispatcher exposes two open entry points. Insensitive to crashes, for the same
# reason as the S1 guard above. The comparisons -eq that follow are already: it is the default
# behavior of PowerShell.
                $isEpmRoute = $path.StartsWith('/EPM/API/', [StringComparison]::OrdinalIgnoreCase)
                # Version control is the only open EPM entry point: it is the dispatcher's availability test, it
# precedes sending a password. The logon is also necessary because it returns the token.
                $isEpmOpen  = $path -eq '/EPM/API/Server/Version' -or $path -eq '/EPM/API/Auth/EPM/Logon'

                # The route of introspection remains out of the guard, and this is not an omission: what it serves to
# prove is that a password has not leaked, including after a rejected logon. In this case, no
# token exists. Requiring it would make control impossible where it counts most.
                $isEpmTestRoute = $path -eq '/EPM/API/_test/requests'

                # The body is read HERE, only once: the input stream is not reread. The following route works on the
# already read object.
                $epmBody = $null
                if ($isEpmRoute -and -not $isEpmTestRoute) {
                    $rawEpm = ''
                    if ($context.Request.HasEntityBody) {
                        $epmReader = [System.IO.StreamReader]::new($context.Request.InputStream, $context.Request.ContentEncoding)
                        try   { $rawEpm = $epmReader.ReadToEnd() }
                        finally { $epmReader.Dispose() }
                    }
                    # An unreadable body is an INVALID REQUEST, not a server failure. Without this try/catch, the
# exception crosses the listening loop to the finally, which stops and closes the listener: a
# NON-authenticated caller would then kill the server in the middle of a series of tests, since this
# block executes before the authentication guard.
                    $unreadableBody = $false
                    if ($rawEpm) {
                        try {
                            $epmBody = $rawEpm | ConvertFrom-Json -ErrorAction Stop
                        }
                        catch {
                            $unreadableBody = $true
                            $epmBody = $null
                        }
                    }

                    # bodyKeys is always a table, even for an unreadable body, because the request
                    # log is consumed under Set-StrictMode.
                    $epmKeys = @()
                    if ($epmBody) { $epmKeys = @($epmBody.PSObject.Properties.Name) }

                    # Query-string values are exposed only on test routes to verify offset and cursor
                    # sequences. Other routes record names only and never retain request values.
                    $epmRequest = @{}
                    if ($path.StartsWith('/EPM/API/_test/')) {
                        foreach ($parameterName in $context.Request.QueryString.AllKeys) {
                            if ($parameterName) { $epmRequest[$parameterName] = $context.Request.QueryString[$parameterName] }
                        }
                    }

                    # authExact is a BOOLEAN, not the header: it says that the value received is exactly the expected
# one, without ever writing a token to the log. The comparison is case-sensitive because the EPM doc
# writes 'basic' in lowercase, and an HTTP client that "helps" would send 'Basic'.
                    $epmHeader = $context.Request.Headers['Authorization']

                    # Journalize before the guard: a refused call is precisely the one that we want to be able to
# inspect.
                    $epmRequests.Add(@{
                        path      = $path
                        method    = $context.Request.HttpMethod
                        hadAuth   = $null -ne $epmHeader
                        authExact = ($epmHeader -ceq 'basic MOCK-EPM-TOKEN')
                        bodyKeys  = $epmKeys
                        query     = $epmRequest
                    })

                    if ($unreadableBody) {
                        Send-Json $context @{ ErrorMessage = 'Unreadable JSON body' } 400
                        continue
                    }
                }

                if ($isEpmRoute -and -not $isEpmOpen -and -not $isEpmTestRoute) {
                    $auth = $context.Request.Headers['Authorization']
                    if (-not (Test-MockAuthHeader $auth 'basic' 'MOCK-EPM-TOKEN')) {
                        Send-Json $context @{ ErrorMessage = 'Unauthorized' } 401
                        continue
                    }
                }

                switch ($path) {
                    '/health'       { Send-Json $context @{ status = 'ok' } }
                    '/always-fails' { Send-Json $context @{ error = 'boom' } 500 }

                    '/_test/redirect' {
                        $destination = $context.Request.QueryString['target']
                        $context.Response.StatusCode = 302
                        $context.Response.RedirectLocation = $destination
                        $context.Response.ContentLength64 = 0
                        $context.Response.OutputStream.Close()
                    }

                    '/echo-headers' {
                        $received = @{}
                        foreach ($name in $context.Request.Headers.AllKeys) {
                            $received[$name] = $context.Request.Headers[$name]
                        }
                        Send-Json $context $received
                    }

                    '/throttled' {
                        $counters.throttled++
                        if ($counters.throttled -eq 1) {
                            Send-Json $context @{ error = 'rate limited' } 429 @{ 'Retry-After' = '1' }
                        }
                        else {
                            Send-Json $context @{ ok = $true; attempts = $counters.throttled }
                        }
                    }

                    '/flaky' {
                        $counters.flaky++
                        if ($counters.flaky -le 2) {
                            Send-Json $context @{ error = 'transient' } 500
                        }
                        else {
                            Send-Json $context @{ ok = $true; attempts = $counters.flaky }
                        }
                    }

                    '/slow' {
                        Start-Sleep -Seconds 5
                        Send-Json $context @{ ok = $true }
                    }

                    '/agents' {
                        $cursor = $context.Request.QueryString['cursor']
                        if (-not $cursor) {
                            Send-Json $context @{
                                data       = @(
                                    @{ id = '1'; computerName = 'MOCK-PC-01' },
                                    @{ id = '2'; computerName = 'MOCK-PC-02' }
                                )
                                pagination = @{ nextCursor = 'Page 2' }
                            }
                        }
                        else {
                            # Real APIs may omit the pagination key on the last page. Under
                            # Set-StrictMode, the module must therefore read the cursor defensively.
                            Send-Json $context @{
                                data = @(@{ id = '3'; computerName = 'MOCK-PC-03' })
                            }
                        }
                    }

                    '/web/api/v2.1/agents' {
                        # Deliberately imperfect fixtures exercise the hygiene findings. osRevision
                        # carries the Windows patch level; osName is a product label, not patch
                        # status, and cannot distinguish the higher remediation tier by itself.
                        $agentIds = @(
                            # Healthy: the agent and Windows are up to date.
                            @{ id = '1001'; computerName = 'MOCK-WKS-01'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-24T09:12:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Windows 11 Pro'; osType = 'windows'; osRevision = '22631.4890'
                               siteName = 'MOCK-SITE-EU'; groupName = 'Workstations' }

                            # Tier 0: silent for almost three months and unavailable for remote remediation.
                            @{ id = '1002'; computerName = 'MOCK-WKS-02'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-05-02T14:03:00Z'; isActive = $false
                               isDecommissioned = $false; networkStatus = 'disconnected'
                               osName = 'Windows 10 Pro'; osType = 'windows'; osRevision = '19045.4046'
                               siteName = 'MOCK-SITE-EU'; groupName = 'Workstations' }

                            # Decommissioned in the console but active yesterday: an inconsistency the report must expose.
                            @{ id = '1003'; computerName = 'MOCK-SRV-01'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-23T22:41:00Z'; isActive = $true
                               isDecommissioned = $true; networkStatus = 'connected'
                               osName = 'Windows Server 2019'; osType = 'windows'; osRevision = '17763.6414'
                               siteName = 'MOCK-SITE-EU'; groupName = 'Servers' }

                            # Tier 1: the agent is outdated, but Windows is current. Move it to a tracking group.
                            @{ id = '1004'; computerName = 'MOCK-WKS-03'; agentVersion = '21.7.1.120'
                               lastActiveDate = '2026-07-24T08:55:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Windows 11 Pro'; osType = 'windows'; osRevision = '22631.4890'
                               siteName = 'MOCK-SITE-EU'; groupName = 'Workstations' }

                            # Tier 2: both the agent and Windows are outdated. The report recommends
                            # human review before any restrictive policy change.
                            @{ id = '1005'; computerName = 'MOCK-WKS-04'; agentVersion = '21.7.1.120'
                               lastActiveDate = '2026-07-24T07:30:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Windows 10 Pro'; osType = 'windows'; osRevision = '19044.1288'
                               siteName = 'MOCK-SITE-EU'; groupName = 'Workstations' }

                            # Permissive group: recent use, should not be reported.
                            @{ id = '1006'; computerName = 'MOCK-WKS-10'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-24T08:00:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Windows 11 Pro'; osType = 'windows'; osRevision = '22631.4890'
                               siteName = 'MOCK-SITE-EU'; groupName = 'grp-permissive' }

                            # Permissive group: old use, alert level.
                            @{ id = '1007'; computerName = 'MOCK-WKS-11'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-24T08:00:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Windows 11 Pro'; osType = 'windows'; osRevision = '22631.4890'
                               siteName = 'MOCK-SITE-EU'; groupName = 'grp-permissive' }

                            # Permissive group: no use, removal level.
                            @{ id = '1008'; computerName = 'MOCK-WKS-12'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-24T08:00:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Windows 11 Pro'; osType = 'windows'; osRevision = '22631.4890'
                               siteName = 'MOCK-SITE-EU'; groupName = 'grp-permissive' }

                            # Device Control does not cover Linux: outside the report's scope.
                            @{ id = '1009'; computerName = 'MOCK-SRV-10'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-24T08:00:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'Ubuntu 22.04 LTS'; osType = 'linux'; osRevision = 'jammy'
                               siteName = 'MOCK-SITE-EU'; groupName = 'grp-permissive' }

                            # Allowlisted unknown system: outside the report's scope.
                            @{ id = '1010'; computerName = 'MOCK-XXX-10'; agentVersion = '23.4.2.350'
                               lastActiveDate = '2026-07-24T08:00:00Z'; isActive = $true
                               isDecommissioned = $false; networkStatus = 'connected'
                               osName = 'FreeBSD 14'; osType = 'freebsd'; osRevision = 'freebsd14'
                               siteName = 'MOCK-SITE-EU'; groupName = 'grp-permissive' }
                        )

                        $limit  = $context.Request.QueryString['limit']
                        $cursor = $context.Request.QueryString['cursor']

                        if ($limit) {
                            # The mock short-circuits pagination when limit is provided; connection
                            # validation needs only one item.
                            Send-Json $context @{
                                data       = @($agentIds | Select-Object -First ([int]$limit))
                                pagination = @{ totalItems = $agentIds.Count; nextCursor = $null }
                            }
                        }
                        elseif (-not $cursor) {
                            Send-Json $context @{
                                data       = @($agentIds[0..1])
                                pagination = @{ totalItems = $agentIds.Count; nextCursor = 'agents-p2' }
                            }
                        }
                        else {
                            # This route returns nextCursor as null while /agents omits the key. The
                            # transport must handle both common final-page representations.
                            Send-Json $context @{
                                data       = @($agentIds[2..($agentIds.Count - 1)])
                                pagination = @{ totalItems = $agentIds.Count; nextCursor = $null }
                            }
                        }
                    }

                    '/web/api/v2.1/device-control/events' {
                        # The detailed event schema remains to be confirmed against vendor behavior.
                        # These fixtures contain only fields required by the current read contract.
                        $events = @(
                            @{ id = 'evt-1006-01'; agentId = '1006'; groupId = 'grp-permissive'
                               siteId = 'MOCK-SITE-EU'; eventTime = '2026-07-19T09:00:00Z' }
                            @{ id = 'evt-1007-01'; agentId = '1007'; groupId = 'grp-permissive'
                               siteId = 'MOCK-SITE-EU'; eventTime = '2026-06-14T11:30:00Z' }
                        )

                        # The server does not record any SentinelOne request values: the filters may contain sensitive data.
# It applies them here, without logging them.
                        $utcFormat = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
                        $startBoundary = $null
                        $endBoundary = $null
                        $validBoundary = $true

                        foreach ($boundaryName in @('eventTime__gte', 'eventTime__lte')) {
                            $boundaryValue = $context.Request.QueryString[$boundaryName]
                            if ($boundaryValue) {
                                if ($boundaryValue -notmatch $utcFormat) {
                                    $validBoundary = $false
                                    break
                                }

                                try {
                                    $boundaryDate = [datetime]::ParseExact(
                                        $boundaryValue,
                                        "yyyy-MM-ddTHH:mm:ss'Z'",
                                        [cultureinfo]::InvariantCulture,
                                        [Globalization.DateTimeStyles]::AssumeUniversal)
                                }
                                catch {
                                    $validBoundary = $false
                                    break
                                }
                                if ($boundaryName -eq 'eventTime__gte') { $startBoundary = $boundaryDate }
                                else { $endBoundary = $boundaryDate }
                            }
                        }

                        if (-not $validBoundary) {
                            Send-Json $context @{ errors = @(@{ code = 4000010; detail = 'eventTime must be exact UTC'; title = 'Bad Request' }) } 400
                        }
                        else {
                            $groupIds = @()
                            $siteIds = @()
                            $calls = @()
                            if ($context.Request.QueryString['agentIds']) { $groupIds = @($context.Request.QueryString['agentIds'] -split ',') }
                            if ($context.Request.QueryString['groupIds']) { $siteIds = @($context.Request.QueryString['groupIds'] -split ',') }
                            if ($context.Request.QueryString['siteIds'])  { $calls = @($context.Request.QueryString['siteIds'] -split ',') }

                            $retained = @($events | Where-Object {
                                $eventDate = [datetime]::ParseExact(
                                    $_.eventTime,
                                    "yyyy-MM-ddTHH:mm:ss'Z'",
                                    [cultureinfo]::InvariantCulture,
                                    [Globalization.DateTimeStyles]::AssumeUniversal)
                                $keep = $true
                                if ($groupIds.Count -gt 0 -and $groupIds -notcontains $_.agentId) { $keep = $false }
                                if ($siteIds.Count -gt 0 -and $siteIds -notcontains $_.groupId) { $keep = $false }
                                if ($calls.Count -gt 0 -and $calls -notcontains $_.siteId) { $keep = $false }
                                if ($null -ne $startBoundary -and $eventDate -lt $startBoundary) { $keep = $false }
                                if ($null -ne $endBoundary -and $eventDate -gt $endBoundary) { $keep = $false }
                                $keep
                            })

                            if ($context.Request.QueryString['countOnly'] -ieq 'true') {
                                Send-Json $context @{ data = @(); pagination = @{ totalItems = $retained.Count; nextCursor = $null } }
                            }
                            else {
                                $pageSize = 1
                                $limit = $context.Request.QueryString['limit']
                                $validLimit = $true
                                if ($limit) {
                                    [int]$requestedLimit = 0
                                    if (-not [int]::TryParse($limit, [ref]$requestedLimit) -or $requestedLimit -lt 1 -or $requestedLimit -gt 1000) {
                                        $validLimit = $false
                                    }
                                    else { $pageSize = $requestedLimit }
                                }

                                $start = 0
                                $cursor = $context.Request.QueryString['cursor']
                                if ($cursor) {
                                    $match = [regex]::Match($cursor, '^events-(\d+)$')
                                    [int]$requestStart = 0
                                    if ($match.Success -and [int]::TryParse($match.Groups[1].Value, [ref]$requestStart)) {
                                        $start = $requestStart
                                    }
                                    else { $validLimit = $false }
                                }

                                if (-not $validLimit -or $start -gt $retained.Count) {
                                    Send-Json $context @{ errors = @(@{ code = 4000010; detail = 'Invalid pagination'; title = 'Bad Request' }) } 400
                                }
                                else {
                                    $batch = @()
                                    if ($start -lt $retained.Count) {
                                        $end = [Math]::Min($start + $pageSize, $retained.Count) - 1
                                        $batch = @($retained[$start..$end])
                                    }

                                    $next = $null
                                    if (($start + $pageSize) -lt $retained.Count) { $next = "events-$($start + $pageSize)" }
                                    Send-Json $context @{ data = @($batch); pagination = @{ totalItems = $retained.Count; nextCursor = $next } }
                                }
                            }
                        }
                    }

                    '/web/api/v2.1/exclusions' {
                        # CreatedBy and createdAt make the report actionable: reporting an unjustified exclusion
                        # without identifying a contact is a dead end. The 2004 case shows the real limit: a
                        # service account leaves an audit trail but does not identify a human contact.
                        Send-Json $context @{
                            data = @(
                                # Correct: precise hash, group scope, justified, traceable.
                                @{ id = '2001'; type = 'white_hash'; value = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
                                   osType = 'windows'; mode = 'suppress'; scopeLevel = 'group'
                                   scopeName = 'Workstations'; description = 'False positive publisher, ticket INC-1042'
                                   createdBy = 'alex.taylor@mock.invalid'; createdAt = '2026-03-14T10:22:00Z'
                                   updatedBy = 'alex.taylor@mock.invalid'; updatedAt = '2026-03-14T10:22:00Z' }

                                # Acceptable: precise application path with a justification.
                                @{ id = '2002'; type = 'path'; value = 'C:\Program Files\VendorApp\'
                                   osType = 'windows'; mode = 'suppress'; scopeLevel = 'group'
                                   scopeName = 'Workstations'; description = 'Application performance issue, ticket INC-1103'
                                   createdBy = 'alex.taylor@mock.invalid'; createdAt = '2026-04-02T16:40:00Z'
                                   updatedBy = 'jordan.lee@mock.invalid'; updatedAt = '2026-06-11T09:05:00Z' }

                                # Much too broad: a drive root without justification. The known author
                                # gives reviewers a contact for follow-up.
                                @{ id = '2003'; type = 'path'; value = 'C:\'
                                   osType = 'windows'; mode = 'suppress'; scopeLevel = 'site'
                                   scopeName = 'MOCK-SITE-EU'; description = ''
                                   createdBy = 'jordan.lee@mock.invalid'; createdAt = '2026-01-09T08:15:00Z'
                                   updatedBy = 'jordan.lee@mock.invalid'; updatedAt = '2026-01-09T08:15:00Z' }

                                # Worst case: a high-level wildcard, no justification, and only a
                                # service-account author. The report must disclose the lack of a human contact.
                                @{ id = '2004'; type = 'path'; value = 'C:\Users\*\AppData\'
                                   osType = 'windows'; mode = 'suppress'; scopeLevel = 'site'
                                   scopeName = 'MOCK-SITE-EU'; description = ''
                                   createdBy = 'svc-import@mock.invalid'; createdAt = '2025-11-20T11:05:00Z'
                                   updatedBy = 'svc-import@mock.invalid'; updatedAt = '2025-11-20T11:05:00Z' }
                            )
                            pagination = @{ totalItems = 4; nextCursor = $null }
                        }
                    }

                    '/web/api/v2.1/restrictions' {
                        Send-Json $context @{
                            data = @(
                                # Correct: a precise device, for a group.
                                @{ id = '3001'; ruleName = 'Quality department USB drive'; action = 'Allow'
                                   matchBy = 'serialId'; vendorId = '0781'; productId = '5583'
                                   serialId = 'AA010203040506'; usbDeviceClass = '08'
                                   interfaceType = 'USB'; scopeLevel = 'group'; scopeName = 'Quality'
                                   description = 'Quality report transfer, ticket SCTASK-2211'
                                   createdBy = 'alex.taylor@mock.invalid'; createdAt = '2026-02-18T13:30:00Z'
                                   updatedBy = 'alex.taylor@mock.invalid'; updatedAt = '2026-02-18T13:30:00Z' }

                                # Too wide: all copies of the model.
                                @{ id = '3002'; ruleName = 'Model of equivalent key'; action = 'Allow'
                                   matchBy = 'productId'; vendorId = '0781'; productId = '5583'
                                   serialId = ''; usbDeviceClass = '08'
                                   interfaceType = 'USB'; scopeLevel = 'group'; scopeName = 'Logistics'
                                   description = ''
                                   createdBy = 'jordan.lee@mock.invalid'; createdAt = '2026-05-06T15:12:00Z'
                                   updatedBy = 'jordan.lee@mock.invalid'; updatedAt = '2026-05-06T15:12:00Z' }

                                # Much worse: everything produced by the manufacturer.
                                @{ id = '3003'; ruleName = 'Peripherals manufacturer X'; action = 'Allow'
                                   matchBy = 'vendorId'; vendorId = '05AC'; productId = ''
                                   serialId = ''; usbDeviceClass = 'FF'
                                   interfaceType = 'USB'; scopeLevel = 'group'; scopeName = 'R&D'
                                   description = ''
                                   createdBy = 'svc-import@mock.invalid'; createdAt = '2025-12-03T07:48:00Z'
                                   updatedBy = 'svc-import@mock.invalid'; updatedAt = '2025-12-03T07:48:00Z' }

                                # The deceptive case: the rule is in the expected group and therefore looks legitimate, but it
                                # matches by manufacturer identifier and consequently authorizes every phone from that vendor.
                                @{ id = '3004'; ruleName = 'Management smartphones'; action = 'Allow'
                                   matchBy = 'vendorId'; vendorId = '05AC'; productId = ''
                                   serialId = ''; usbDeviceClass = '06'
                                   interfaceType = 'USB'; scopeLevel = 'group'; scopeName = 'Smartphones'
                                   description = 'Management request, no ticket number'
                                   createdBy = 'jordan.lee@mock.invalid'; createdAt = '2026-06-25T17:02:00Z'
                                   updatedBy = 'alex.taylor@mock.invalid'; updatedAt = '2026-07-09T08:20:00Z' }

                                # Precise serial number, but site scope instead of group scope.
                                @{ id = '3005'; ruleName = 'Chief technology officer smartphone'; action = 'Allow'
                                   matchBy = 'serialId'; vendorId = '05AC'; productId = '12A8'
                                   serialId = 'FF998877665544'; usbDeviceClass = '06'
                                   interfaceType = 'USB'; scopeLevel = 'site'; scopeName = 'MOCK-SITE-EU'
                                   description = 'Ticket SCTASK-2480'
                                   createdBy = 'alex.taylor@mock.invalid'; createdAt = '2026-07-01T11:44:00Z'
                                   updatedBy = 'alex.taylor@mock.invalid'; updatedAt = '2026-07-01T11:44:00Z' }
                            )
                            pagination = @{ totalItems = 5; nextCursor = $null }
                        }
                    }

                    '/web/api/v2.1/agents/actions/move-to-group' {
                        $body = ''
                        if ($context.Request.HasEntityBody) {
                            $reader = [System.IO.StreamReader]::new($context.Request.InputStream, $context.Request.ContentEncoding)
                            try   { $body = $reader.ReadToEnd() }
                            finally { $reader.Dispose() }
                        }

                        $request = $null
                        if ($body) { $request = $body | ConvertFrom-Json }

                        $agentIds = @()
                        $group = ''
                        if ($request) {
                            if ($request.PSObject.Properties.Name -contains 'agentIds') { $agentIds = @($request.agentIds) }
                            if ($request.PSObject.Properties.Name -contains 'groupId')  { $group = [string]$request.groupId }
                        }

                        if ($agentIds.Count -eq 0 -or -not $group) {
                            Send-Json $context @{
                                errors = @(@{ code = 4000010; detail = 'agentIds and groupId are required'; title = 'Bad Request' })
                            } 400
                        }
                        else {
                            foreach ($a in $agentIds) {
                                $moves.Add(@{ agentId = [string]$a; groupId = $group })
                            }
                            Send-Json $context @{ data = @{ affected = $agentIds.Count } }
                        }
                    }

                    '/web/api/v2.1/_test/moves' {
                        # Introspection route, reserved for tests: it exposes what the server actually received. This is
# what makes it verifiable to distinguish between -WhatIf and a real execution, instead of assuming
# it.
                        Send-Json $context @{ data = @($moves.ToArray()); pagination = @{ totalItems = $moves.Count; nextCursor = $null } }
                    }

                    '/EPM/API/Server/Version' {
                        # Entry point open: dispatcher's availability.
                        Send-Json $context @{ Version = '23.6.0.1' }
                    }

                    '/EPM/API/Auth/EPM/Logon' {
                        $user = ''
                        $password  = ''
                        $application = ''
                        if ($epmBody) {
                            $receivedFields = @($epmBody.PSObject.Properties.Name)
                            if ($receivedFields -contains 'Username')      { $user = [string]$epmBody.Username }
                            if ($receivedFields -contains 'Password')      { $password  = [string]$epmBody.Password }
                            if ($receivedFields -contains 'ApplicationID') { $application = [string]$epmBody.ApplicationID }
                        }

                        if (-not $user -or -not $password -or -not $application) {
                            # Poorly formatted request: the three fields are mandatory according to the doc. This is not a
# refusal of identifiers, and the return code must say so.
                            Send-Json $context @{ ErrorMessage = 'Username, Password, and ApplicationID are required' } 400
                        }
                        elseif ($user -ne 'mock-epm-user' -or $password -ne 'MOCK-EPM-PASSWORD') {
                            Send-Json $context @{ ErrorMessage = 'Invalid credentials' } 401
                        }
                        elseif ($application -eq 'EndpointOps-ManagerKo') {
                            # NORMAL authentication, but the ManagerURL returned points to a manager who will refuse the
# validation call. This is the only setup that separates the two steps: the token is delivered
# correctly, the state is set correctly, and it is the validation that fails.
                            #
                            # The trigger is the ApplicationID because it is the only free field
                            # that the doc leaves to the caller, and that it avoids inventing a test
                            # parameter in the module itself. The dispatcher, on the other hand,
                            # cannot take a path: the local loop guard requires a URL without a
                            # segment.
                            Send-Json $context @{
                                EPMAuthenticationResult = 'MOCK-EPM-TOKEN'
                                ManagerURL              = "http://localhost:$Port/EPM/API/_test/manager-ko"
                                IsPasswordExpired       = $false
                            }
                        }
                        else {
                            # ManagerURL points to the same mock server: without it, the dispatcher -> ManagerURL model would
# not be executable offline.
                            Send-Json $context @{
                                EPMAuthenticationResult = 'MOCK-EPM-TOKEN'
                                ManagerURL              = "http://localhost:$Port"
                                IsPasswordExpired       = $false
                            }
                        }
                    }

                    '/EPM/API/Sets' {
                        # Field shape from the documentation JSON example (Id / Name / Description / IsNPVDI), not the
# its descriptive table, which names them SetId / SetName / SetDescription. The two contradict each
# other and nothing allows us to decide without access to a real tenant; ConvertTo-EpmSet therefore accepts
# both, and the mock server uses the one that has the greatest chance of being the real one.
                        $sets = @(
                            @{ Id = '11111111-1111-1111-1111-111111111111'
                               Name = 'Production'; Description = 'Production endpoints'; IsNPVDI = $false }

                            # Description is present but empty. The response preserves an empty string
                            # rather than converting it to $null.
                            @{ Id = '22222222-2222-2222-2222-222222222222'
                               Name = 'Servers'; Description = ''; IsNPVDI = $false }
                        )

                        $setLimit   = 50
                        $setOffset = 0
                        if ($context.Request.QueryString['limit'])  { $setLimit   = [int]$context.Request.QueryString['limit'] }
                        if ($context.Request.QueryString['offset']) { $setOffset = [int]$context.Request.QueryString['offset'] }

                        if ($setLimit -le 0 -or ($setOffset % $setLimit) -ne 0) {
                            Send-Json $context @{ ErrorMessage = 'The offset value must be a whole-number multiple of limit' } 400
                        }
                        else {
                            $setBatch = @()
                            if ($setOffset -lt $sets.Count) {
                                $setEnd = [Math]::Min($setOffset + $setLimit, $sets.Count) - 1
                                $setBatch = @($sets[$setOffset..$setEnd])
                            }
                            # SetsCount is the tenant total, not the page size: this is what the documentation
# describes, and it is NOT the TotalCount on which the calling layer knows to stop. The empty page
# remains therefore the only stopping condition on this route.
                            Send-Json $context @{ SetsCount = $sets.Count; Sets = @($setBatch) }
                        }
                    }

                    { $_ -match '^/EPM/API/Sets/[^/]+/Policies/Server(/[^/]+)?$' } {
                        # Route matched by PATTERN rather than equality: the path carries the set identifier and the
# the policy when you ask for the detail.
                        #
                        # The two entry points live here because they share the same catalog, and
                        # the property to hold is precisely their DIFFERENCE: the list does not
                        # carry Description, only the detail does.
                        $policySegments = @($path.Trim('/') -split '/')
                        $setId  = $policySegments[3]
                        $policySegment  = ''
                        if ($policySegments.Count -ge 7) { $policySegment = $policySegments[6] }

                        # Each entry has a Description because this is the representation returned by the detail endpoint.
                        # The list endpoint returns the reduced projection built below.
                        $catalog = @{
                            '11111111-1111-1111-1111-111111111111' = @(
                                @{ PolicyId = '00000000-0000-0000-0000-000000000001'; PolicyName = 'Elevate Dev Tools'
                                   Description = 'Request RITM0012345, dev tools'
                                   IsActive = $true; IsAppliedToAllComputers = $false
                                   Action = 'Elevate'; PolicyType = 'ApplicationPolicy'; Order = 1; OsType = 'Windows'
                                   CreatedDate = '2025-03-11T09:20:00Z'; ModifiedDate = '2026-01-08T14:05:00Z' }

                                # Applied to the entire fleet without a description: maximum scope with no written justification.
                                @{ PolicyId = '00000000-0000-0000-0000-000000000002'; PolicyName = 'Allow Temp'
                                   Description = ''
                                   IsActive = $true; IsAppliedToAllComputers = $true
                                   Action = 'Allow'; PolicyType = 'ApplicationPolicy'; Order = 2; OsType = 'Windows'
                                   CreatedDate = '2025-06-02T11:00:00Z'; ModifiedDate = '2025-06-02T11:00:00Z' }

                                @{ PolicyId = '00000000-0000-0000-0000-000000000003'; PolicyName = 'Block USB Tools'
                                   Description = 'USB tool blocking'
                                   IsActive = $true; IsAppliedToAllComputers = $false
                                   Action = 'Block'; PolicyType = 'ApplicationPolicy'; Order = 3; OsType = 'Windows'
                                   CreatedDate = '2025-09-19T16:42:00Z'; ModifiedDate = '2026-04-21T08:12:00Z' }

                                @{ PolicyId = '00000000-0000-0000-0000-000000000004'; PolicyName = 'Elevate Legacy App'
                                   Description = ''
                                   IsActive = $true; IsAppliedToAllComputers = $false
                                   Action = 'Elevate'; PolicyType = 'ApplicationPolicy'; Order = 4; OsType = 'Windows'
                                   CreatedDate = '2024-11-05T13:30:00Z'; ModifiedDate = '2024-11-05T13:30:00Z' }

                                # Inactive: an inactive policy is not an absent policy, and the report should not confuse them.
                                @{ PolicyId = '00000000-0000-0000-0000-000000000005'; PolicyName = 'Old Test Policy'
                                   Description = ''
                                   IsActive = $false; IsAppliedToAllComputers = $false
                                   Action = 'Elevate'; PolicyType = 'ApplicationPolicy'; Order = 5; OsType = 'Windows'
                                   CreatedDate = '2024-02-14T10:05:00Z'; ModifiedDate = '2025-01-30T09:00:00Z' }

                                # THREE SPACES, and it is deliberately tricky: the field has been filled, so it is not empty, but it
# conveys no information. The module must preserve it as returned so that the user can decide.
                                @{ PolicyId = '00000000-0000-0000-0000-000000000006'; PolicyName = 'Elevate Installers'
                                   Description = '   '
                                   IsActive = $true; IsAppliedToAllComputers = $false
                                   Action = 'Elevate'; PolicyType = 'ApplicationPolicy'; Order = 6; OsType = 'Windows'
                                   CreatedDate = '2026-05-07T07:55:00Z'; ModifiedDate = '2026-05-07T07:55:00Z' }
                            )
                            # Together WITHOUT any policy: an empty list is a normal result, not an error.
                            '22222222-2222-2222-2222-222222222222' = @()
                        }

                        if (-not $catalog.ContainsKey($setId)) {
                            # 404 on an unknown SetId: the documentation gives the same code for the missing resource, the wrong
# SetId and the lack of permissions.
                            Send-Json $context @{ ErrorMessage = 'Not found' } 404
                        }
                        elseif ($policySegment -eq 'Search') {
                            if ($context.Request.HttpMethod -ne 'POST') {
                                # The list is a POST while it is a read. Responding also in GET would make the method test unable to
# fail.
                                Send-Json $context @{ ErrorMessage = 'Method Not Allowed' } 405
                            }
                            else {
                                # The filter is read from the body and nowhere else. This makes the result conclusive when
# a caller would have put it in the query string.
                                $receivedFilter = ''
                                if ($epmBody) {
                                    $filterNames = @($epmBody.PSObject.Properties.Name)
                                    if ($filterNames -contains 'filter') { $receivedFilter = [string]$epmBody.filter }
                                }

                                $retained = @($catalog[$setId])
                                if ($receivedFilter -match '^PolicyName CONTAINS (.+)$') {
                                    # Use .Contains rather than -like: '?' is a wildcard for -like, so an unsafe pattern could match everything
# back without us noticing.
                                    $policyPattern = $Matches[1]
                                    $retained = @($retained | Where-Object { $_.PolicyName.Contains($policyPattern) })
                                }

                                $policyLimit   = 50
                                $policyOffset = 0
                                if ($context.Request.QueryString['limit'])  { $policyLimit   = [int]$context.Request.QueryString['limit'] }
                                if ($context.Request.QueryString['offset']) { $policyOffset = [int]$context.Request.QueryString['offset'] }

                                if ($policyLimit -le 0 -or ($policyOffset % $policyLimit) -ne 0) {
                                    Send-Json $context @{ ErrorMessage = 'The offset value must be a whole-number multiple of limit' } 400
                                }
                                else {
                                    $policyBatch = @()
                                    if ($policyOffset -lt $retained.Count) {
                                        $policyEnd = [Math]::Min($policyOffset + $policyLimit, $retained.Count) - 1
                                        $policyBatch = @($retained[$policyOffset..$policyEnd])
                                    }

                                    # The projection omits Description. This is the central property of this route: the
                                    # documentation lists the fields returned by Get policies, and Description is not among them.
                                    $policyProjection = @($policyBatch | ForEach-Object {
                                            @{ PolicyId                = $_.PolicyId
                                               PolicyName              = $_.PolicyName
                                               Action                  = $_.Action
                                               IsActive                = $_.IsActive
                                               PolicyType              = $_.PolicyType
                                               Order                   = $_.Order
                                               IsAppliedToAllComputers = $_.IsAppliedToAllComputers
                                               OsType                  = $_.OsType
                                               CreatedDate             = $_.CreatedDate
                                               ModifiedDate            = $_.ModifiedDate }
                                        })

                                    Send-Json $context @{
                                        Policies      = @($policyProjection)
                                        ActiveCount   = @($catalog[$setId] | Where-Object { $_.IsActive }).Count
                                        TotalCount    = @($catalog[$setId]).Count
                                        FilteredCount = $retained.Count
                                    }
                                }
                            }
                        }
                        elseif ($policySegment) {
                            $found = @($catalog[$setId] | Where-Object { $_.PolicyId -eq $policySegment })
                            if ($found.Count -eq 0) {
                                # A deliberately minimal 404 without an explanation: this is all a real server may return,
                                # which is why callers must be careful about what they conclude.
                                Send-Json $context @{ ErrorMessage = 'Not found' } 404
                            }
                            else {
                                Send-Json $context $found[0]
                            }
                        }
                        else {
                            Send-Json $context @{ ErrorMessage = 'Not found' } 404
                        }
                    }

                    { $_ -match '^/EPM/API/Sets/[^/]+/Events/Search$' } {
                        # Elevation events. POST filter, cursor pagination, and items under 'events'.
                        #
                        # This route genuinely filters on the request body, and this is
                        # deliberate. The introspection log only retains the names of the keys
                        # received, never their values: it cannot therefore prove that a date was
                        # sent in UTC. Expanding the log to include values would make it the very
                        # place of the leak it is used to exclude. The proof therefore lies in the
                        # BEHAVIOR: a malformed boundary is rejected, while a valid boundary selects a
                        # different subset when shifted by one hour.
                        $eventSegments = @($path.Trim('/') -split '/')
                        $eventSetId = $eventSegments[3]

                        # 38 repeated characters + 2: a SHA1 is 40 hexadecimal characters long, and a too short hash
# would fool anyone who connected a reputation service to it.
                        $hContoso   = ('A' * 38) + '01'
                        $hUnknown   = ('B' * 38) + '02'
                        $hFabrikam  = ('C' * 38) + '03'
                        $hMicrosoft = ('D' * 38) + '04'
                        $hNorthwind = ('F' * 38) + '06'

                        $eventsBySet = @{
                            '11111111-1111-1111-1111-111111111111' = @(
                                # Four events, FOUR distinct users, the same publisher and the same signature: this is the case that
# justifies a proposal for a rule.
                                @{ hash = $hContoso; publisher = 'Contoso Software'; eventType = 'ElevationRequest'
                                   userName = 'alice'; computerName = 'MOCK-WKS-01'; userIsAdmin = $false
                                   fileName = 'setup.exe'; filePath = 'C:\Temp\setup.exe'
                                   fileDescription = 'Contoso Suite Setup'; productName = 'Contoso Suite'; company = 'Contoso Software'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Business-requested installation'
                                   firstEventDate = '2026-07-09T08:00:00Z'; lastEventDate = '2026-07-10T08:00:00Z'
                                   agentId = 'AGENT-0001' }

                                @{ hash = $hContoso; publisher = 'Contoso Software'; eventType = 'ElevationRequest'
                                   userName = 'bob'; computerName = 'MOCK-WKS-02'; userIsAdmin = $false
                                   fileName = 'setup.exe'; filePath = 'C:\Temp\setup.exe'
                                   fileDescription = 'Contoso Suite Setup'; productName = 'Contoso Suite'; company = 'Contoso Software'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Application update'
                                   firstEventDate = '2026-07-09T09:00:00Z'; lastEventDate = '2026-07-10T09:00:00Z'
                                   agentId = 'AGENT-0002' }

                                @{ hash = $hContoso; publisher = 'Contoso Software'; eventType = 'ElevationRequest'
                                   userName = 'carol'; computerName = 'MOCK-WKS-03'; userIsAdmin = $false
                                   fileName = 'setup.exe'; filePath = 'C:\Temp\setup.exe'
                                   fileDescription = 'Contoso Suite Setup'; productName = 'Contoso Suite'; company = 'Contoso Software'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Installation of new endpoint'
                                   firstEventDate = '2026-07-11T10:00:00Z'; lastEventDate = '2026-07-12T10:00:00Z'
                                   agentId = 'AGENT-0003' }

                                @{ hash = $hContoso; publisher = 'Contoso Software'; eventType = 'ElevationRequest'
                                   userName = 'david'; computerName = 'MOCK-WKS-04'; userIsAdmin = $false
                                   fileName = 'setup.exe'; filePath = 'C:\Temp\setup.exe'
                                   fileDescription = 'Contoso Suite Setup'; productName = 'Contoso Suite'; company = 'Contoso Software'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Publisher''s correction'
                                   firstEventDate = '2026-07-13T11:00:00Z'; lastEventDate = '2026-07-14T11:00:00Z'
                                   agentId = 'AGENT-0004' }

                                # Publisher has NULL: unsigned binary. It must be propagated to an empty string, never to $null, at the
# risk of having the first report that reads it under Set-StrictMode raised.
                                @{ hash = $hUnknown; publisher = $null; eventType = 'ManualRequest'
                                   userName = 'erin'; computerName = 'MOCK-WKS-05'; userIsAdmin = $false
                                   fileName = 'tool.exe'; filePath = 'C:\Users\erin\Downloads\tool.exe'
                                   fileDescription = ''; productName = ''; company = ''
                                   sourceType = 'Download'; sourceName = 'https://mock.invalid/tool.exe'
                                   policyName = ''; policyAction = 'Elevate'
                                   justification = 'Downloaded tool for a one-off requirement'
                                   firstEventDate = '2026-07-15T12:00:00Z'; lastEventDate = '2026-07-16T12:00:00Z'
                                   agentId = 'AGENT-0005' }

                                # Removable origin: two users, same binary launched from a key.
                                @{ hash = $hFabrikam; publisher = 'Fabrikam Inc'; eventType = 'ElevationRequest'
                                   userName = 'frank'; computerName = 'MOCK-WKS-06'; userIsAdmin = $true
                                   fileName = 'admin.exe'; filePath = 'E:\admin.exe'
                                   fileDescription = 'Fabrikam Admin Tool'; productName = 'Fabrikam Admin'; company = 'Fabrikam Inc'
                                   sourceType = 'RemovableDrive'; sourceName = 'E:'
                                   policyName = 'Elevate Installers'; policyAction = 'Elevate'
                                   justification = 'Contractor support activity'
                                   firstEventDate = '2026-07-17T13:00:00Z'; lastEventDate = '2026-07-18T13:00:00Z'
                                   agentId = 'AGENT-0006' }

                                @{ hash = $hFabrikam; publisher = 'Fabrikam Inc'; eventType = 'ElevationRequest'
                                   userName = 'grace'; computerName = 'MOCK-WKS-07'; userIsAdmin = $false
                                   fileName = 'admin.exe'; filePath = 'E:\admin.exe'
                                   fileDescription = 'Fabrikam Admin Tool'; productName = 'Fabrikam Admin'; company = 'Fabrikam Inc'
                                   sourceType = 'RemovableDrive'; sourceName = 'E:'
                                   policyName = 'Elevate Installers'; policyAction = 'Elevate'
                                   justification = 'Contractor support activity'
                                   firstEventDate = '2026-07-19T14:00:00Z'; lastEventDate = '2026-07-20T14:00:00Z'
                                   agentId = 'AGENT-0007' }

                                @{ hash = $hMicrosoft; publisher = 'Microsoft Windows'; eventType = 'ManualRequest'
                                   userName = 'henry'; computerName = 'MOCK-SRV-01'; userIsAdmin = $true
                                   fileName = 'mmc.exe'; filePath = 'C:\Windows\System32\mmc.exe'
                                   fileDescription = 'Microsoft Management Console'; productName = 'Microsoft Windows'; company = 'Microsoft Corporation'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = ''; policyAction = 'Elevate'
                                   justification = 'Server administration'
                                   firstEventDate = '2026-07-21T15:00:00Z'; lastEventDate = '2026-07-22T15:00:00Z'
                                   agentId = 'AGENT-0008' }

                                @{ hash = $hNorthwind; publisher = 'Northwind Traders'; eventType = 'ElevationRequest'
                                   userName = 'heidi'; computerName = 'MOCK-WKS-07'; userIsAdmin = $false
                                   fileName = 'report.exe'; filePath = 'C:\Program Files\Northwind\report.exe'
                                   fileDescription = 'Northwind Reporting'; productName = 'Northwind Reporting'; company = 'Northwind Traders'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Monthly report'
                                   firstEventDate = '2026-07-12T10:00:00Z'; lastEventDate = '2026-07-12T10:00:00Z'
                                   agentId = 'AGENT-0007' }
                            )
                            # No events: an empty list is a normal result, not an error.
                            '22222222-2222-2222-2222-222222222222' = @()

                            # Set dedicated to the RANKING BY USER. The production set gives exactly one event per user: a
# ranking by number of requests would be flat, and a sorting test on equal counts cannot fail,
# so it proves nothing. Here zoe carries THREE requests on TWO binaries, aaron one: descending
# sorting, ascending sorting and alphabetical order give three different results.
                            #
                            # This set is deliberately not published by the /EPM/API/Sets route: it
                            # must not change the set count observed by the Get-EpmSet tests.
                            '33333333-3333-3333-3333-333333333333' = @(
                                @{ hash = $hContoso; publisher = 'Contoso Software'; eventType = 'ElevationRequest'
                                   userName = 'zoe'; computerName = 'MOCK-WKS-10'; userIsAdmin = $false
                                   fileName = 'setup.exe'; filePath = 'C:\Temp\setup.exe'
                                   fileDescription = 'Contoso Suite Setup'; productName = 'Contoso Suite'; company = 'Contoso Software'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Business-requested installation'
                                   firstEventDate = '2026-07-01T08:00:00Z'; lastEventDate = '2026-07-01T09:00:00Z'
                                   agentId = 'AGENT-0010' }

                                @{ hash = $hContoso; publisher = 'Contoso Software'; eventType = 'ElevationRequest'
                                   userName = 'zoe'; computerName = 'MOCK-WKS-11'; userIsAdmin = $false
                                   fileName = 'setup.exe'; filePath = 'C:\Temp\setup.exe'
                                   fileDescription = 'Contoso Suite Setup'; productName = 'Contoso Suite'; company = 'Contoso Software'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = 'Elevate Dev Tools'; policyAction = 'Elevate'
                                   justification = 'Second endpoint'
                                   firstEventDate = '2026-07-02T08:00:00Z'; lastEventDate = '2026-07-02T09:00:00Z'
                                   agentId = 'AGENT-0011' }

                                @{ hash = $hMicrosoft; publisher = 'Microsoft Windows'; eventType = 'ManualRequest'
                                   userName = 'zoe'; computerName = 'MOCK-WKS-10'; userIsAdmin = $false
                                   fileName = 'mmc.exe'; filePath = 'C:\Windows\System32\mmc.exe'
                                   fileDescription = 'Microsoft Management Console'; productName = 'Microsoft Windows'; company = 'Microsoft Corporation'
                                   sourceType = 'LocalDisk'; sourceName = 'C:'
                                   policyName = ''; policyAction = 'Elevate'
                                   justification = 'Management console'
                                   firstEventDate = '2026-07-03T08:00:00Z'; lastEventDate = '2026-07-03T09:00:00Z'
                                   agentId = 'AGENT-0012' }

                                @{ hash = $hFabrikam; publisher = 'Fabrikam Inc'; eventType = 'ElevationRequest'
                                   userName = 'aaron'; computerName = 'MOCK-WKS-12'; userIsAdmin = $false
                                   fileName = 'admin.exe'; filePath = 'E:\admin.exe'
                                   fileDescription = 'Fabrikam Admin Tool'; productName = 'Fabrikam Admin'; company = 'Fabrikam Inc'
                                   sourceType = 'RemovableDrive'; sourceName = 'E:'
                                   policyName = 'Elevate Installers'; policyAction = 'Elevate'
                                   justification = 'Contractor support activity'
                                   firstEventDate = '2026-07-04T08:00:00Z'; lastEventDate = '2026-07-04T09:00:00Z'
                                   agentId = 'AGENT-0013' }
                            )
                        }

                        if (-not $eventsBySet.ContainsKey($eventSetId)) {
                            Send-Json $context @{ ErrorMessage = 'Not found' } 404
                        }
                        elseif ($context.Request.HttpMethod -ne 'POST') {
                            Send-Json $context @{ ErrorMessage = 'Method Not Allowed' } 405
                        }
                        else {
                            $eventFilter = ''
                            if ($epmBody) {
                                $eventNames = @($epmBody.PSObject.Properties.Name)
                                if ($eventNames -contains 'filter') { $eventFilter = [string]$epmBody.filter }
                            }

                            $stylesEvt = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                                         [System.Globalization.DateTimeStyles]::AssumeUniversal

                            $eventTypes = @()
                            if ($eventFilter -match 'eventType IN ([A-Za-z,]+)') {
                                $eventTypes = @($Matches[1] -split ',' | Where-Object { $_ })
                            }

                            # Validate the format BEFORE the value: a boundary without a Z suffix is not in UTC, and
# accepting it silently would be equivalent to allowing exactly the default that this assembly must
# catch.
                            $invalidEventFormat = $false
                            $eventFromDate   = $null
                            $eventUntilDate   = $null
                            $isoPattern    = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'

                            if ($eventFilter -match 'eventDate GE (\S+)') {
                                $tokenGe = $Matches[1]
                                if ($tokenGe -notmatch $isoPattern) { $invalidEventFormat = $true }
                                else { $eventFromDate = [datetime]::Parse($tokenGe, [cultureinfo]::InvariantCulture, $stylesEvt) }
                            }
                            if ($eventFilter -match 'eventDate LE (\S+)') {
                                $tokenLe = $Matches[1]
                                if ($tokenLe -notmatch $isoPattern) { $invalidEventFormat = $true }
                                else { $eventUntilDate = [datetime]::Parse($tokenLe, [cultureinfo]::InvariantCulture, $stylesEvt) }
                            }

                            $eventCursor = $context.Request.QueryString['nextCursor']
                            $eventStart   = -1
                            if (-not $eventCursor -or $eventCursor -eq 'start') { $eventStart = 0 }
                            elseif ($eventCursor -match '^evt-(\d+)$')          { $eventStart = [int]$Matches[1] }

                            if ($invalidEventFormat) {
                                Send-Json $context @{ ErrorMessage = 'eventDate must be expressed in ISO-8601 UTC, Z suffix' } 400
                            }
                            elseif ($eventStart -lt 0) {
                                Send-Json $context @{ ErrorMessage = 'Unknown cursor' } 400
                            }
                            else {
                                $retainedEvents = @($eventsBySet[$eventSetId] | Where-Object {
                                        $keep = $true
                                        if ($eventTypes.Count -gt 0 -and $eventTypes -notcontains $_.eventType) { $keep = $false }
                                        if ($keep) {
                                            $timestamp = [datetime]::Parse($_.lastEventDate, [cultureinfo]::InvariantCulture, $stylesEvt)
                                            if ($null -ne $eventFromDate -and $timestamp -lt $eventFromDate) { $keep = $false }
                                            if ($null -ne $eventUntilDate -and $timestamp -gt $eventUntilDate) { $keep = $false }
                                        }
                                        $keep
                                    })

                                # Page size imposed by the SERVER, not by the client: nine events thus make three pages regardless
# of the requested limit, which exercises cursor pagination.
                                $eventPageSize = 3
                                $eventBatch = @()
                                if ($eventStart -lt $retainedEvents.Count) {
                                    $eventEnd = [Math]::Min($eventStart + $eventPageSize, $retainedEvents.Count) - 1
                                    $eventBatch = @($retainedEvents[$eventStart..$eventEnd])
                                }

                                $nextEvent = ''
                                if (($eventStart + $eventPageSize) -lt $retainedEvents.Count) {
                                    $nextEvent = "evt-$($eventStart + $eventPageSize)"
                                }

                                Send-Json $context @{ events = @($eventBatch); nextCursor = $nextEvent }
                            }
                        }
                    }

                    '/EPM/API/_test/offset-pages' {
                        # Test route: pagination by offset. It is used to prove that the caller is advancing from limit to
# limit.
                        #
                        # Two properties are deliberated: - an offset that is not an integer
                        # multiple of limit is REJECTED, as documented by CyberArk; - the middle
                        # page is PARTIAL (only one element while limit is 2). Without it, a caller
                        # that advances from the received size would produce the same sequence as a
                        # correct caller, and the defect would go unnoticed.
                        $limit   = 2
                        $offset = 0
                        if ($context.Request.QueryString['limit'])  { $limit   = [int]$context.Request.QueryString['limit'] }
                        if ($context.Request.QueryString['offset']) { $offset = [int]$context.Request.QueryString['offset'] }

                        if ($limit -le 0 -or ($offset % $limit) -ne 0) {
                            Send-Json $context @{ ErrorMessage = 'The offset value must be a whole-number multiple of limit' } 400
                        }
                        else {
                            $pagesByOffset = @{
                                0 = @(@{ id = 'ep-1' }, @{ id = 'ep-2' })
                                2 = @(@{ id = 'ep-3' })
                                4 = @(@{ id = 'ep-4' }, @{ id = 'ep-5' })
                            }
                            $batch = @()
                            if ($limit -eq 2 -and $pagesByOffset.ContainsKey($offset)) {
                                $batch = $pagesByOffset[$offset]
                            }
                            Send-Json $context @{ events = @($batch); TotalCount = 5 }
                        }
                    }

                    '/EPM/API/_test/offset-no-total' {
                        # Even pagination by offset, but WITHOUT TotalCount. Nothing in the documentation guarantees this
# field on all paginated routes, and the form of a list response is part of what could not be
# confirmed. On a route that omits it, the empty page is the ONLY pagination stopping condition.
                        $limitWithoutTotal   = 2
                        $offsetWithoutTotal = 0
                        if ($context.Request.QueryString['limit'])  { $limitWithoutTotal   = [int]$context.Request.QueryString['limit'] }
                        if ($context.Request.QueryString['offset']) { $offsetWithoutTotal = [int]$context.Request.QueryString['offset'] }

                        if ($limitWithoutTotal -le 0 -or ($offsetWithoutTotal % $limitWithoutTotal) -ne 0) {
                            Send-Json $context @{ ErrorMessage = 'The offset value must be a whole-number multiple of limit' } 400
                        }
                        else {
                            $pagesWithoutTotal = @{
                                0 = @(@{ id = 'et-1' }, @{ id = 'et-2' })
                                2 = @(@{ id = 'et-3' })
                            }
                            $batchWithoutTotal = @()
                            if ($limitWithoutTotal -eq 2 -and $pagesWithoutTotal.ContainsKey($offsetWithoutTotal)) {
                                $batchWithoutTotal = $pagesWithoutTotal[$offsetWithoutTotal]
                            }
                            # No TotalCount, ever, including on the blank page.
                            Send-Json $context @{ events = @($batchWithoutTotal) }
                        }
                    }

                    '/EPM/API/_test/cursor-pages-empty' {
                        # End of pagination by EMPTY STRING: this is the form advertised by the text of the documentation.
                        switch ($context.Request.QueryString['nextCursor']) {
                            'start'     { Send-Json $context @{ events = @(@{ id = 'ec-1' }, @{ id = 'ec-2' }); nextCursor = 'Page 2 of the document' } }
                            'Page 2 of the document' { Send-Json $context @{ events = @(@{ id = 'ec-3' }, @{ id = 'ec-4' }); nextCursor = 'Page 3' } }
                            'Page 3' { Send-Json $context @{ events = @(@{ id = 'ec-5' }); nextCursor = '' } }
                            default     { Send-Json $context @{ ErrorMessage = 'Unknown cursor' } 400 }
                        }
                    }

                    '/EPM/API/_test/cursor-pages-null' {
                        # End of pagination by NULL: this is the form shown by the example on the same documentation page, which
# contradicts its own text. Both must work.
                        switch ($context.Request.QueryString['nextCursor']) {
                            'start'     { Send-Json $context @{ events = @(@{ id = 'en-1' }, @{ id = 'en-2' }); nextCursor = 'Page 2' } }
                            'Page 2' { Send-Json $context @{ events = @(@{ id = 'en-3' }); nextCursor = $null } }
                            default     { Send-Json $context @{ ErrorMessage = 'Unknown cursor' } 400 }
                        }
                    }

                    '/EPM/API/_test/cursor-runaway' {
                        # Server that returns a NEW cursor to each page: this is the case when the page limit must stop.
                        #
                        # It still stops after 40 pages, and it is deliberate: without this limit,
                        # removing the limit to prove that its test can fail would make the rest
                        # run endlessly instead of failing it. A test that cannot be failed without
                        # blocking the rest is not a test. 40 is far above any limit used by
                        # tests, and negligible in duration.
                        $cursorIndex = 0
                        if ($context.Request.QueryString['nextCursor'] -match 'runaway-(\d+)') {
                            $cursorIndex = [int]$Matches[1]
                        }

                        $next = "runaway-$($cursorIndex + 1)"
                        if ($cursorIndex -ge 40) { $next = '' }
                        Send-Json $context @{ events = @(@{ id = "er-$cursorIndex" }); nextCursor = $next }
                    }

                    '/EPM/API/_test/cursor-repeat' {
                        # Server that sends BACK TWICE the same cursor: it is an API that loops on itself. The page limit
# would eventually stop it, but much later and with a message that would indicate the wrong cause.
                        Send-Json $context @{ events = @(@{ id = 'eb-1' }); nextCursor = 'noose' }
                    }

                    '/EPM/API/_test/expired' {
                        # Token syntactically accepted by the guard, but session expired server side: it is the 401 "Your
# session has expired" from the documentation, distinct from rejected credentials.
                        Send-Json $context @{ ErrorMessage = 'Your session has expired' } 401
                    }

                    '/EPM/API/_test/manager-ko/EPM/API/Sets' {
                        # The manager is designated by the ManagerURL of the logon 'EndpointOps-ManagerKo'. The token is
# VALID, so the authentication guard allows it to pass: what fails is the validation call, not the
# authentication.
                        #
                        # 403 rather than 500: a 500 is retried four times by the transport layer
                        # and would add seven seconds of waiting time for each subsequent execution.
                        # Rather than 401 too, which Invoke-EpmRequest reformulates as "session
                        # expired": the cause would then be ambiguous to the reader. The EPM doc
                        # gives 403 for a license violation, so the case is realistic.
                        Send-Json $context @{ ErrorMessage = 'Forbidden' } 403
                    }

                    '/EPM/API/_test/requests' {
                        # Introspection route reserved for tests, on the /web/api/v2.1/_test/moves. model
                        Send-Json $context @{ requests = @($epmRequests.ToArray()) }
                    }

                    '/_test/reputation' {
                        Send-Json $context @{ requests = @($reputationRequests.ToArray()) }
                    }

                    '/_test/hits' {
                        # Introspection route reserved for tests, on the model of /web/api/v2.1/_test/moves and
# /EPM/API/_test/requests. It shows the number of ACTUAL requests received by path: this is what
# makes it verifiable that a response has not been retried, instead of deducing it from a duration.
                        #
                        # Path outside /web/api/v2.1/ and /EPM/API/, therefore outside the two
                        # authentication guards, as with the other generic routes it observes:
                        # requiring a token to read a /health counter would make no sense.
                        #
                        # Typed list rather than $x = @() ; $x += ... : an assignment of an empty
                        # array flattens into $null, and rereading its .Count raises under
                        # Set-StrictMode.
                        $hitList = [System.Collections.Generic.List[object]]::new()
                        foreach ($key in ($hits.Keys | Sort-Object)) {
                            $hitList.Add(@{ path = $key; count = $hits[$key] })
                        }
                        Send-Json $context @{ hits = @($hitList.ToArray()) }
                    }

                    '/shutdown' {
                        Send-Json $context @{ stopping = $true }
                        $listener.Stop()
                    }

                    default {
                        Send-Json $context @{ error = 'not found'; path = $path } 404
                    }
                }
            }
        }
        finally {
            if ($listener.IsListening) { $listener.Stop() }
            $listener.Close()
        }
    }

    $baseUrl = "http://localhost:$Port"

    # Wait for the listener to be ready: without it, the first test starts running.
    $deadline = (Get-Date).AddSeconds(20)
    $ready = $false
    do {
        Start-Sleep -Milliseconds 200
        try {
            $ready = $null -ne (Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 2 -ErrorAction Stop)
        }
        catch {
            # The listener is not yet ready to accept connections: it is expected until the deadline, we try
# again.
            $ready = $false
        }
    } until ($ready -or (Get-Date) -gt $deadline)

    if (-not $ready) {
        $output = Receive-Job -Job $job 2>&1 | Out-String
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "The mock server did not start on $baseUrl. Job exit: $output"
    }

    return [pscustomobject]@{ Job = $job; BaseUrl = $baseUrl; Port = $Port }
}

function Get-MockApiServerHitCount {
    <#
    .SYNOPSIS
        Number of requests received by the mock server for a given path.
    .DESCRIPTION
        Queries the introspection route /_test/hits. Returns 0 for a never called path: the absence of
        input is information, not an error, and a test that proves that a route that has NOT been
        called must be able to read this zero without protecting itself.

        The expiration time is deliberately long. The /slow route blocks the HttpListener for 5
        seconds per request, even after the client has abandoned its connection: a read made just
        after waiting therefore waits for the server to finish serving what it already had in the
        queue. With a short default, a faulty behavior (for example 4 retries, i.e. 20 seconds in
        the queue) would fail the test on an expiration time instead of the countdown: it would fail
        for the wrong reason, and the message would learn nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Server,
        [Parameter(Mandatory)][string]$Path,
        [int]$TimeoutSec = 60
    )

    $response = Invoke-RestMethod -Uri "$($Server.BaseUrl)/_test/hits" -TimeoutSec $TimeoutSec -ErrorAction Stop
    $inputs = @($response.hits)
    foreach ($entry in $inputs) {
        if ($entry.path -eq $Path) { return [int]$entry.count }
    }
    return 0
}

function Stop-MockApiServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Test utility: stopping a local mock server, no real data at stake.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Server)

    try {
        Invoke-RestMethod -Uri "$($Server.BaseUrl)/shutdown" -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
    }
    finally {
        Remove-Job -Job $Server.Job -Force -ErrorAction SilentlyContinue
    }
}
