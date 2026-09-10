function Invoke-EndpointOpsHttpRequest {
    <#
    .SYNOPSIS
        Executes one HTTP request, retrying 429 and 5xx responses.
    .NOTES
        Timed-out requests are not retried. Without an explicit server signal, the module cannot
        distinguish transient latency from a persistent failure, and retrying would multiply the
        caller's wait time.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'Get',
        [hashtable]$Headers = @{},
        [int]$MaxAttempts = 4,
        [int]$TimeoutSec = 30,
        [double]$BackoffBaseSec = 1,
        [ValidateRange(1, 3600)][double]$MaxRetryAfterSec = 60,
        [string]$Body
    )

    # Log header names only. Header values may contain credentials and must never reach verbose or
    # CI output.
    Write-Verbose "$Method $Uri (headers: $($Headers.Keys -join ', '))"

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $requestParameters = @{
                Uri                = $Uri
                Method             = $Method
                Headers            = $Headers
                TimeoutSec         = $TimeoutSec
                # HttpClient forwards custom headers during redirects, including cross-origin
                # redirects. Following a 3xx response could therefore disclose x-apikey or another
                # credential to the Location target.
                MaximumRedirection = 0
                SkipHttpErrorCheck = $true
                ErrorAction        = 'Stop'
            }
            # The body is only transmitted if it exists: passing Body = $null would fail some methods.
            if ($Body) { $requestParameters['Body'] = $Body }

            # Invoke-WebRequest inherits the caller's debug preference and emits a WebRequest Detail
            # block containing request headers and bodies. Force debugging off at this central
            # transport boundary so EPM passwords and authenticated request headers cannot leak to
            # consoles, CI logs, or incident reports.
            $response = Invoke-WebRequest @requestParameters -Debug:$false
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'MaximumRedirectExceeded,*') {
                throw "EndpointOps: HTTP redirection blocked for $Uri; no automatic redirection is allowed"
            }
            throw "EndpointOps: call to $Uri interrupted ($($_.Exception.Message))"
        }

        $status = [int]$response.StatusCode

        # A 3xx response is never a successful transport result. If a future PowerShell version
        # returns it instead of throwing, do not deserialize or present it as success.
        if ($status -lt 300) {
            return $response
        }

        $retryable = ($status -eq 429) -or ($status -ge 500)

        if (-not $retryable -or $attempt -eq $MaxAttempts) {
            throw "EndpointOps: $Method $Uri returned $status after $attempt attempt(s)"
        }

        $wait = if ($status -eq 429 -and $response.Headers['Retry-After']) {
            $rawRetryAfter = ([string]@($response.Headers['Retry-After'])[0]).Trim()
            $deltaSeconds = 0L
            if ($rawRetryAfter -match '^\d+$' -and [long]::TryParse(
                    $rawRetryAfter,
                    [System.Globalization.NumberStyles]::None,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$deltaSeconds)) {
                [double]$deltaSeconds
            }
            elseif ($rawRetryAfter -match '^[+-]?(?:(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|NaN|Infinity)$') {
                throw "EndpointOps: invalid Retry-After value returned by $Uri"
            }
            else {
                $retryDate = [DateTimeOffset]::MinValue
                $httpDateFormats = [string[]]@(
                    "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'",
                    "dddd, dd-MMM-yy HH':'mm':'ss 'GMT'",
                    "ddd MMM d HH':'mm':'ss yyyy"
                )
                $dateStyles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
                    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                    [System.Globalization.DateTimeStyles]::AdjustToUniversal
                $isHttpDate = [DateTimeOffset]::TryParseExact(
                    $rawRetryAfter,
                    $httpDateFormats,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    $dateStyles,
                    [ref]$retryDate)
                if (-not $isHttpDate) {
                    throw "EndpointOps: invalid Retry-After value returned by $Uri"
                }
                [Math]::Max([double]0, ($retryDate - [DateTimeOffset]::UtcNow).TotalSeconds)
            }
        }
        else {
            $BackoffBaseSec * [Math]::Pow(2, $attempt - 1)
        }

        if ([double]::IsNaN($wait) -or [double]::IsInfinity($wait) -or $wait -lt 0) {
            throw "EndpointOps: invalid Retry-After value returned by $Uri"
        }
        if ($wait -gt $MaxRetryAfterSec) {
            throw "EndpointOps: retry delay exceeds the $MaxRetryAfterSec second policy limit for $Uri"
        }

        Write-Verbose "Status $status; retrying in $wait s (attempt $attempt/$MaxAttempts)"
        Start-Sleep -Seconds $wait
    }
}
