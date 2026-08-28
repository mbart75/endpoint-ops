function Invoke-VtRequest {
    <#
    .SYNOPSIS
        Calls a VirusTotal endpoint with the current API key.
    .DESCRIPTION
        Central entry point for VirusTotal calls. It enforces pacing before each request, counts
        every attempt against an in-memory daily quota, and sends the key in the x-apikey header.

        The quota and its counter do not survive the PowerShell session. They protect an execution
        against an overflow, but do not constitute reliable accounting between multiple sessions.

        The shared transport receives a single-attempt request, so a 429 is returned without retry.
        Only a 500 response receives one additional attempt, also subject to pacing and quota.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [hashtable]$Query = @{},
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 15000,
        [ValidateRange(1, 100000)][int]$DailyQuota = 500
    )

    $state = Get-VtConnectionState
    $uri = "$($state.BaseUri)$Path"

    if ($Query.Count -gt 0) {
        $pairs = foreach ($key in $Query.Keys) {
            "$([uri]::EscapeDataString($key))=$([uri]::EscapeDataString([string]$Query[$key]))"
        }
        $uri = "$uri`?$($pairs -join '&')"
    }

    $headers = @{
        'x-apikey' = ConvertFrom-SecureString -SecureString $state.ApiKey -AsPlainText
    }
    $arguments = @{
        Uri         = $uri
        Headers     = $headers
        Method      = 'Get'
        MaxAttempts = 1
    }

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $beforePacingUtc = Get-VtUtcNow
        $today = $beforePacingUtc.Date
        if ($state.DailyRequestDateUtc -ne $today) {
            $state.DailyRequestDateUtc = $today
            $state.DailyRequestCount = 0
        }

        if ($state.DailyRequestCount -ge $DailyQuota) {
            throw "EndpointOps: daily VirusTotal quota of $DailyQuota requests reached; no call has been issued."
        }

        if ($null -ne $state.LastRequestAtUtc -and $MinIntervalMs -gt 0) {
            $elapsedMs = ($beforePacingUtc - $state.LastRequestAtUtc).TotalMilliseconds
            $remainingMs = $MinIntervalMs - $elapsedMs
            if ($remainingMs -gt 0) {
                Start-Sleep -Milliseconds ([int][Math]::Ceiling($remainingMs))
            }
        }

        $afterPacingUtc = Get-VtUtcNow
        if ($state.DailyRequestDateUtc -ne $afterPacingUtc.Date) {
            $state.DailyRequestDateUtc = $afterPacingUtc.Date
            $state.DailyRequestCount = 0
        }
        $state.LastRequestAtUtc = $afterPacingUtc
        $state.DailyRequestCount++

        try {
            return Invoke-EndpointOpsRequest @arguments
        }
        catch {
            $status = Get-HttpStatusFromError -Message $_.Exception.Message

            if ($status -eq 500 -and $attempt -eq 1) {
                continue
            }
            throw
        }
    }
}
