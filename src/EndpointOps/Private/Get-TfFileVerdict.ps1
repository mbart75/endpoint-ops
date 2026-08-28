Set-StrictMode -Version 3.0

function Get-TfFileVerdict {
    <#
    .SYNOPSIS
        Returns the ThreatFox verdict for a VirusTotal SHA-256 hash.
    .DESCRIPTION
        Queries ThreatFox with the abuse.ch key already held by the MalwareBazaar connection. Only
        SHA-256 is accepted; every other hash format is rejected before connection state is read or
        any request is issued.

        A match adds a malicious signal. No match provides no evidence and therefore remains
        Unknown. Failures and malformed responses produce an Unavailable result instead of failing
        the orchestrator.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Hash
    )

    $queryDate = [datetime]::UtcNow
    $verdict = 'Unavailable'
    $detail = 'ThreatFox is unavailable for this hash.'

    if ($Hash -notmatch '^[0-9A-Fa-f]{64}$') {
        return [pscustomobject]@{
            PSTypeName = 'EndpointOps.Reputation.Verdict'
            Source     = 'ThreatFox'
            Verdict    = $verdict
            Detail     = $detail
            HashUsed   = $Hash
            HashSource = 'VirusTotal'
            QueryDate  = $queryDate
        }
    }

    try {
        $state = Get-MbConnectionState
        $headers = @{
            'Auth-Key'    = ConvertFrom-SecureString -SecureString $state.AuthKey -AsPlainText
            'Content-Type' = 'application/json'
        }
        $body = @{ query = 'search_hash'; hash = $Hash } | ConvertTo-Json -Compress
        $response = Invoke-EndpointOpsRequest -Uri "$($state.ThreatFoxBaseUri)/api/v1/" `
            -Method Post -Headers $headers -Body $body -MaxAttempts 1

        if ($null -eq $response -or
            $response.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject] -or
            $response.PSObject.Properties.Name -notcontains 'query_status') {
            throw [System.IO.InvalidDataException]::new('ThreatFox: malformed response envelope.')
        }

        $queryStatus = [string]$response.query_status
        if ($queryStatus -ceq 'ok') {
            if ($response.PSObject.Properties.Name -notcontains 'data' -or $null -eq $response.data) {
                throw [System.IO.InvalidDataException]::new('ThreatFox: query_status is ok but data is missing.')
            }

            $records = @($response.data)
            if ($records.Count -eq 0) {
                $verdict = 'Unknown'
                $detail = 'ThreatFox returned no indicator for this hash. Missing evidence does not establish that the file is clean.'
            }
            else {
                $record = $records[0]
                if ($null -eq $record -or
                    $record.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject] -or
                    $record.PSObject.Properties.Name -notcontains 'malware_printable' -or
                    $record.PSObject.Properties.Name -notcontains 'tags') {
                    throw [System.IO.InvalidDataException]::new('ThreatFox: malformed indicator.')
                }

                $family = [string]$record.malware_printable
                $tags = @($record.tags | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                $details = [System.Collections.Generic.List[string]]::new()
                if (-not [string]::IsNullOrWhiteSpace($family)) {
                    $details.Add("family: $family")
                }
                if ($tags.Count -gt 0) {
                    $details.Add("tags: $($tags -join ', ')")
                }

                $verdict = 'Malicious'
                $detail = if ($details.Count -eq 0) {
                    'ThreatFox associates this hash with a malicious indicator.'
                }
                else {
                    "ThreatFox associates this hash with a malicious indicator ($($details -join '; '))."
                }
            }
        }
        else {
            $detail = 'ThreatFox returned an unusable application status.'
        }
    }
    catch {
        $verdict = 'Unavailable'
        $detail = 'ThreatFox is unavailable for this hash.'
    }

    return [pscustomobject]@{
        PSTypeName = 'EndpointOps.Reputation.Verdict'
        Source     = 'ThreatFox'
        Verdict    = $verdict
        Detail     = $detail
        HashUsed   = $Hash
        HashSource = 'VirusTotal'
        QueryDate  = $queryDate
    }
}
