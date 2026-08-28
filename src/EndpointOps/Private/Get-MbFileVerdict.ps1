Set-StrictMode -Version 3.0

function Get-MbFileVerdict {
    <#
    .SYNOPSIS
        Returns the MalwareBazaar verdict for a SHA-1 hash.
    .DESCRIPTION
        MalwareBazaar contains confirmed malware samples. A match is therefore a strong malicious
        signal. A missing hash is normal for legitimate software and provides no reassurance.

        Missing connections, transport failures, malformed responses, and unexpected application
        statuses produce an Unavailable result so enrichment does not fail the calling report.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Hash
    )

    $queryDate = [datetime]::UtcNow
    $verdict = 'Unavailable'
    $detail = 'MalwareBazaar is unavailable for this hash.'

    try {
        $response = Invoke-MbRequest -Hash $Hash

        switch ($response.QueryStatus) {
            'ok' {
                if ($null -eq $response.Data -or @($response.Data).Count -eq 0) {
                    throw [System.IO.InvalidDataException]::new(
                        'MalwareBazaar: query_status is ok but data is empty.')
                }

                $record = @($response.Data)[0]
                $signature = if ($record.PSObject.Properties.Name -contains 'signature') {
                    [string]$record.signature
                }
                else {
                    ''
                }

                $verdict = 'Malicious'
                $detail = if ([string]::IsNullOrWhiteSpace($signature)) {
                    'MalwareBazaar associates this hash with confirmed malware.'
                }
                else {
                    "MalwareBazaar associates this hash with confirmed malware (family: $signature)."
                }
            }
            'hash_not_found' {
                $verdict = 'Unknown'
                $detail = 'MalwareBazaar does not contain this hash. Missing evidence does not establish that the file is clean.'
            }
            'illegal_hash' {
                $detail = 'MalwareBazaar rejected the requested hash format.'
            }
            'no_selector' {
                $detail = 'MalwareBazaar rejected the expected query selector.'
            }
            default {
                $detail = 'MalwareBazaar returned an unknown application status.'
            }
        }
    }
    catch {
        $verdict = 'Unavailable'
        $detail = 'MalwareBazaar is unavailable for this hash.'
    }

    return [pscustomobject]@{
        PSTypeName = 'EndpointOps.Reputation.Verdict'
        Source     = 'MalwareBazaar'
        Verdict    = $verdict
        Detail     = $detail
        HashUsed   = $Hash
        HashSource = 'EPM'
        QueryDate  = $queryDate
    }
}
