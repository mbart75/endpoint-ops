Set-StrictMode -Version 3.0

function Get-HaFileVerdict {
    <#
    .SYNOPSIS
        Returns the Hybrid Analysis verdict for a file hash.
    .DESCRIPTION
        A malicious match is evidence from a sandbox execution. Neither a missing match nor any
        other sandbox verdict is treated as proof that a file is clean. Transport failures, missing
        connections, and malformed responses produce an Unavailable result instead of failing the
        orchestrator.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$')]
        [string]$Hash
    )

    $queryDate = [datetime]::UtcNow
    $verdict = 'Unavailable'
    $detail = 'Hybrid Analysis is unavailable for this hash.'

    try {
        $response = Invoke-HaRequest -Hash $Hash
        if ($null -eq $response -or $response.PSObject.Properties.Name -notcontains 'Data') {
            throw [System.IO.InvalidDataException]::new('Hybrid Analysis: malformed response envelope.')
        }

        $data = $response.Data
        if ($null -eq $data -or
            $data.PSObject.Properties.Name -notcontains 'sha256s' -or
            $data.PSObject.Properties.Name -notcontains 'reports') {
            throw [System.IO.InvalidDataException]::new('Hybrid Analysis: incomplete SearchByHash response.')
        }

        $reports = @($data.reports)
        if ($reports.Count -eq 0) {
            $verdict = 'Unknown'
            $detail = 'Hybrid Analysis returned no report for this hash. Missing evidence does not establish that the file is clean.'
        }
        else {
            $maliciousReport = $null
            foreach ($report in $reports) {
                if ($null -eq $report -or $report.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
                    throw [System.IO.InvalidDataException]::new('Hybrid Analysis: malformed sandbox report.')
                }

                foreach ($propertyName in @('state', 'verdict', 'environment_description')) {
                    if ($report.PSObject.Properties.Name -notcontains $propertyName) {
                        throw [System.IO.InvalidDataException]::new(
                            "Hybrid Analysis: required field '$propertyName' is missing from the sandbox report.")
                    }
                }

                $sandboxVerdict = Get-PropertyOrDefault -InputObject $report -Name 'verdict'
                if ([string]::Equals([string]$sandboxVerdict, 'malicious', [StringComparison]::OrdinalIgnoreCase)) {
                    $maliciousReport = $report
                    break
                }
            }

            if ($null -eq $maliciousReport) {
                $representativeReport = $reports[0]
                $reportState = [string](Get-PropertyOrDefault -InputObject $representativeReport -Name 'state')
                $returnedVerdict = [string](Get-PropertyOrDefault -InputObject $representativeReport -Name 'verdict')
                $environment = [string](Get-PropertyOrDefault -InputObject $representativeReport -Name 'environment_description')
                if (-not [string]::Equals($reportState, 'SUCCESS', [StringComparison]::OrdinalIgnoreCase) -or
                    [string]::IsNullOrWhiteSpace($returnedVerdict) -or
                    [string]::IsNullOrWhiteSpace($environment)) {
                    throw [System.IO.InvalidDataException]::new(
                        'Hybrid Analysis: sandbox report has no usable verdict.')
                }

                $verdict = 'Unknown'
                $detail = "Hybrid Analysis returned sandbox verdict '$returnedVerdict' in environment '$environment'. This verdict does not establish that the file is clean."
            }
            else {
                $environment = [string](Get-PropertyOrDefault -InputObject $maliciousReport -Name 'environment_description')
                if ([string]::IsNullOrWhiteSpace($environment)) {
                    throw [System.IO.InvalidDataException]::new(
                        'Hybrid Analysis: malicious report has no environment description.')
                }

                $returnedVerdict = [string](Get-PropertyOrDefault -InputObject $maliciousReport -Name 'verdict')
                $verdict = 'Malicious'
                $detail = "Hybrid Analysis classified this file as malicious: sandbox verdict '$returnedVerdict' in environment '$environment'."
            }
        }
    }
    catch {
        $verdict = 'Unavailable'
        $detail = 'Hybrid Analysis is unavailable for this hash.'
    }

    return [pscustomobject]@{
        PSTypeName = 'EndpointOps.Reputation.Verdict'
        Source     = 'HybridAnalysis'
        Verdict    = $verdict
        Detail     = $detail
        HashUsed   = $Hash
        HashSource = 'EPM'
        QueryDate  = $queryDate
    }
}
