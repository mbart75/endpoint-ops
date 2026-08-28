# Session cache only. OrdinalIgnoreCase is explicit: the same SHA-1 hash in uppercase or
# lowercase designates the same file.
$script:VtFileReportCache = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

function Get-VtFileReport {
    <#
    .SYNOPSIS
        Returns the VirusTotal reputation of a file hash.
    .DESCRIPTION
        Queries the VirusTotal file report and maps the verdict to Malicious, Clean, Unknown, or
        Unavailable. Service errors are not propagated: reputation enriches a report and must never
        cause the report to fail.

        An Unknown verdict DOES NOT mean that the file is clean: it means that no engine has
        submitted it to VirusTotal. This is the case of a legitimate internal tool as well as a
        binary manufactured for a targeted intrusion. Never present Unknown as reassuring.

        The module only sends hashes, never a file. However, querying a hash reveals to
        a third party that it has been seen in the fleet: it is a weak but real disclosure, and that
        is why enrichment is optional rather than active by default.
    .PARAMETER Hash
        MD5, SHA-1 or SHA-256 hash accepted by VirusTotal.
    .PARAMETER MinIntervalMs
        Minimum interval between two calls. The default public value respects the four requests per
        minute of the public API.
    .EXAMPLE
        'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3' | Get-VtFileReport
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidatePattern('^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$')]
        [string]$Hash,
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 15000
    )

    process {
        if ($script:VtFileReportCache.ContainsKey($Hash)) {
            Copy-VtReport -Report $script:VtFileReportCache[$Hash]
            return
        }

        try {
            $response = Invoke-VtRequest -Path "/api/v3/files/$Hash" -MinIntervalMs $MinIntervalMs
        }
        catch {
            $status = Get-HttpStatusFromError -Message $_.Exception.Message
            $verdict = if ($status -in @(400, 404)) { 'Unknown' } else { 'Unavailable' }

            $report = [pscustomobject]@{
                PSTypeName       = 'EndpointOps.VirusTotal.FileReport'
                Hash             = $Hash
                Verdict          = $verdict
                MaliciousCount   = $null
                TotalEngines     = $null
                LastAnalysisDate = $null
                Permalink        = $null
                Sha1             = $null
                Sha256           = $null
                Md5              = $null
            }
            $script:VtFileReportCache[$Hash] = $report
            Copy-VtReport -Report $report
            return
        }

        try {
            $data = Get-PropertyOrDefault -InputObject $response -Name 'data'
            $attributes = Get-PropertyOrDefault -InputObject $data -Name 'attributes'
            $statistics = Get-PropertyOrDefault -InputObject $attributes -Name 'last_analysis_stats'
            $maliciousCount = $null
            $totalEngines = $null

            if ($null -ne $statistics) {
                $statisticsBase = $statistics.PSObject.BaseObject
                if ($statisticsBase -isnot [System.Management.Automation.PSCustomObject]) {
                    throw [System.IO.InvalidDataException]::new('VirusTotal: last_analysis_stats must be an object.')
                }

                $maliciousCount = 0
                $totalEngines = 0
                foreach ($property in $statistics.PSObject.Properties) {
                    $value = 0
                    if (-not [int]::TryParse([string]$property.Value, [ref]$value) -or $value -lt 0) {
                        throw [System.IO.InvalidDataException]::new(
                            "VirusTotal: statistic '$($property.Name)' is invalid.")
                    }
                    $totalEngines += $value
                    if ($property.Name -eq 'malicious') {
                        $maliciousCount = $value
                    }
                }
            }

            $analysisTimestamp = Get-PropertyOrDefault -InputObject $attributes -Name 'last_analysis_date'
            $lastAnalysisDate = $null
            if ($null -ne $analysisTimestamp) {
                $seconds = 0L
                if (-not [long]::TryParse([string]$analysisTimestamp, [ref]$seconds)) {
                    throw [System.IO.InvalidDataException]::new('VirusTotal: last_analysis_date is invalid.')
                }
                try {
                    $lastAnalysisDate = [datetimeoffset]::FromUnixTimeSeconds($seconds).UtcDateTime
                }
                catch [System.ArgumentOutOfRangeException] {
                    throw [System.IO.InvalidDataException]::new(
                        'VirusTotal: last_analysis_date out of range.', $_.Exception)
                }
            }

            $sha1 = Get-PropertyOrDefault -InputObject $attributes -Name 'sha1'
            $sha256 = Get-PropertyOrDefault -InputObject $attributes -Name 'sha256'
            $md5 = Get-PropertyOrDefault -InputObject $attributes -Name 'md5'
            $permalink = if (-not [string]::IsNullOrEmpty([string]$sha256)) {
                "https://www.virustotal.com/gui/file/$sha256"
            }
            else {
                $null
            }

            $report = [pscustomobject]@{
                PSTypeName       = 'EndpointOps.VirusTotal.FileReport'
                Hash             = $Hash
                Verdict          = ConvertTo-VtVerdict -Statistics $statistics
                MaliciousCount   = $maliciousCount
                TotalEngines     = $totalEngines
                LastAnalysisDate = $lastAnalysisDate
                Permalink        = $permalink
                Sha1             = $sha1
                Sha256           = $sha256
                Md5              = $md5
            }
        }
        catch [System.IO.InvalidDataException] {
            $report = [pscustomobject]@{
                PSTypeName       = 'EndpointOps.VirusTotal.FileReport'
                Hash             = $Hash
                Verdict          = 'Unavailable'
                MaliciousCount   = $null
                TotalEngines     = $null
                LastAnalysisDate = $null
                Permalink        = $null
                Sha1             = $null
                Sha256           = $null
                Md5              = $null
            }
        }
        $script:VtFileReportCache[$Hash] = $report
        Copy-VtReport -Report $report
    }
}
