# Session cache only. Ordinal preserves the case of the path and the query: two URLs that differ
# only in case can be distinct.
$script:VtUrlReportCache = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::Ordinal)

function Get-VtUrlReport {
    <#
    .SYNOPSIS
        Returns the VirusTotal reputation of a URL.
    .DESCRIPTION
        Queries the VirusTotal URL report and maps the verdict to Malicious, Clean, Unknown, or
        Unavailable. Service errors are not propagated: reputation enriches a report and must never
        cause the report to fail.

        An Unknown verdict DOES NOT mean that the URL is safe: it means that no one has submitted it
        to VirusTotal. Never present Unknown as reassuring.

        The URL is transmitted to VirusTotal in the form of a base64url identifier. However, this
        request reveals the URL seen in the fleet to a third party. This is why enrichment remains
        optional rather than active by default.
    .PARAMETER Url
        URL whose reputation must be consulted.
    .PARAMETER MinIntervalMs
        Minimum interval between two calls. The default public value respects the four requests per
        minute of the public API.
    .EXAMPLE
        'https://download.example.invalid/tool.exe' | Get-VtUrlReport
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,
        [ValidateRange(0, 600000)][int]$MinIntervalMs = 15000
    )

    process {
        if ($script:VtUrlReportCache.ContainsKey($Url)) {
            Copy-VtReport -Report $script:VtUrlReportCache[$Url]
            return
        }

        $urlId = ConvertTo-VtUrlId -Url $Url

        try {
            $response = Invoke-VtRequest -Path "/api/v3/urls/$urlId" -MinIntervalMs $MinIntervalMs
        }
        catch {
            $status = Get-HttpStatusFromError -Message $_.Exception.Message
            $verdict = if ($status -in @(400, 404)) { 'Unknown' } else { 'Unavailable' }

            $report = [pscustomobject]@{
                PSTypeName       = 'EndpointOps.VirusTotal.UrlReport'
                Url              = $Url
                UrlId            = $urlId
                Verdict          = $verdict
                MaliciousCount   = $null
                TotalEngines     = $null
                LastAnalysisDate = $null
                Permalink        = $null
            }
            $script:VtUrlReportCache[$Url] = $report
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

            $report = [pscustomobject]@{
                PSTypeName       = 'EndpointOps.VirusTotal.UrlReport'
                Url              = $Url
                UrlId            = $urlId
                Verdict          = ConvertTo-VtVerdict -Statistics $statistics
                MaliciousCount   = $maliciousCount
                TotalEngines     = $totalEngines
                LastAnalysisDate = $lastAnalysisDate
                Permalink        = "https://www.virustotal.com/gui/url/$urlId"
            }
        }
        catch [System.IO.InvalidDataException] {
            $report = [pscustomobject]@{
                PSTypeName       = 'EndpointOps.VirusTotal.UrlReport'
                Url              = $Url
                UrlId            = $urlId
                Verdict          = 'Unavailable'
                MaliciousCount   = $null
                TotalEngines     = $null
                LastAnalysisDate = $null
                Permalink        = $null
            }
        }

        $script:VtUrlReportCache[$Url] = $report
        Copy-VtReport -Report $report
    }
}
