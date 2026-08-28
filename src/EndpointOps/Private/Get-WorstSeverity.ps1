# Severity vocabulary shared by all reports. The rank is used for comparison and is never exposed: a
# report talks about 'Critical', not 4.
$script:SeverityRank = @{
    'None'     = 0
    'Low'      = 1
    'Medium'   = 2
    'High'     = 3
    'Critical' = 4
}

function Get-WorstSeverity {
    <#
    .SYNOPSIS
        Returns the worst severity from a list of findings.
    .DESCRIPTION
        An unknown severity is ignored rather than failing the calculation: an entire report should
        not fail because a reason was assigned an unknown label.

        An explicit loop avoids sorting a small collection and avoids hash-table lookup behavior in
        a Sort-Object expression under Set-StrictMode.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Findings
    )

    $worstSeverity = 'None'

    if ($null -eq $Findings) {
        return $worstSeverity
    }

    foreach ($finding in $Findings) {
        if ($null -eq $finding) { continue }

        $severity = Get-PropertyOrDefault -InputObject $finding -Name 'Severity'
        if (-not $severity -or -not $script:SeverityRank.ContainsKey($severity)) { continue }

        if ($script:SeverityRank[$severity] -gt $script:SeverityRank[$worstSeverity]) {
            $worstSeverity = $severity
        }
    }

    return $worstSeverity
}
