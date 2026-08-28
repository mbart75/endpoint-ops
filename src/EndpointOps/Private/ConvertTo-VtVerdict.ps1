function ConvertTo-VtVerdict {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Statistics,
        [ValidateRange(1, [int]::MaxValue)][int]$MinimumDetection = 2
    )

    # A single engine detection is noise, not a verdict: isolated false positives are common,
    # including for signed Microsoft binaries. The threshold is an explicit decision, not a hidden
    # constant, hence the parameter.
    #
    # All-zero statistics produce Unknown, not Clean: a file that no engine has analyzed has not
    # been declared clean; it has not been assessed. Confusing the two could cause real harm.
    if ($null -eq $Statistics) {
        return 'Unknown'
    }

    $malicious = 0
    $total = 0
    $hasStatistics = $false

    foreach ($property in $Statistics.PSObject.Properties) {
        $hasStatistics = $true
        $value = [int]$property.Value
        $total += $value

        if ($property.Name -eq 'malicious') {
            $malicious = $value
        }
    }

    if (-not $hasStatistics -or $total -eq 0) {
        return 'Unknown'
    }

    if ($malicious -ge $MinimumDetection) {
        return 'Malicious'
    }

    return 'Clean'
}
