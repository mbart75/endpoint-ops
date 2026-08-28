function Test-ObservationWindow {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$WindowDays,
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$RetentionDays
    )

    # A window EQUAL to retention is not reliable. To state "no activity for 60 days", events must
    # cover the entire 60-day period. If retention is exactly 60 days, the query reaches the purge
    # boundary, which is never precise to the second. Returning a result here would create an
    # unsupported "no usage" finding.
    if ($WindowDays -lt $RetentionDays) {
        return 'Usable'
    }

    return 'Indeterminate'
}
