function Copy-VtReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Report
    )

    # Reports contain only strings, numeric values, and a date. PSObject.Copy preserves their fields
    # and PSTypeName while returning an independent object to the caller.
    $Report.PSObject.Copy()
}
