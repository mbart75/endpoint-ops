function Get-HttpStatusFromError {
    <#
    .SYNOPSIS
        Reads the status from the first native HTTP exception in an exception chain.
    .DESCRIPTION
        Generic wrappers are skipped. A native HTTP exception is authoritative even when its status
        is null: an inner exception or a number in diagnostic text must not override it.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowNull()][System.Exception]$Exception
    )

    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.Net.Http.HttpRequestException]) {
            if ($null -ne $current.StatusCode) { return [int]$current.StatusCode }
            return
        }
        $current = $current.InnerException
    }
}
