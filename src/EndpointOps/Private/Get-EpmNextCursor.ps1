function Get-EpmNextCursor {
    <#
    .SYNOPSIS
        Reads the next-page cursor from an EPM response.
    .DESCRIPTION
        The EPM documentation represents the end of pagination inconsistently: the text specifies an
        empty string, while the example shows null. Both values, and a missing key, end pagination.

        'start' is rejected as an output value: it is the input value of the first page. If a server returned
        it, the loop would start again from the beginning.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Page
    )

    if ($null -eq $Page) { return $null }

    $cursor = Get-PropertyOrDefault -InputObject $Page -Name 'nextCursor'

    if ([string]::IsNullOrWhiteSpace($cursor)) { return $null }
    if ($cursor -eq 'start') { return $null }

    return $cursor
}
