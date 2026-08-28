function Get-HttpStatusFromError {
    <#
    .SYNOPSIS
        Extracts an HTTP status code from a transport error message.
    .DESCRIPTION
        The shared transport layer does not expose a typed status-code exception. This helper accepts
        a three-digit code only after the word "returned" so it cannot mistake a number in a URL for
        an HTTP status.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Message
    )

    if ($Message -match 'returned\s+(\d{3})\b') {
        return [int]$Matches[1]
    }
}
