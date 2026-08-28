function Get-VtUtcNow {
    <#
    .SYNOPSIS
        Returns the current UTC time for VirusTotal transport.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param()

    return [datetime]::UtcNow
}
