function Get-EndpointOpsVersion {
    <#
    .SYNOPSIS
        Returns the version of the EndpointOps module.
    .NOTES
        $PSScriptRoot points to Public/, not the module root. Querying the module itself
        avoids hardcoding a parent-directory path that would break if the directory layout changed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return $MyInvocation.MyCommand.Module.Version.ToString()
}
