function Measure-ExclusionBreadth {
    <#
    .SYNOPSIS
        Assesses the scope of an exclusion and returns its risk reasons.
    .DESCRIPTION
        Returns a collection of findings, each with a severity and a readable reason. An empty collection
        means that no problems were found.

        The reasons accumulate: an exclusion can be both on a disk root, at the site level and
        without justification. This is intentional because a review with the responsible person
        must address all three.
    .PARAMETER Exclusion
        An exclusion such as returned by Get-S1Exclusion.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]$Exclusion
    )

    $reasons = [System.Collections.Generic.List[object]]::new()
    $value = [string](Get-PropertyOrDefault -InputObject $Exclusion -Name 'Value' -Default '')
    $type   = Get-PropertyOrDefault -InputObject $Exclusion -Name 'Type'
    $scopeLevel = Get-PropertyOrDefault -InputObject $Exclusion -Name 'ScopeLevel'
    $justification = Get-PropertyOrDefault -InputObject $Exclusion -Name 'Description'

    # The three forms of path are exclusive: we retain the most serious one.
    if ($value -match '^[A-Za-z]:\\?$') {
        $reasons.Add([pscustomobject]@{
            Severity = 'Critical'
            Reason   = 'Disk root excluded; protection no longer covers this volume'
        })
    }
    elseif ($value -match '^[A-Za-z]:\\[^\\]+\\\*') {
        $reasons.Add([pscustomobject]@{
            Severity = 'High'
            Reason   = 'High-level wildcard: the actual scope is difficult to determine'
        })
    }
    elseif ($value -match '\*') {
        $reasons.Add([pscustomobject]@{
            Severity = 'Medium'
            Reason   = 'Wildcard in path'
        })
    }

    if ($type -eq 'path') {
        $reasons.Add([pscustomobject]@{
            Severity = 'Low'
            Reason   = 'Path exclusion: a hash would provide a narrower scope'
        })
    }

    if ($scopeLevel -eq 'site') {
        $reasons.Add([pscustomobject]@{
            Severity = 'High'
            Reason   = 'Site scope instead of group scope; the exclusion affects many more machines than necessary'
        })
    }

    if ([string]::IsNullOrWhiteSpace($justification)) {
        $reasons.Add([pscustomobject]@{
            Severity = 'Medium'
            Reason   = 'No justification; the original request cannot be identified'
        })
    }

    return $reasons.ToArray()
}
