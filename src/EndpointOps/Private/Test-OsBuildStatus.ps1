function Test-OsBuildStatus {
    <#
    .SYNOPSIS
        Evaluates an operating-system build against supported branch revisions.
    .DESCRIPTION
        A build cannot be compared in absolute terms: 19044.1288 and 22631.4890 belong to two
        different branches, so comparing them as a single number is meaningless. Each reference
        key identifies a branch and its value gives the minimum expected revision for that branch.

        A branch missing from the reference returns 'UnsupportedBranch', which is more serious than
        a delayed patch: the endpoint will no longer receive patches at all.

        Empty reference data returns 'Unknown', not 'UpToDate': missing knowledge is not evidence
        that the endpoint is current.
    .OUTPUTS
        'UpToDate', 'OutdatedRevision', 'UnsupportedBranch', or 'Unknown'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$OsRevision,
        [Parameter(Mandatory)][hashtable]$SupportedBuilds
    )

    if ($SupportedBuilds.Count -eq 0) {
        return 'Unknown'
    }

    if ([string]::IsNullOrWhiteSpace($OsRevision)) {
        return 'Unknown'
    }

    $revisionParts = $OsRevision -split '\.'
    if ($revisionParts.Count -lt 2) {
        return 'Unknown'
    }

    $buildBranch  = $revisionParts[0]
    $revision = 0
    if (-not [int]::TryParse($revisionParts[1], [ref]$revision)) {
        return 'Unknown'
    }

    if (-not $SupportedBuilds.ContainsKey($buildBranch)) {
        return 'UnsupportedBranch'
    }

    if ($revision -lt [int]$SupportedBuilds[$buildBranch]) {
        return 'OutdatedRevision'
    }

    return 'UpToDate'
}
