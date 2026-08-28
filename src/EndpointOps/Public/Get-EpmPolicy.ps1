function Get-EpmPolicy {
    <#
    .SYNOPSIS
        Lists the applicable policies of a CyberArk EPM set.
    .DESCRIPTION
        Although this is a read operation, the documented endpoint uses POST and carries the filter
        in the request body rather than the URL.

        The list omits both description and author. Descriptions are obtained one policy at a time
        through Get-EpmPolicyDetail. No
        Description field is therefore created here: an empty field would be indistinguishable from
        a policy that genuinely lacks a description, causing a report to flag policies whose details
        were simply never retrieved.

        The author does not exist anywhere in the public EPM API. A report should say so rather than
        leaving a blank field that suggests the information might be available elsewhere.
    .PARAMETER SetId
        Identifier of the set, as returned by Get-EpmSet.
    .PARAMETER Filter
        EPM filtering expression, for example 'PolicyName CONTAINS Elevate'. It is transmitted in
        the BODY of the request, never in the URL.
    .PARAMETER Limit
        Page size requested from the server. The documentation allows 1 to 1000.
    .EXAMPLE
        Get-EpmPolicy -SetId $setRecord.Id | Where-Object { $_.IsAppliedToAllComputers }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SetId,
        [string]$Filter,
        [ValidateRange(1, 1000)][int]$Limit = 250
    )

    # Send a body even without a filter because this read endpoint uses POST, and the transport adds
    # Content-Type only when a body is present.
    $requestBody = '{}'
    if ($PSBoundParameters.ContainsKey('Filter') -and $Filter) {
        $requestBody = @{ filter = $Filter } | ConvertTo-Json -Compress
    }

    $rawRecord = Invoke-EpmRequest -Path "/EPM/API/Sets/$SetId/Policies/Server/Search" `
        -Method 'Post' -Body $requestBody -PaginationStyle Offset -ItemsProperty 'Policies' -Limit $Limit

    foreach ($policy in $rawRecord) {
        [pscustomobject]@{
            PSTypeName              = 'EndpointOps.Epm.Policy'
            PolicyId                = Get-PropertyOrDefault -InputObject $policy -Name 'PolicyId'
            PolicyName              = Get-PropertyOrDefault -InputObject $policy -Name 'PolicyName'
            IsActive                = [bool](Get-PropertyOrDefault -InputObject $policy -Name 'IsActive' -Default $false)
            Action                  = Get-PropertyOrDefault -InputObject $policy -Name 'Action'
            PolicyType              = Get-PropertyOrDefault -InputObject $policy -Name 'PolicyType'
            Order                   = Get-PropertyOrDefault -InputObject $policy -Name 'Order'
            IsAppliedToAllComputers = [bool](Get-PropertyOrDefault -InputObject $policy -Name 'IsAppliedToAllComputers' -Default $false)
            OsType                  = Get-PropertyOrDefault -InputObject $policy -Name 'OsType'
            CreatedDate             = Get-PropertyOrDefault -InputObject $policy -Name 'CreatedDate'
            ModifiedDate            = Get-PropertyOrDefault -InputObject $policy -Name 'ModifiedDate'
        }
    }
}
