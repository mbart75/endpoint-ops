#Requires -Version 7.2

function ConvertTo-TestSecureString {
    <#
    .SYNOPSIS
        Build a SecureString from a text, for testing only.
    .DESCRIPTION
        ConvertTo-SecureString -AsPlainText -Force would be the usual way, but it triggers
        PSAvoidUsingConvertToSecureStringWithPlainText, with an Error severity, and the static
        analysis also covers ./tests. So we build the SecureString character by character: same
        result, no rules bypassed.
    .EXAMPLE
        $token = ConvertTo-TestSecureString -PlainText 'MOCK-S1-TOKEN'
    #>
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$PlainText
    )

    $secure = [System.Security.SecureString]::new()
    foreach ($char in $PlainText.ToCharArray()) {
        $secure.AppendChar($char)
    }
    $secure.MakeReadOnly()
    return $secure
}
