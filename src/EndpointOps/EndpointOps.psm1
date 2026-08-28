#Requires -Version 7.2
Set-StrictMode -Version 3.0

$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
$publicFiles  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1'          -ErrorAction SilentlyContinue)

foreach ($file in $privateFiles + $publicFiles) {
    . $file.FullName
}

Export-ModuleMember -Function @($publicFiles | ForEach-Object BaseName)
