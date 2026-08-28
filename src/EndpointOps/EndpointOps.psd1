@{
    RootModule           = 'EndpointOps.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'b7c1e2a4-3f56-4c8a-9d21-0e5f7a9c4b13'
    Author               = 'Maxence Barthelemy'
    CompanyName          = 'Maxence Barthelemy'
    Copyright            = '(c) 2026 Maxence Barthelemy. Licensed under the MIT License.'
    Description          = 'Automation toolkit for SentinelOne, CyberArk EPM and VirusTotal endpoint operations.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Connect-EpmTenant',
        'Connect-S1Tenant',
        'Connect-VirusTotal',
        'Disconnect-EpmTenant',
        'Disconnect-S1Tenant',
        'Disconnect-VirusTotal',
        'Get-EndpointOpsVersion',
        'Get-EpmElevationEvent',
        'Get-EpmElevationSummary',
        'Get-EpmPolicy',
        'Get-EpmPolicyDetail',
        'Get-EpmPolicyHygieneReport',
        'Get-EpmSet',
        'Get-S1Agent',
        'Get-S1DeviceControlEvent',
        'Get-S1DeviceControlRiskReport',
        'Get-S1DeviceControlRule',
        'Get-S1Exclusion',
        'Get-S1ExclusionRiskReport',
        'Get-S1FleetHygieneReport',
        'Get-S1UnusedAuthorizationReport',
        'Get-VtFileReport',
        'Get-VtUrlReport',
        'Invoke-EndpointOpsRequest',
        'Invoke-S1FleetRemediation'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('SentinelOne', 'CyberArk', 'EPM', 'EDR', 'Security')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/mbart75/endpoint-ops'
        }
    }
}
