# endpoint-ops

**A PowerShell toolkit for evidence-driven endpoint security reviews.** endpoint-ops turns documented SentinelOne, CyberArk EPM, and VirusTotal API responses into reviewable hygiene, policy, and reputation findings without turning an API client into an autonomous security decision-maker.

It is designed for endpoint engineers who prefer auditable command-line workflows to opaque console clicks. Read operations are separated from reporting logic; reports state their reasons in plain text; and the only write workflow is deliberately narrow, protected by PowerShell `ShouldProcess`.

> **Validation boundary:** this repository is implemented from public product documentation and tested only against its local mock HTTP server. It has not been validated against a real tenant, real tenant data, or production credentials.

## Architecture

```
Layer 4  Workflows          Get-S1FleetHygieneReport · Get-S1ExclusionRiskReport
                             Get-S1DeviceControlRiskReport · Invoke-S1FleetRemediation
                             Get-S1UnusedAuthorizationReport
                             Get-EpmPolicyHygieneReport · Get-EpmElevationSummary
                                        |
Layer 3  Product queries    Get-S1Agent · Get-S1Exclusion · Get-S1DeviceControlRule
                             Get-S1DeviceControlEvent
                             Get-EpmSet · Get-EpmPolicy · Get-EpmPolicyDetail
                             Get-EpmElevationEvent · Get-VtFileReport · Get-VtUrlReport
                                        |
Layer 2  Connections        Connect-S1Tenant · Disconnect-S1Tenant
                             Connect-EpmTenant · Disconnect-EpmTenant
                             Connect-VirusTotal · Disconnect-VirusTotal
                                        |
Layer 1  Transport          Invoke-EndpointOpsRequest
```

## Capabilities

| Area | Commands | Purpose |
|---|---|---|
| Shared transport | `Invoke-EndpointOpsRequest`, `Get-EndpointOpsVersion` | HTTP requests with retries, backoff, timeouts, and SentinelOne cursor pagination. |
| SentinelOne connection and queries | `Connect-S1Tenant`, `Disconnect-S1Tenant`, `Get-S1Agent`, `Get-S1Exclusion`, `Get-S1DeviceControlRule`, `Get-S1DeviceControlEvent` | Retrieve endpoint, exclusion, and Device Control information. HTTPS is required except for local mock-server addresses. |
| SentinelOne review workflows | `Get-S1FleetHygieneReport`, `Get-S1ExclusionRiskReport`, `Get-S1DeviceControlRiskReport`, `Get-S1UnusedAuthorizationReport` | Produce explainable findings for endpoint hygiene, broad exclusions, permissive device rules, and unused authorizations. |
| SentinelOne remediation | `Invoke-S1FleetRemediation` | The module’s only write command. It can only perform stage-one movement to a tracking group and uses `ShouldProcess`. |
| CyberArk EPM | `Connect-EpmTenant`, `Disconnect-EpmTenant`, `Get-EpmSet`, `Get-EpmPolicy`, `Get-EpmPolicyDetail`, `Get-EpmElevationEvent`, `Get-EpmPolicyHygieneReport`, `Get-EpmElevationSummary` | Query EPM sets, policies, and elevation events, then surface policy-hygiene and elevation proposals. |
| VirusTotal | `Connect-VirusTotal`, `Disconnect-VirusTotal`, `Get-VtFileReport`, `Get-VtUrlReport` | Optional reputation lookup for hashes and URLs. No file-upload path exists in this module. |

CyberArk EPM uses a dispatcher model: authentication returns both a session token and `ManagerURL`; subsequent EPM requests use that returned manager URL. EPM list pagination uses offsets, while event pagination uses an opaque cursor.

VirusTotal enrichment is optional and can only weaken or reject an existing EPM proposal. It never authorizes an elevation automatically. The public API rate limit is documented as four requests per minute, so enriching 80 hashes can take about 20 minutes. The output value `Unknown` must never be read as safe.

## Quick start

Import the module from the repository and connect with a PowerShell secure string.

```powershell
Import-Module ./src/EndpointOps/EndpointOps.psd1

$token = Read-Host -AsSecureString 'SentinelOne API token'
Connect-S1Tenant -BaseUri 'https://example.sentinelone.net' -ApiToken $token

# Endpoints that have stopped reporting
Get-S1Agent | Where-Object { -not $_.IsActive }

# Decommissioned endpoints that are still active
Get-S1Agent |
    Where-Object { $_.IsDecommissioned -and $_.LastActiveDate -gt (Get-Date).AddDays(-7) }

# Path exclusions without justification
Get-S1Exclusion |
    Where-Object { $_.Type -eq 'path' -and -not $_.Description } |
    Select-Object Id, Value, ScopeLevel, CreatedBy, CreatedAt

Disconnect-S1Tenant
```

An EPM policy review illustrates the workflow layer:

```powershell
$credential = Get-Credential
Connect-EpmTenant -DispatcherUri 'https://login.epm.cyberark.com' -Credential $credential

$production = Get-EpmSet | Where-Object Name -eq 'Production'

Get-EpmPolicyHygieneReport -SetId $production.Id |
    Format-Table PolicyName, Severity, Reason, Contact

Get-EpmElevationSummary -SetId $production.Id -Since (Get-Date).AddDays(-30) |
    Format-Table Publisher, FileName, DistinctUserCount, ProposalLevel, Rationale

Disconnect-EpmTenant
```

## Security boundaries

- Tokens remain in memory for the active session and are not written to disk. They are converted to plaintext only when an HTTP authorization header is constructed.
- Verbose logging records header names, not header values. The HTTP transport disables the `Invoke-WebRequest` debug stream to prevent credentials from appearing in debug output.
- The local mock server requires a token on product routes, while generic transport routes remain unauthenticated to isolate transport tests from authentication tests.
- `Invoke-S1FleetRemediation` is the only state-changing command. It moves endpoints only to a specified tracking group, uses `SupportsShouldProcess`, sets `ConfirmImpact = 'High'`, and supports `-WhatIf`.
- `-WhatIf` does not bypass connection validation: a disconnected module fails rather than claiming it would act.
- VirusTotal requests disclose a hash or a reversible base64url URL identifier to that third party. Enrichment is opt-in and never uploads files.

## Validation and CI

The test suite uses `tests/mock/MockApiServer.ps1`, a local PowerShell HTTP server. It exercises request serialization, status handling, JSON bodies, pagination, retries, and write journaling. It does **not** prove compatibility with a real product tenant.

```bash
pwsh -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./tests -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"
```

CI runs the following gates:

| Stage | Assurance |
|---|---|
| Static analysis | Source and tests are checked with the selected PSScriptAnalyzer rules; the job fails if it finds no PowerShell files to scan. |
| Unit tests | The module imports, exports the expected public surface, and keeps its manifest aligned with `Public/`. |
| Canary | The mock API server starts and returns expected success, failure, and 404 responses before contract tests run. |
| Contract tests | The HTTP client meets the assumed API contract for pagination, retries, timeouts, and rate limiting. |
| Security tests | Tokens and passwords do not appear in verbose output, debug output, or error messages. |
| Secret scanning | Gitleaks checks the Git history for committed secrets. |
| Manifest validation | `EndpointOps.psd1` remains a valid PowerShell module manifest. |

## Limitations

- The project has been written against public documentation and a mock server only. No real SentinelOne, CyberArk EPM, or VirusTotal tenant has been used for validation, and the repository contains no tenant data, tokens, or tenant addresses.
- Several upstream behaviours remain ambiguous in public documentation, including some EPM field names and pagination endings. The module handles documented alternatives defensively, but a real tenant is required to resolve them.
- EPM policy details are rate limited to 30 calls per minute and each policy description requires its own detail request. Reviewing 200 policies therefore takes more than seven minutes.
- The VirusTotal quota counter is in memory and applies only to the current process. It paces that session; it is not an authoritative daily-quota ledger.
- SentinelOne retention is tenant-dependent. `Get-S1UnusedAuthorizationReport` requires `RetentionDays` rather than assuming a universal retention period.

## Project structure

```
src/EndpointOps/       PowerShell module, public commands, and private helpers
tests/unit/            Module and command-level tests
tests/contract/        HTTP contract and mock-server tests
tests/security/        Credential-leak and safety regression tests
tests/mock/            Local mock HTTP server and fixtures
docs/                  API research, detection backlog, and design decisions
```

## Technical decisions

The implementation rationale, known trade-offs, and security constraints are documented in [technical decisions](docs/decisions.md). Supporting public-API research is available in [SentinelOne, EPM, and VirusTotal notes](docs/api-notes.md), [EPM API notes](docs/api-notes-epm.md), and [reputation-service notes](docs/api-notes-reputation.md).
