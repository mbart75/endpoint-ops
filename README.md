# endpoint-ops

**A PowerShell toolkit for evidence-driven endpoint security reviews.** endpoint-ops turns documented SentinelOne, CyberArk EPM, VirusTotal, MalwareBazaar, Hybrid Analysis, and ThreatFox API responses into reviewable hygiene, policy, and reputation findings without turning an API client into an autonomous security decision-maker.

It is designed for endpoint engineers who prefer auditable command-line workflows to opaque console clicks. Read operations are separated from reporting logic; reports state their reasons in plain text; and the only write workflow is deliberately narrow, protected by PowerShell `ShouldProcess`.

> **Validation boundary:** this repository is implemented from public product documentation and tested only against its local mock HTTP server. The SentinelOne, CyberArk EPM, VirusTotal, MalwareBazaar, Hybrid Analysis, and ThreatFox integrations are documentation- and mock-backed contracts, not guarantees of real-service compatibility. No real tenant, provider account, tenant data, or production credential was used.

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
                             Get-FileReputation · Clear-ReputationCache
                                        |
Layer 2  Connections        Connect-S1Tenant · Disconnect-S1Tenant
                             Connect-EpmTenant · Disconnect-EpmTenant
                             Connect-VirusTotal · Disconnect-VirusTotal
                             Connect-MalwareBazaar · Disconnect-MalwareBazaar
                             Connect-HybridAnalysis · Disconnect-HybridAnalysis
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
| Reputation enrichment | `Connect-VirusTotal`, `Disconnect-VirusTotal`, `Get-VtFileReport`, `Get-VtUrlReport`, `Connect-MalwareBazaar`, `Disconnect-MalwareBazaar`, `Connect-HybridAnalysis`, `Disconnect-HybridAnalysis`, `Get-FileReputation`, `Clear-ReputationCache` | Optional hash-only file enrichment with ordered per-source evidence. URL lookup remains VirusTotal-specific. No file upload or automatic authorization exists. |

CyberArk EPM uses a dispatcher model: authentication returns both a session token and `ManagerURL`; subsequent EPM requests use that returned manager URL. EPM list pagination uses offsets, while event pagination uses an opaque cursor.

File-reputation enrichment always starts with VirusTotal. After a `Malicious`, `Unknown`, or `Unavailable` VirusTotal result, it consults MalwareBazaar. Hybrid Analysis is queried only after the aggregate contains malicious evidence; ThreatFox is queried at that stage only when VirusTotal supplied a valid SHA-256 pivot. Provider silence or absence is never converted to `Clean`. Reputation can only weaken or reject an existing EPM proposal and never authorizes an elevation automatically. The output value `Unknown` must never be read as safe.

## Opt-in reputation cache

Persistent caching is disabled unless `Get-FileReputation` receives `-UseCache`. Its default path is `ApplicationData/EndpointOps/reputation-cache.json` under the current user profile. A custom `-CachePath` should be protected as sensitive local software-inventory data.

The versioned cache stores the lookup hash, a validated canonical SHA-256 relationship when available, each provider's evidence hash and provenance, the verdict, and the query date; it never stores API keys. Legacy entries remain reusable only by exact hash. `Clean` and `Unknown` entries expire after 7 days, `Malicious` entries after 90 days, and `Unavailable` results are never cached.

```powershell
Get-FileReputation -Hash $sha1 -UseCache
Clear-ReputationCache
```

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
- Each reputation provider that is queried learns a file hash. ThreatFox receives the VirusTotal-derived SHA-256 pivot. VirusTotal URL lookups disclose a reversible base64url URL identifier. Enrichment is opt-in and never uploads file contents.

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

- The project has been written against public documentation and a mock server only. No real SentinelOne or CyberArk EPM tenant and no real VirusTotal, MalwareBazaar, Hybrid Analysis, or ThreatFox account was used for validation. The repository contains no tenant data, tokens, or tenant addresses.
- Several upstream behaviours remain ambiguous in public documentation, including some EPM field names and pagination endings. The module handles documented alternatives defensively, but a real tenant is required to resolve them.
- EPM policy details are rate limited to 30 calls per minute and each policy description requires its own detail request. Reviewing 200 policies therefore takes more than seven minutes.
- The VirusTotal quota counter is in memory and applies only to the current process. It paces that session; it is not an authoritative daily-quota ledger.
- The tested ThreatFox entry point and absence-status contract are represented by the local mock only and require confirmation against the real service.
- SentinelOne retention is tenant-dependent. `Get-S1UnusedAuthorizationReport` requires `RetentionDays` rather than assuming a universal retention period.

## Roadmap

The [Device Control rule-usage inventory roadmap](docs/device-control-rule-usage-roadmap.md) proposes an additive, read-only view that would correlate individual rules with tenant-wide events and preserve historical rule evidence for later impact analysis. It does not replace the existing machine/group report, claim a verified vendor schema, or authorize automatic rule changes.

## Project structure

```
src/EndpointOps/       PowerShell module, public commands, and private helpers
tests/unit/            Module and command-level tests
tests/contract/        HTTP contract and mock-server tests
tests/security/        Credential-leak and safety regression tests
tests/mock/            Local mock HTTP server and fixtures
docs/                  API research, detection backlog, and design decisions
```

## Architecture knowledge graph

The repository includes a generated [knowledge-graph report](graphify-out/GRAPH_REPORT.md), the [raw GraphRAG-ready graph](graphify-out/graph.json), and a [single-file interactive viewer](graphify-out/graph.html). The graph combines structural PowerShell relationships with explicitly labelled documentation relationships so architectural links, central components, and validation gaps can be explored without treating inferred edges as facts.

Download `graph.html` and open it locally to use the interactive view. It loads the integrity-pinned `vis-network` library from a public CDN; the report and JSON remain fully readable without executing the viewer.

## Technical decisions

The implementation rationale, known trade-offs, and security constraints are documented in [technical decisions](docs/decisions.md). Supporting research is available in the [general API notes](docs/api-notes.md), [EPM API notes](docs/api-notes-epm.md), [reputation-service notes](docs/api-notes-reputation.md), and [Device Control rule-usage roadmap](docs/device-control-rule-usage-roadmap.md).
