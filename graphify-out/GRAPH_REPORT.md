# Graph Report - endpoint-ops (2026-08-30)

## Corpus Check
- 133 files · ~77,961 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 233 nodes · 198 edges · 84 communities
- Extraction: 57% EXTRACTED · 43% INFERRED · 0% AMBIGUOUS · INFERRED: 86 edges (avg confidence: 0.8)
- Token cost: 18,839 input · 7,600 output

## Community Hubs (Navigation)
- Scoring and EPM Requests
- Architecture and API Research
- SentinelOne Observation Flow
- Cache and Shared Requests
- VirusTotal Client Flow
- Detection and Device Control
- CI Assurance Pipeline
- Hybrid Analysis Transport
- EPM Elevation and State

## God Nodes (most connected - your core abstractions)
1. `Get-PropertyOrDefault()` - 19 edges
2. `endpoint-ops` - 11 edges
3. `Invoke-EpmRequest()` - 10 edges
4. `Invoke-S1Request()` - 9 edges
5. `Device Control Rule-Usage Inventory Roadmap` - 9 edges
6. `Get-FileReputation()` - 8 edges
7. `Invoke-EndpointOpsRequest()` - 8 edges
8. `CI Validation Pipeline` - 8 edges
9. `Invoke-VtRequest()` - 7 edges
10. `Get-VtFileReport()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `Multi-Source Reputation Cascade` --semantically_similar_to--> `Evidence-Preserving Reputation Reconciliation`  [INFERRED] [semantically similar]
  README.md → docs/api-notes-reputation.md
- `CI Validation Pipeline` --conceptually_related_to--> `endpoint-ops`  [INFERRED]
  .github/workflows/ci.yml → README.md
- `endpoint-ops` --references--> `Device Control Rule-Usage Inventory Roadmap`  [EXTRACTED]
  README.md → docs/device-control-rule-usage-roadmap.md
- `Get-VtUrlReport()` --calls--> `ConvertTo-VtUrlId()`  [INFERRED]
  src/EndpointOps/Public/Get-VtUrlReport.ps1 → src/EndpointOps/Private/ConvertTo-VtUrlId.ps1
- `Invoke-EpmRequest()` --calls--> `Get-EpmConnectionState()`  [INFERRED]
  src/EndpointOps/Private/Invoke-EpmRequest.ps1 → src/EndpointOps/Private/Get-EpmConnectionState.ps1

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Seven-Stage CI Assurance** — github_workflows_ci_static_analysis, github_workflows_ci_unit_tests, github_workflows_ci_canary, github_workflows_ci_contract_tests, github_workflows_ci_security_tests, github_workflows_ci_secret_scanning, github_workflows_ci_manifest_validation [EXTRACTED 1.00]
- **Ordered Multi-Source Reputation Evidence Cascade** — docs_api_notes_reputation_virustotal, docs_api_notes_reputation_malwarebazaar, docs_api_notes_reputation_hybrid_analysis, docs_api_notes_reputation_threatfox, docs_api_notes_reputation_reconciliation [EXTRACTED 1.00]
- **Device Control Rule-Usage Evidence Model** — docs_device_control_rule_usage_roadmap_traceability_model, docs_device_control_rule_usage_roadmap_correlation_levels, docs_device_control_rule_usage_roadmap_separate_usage_and_demand, docs_device_control_rule_usage_roadmap_logging_coverage_gate, docs_device_control_rule_usage_roadmap_read_only_snapshots [EXTRACTED 1.00]

## Communities (84 total, 75 thin communities available in the graph only)

The report expands the nine multi-node architectural communities below. Smaller test- and command-specific communities remain available in `graph.json` and `graph.html` without being repeated as one-line report sections.

### Community 0 - "Scoring and EPM Requests"
Cohesion: 0.08
Nodes (16): ConvertTo-EpmSet(), Get-EpmConnectionState(), Get-EpmNextCursor(), Get-PropertyOrDefault(), Get-WorstSeverity(), Invoke-EpmRequest(), Measure-DeviceRuleBreadth(), Measure-ExclusionBreadth() (+8 more)

### Community 1 - "Architecture and API Research"
Cohesion: 0.11
Nodes (21): API Research Notes, CyberArk EPM API Notes, Defensive EPM Response Handling, CyberArk EPM Dispatcher Authentication Model, EPM Offset and Cursor Pagination, Hybrid Analysis Reputation Source, MalwareBazaar Reputation Source, Evidence-Preserving Reputation Reconciliation (+13 more)

### Community 2 - "SentinelOne Observation Flow"
Cohesion: 0.11
Nodes (10): Get-S1ConnectionState(), Invoke-S1Request(), Test-ObservationWindow(), Test-OsBuildStatus(), Connect-S1Tenant(), Get-S1Agent(), Get-S1DeviceControlEvent(), Get-S1FleetHygieneReport() (+2 more)

### Community 3 - "Cache and Shared Requests"
Cohesion: 0.12
Nodes (9): Get-MbConnectionState(), Get-MbFileVerdict(), Get-ReputationCacheEntry(), Get-TfFileVerdict(), Invoke-MbRequest(), Write-ReputationCacheEntry(), Connect-EpmTenant(), Get-FileReputation() (+1 more)

### Community 4 - "VirusTotal Client Flow"
Cohesion: 0.16
Nodes (8): ConvertTo-VtUrlId(), ConvertTo-VtVerdict(), Copy-VtReport(), Get-HttpStatusFromError(), Get-VtUtcNow(), Invoke-VtRequest(), Get-VtFileReport(), Get-VtUrlReport()

### Community 5 - "Detection and Device Control"
Cohesion: 0.18
Nodes (14): Device Control Rule and Event Contract Gap, Detection Backlog, W1 SentinelOne Fleet Hygiene, W2 EPM Events to Policy Proposals, W3 SentinelOne Exclusion Review, W4.7 Unused Authorization Review, W4.8 Rule-Level Usage Inventory, W4 Device Control Review (+6 more)

### Community 6 - "CI Assurance Pipeline"
Cohesion: 0.29
Nodes (8): Mock Server Canary Gate, CI Validation Pipeline, Contract Test Gate, PowerShell Manifest Validation Gate, Gitleaks Secret Scanning Gate, Security Test Gate, Static Analysis Gate, Unit Test Gate

### Community 7 - "Hybrid Analysis Transport"
Cohesion: 0.25
Nodes (4): Get-HaConnectionState(), Get-HaFileVerdict(), Invoke-EndpointOpsHttpRequest(), Invoke-HaRequest()

### Community 8 - "EPM Elevation and State"
Cohesion: 0.33
Nodes (3): Get-VtConnectionState(), Get-EpmElevationEvent(), Get-EpmElevationSummary()

## Knowledge Gaps
- **15 isolated node(s):** `Static Analysis Gate`, `Unit Test Gate`, `Security Test Gate`, `Gitleaks Secret Scanning Gate`, `PowerShell Manifest Validation Gate` (+10 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Get-PropertyOrDefault()` connect `Scoring and EPM Requests` to `SentinelOne Observation Flow`, `Cache and Shared Requests`, `VirusTotal Client Flow`, `Hybrid Analysis Transport`, `EPM Elevation and State`?**
  _High betweenness centrality (0.099) - this node is a cross-community bridge._
- **Why does `Invoke-EndpointOpsRequest()` connect `Cache and Shared Requests` to `Scoring and EPM Requests`, `SentinelOne Observation Flow`, `VirusTotal Client Flow`, `Hybrid Analysis Transport`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Why does `Get-FileReputation()` connect `Cache and Shared Requests` to `EPM Elevation and State`, `VirusTotal Client Flow`, `Hybrid Analysis Transport`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **Are the 18 inferred relationships involving `Get-PropertyOrDefault()` (e.g. with `ConvertTo-EpmSet()` and `Get-EpmNextCursor()`) actually correct?**
  _`Get-PropertyOrDefault()` has 18 INFERRED edges - model-reasoned connections that need verification._
- **Are the 9 inferred relationships involving `Invoke-EpmRequest()` (e.g. with `Get-EpmConnectionState()` and `Get-EpmNextCursor()`) actually correct?**
  _`Invoke-EpmRequest()` has 9 INFERRED edges - model-reasoned connections that need verification._
- **Are the 8 inferred relationships involving `Invoke-S1Request()` (e.g. with `Get-S1ConnectionState()` and `Invoke-EndpointOpsRequest()`) actually correct?**
  _`Invoke-S1Request()` has 8 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Static Analysis Gate`, `Unit Test Gate`, `Security Test Gate` to the rest of the system?**
  _15 weakly-connected nodes found - possible documentation gaps or missing edges._
