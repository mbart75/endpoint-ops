# Graph Report - endpoint-ops (2026-09-30)

## Corpus Check
- 145 files · ~105,499 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 265 nodes · 228 edges · 91 communities
- Extraction: 63% EXTRACTED · 37% INFERRED · 0% AMBIGUOUS · INFERRED: 84 edges (avg confidence: 0.82)
- Token accounting: unavailable for agent-assisted semantic extraction in this run; zero in the generator metadata does not mean zero usage.

## Graph Freshness
- Built from commit: `6ea76e14`
- Compare this source commit with later code/documentation changes; a graph-only commit does not invalidate the map.
- Refresh after code or documentation changes; code extraction is local, while changed documentation needs semantic extraction.

## Community Hubs (Navigation)
- API Trust, Policy, and Evidence
- EPM Scoring and Requests
- Persistent Reputation Cache
- SentinelOne Observation Flow
- EPM and Provider Requests
- CI and Windows ACL Assurance
- HTTP Transport and Hybrid Analysis
- Reputation Evidence Sources
- VirusTotal Requests
- Detection Workflows

## God Nodes (most connected - your core abstractions)
1. `Get-PropertyOrDefault()` - 15 edges
2. `EndpointOps overview` - 13 edges
3. `CI validation pipeline` - 11 edges
4. `Invoke-S1Request()` - 9 edges
5. `Device Control rule-usage inventory roadmap` - 9 edges
6. `Invoke-EndpointOpsRequest()` - 8 edges
7. `Invoke-EpmRequest()` - 7 edges
8. `Reputation-service API research` - 7 edges
9. `SHA-1 reputation cascade` - 7 edges
10. `Detection backlog` - 6 edges

## Surprising Connections (you probably didn't know these)
- `SHA-1 reputation cascade` --semantically_similar_to--> `Reputation cannot authorize`  [INFERRED] [semantically similar]
  docs/api-notes-reputation.md → README.md
- `Authentication, hash, and cache trust boundaries` --semantically_similar_to--> `Mock-backed validation boundary`  [INFERRED] [semantically similar]
  docs/superpowers/specs/2026-09-07-independent-review-hardening-design.md → README.md
- `Fail-soft optional reputation` --semantically_similar_to--> `Reputation cannot authorize`  [INFERRED] [semantically similar]
  docs/decisions.md → README.md
- `CI validation pipeline` --conceptually_related_to--> `Mock-backed validation boundary`  [INFERRED]
  .github/workflows/ci.yml → README.md
- `Native Windows execution proof` --conceptually_related_to--> `Native Windows cache ACL assurance`  [INFERRED]
  docs/superpowers/plans/2026-09-30-pwsh76-windows-acl.md → README.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Native Windows cache ACL assurance** — github_workflows_ci_windows_acl_job, readme_native_windows_cache_acl_assurance, docs_decisions_explicit_windows_acl_proof, docs_superpowers_plans_2026_09_30_pwsh76_windows_acl_native_execution_proof [INFERRED 0.95]
- **Independent-review hardening cycle** — docs_superpowers_specs_2026_09_07_independent_review_hardening_design_hardening_design, docs_superpowers_plans_2026_09_07_lot8_security_behavioral_blockers_lot8_plan, docs_superpowers_plans_2026_09_07_lot9_evidence_cache_integrity_lot9_plan, docs_superpowers_plans_2026_09_07_lot10_transport_preventive_controls_lot10_plan [EXTRACTED 1.00]
- **Ordered Multi-Source Reputation Evidence Cascade** — docs_api_notes_reputation_virustotal, docs_api_notes_reputation_malwarebazaar, docs_api_notes_reputation_hybrid_analysis, docs_api_notes_reputation_threatfox, docs_api_notes_reputation_reconciliation [EXTRACTED 1.00]
- **Seven-Stage CI Assurance** — github_workflows_ci_static_analysis, github_workflows_ci_unit_tests, github_workflows_ci_canary, github_workflows_ci_contract_tests, github_workflows_ci_security_tests, github_workflows_ci_secret_scanning, github_workflows_ci_manifest_validation [EXTRACTED 1.00]
- **Device Control Rule-Usage Evidence Model** — docs_device_control_rule_usage_roadmap_traceability_model, docs_device_control_rule_usage_roadmap_correlation_levels, docs_device_control_rule_usage_roadmap_allowed_vs_blocked, docs_device_control_rule_usage_roadmap_coverage_before_nonuse, docs_device_control_rule_usage_roadmap_read_only_snapshots [EXTRACTED 1.00]

## Communities (91 total; ten substantive communities displayed)

The remaining small or structural-only communities remain in `graph.json` and `graph.html`; they are omitted here to keep the report navigable.
Node counts include source-file nodes paired with code functions, even when only function labels are shown below.

### Community 0 - "API Trust, Policy, and Evidence"
Cohesion: 0.09
Nodes (33): API research notes, Device Control contract uncertainty, EPM dispatcher-to-manager topology, EPM offset and cursor pagination, CyberArk EPM API research, SentinelOne cursor contract, Persistent evidence integrity, Explicit restrictive Windows ACL proof (+25 more)

### Community 1 - "EPM Scoring and Requests"
Cohesion: 0.11
Nodes (24): Get-EpmNextCursor(), Get-PropertyOrDefault(), Get-WorstSeverity(), Measure-DeviceRuleBreadth(), Measure-ExclusionBreadth(), Get-EpmPolicy(), Get-EpmPolicyDetail(), Get-EpmPolicyHygieneReport() (+16 more, including paired source-file nodes)

### Community 2 - "Persistent Reputation Cache"
Cohesion: 0.10
Nodes (22): Get-MbFileVerdict(), Invoke-ReputationCacheReplace(), Invoke-WithReputationCacheLock(), Move-ReputationCacheFile(), Test-ReputationCacheFile(), Write-ReputationCacheEntry(), Write-ReputationCacheFile(), Clear-ReputationCache() (+14 more)

### Community 3 - "SentinelOne Observation Flow"
Cohesion: 0.11
Nodes (20): Get-S1ConnectionState(), Invoke-S1Request(), Test-ObservationWindow(), Test-OsBuildStatus(), Connect-S1Tenant(), Get-S1Agent(), Get-S1DeviceControlEvent(), Get-S1FleetHygieneReport() (+12 more)

### Community 4 - "EPM and Provider Requests"
Cohesion: 0.12
Nodes (18): ConvertTo-EpmSet(), Get-MbConnectionState(), Get-TfFileVerdict(), Invoke-EpmRequest(), Invoke-MbRequest(), Connect-EpmTenant(), Get-EpmElevationEvent(), Get-EpmSet() (+10 more)

### Community 5 - "CI and Windows ACL Assurance"
Cohesion: 0.17
Nodes (13): Native Windows execution proof, PowerShell 7.6 support floor, ACL test selection and skip gate, Mock Server Canary Gate, Contract Test Gate, PowerShell Manifest Validation Gate, PowerShell 7.6 runtime gate, Gitleaks Secret Scanning Gate (+5 more)

### Community 6 - "HTTP Transport and Hybrid Analysis"
Cohesion: 0.20
Nodes (10): Get-EndpointOpsUtcNow(), Get-HaConnectionState(), Get-HaFileVerdict(), Invoke-EndpointOpsHttpRequest(), Invoke-HaRequest() (+5 paired source-file nodes)

### Community 7 - "Reputation Evidence Sources"
Cohesion: 0.36
Nodes (9): Validated VirusTotal SHA-256 pivot, Hybrid Analysis Reputation Source, MalwareBazaar Reputation Source, Evidence-Preserving Reputation Reconciliation, Reputation-service API research, SHA-1 reputation cascade, ThreatFox Reputation Source, VirusTotal Reputation Source (+1 more)

### Community 8 - "VirusTotal Requests"
Cohesion: 0.25
Nodes (8): Get-HttpStatusFromError(), Get-VtConnectionState(), Get-VtUtcNow(), Invoke-VtRequest() (+4 paired source-file nodes)

### Community 9 - "Detection Workflows"
Cohesion: 0.43
Nodes (7): Detection backlog, W1 SentinelOne Fleet Hygiene, W2 EPM Events to Policy Proposals, W3 SentinelOne Exclusion Review, W4.7 machine/group unused-authorization review, W4.8 proposed rule-level usage inventory, W4 Device Control Review

## Knowledge Gaps
- **13 isolated node(s):** `Versioned read-only rule snapshot`, `W1 SentinelOne Fleet Hygiene`, `W2 EPM Events to Policy Proposals`, `W3 SentinelOne Exclusion Review`, `Architecture knowledge graph` (+8 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Invoke-EndpointOpsRequest()` connect `EPM and Provider Requests` to `VirusTotal Requests`, `SentinelOne Observation Flow`, `HTTP Transport and Hybrid Analysis`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Why does `Get-PropertyOrDefault()` connect `EPM Scoring and Requests` to `SentinelOne Observation Flow`, `EPM and Provider Requests`, `HTTP Transport and Hybrid Analysis`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Why does `EndpointOps overview` connect `API Trust, Policy, and Evidence` to `Reputation Evidence Sources`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Are the 14 inferred relationships involving `Get-PropertyOrDefault()` (e.g. with `ConvertTo-EpmSet()` and `Get-EpmNextCursor()`) actually correct?**
  _`Get-PropertyOrDefault()` has 14 INFERRED edges - model-reasoned connections that need verification._
- **Are the 8 inferred relationships involving `Invoke-S1Request()` (e.g. with `Get-S1ConnectionState()` and `Invoke-EndpointOpsRequest()`) actually correct?**
  _`Invoke-S1Request()` has 8 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Versioned read-only rule snapshot`, `W1 SentinelOne Fleet Hygiene`, `W2 EPM Events to Policy Proposals` to the rest of the system?**
  _13 weakly-connected nodes found - possible documentation gaps or missing edges._
