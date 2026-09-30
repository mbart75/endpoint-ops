# Graph Report - endpoint-ops (2026-09-30)

## Corpus Check
- 143 files · ~103,972 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 253 nodes · 212 edges · 90 communities
- Extraction: 63% EXTRACTED · 37% INFERRED · 0% AMBIGUOUS · INFERRED: 79 edges (avg confidence: 0.81)
- Token accounting: unavailable for agent-assisted semantic extraction in this run; zero in the generator metadata does not mean zero usage.

## Graph Freshness
- Built from commit: `8d07290e`
- Compare this source commit with later code/documentation changes; a graph-only commit does not invalidate the map.
- Refresh after code or documentation changes; code-only extraction is local, while changed documentation needs semantic extraction.

## Community Hubs (Navigation)
- EPM Scoring and Requests
- API Trust and Evidence
- Persistent Reputation Cache
- SentinelOne Observation Flow
- Reputation Provider Requests
- HTTP Transport and Hybrid Analysis
- Device Control Evidence
- CI Assurance Pipeline
- Detection Workflows

## God Nodes (most connected - your core abstractions)
1. `Get-PropertyOrDefault()` - 15 edges
2. `EndpointOps overview` - 11 edges
3. `Invoke-S1Request()` - 9 edges
4. `Device Control rule-usage inventory roadmap` - 9 edges
5. `Invoke-EndpointOpsRequest()` - 8 edges
6. `CI validation pipeline` - 8 edges
7. `Invoke-EpmRequest()` - 7 edges
8. `Reputation-service API research` - 7 edges
9. `SHA-1 reputation cascade` - 7 edges
10. `Detection backlog` - 6 edges

## Surprising Connections (you probably didn't know these)
- `Authentication, hash, and cache trust boundaries` --semantically_similar_to--> `Mock-backed validation boundary`  [INFERRED] [semantically similar]
  docs/superpowers/specs/2026-09-07-independent-review-hardening-design.md → README.md
- `SHA-1 reputation cascade` --semantically_similar_to--> `Reputation cannot authorize`  [INFERRED] [semantically similar]
  docs/api-notes-reputation.md → README.md
- `Fail-soft optional reputation` --semantically_similar_to--> `Reputation cannot authorize`  [INFERRED] [semantically similar]
  docs/decisions.md → README.md
- `CI validation pipeline` --conceptually_related_to--> `Mock-backed validation boundary`  [INFERRED]
  .github/workflows/ci.yml → README.md
- `EndpointOps overview` --references--> `API research notes`  [EXTRACTED]
  README.md → docs/api-notes.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Independent-review hardening cycle** — docs_superpowers_specs_2026_09_07_independent_review_hardening_design_hardening_design, docs_superpowers_plans_2026_09_07_lot8_security_behavioral_blockers_lot8_plan, docs_superpowers_plans_2026_09_07_lot9_evidence_cache_integrity_lot9_plan, docs_superpowers_plans_2026_09_07_lot10_transport_preventive_controls_lot10_plan [EXTRACTED 1.00]
- **Seven-Stage CI Assurance** — github_workflows_ci_static_analysis, github_workflows_ci_unit_tests, github_workflows_ci_canary, github_workflows_ci_contract_tests, github_workflows_ci_security_tests, github_workflows_ci_secret_scanning, github_workflows_ci_manifest_validation [EXTRACTED 1.00]
- **Ordered Multi-Source Reputation Evidence Cascade** — docs_api_notes_reputation_virustotal, docs_api_notes_reputation_malwarebazaar, docs_api_notes_reputation_hybrid_analysis, docs_api_notes_reputation_threatfox, docs_api_notes_reputation_reconciliation [EXTRACTED 1.00]

## Communities (90 total; nine substantive communities displayed)

The remaining small or structural-only communities remain in `graph.json` and `graph.html`; they are omitted here to keep the report navigable.

### Community 0 - "EPM Scoring and Requests"
Cohesion: 0.08
Nodes (16): ConvertTo-EpmSet(), Get-EpmNextCursor(), Get-PropertyOrDefault(), Get-WorstSeverity(), Invoke-EpmRequest(), Measure-DeviceRuleBreadth(), Measure-ExclusionBreadth(), Get-EpmElevationEvent() (+8 more)

### Community 1 - "API Trust and Evidence"
Cohesion: 0.11
Nodes (28): EPM dispatcher-to-manager topology, EPM offset and cursor pagination, CyberArk EPM API research, Validated VirusTotal SHA-256 pivot, Hybrid Analysis Reputation Source, MalwareBazaar Reputation Source, Evidence-Preserving Reputation Reconciliation, Reputation-service API research (+20 more)

### Community 2 - "Persistent Reputation Cache"
Cohesion: 0.11
Nodes (10): Get-MbFileVerdict(), Invoke-WithReputationCacheLock(), Move-ReputationCacheFile(), Test-ReputationCacheFile(), Write-ReputationCacheEntry(), Write-ReputationCacheFile(), Clear-ReputationCache(), Get-EpmElevationSummary() (+2 more)

### Community 3 - "SentinelOne Observation Flow"
Cohesion: 0.11
Nodes (10): Get-S1ConnectionState(), Invoke-S1Request(), Test-ObservationWindow(), Test-OsBuildStatus(), Connect-S1Tenant(), Get-S1Agent(), Get-S1DeviceControlEvent(), Get-S1FleetHygieneReport() (+2 more)

### Community 4 - "Reputation Provider Requests"
Cohesion: 0.12
Nodes (9): Get-HttpStatusFromError(), Get-MbConnectionState(), Get-TfFileVerdict(), Get-VtConnectionState(), Get-VtUtcNow(), Invoke-MbRequest(), Invoke-VtRequest(), Connect-EpmTenant() (+1 more)

### Community 5 - "HTTP Transport and Hybrid Analysis"
Cohesion: 0.20
Nodes (5): Get-EndpointOpsUtcNow(), Get-HaConnectionState(), Get-HaFileVerdict(), Invoke-EndpointOpsHttpRequest(), Invoke-HaRequest()

### Community 6 - "Device Control Evidence"
Cohesion: 0.28
Nodes (9): API research notes, Device Control contract uncertainty, Allowed usage versus blocked demand, Direct Candidate and Unresolved Correlation Levels, Coverage prerequisite for non-use, Read-Only Versioned Rule Snapshots, Versioned read-only rule snapshot, Device Control rule-usage inventory roadmap (+1 more)

### Community 7 - "CI Assurance Pipeline"
Cohesion: 0.29
Nodes (8): Mock Server Canary Gate, Contract Test Gate, PowerShell Manifest Validation Gate, Gitleaks Secret Scanning Gate, Security Test Gate, Static Analysis Gate, Unit Test Gate, CI validation pipeline

### Community 8 - "Detection Workflows"
Cohesion: 0.43
Nodes (7): Detection backlog, W1 SentinelOne Fleet Hygiene, W2 EPM Events to Policy Proposals, W3 SentinelOne Exclusion Review, W4.7 machine/group unused-authorization review, W4.8 proposed rule-level usage inventory, W4 Device Control Review

## Knowledge Gaps
- **12 isolated node(s):** `Architecture knowledge graph`, `Typed HTTP exceptions debt`, `Versioned read-only rule snapshot`, `Static Analysis Gate`, `Unit Test Gate` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Invoke-EndpointOpsRequest()` connect `Reputation Provider Requests` to `EPM Scoring and Requests`, `SentinelOne Observation Flow`, `HTTP Transport and Hybrid Analysis`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Why does `Get-PropertyOrDefault()` connect `EPM Scoring and Requests` to `SentinelOne Observation Flow`, `HTTP Transport and Hybrid Analysis`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Why does `Invoke-S1Request()` connect `SentinelOne Observation Flow` to `EPM Scoring and Requests`, `Reputation Provider Requests`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Are the 14 inferred relationships involving `Get-PropertyOrDefault()` (e.g. with `ConvertTo-EpmSet()` and `Get-EpmNextCursor()`) actually correct?**
  _`Get-PropertyOrDefault()` has 14 INFERRED edges - model-reasoned connections that need verification._
- **Are the 8 inferred relationships involving `Invoke-S1Request()` (e.g. with `Get-S1ConnectionState()` and `Invoke-EndpointOpsRequest()`) actually correct?**
  _`Invoke-S1Request()` has 8 INFERRED edges - model-reasoned connections that need verification._
- **Are the 7 inferred relationships involving `Invoke-EndpointOpsRequest()` (e.g. with `Get-TfFileVerdict()` and `Invoke-EpmRequest()`) actually correct?**
  _`Invoke-EndpointOpsRequest()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Architecture knowledge graph`, `Typed HTTP exceptions debt`, `Versioned read-only rule snapshot` to the rest of the system?**
  _12 weakly-connected nodes found - possible documentation gaps or missing edges._
