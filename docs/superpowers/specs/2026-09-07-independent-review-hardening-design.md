# Independent Review Hardening Cycle Design

**Date:** 2026-09-07

**Status:** Approved for implementation

**Repository:** `mbart75/endpoint-ops`

**Scope:** Findings reproduced during the independent review of public `main` at `9f27d94`

## Purpose

The public repository is portfolio-ready and its current validation is green, but an independent adversarial review reproduced several defects that are not covered by the existing 757-test suite. This cycle closes those findings before the project is described as production-ready.

The work is split into three ordered lots and seven independently reviewable tasks. Every task receives its own GitHub issue, branch, pull request, red-green TDD cycle, fault injection, independent review, CI run, merge, and post-merge validation.

Device Control issues #11 and #12 are not part of this cycle. They remain blocked until an authorized SentinelOne tenant or an equivalent authoritative contract is available.

## Design principles

- Fix reproduced behavior, not hypothetical product features.
- Preserve all lot 1-7 behavior unless a finding proves that behavior wrong.
- Treat authentication destinations, hash identity, and cached evidence as trust boundaries.
- Fail closed for secret handling and evidence identity.
- Fail soft for optional reputation enrichment so base EPM reporting remains available.
- External reputation may reject or weaken a proposal, never authorize one.
- Do not upload files or introduce automatic security authorization or destructive remediation.
- Keep public documentation in English and keep personal context outside the repository.
- Do not claim real-tenant compatibility; the mock remains a simulated contract.

## Delivery structure

### Lot 8: security and behavioral blockers

Lot 8 removes the findings that currently block a production-ready claim. Its three tasks are intentionally sequential because they share EPM and VirusTotal behavior.

#### Task 8.1: validate the EPM manager destination

**Problem**

`Connect-EpmTenant` validates the operator-supplied dispatcher but accepts the returned `ManagerURL` without transport validation. The subsequent automatic validation sends the EPM token to that URL. A reproduced authentication response containing a non-loopback HTTP URL received the authorization header.

**Design**

- Parse `ManagerURL` as an absolute URI before constructing or storing the secure token state.
- Require HTTPS for every non-loopback manager.
- Retain narrowly scoped HTTP support for exact loopback hosts used by the local mock server.
- Reject missing hosts, relative values, fragments, credentials embedded in the authority, and unsupported schemes.
- Do not require the manager host to equal the dispatcher host. CyberArk uses a dispatcher-to-manager topology and the real host relationship has not been validated against a tenant.
- Clear any partial EPM connection state after rejection.
- Keep errors sanitized: the token and submitted credential body must not enter messages or error records.

**Acceptance criteria**

- Non-loopback HTTP, relative, credential-bearing, fragment-bearing, and malformed manager URLs are rejected before any manager request.
- Valid HTTPS and exact loopback mock URLs retain current behavior.
- A security test proves that an injected HTTP manager never receives the token.
- Existing EPM connection and secret-handling tests remain green.

#### Task 8.2: preserve EPM output when reputation is unavailable

**Problem**

`Get-EpmElevationSummary -IncludeReputation` currently validates the VirusTotal connection before collecting EPM events. This contradicts the documented invariant that an optional provider failure must not prevent base EPM grouping.

**Design**

- Remove the report-level VirusTotal connection preflight.
- Collect and group EPM data independently of reputation state.
- Let per-group reputation calls map disconnected or failed providers to `Unavailable` evidence.
- Preserve the original proposal when evidence is unavailable or unknown.
- Continue to reject `-IncludeReputation -GroupBy User` before any network request because that parameter combination has no meaningful output.

**Acceptance criteria**

- With VirusTotal disconnected, every expected EPM binary grouping is returned.
- Each grouping exposes unavailable reputation without becoming more permissive or more restrictive.
- The test proves that the EPM endpoint was queried and the grouping fields are unchanged.
- Malicious evidence still degrades the proposal and no reputation state can promote it.

#### Task 8.3: give the VirusTotal session cache bounded freshness

**Problem**

The process-lifetime VirusTotal cache has no retrieval timestamp. It can bypass the persistent seven-day lifetime for clean or unknown evidence, and it can retain a transient `Unavailable` result for the entire session.

**Design**

- Store an internal cache envelope containing the copied report and its retrieval time.
- Apply seven-day freshness to `Clean` and `Unknown`, and 90-day freshness to `Malicious`.
- Never add `Unavailable` to the session cache.
- Evict stale entries before making the provider request.
- Keep the public `Get-VtFileReport` output shape unchanged.
- Continue clearing file and URL session caches on `Disconnect-VirusTotal`.

**Acceptance criteria**

- A stale clean or unknown entry triggers a new provider request.
- A stale malicious entry triggers a new provider request after its longer lifetime.
- A transient unavailable result is retried on the next call and can recover to clean, unknown, or malicious.
- Cached objects remain defensive copies and caller mutation cannot poison later results.

**Lot 8 gate**

After all three pull requests are merged, run an independent security review of the EPM destination boundary, degraded-report behavior, cache lifetimes, and secret handling. Lot 9 starts only after that review has no unresolved critical finding.

### Lot 9: evidence and persistent-cache integrity

#### Task 9.1: make persistent cache updates recoverable and concurrent-safe

**Problem**

Persistent cache updates currently perform an unlocked read-modify-write and overwrite the live file in place. Concurrent processes can lose another writer's evidence or leave truncated JSON. `Clear-ReputationCache` can also delete any supplied leaf without `ShouldProcess`, while the README describes remediation as the only state-changing command.

**Design**

- Coordinate writers and clearing through an exclusive sidecar lock with a bounded acquisition timeout.
- Re-read and validate the live cache only after the lock is acquired.
- Write the complete next envelope to a unique sibling temporary file.
- Flush the temporary file, then replace the live cache atomically on the same filesystem.
- Remove the temporary file on failure without deleting the last valid cache.
- Preserve the monotonic rule that malicious evidence cannot be replaced by weaker evidence for the same binding.
- Add `SupportsShouldProcess` to `Clear-ReputationCache`.
- Validate a normal cache envelope before deletion. Provide an explicit force path for a corrupted cache, still guarded by `ShouldProcess`.
- Update the README to distinguish the only remote product write from local cache-file state changes.

**Acceptance criteria**

- Concurrent writers retain both valid entries and cannot downgrade malicious evidence.
- An injected interruption leaves either the previous complete cache or the next complete cache, never truncated JSON.
- Clearing honors `-WhatIf`, coordinates with a writer, and cannot silently delete an unrelated valid file.
- Cache content remains minimal and contains no provider secret, endpoint, user, or machine data.

#### Task 9.2: enforce hash identity end to end

**Problem**

The cascade originates from EPM SHA-1 values, but `Get-FileReputation` does not declare that boundary and can fail partway through when MD5 or SHA-256 reaches the SHA-1-only MalwareBazaar stage. MalwareBazaar evidence is accepted without matching the returned SHA-1 to the requested value. EPM grouping can also split the same hexadecimal hash when only its case differs. Finally, a mutation that bypassed the VirusTotal alias check survived the complete suite.

**Design**

- Make the `Get-FileReputation` cascade contract explicitly SHA-1-only while leaving `Get-VtFileReport` capable of direct MD5, SHA-1, and SHA-256 lookups.
- Validate the cascade input before any provider request.
- Accept MalwareBazaar malicious evidence only when one unambiguous returned record matches the requested SHA-1 case-insensitively.
- Treat missing, mismatched, or contradictory MalwareBazaar identity as `Unavailable`, not malicious and not clean.
- Normalize the hash component used for EPM binary grouping while preserving a stable display value.
- Add a live-response fixture where VirusTotal returns a valid SHA-256 pivot with a mismatched alias for the requested SHA-1.
- Prove that disabling the alias comparison makes the new test red.

**Acceptance criteria**

- Unsupported cascade hash lengths fail locally before disclosure to a provider.
- Mismatched MalwareBazaar records cannot reject a legitimate EPM proposal.
- Uppercase and lowercase forms of the same SHA-1 produce one binary grouping.
- ThreatFox is never queried from an unbound VirusTotal SHA-256 pivot.
- The previously surviving canonical-alias mutation is killed by the targeted test.

### Lot 10: transport resilience and preventive controls

#### Task 10.1: bound pagination and provider-directed waiting

**Problem**

SentinelOne cursor pagination detects repeated URLs but has no page-count bound for a server that continually returns unique cursors. EPM offset pagination can silently accept a total that contradicts the collected page. Numeric `Retry-After` values are used directly without a finite upper bound.

**Design**

- Add a validated `MaxPages` parameter to shared SentinelOne pagination, with the same default bound used by EPM unless existing call sites require a lower explicit value.
- Stop before issuing a request beyond the configured limit and produce a sanitized diagnostic.
- Validate EPM totals as non-negative integers and reject impossible relationships instead of returning a silently incomplete report.
- Parse supported `Retry-After` forms defensively.
- Reject negative, non-finite, malformed, or policy-exceeding waits rather than sleeping indefinitely or retrying too early.
- Keep total attempts, timeout behavior, and redirect blocking unchanged.

**Acceptance criteria**

- A stream of unique cursors stops at exactly `MaxPages` requests.
- Repeated-cursor detection still triggers before the page limit where applicable.
- Contradictory EPM totals fail with a diagnostic that names the invalid contract.
- Malformed or excessive retry instructions cannot create an unbounded sleep.
- Normal 429 and exponential-backoff tests remain deterministic.

#### Task 10.2: close and redact the dynamic secret-sink test gap

**Problem**

The repository scanner resolves direct, module-qualified, and statically parenthesized connection commands, but it deliberately ignores dynamic command expressions. A literal passed to `-ApiKey` or `-AuthKey` through a dynamic invocation can therefore survive that scanner.

The scanner also includes the matched literal in each finding string. If a real secret reaches this guard, a failed Pester assertion could echo it into local or CI logs.

**Design**

- Treat a literal value bound to a known sensitive parameter name in a dynamic invocation as a finding even when the command target cannot be resolved.
- Redact every textual and AST finding so diagnostics identify only file, line, and finding category or parameter name, never the matched value.
- Keep the stricter resolved-command checks for known connection sinks.
- Retain only exact synthetic fixture exemptions under `tests/`.
- Do not attempt general PowerShell data-flow analysis or claim that arbitrary runtime secret construction can be proven safe statically.
- Document the remaining boundary: the repository scanner prevents known committed literals; Gitleaks remains an independent generic layer.

**Acceptance criteria**

- The existing dynamic literal fixture becomes a positive finding.
- Synthetic-secret tests prove that serialized findings never contain the detected value.
- Variable or secure-string arguments do not become false positives.
- Test-only exact fixtures remain allowed, while variants and source-tree copies fail.
- A fault injection that restores the dynamic skip makes the security test red.

## Per-task workflow

Every task follows this sequence:

1. Create an English GitHub issue with the reproduced defect, security or correctness impact, non-goals, and executable acceptance criteria.
2. Create a dedicated branch from current `main`.
3. Add the smallest test that reproduces the defect and demonstrate the red state for the expected reason.
4. Implement the minimal correction without unrelated refactoring.
5. Demonstrate green targeted tests and replay the relevant fault injection.
6. Run the complete Pester suite and require `Result = Passed` and `FailedContainersCount = 0`.
7. Run PSScriptAnalyzer with a typed diagnostic list, manifest/public-export synchronization, `git diff --check`, and Gitleaks.
8. Request an independent plan-compliance review, then a separate code-quality or security review. Reviewers must execute relevant tests and injections.
9. Open one English pull request linked to the issue and wait for required CI.
10. Merge only after all findings are resolved, then validate the resulting `main` commit before starting the next task.

## Documentation updates

Each task updates only the public documentation made inaccurate by its change. The final task in each lot reconciles:

- `README.md` capability and security-boundary claims;
- `docs/decisions.md` for non-obvious trust and failure semantics;
- the relevant API notes when a simulated contract is narrowed;
- exact test, container, diagnostic, and exported-function counters.

Personal interview notes, session state, and private-repository context remain outside this repository.

## Cycle exit criteria

The hardening cycle is complete only when:

- all seven issues are closed by their own merged pull requests;
- the Lot 8 security gate and final independent review have no unresolved critical or important finding in this scope;
- every required mutation is proven red against the broken variant and green after restoration;
- the complete test suite, PSScriptAnalyzer, manifest synchronization, Gitleaks, and GitHub CI are freshly green on `main`;
- the worktree is clean and synchronized with `origin/main`;
- Device Control #11 and #12 remain explicitly blocked rather than being simulated against an invented contract;
- public claims distinguish mock-backed validation from real-tenant compatibility.

## Explicit non-goals

- Implementing Device Control rule-usage inventory issues #11 or #12.
- Adding new providers, workflows, remediation actions, or a graphical interface.
- Uploading files to reputation services.
- Authorizing software or devices from an external verdict.
- Claiming compatibility with a real SentinelOne or CyberArk EPM tenant.
- Refactoring unrelated lot 1-7 code.
