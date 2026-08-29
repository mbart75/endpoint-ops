# Technical decisions

This document records implementation trade-offs, rationale, and known costs. It describes a public-documentation and mock-server project; it must not be read as evidence of real-tenant compatibility.

## Transport and test harness

1. **Local mock HTTP server over function mocks.** Contract tests use `tests/mock/MockApiServer.ps1` so they exercise HTTP serialization, headers, status codes, JSON bodies, and URL cursor handling rather than only a PowerShell call shape. The cost is a more complex harness.
2. **PowerShell mock server.** `HttpListener` keeps the repository single-language and avoids another runtime dependency. It is substantially more verbose than a small Python server, particularly around lifecycle and `Start-Job`.
3. **No retry after a timeout.** Without real-tenant behaviour, a timeout cannot be classified reliably as transient or structural. Retrying a slow request multiplies caller delay without a justified expectation of success.
4. **Retry only 429 and 5xx responses.** A 401 or 404 is a request or authentication problem that retries do not repair.
5. **Cursor-loop detection.** `Invoke-EndpointOpsRequest -Paginate` remembers cursor URIs and fails explicitly if one repeats. This makes a server or parsing defect diagnosable instead of leaving CI in an infinite loop.
6. **Dedicated canary stage.** The mock-server canary runs before contract tests. If the harness is broken, later green or red results are not meaningful.
7. **Header names, never values, in verbose output.** Logging `$Headers.Keys` preserves troubleshooting context without leaking credentials. Security tests lock this boundary.
8. **Two terminal-pagination shapes.** The mock server covers an omitted `pagination` property and a present `nextCursor: null`. Defensive property access handles both.
9. **`$args` in the mock-server `Start-Job` block.** This avoids a PSScriptAnalyzer 1.25.0 false positive for that specific pattern. It is not a security control; human review remains necessary to catch scope leakage.
10. **Static analysis loops over paths.** PSScriptAnalyzer 1.25.0 accepts one string for `-Path`, not a string array. CI scans `./src` and `./tests` separately and aggregates findings.
11. **CI confirms it scanned files.** A zero-file static-analysis pass fails so a renamed path cannot silently turn the gate green.
12. **One JSON-property helper.** Under `Set-StrictMode -Version 3.0`, absent properties throw. `Get-PropertyOrDefault` distinguishes absent properties from explicit nulls.
13. **Mock-server authentication is scoped.** Product routes require the expected token; generic transport-test routes remain unauthenticated to avoid conflating authentication with retry and pagination tests.
14. **HTTPS except local mock addresses.** `Connect-S1Tenant` refuses HTTP except `localhost` and `127.0.0.1`. The exception enables local tests without permitting cleartext tenant traffic.
15. **Connection validation uses a one-item agent request.** `Connect-S1Tenant` calls `/web/api/v2.1/agents?limit=1` instead of inventing an unconfirmed health endpoint, and clears state after failure.

## Data handling and report design

16. **Product-query commands report; workflows interpret.** `Get-S1*` commands return source observations. Thresholds and scoring live in workflows so network access and judgment can be tested independently.
17. **Fixtures contain deliberate defects.** Inactive or contradictory agents, root-path exclusions, and broad device rules ensure workflows prove they can identify a problem.
18. **Read-focused verb choice.** No command in the initial surface was named `New-*` or `Set-*`; the remaining write command declares its `ShouldProcess` behaviour explicitly.
19. **Test secure strings avoid plaintext conversion.** `ConvertTo-TestSecureString` builds values character by character to satisfy PSScriptAnalyzer while preserving test intent.
20. **Capture `osRevision`, not only `osName`.** Marketing OS names cannot establish patch state. The workflow compares a revision with the target for its own branch.
21. **Preserve available provenance.** Exclusions and device rules retain `createdBy`, `createdAt`, `updatedBy`, and `updatedAt`. A service account is not represented as a human contact.
22. **Tests must state what they prove.** A test that stayed green after removing the intended state reset was renamed and the substantive assertion moved to where it could fail.
23. **Do not collect the last logged-on user.** Current signals do not need it and it is personal data. Collection minimisation is a design decision, not a product limitation.
24. **Build maps are workflow input.** A build branch is not comparable to a different branch. Missing branch data means unsupported; an empty map means unknown, not current.
25. **Separate exclusion and Device Control scoring.** Their output vocabulary is shared, but their logic is materially different. A single parameterised engine would hide two disjoint implementations.
26. **Reasons are first-class output.** Severity is the maximum of plain-language reasons; it is not a black-box numeric score.
27. **Contact is meaningful or absent.** Prefer the latest modifier to the creator where available. An empty human contact is better than a fictitious owner.

## Bounded remediation

28. **One write command, with the least disruptive action.** `Invoke-S1FleetRemediation` only moves endpoints to a tracking group (stage 1). Stage 0 cannot remotely fix a silent endpoint; stage 2 remains a human proposal.
29. **Write intent is visible to tests.** A test-only mock-server inspection route journals requested moves, allowing `-WhatIf` to be verified against observable state rather than absence of an exception.
30. **Validate connection before `-WhatIf`.** A disconnected module must fail instead of reporting an action it cannot actually perform.
31. **Reference dates are injectable.** `Get-S1FleetHygieneReport -ReferenceDate` makes time-dependent tests deterministic.

## CyberArk EPM

32. **EPM pagination is distinct from SentinelOne pagination.** EPM differs in cursor location, literal `start`, terminal cursor ambiguity, and offset rules. Shared retry/backoff/timeout behaviour remains in the lower-level HTTP transport.
33. **EPM policy provenance is unavailable.** The API exposes dates but not policy-author identity. Reports state that contact data is unavailable through the EPM API; a contract test rejects an empty `Contact` field.
34. **Whitespace-only descriptions are empty.** `[string]::IsNullOrWhiteSpace` catches null, empty, and filler-space descriptions without inventing an arbitrary minimum length.
35. **Unsigned binaries never become strong proposals.** A high distinct-user count measures distribution, not trust; it cannot compensate for missing publisher identity.
36. **Pace EPM policy requests proactively.** `Invoke-EpmRequest -MinIntervalMs` honours the documented 30-per-minute policy limit before requests hit it. `Get-EpmPolicyDetail` defaults to 2100 ms and reports progress.
37. **Disable `Invoke-WebRequest` debug output.** That stream can render HTTP headers and JSON bodies verbatim, exposing EPM passwords and session tokens. The suppression belongs in the shared HTTP choke point.
38. **Plaintext-password cleanup is limited.** Clearing a local reference makes an immutable .NET string eligible for collection; it does not overwrite memory or guarantee immediate removal. The code does not claim otherwise.
39. **Some loud failure branches remain untested.** Password-expired and incomplete-login responses fail clearly with named causes and no misleading state. State clearing after validation failure is tested because it can fail silently.
40. **Typed HTTP exceptions remain technical debt.** The shared transport currently throws formatted strings, so EPM detects 401 through message matching. A typed status exception is the durable solution but would change the shared error surface.

## Reputation enrichment

41. **Unknown is not clean.** Reputation output has the source-defined states `Malicious`, `Clean`, `Unknown`, and `Unavailable`; no boolean turns missing knowledge into approval.
42. **One engine does not establish a malicious verdict.** The public threshold requires the configured minimum number of malicious engines. A single detection can be a false positive.
43. **Reputation only downgrades.** A clean result cannot prove legitimacy or justify an elevation. Reputation may reject or weaken an event-derived proposal, never strengthen it.
44. **Enrichment is optional.** VirusTotal’s public quota makes mandatory enrichment operationally unsuitable for larger reports. The EPM report remains useful without it.
45. **No file upload exists.** The module has no file-submission code path. Hash and reversible URL-identifier disclosure still make enrichment opt-in.
46. **Quota accounting is process-local.** The counter enforces session pacing but does not survive a new session or track another process.

### Multi-source and cache decisions

- **Complementary sources add evidence, not votes.** Provider silence has source-specific meaning; there is no average or majority score. Any malicious evidence makes the aggregate malicious, while clean, unknown, or failed responses can never authorize software or promote a proposal.
- **The cascade includes VirusTotal-unknown and VirusTotal-unavailable states.** MalwareBazaar may know a recent malicious sample that VirusTotal does not, and a VirusTotal outage must not hide independent evidence.
- **ThreatFox is a SHA-256 deepening step, not SHA-1 coverage.** It runs only with a valid VirusTotal-derived SHA-256 and cannot address a VirusTotal-unknown EPM SHA-1 by itself.
- **Persistent caching is opt-in software-inventory storage.** Versioned entries store an explicit lookup-to-evidence relationship, provider provenance, verdict, and query date, never keys. Legacy entries are reused only by exact hash. `Clean` and `Unknown` expire after 7 days, `Malicious` after 90 days, and `Unavailable` is never cached.
- **Cached malicious evidence is monotonic.** Any fresh malicious entry is decisive even if another fresh entry is clean or the original EPM lookup key differs from a VirusTotal-derived SHA-256. Cache completeness must not require every source to be stored under one hash.
- **Canonical cache reuse requires an explicit identity binding.** A provider-derived SHA-256 is persisted and reused only when VirusTotal's alias for the input hash matches that input exactly. Loose cross-hash searches are forbidden because they could attach another file's evidence to the lookup.

## Device Control and retention

47. **Retention is a required input.** SentinelOne retention varies by tenant and SKU. Assuming it would convert purged events into false evidence of non-use.
48. **A window equal to retention is indeterminate.** Oldest events may already be purged, so a reliable window must be strictly shorter than retention; the report returns `Indeterminate` rather than a false `NoUsage`.
49. **Use three states, not two.** `NoUsage`, `Indeterminate`, and `OutOfScope` distinguish an observation, an unmeasurable period, and a source unable to observe.
50. **Linux is explicitly out of scope for Device Control.** Device Control covers Windows and macOS. Treating Linux as “no use” would be a high-confidence false positive.
51. **Require explicit SKU confirmation.** The agent data does not expose Control SKU availability. Without `-ControlSkuAvailable`, the report does not query Device Control events.
52. **Keep a staged timing threshold.** The default alert threshold is 30 days and the removal threshold is 60 days. Callers may configure both, but `AlertAfterDays` must remain strictly below `RemoveAfterDays`.
