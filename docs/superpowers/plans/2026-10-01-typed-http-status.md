# Typed HTTP status implementation plan

## Approved scope

Replace message-based HTTP classification with native `System.Net.Http.HttpRequestException.StatusCode`. Preserve sanitized human-readable messages, bounded retries, EPM reconnection guidance, VirusTotal quota accounting and fail-soft verdicts. No new exported function, automatic reconnection, remediation, or vendor contract assumption.

For a completed HTTP failure (non-retryable or exhausted retries), the transport throws a new native exception with the observed status and no inner exception, response, headers, or body attached. Network, redirect and retry-policy errors remain unclassified; their text must never invent a status. The private status reader unwraps generic exception wrappers and stops at the first native HTTP exception, including a null status. EPM rephrases only a typed 401 for session guidance and a typed 404 for policy-detail ambiguity, preserving their statuses. VirusTotal retries only a typed 500 once and classifies only typed 400/404 as Unknown; other failures remain Unavailable and uncached.

Review reconciliation: inspection identified one additional EPM consumer, `Get-EpmPolicyDetail`, whose existing 404 guidance also parsed message text. Migrate that consumer in this task without changing its warning semantics; add red/green tests for typed 404 and misleading non-404 messages. Existing helper unit tests are migrated in place rather than retaining a message-based contract or duplicating helper coverage in the contract file.

Native nullable status API: [Microsoft documentation](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httprequestexception.statuscode?view=net-10.0).

## Task 1: status boundary and all consumers (one coherent change)

1. Add behavioral tests for real transport failures, misleading message text, nested/null statuses, EPM 401 versus a 404 URL containing 401, VT retry/quota counts, file/URL verdict caching, and response/credential non-disclosure. Run them against the old implementation and inspect failures.
2. Change the shared HTTP exception and private status reader; migrate EPM and all three VT consumers together. Update two existing mock-404 tests to throw native exceptions rather than pretend that messages are an API.
3. Run the targeted tests, complete Pester suite and typed-list PSScriptAnalyzer; check ASCII/BOM and the public export manifest.
4. Inject status/message fallback and raw-response retention defects in isolated temporary copies. Require the relevant tests to fail, then rerun the unmodified tests. Do not mutate the shared working tree for injections.
5. Obtain independent conformity and quality reviews with executable evidence, address important findings, inspect the final diff and create a targeted issue/PR. Both mandatory Linux and native Windows checks must be green before merge.

## Separate documentation follow-up

Research W4.7 group-move activity types only in official public sources. If no authoritative numeric mapping is found, document the search boundary and attach the optional enrichment's validation checklist to existing issue #11. Preserve W4.7 behavior and the #12 validation prerequisite. This follow-up has its own documentation PR, not the transport commit.
