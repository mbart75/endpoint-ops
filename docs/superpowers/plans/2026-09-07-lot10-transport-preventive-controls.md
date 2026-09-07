# Lot 10 Transport Resilience and Preventive Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound server-controlled pagination and retry delays, reject contradictory EPM pagination metadata, and close the remaining dynamic-invocation and diagnostic-redaction gaps in the repository secret scanner.

**Architecture:** Put explicit policy bounds at the shared transport boundaries, retain EPM-specific contract validation in `Invoke-EpmRequest`, and extend the AST scanner only where a dynamic invocation binds a literal to a known secret parameter. Each task is delivered through its own English issue and pull request from freshly validated `main`.

**Tech Stack:** PowerShell 7.2+, Pester 6, PowerShell AST APIs, PSScriptAnalyzer, local `HttpListener` mock server, GitHub CLI, Gitleaks.

**Spec:** `docs/superpowers/specs/2026-09-07-independent-review-hardening-design.md`

## Global Constraints

- Begin only after the Lot 9 gate is clean and its final pull request is merged.
- Work only in the public `mbart75/endpoint-ops` repository and keep every public artifact in English.
- Deliver each task through its own issue, fresh branch, pull request, CI run, merge, and post-merge validation.
- Keep transport errors sanitized; never include authorization headers, request bodies, provider keys, or EPM tokens.
- Stop before issuing a request beyond `MaxPages` and before honoring an invalid or excessive retry delay.
- Preserve existing retry attempt counts, redirect blocking, timeout semantics, and repeated-cursor detection.
- Preserve EPM routes that legitimately omit `TotalCount`; an empty page remains their termination signal.
- Treat the repository scanner as a prevention layer for committed literals, not as general PowerShell data-flow analysis.
- Use only exact synthetic fixture credentials in tests and keep Gitleaks as an independent scanner.
- A task is complete only after targeted red-green proof, deterministic fault injection, full Pester result checks, typed-list analyzer count zero, manifest/export synchronization, `git diff --check`, Gitleaks, independent compliance and quality reviews, CI, merge, and fresh validation of `main`.

---

### Task 10.1: Bound pagination and provider-directed waiting

**Issue title:** `Transport: bound pagination and retry delays`

**Branch:** `fix/transport-pagination-retry-bounds`

**Files:**
- Modify: `src/EndpointOps/Public/Invoke-EndpointOpsRequest.ps1`
- Modify: `src/EndpointOps/Private/Invoke-EpmRequest.ps1`
- Modify: `src/EndpointOps/Private/Invoke-EndpointOpsHttpRequest.ps1`
- Modify: `tests/contract/Transport.Pagination.Tests.ps1`
- Modify: `tests/contract/Invoke-EpmRequest.Tests.ps1`
- Modify: `tests/contract/Transport.RateLimit.Tests.ps1`
- Modify only if integration coverage needs new deterministic routes: `tests/mock/MockApiServer.ps1`
- Modify: `README.md`
- Modify: `docs/decisions.md`
- Modify: `docs/api-notes.md`
- Modify: `docs/api-notes-epm.md`

**Interfaces:**
- Adds `[ValidateRange(1, 10000)][int]$MaxPages = 200` to `Invoke-EndpointOpsRequest`; it is used only when `-Paginate` is present.
- Adds `[ValidateRange(1, 3600)][double]$MaxRetryAfterSec = 60` to `Invoke-EndpointOpsHttpRequest` and forwards it from `Invoke-EndpointOpsRequest`.
- Preserves the existing `[ValidateRange(1, 10000)][int]$MaxPages = 200` EPM parameter while strengthening its offset-total validation.
- Supports `Retry-After` delta-seconds and RFC-compatible HTTP dates. A past HTTP date produces a zero-second wait; malformed, non-finite, negative, or above-policy values throw before `Start-Sleep`.
- For an EPM offset route that exposes `TotalCount`, the first value becomes the response contract for the request. Later pages must expose the same value, the collected count must never exceed it, and an empty page before reaching it is an incomplete response.

- [ ] **Step 1: Create the issue and fresh task branch**

```bash
git switch main
git fetch origin
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "Transport: bound pagination and retry delays" \
  --body "The independent review reproduced three transport-boundary defects: shared cursor pagination can follow an unlimited sequence of unique cursors, EPM offset pagination can accept a TotalCount smaller than the collected result, and Retry-After can direct an unbounded or invalid sleep. Add a shared MaxPages policy, validate EPM total consistency without breaking routes that omit TotalCount, and bound supported Retry-After values before sleeping. Preserve existing retry counts, timeouts, redirect blocking, and repeated-cursor detection. This issue implements Task 10.1 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c fix/transport-pagination-retry-bounds
```

- [ ] **Step 2: Add red shared-pagination tests without changing the mock server**

Append an `InModuleScope EndpointOps` context to `tests/contract/Transport.Pagination.Tests.ps1`. Mock the private transport so every response has one item and a different cursor:

```powershell
Context 'Page-count guard' {
    It 'stops before requesting a page beyond MaxPages' {
        InModuleScope EndpointOps {
            $script:PageNumber = 0
            Mock Invoke-EndpointOpsHttpRequest {
                $script:PageNumber++
                [pscustomobject]@{
                    Content = (@{
                            data = @(@{ id = "item-$script:PageNumber" })
                            pagination = @{ nextCursor = "cursor-$script:PageNumber" }
                        } | ConvertTo-Json -Depth 5)
                }
            }

            {
                Invoke-EndpointOpsRequest -Uri 'https://tenant.example.invalid/agents' `
                    -Paginate -MaxPages 3
            } | Should -Throw -ExpectedMessage '*3 page limit*'

            Should -Invoke Invoke-EndpointOpsHttpRequest -Times 3 -Exactly
        }
    }
}
```

Retain the existing two-page integration tests and add a case asserting that `-MaxPages 1` fails after one mock-server request when the first page returns a next cursor.

- [ ] **Step 3: Prove the shared page-bound test is red for the missing parameter**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Transport.Pagination.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the new test fails because `Invoke-EndpointOpsRequest` does not accept `MaxPages` and the three-request boundary is not enforced.

- [ ] **Step 4: Implement the shared cursor page bound**

Add this parameter to `Invoke-EndpointOpsRequest`:

```powershell
[ValidateRange(1, 10000)][int]$MaxPages = 200,
```

Track the number of issued page requests and guard before calling `Invoke-EndpointOpsHttpRequest`:

```powershell
$pageCount = 0
while ($nextUri) {
    if (-not $seen.Add($nextUri)) {
        throw "EndpointOps: repeated pagination cursor on $nextUri; stopped to avoid an infinite loop"
    }
    if ($pageCount -ge $MaxPages) {
        throw "EndpointOps: $MaxPages page limit reached on $Uri; pagination aborted"
    }

    $page = (Invoke-EndpointOpsHttpRequest -Uri $nextUri @callArgs).Content | ConvertFrom-Json
    $pageCount++
    # Existing item and cursor handling follows unchanged.
}
```

Do not apply the limit to a non-paginated request. Repeated-cursor detection remains before the limit check so the more precise fault is reported when both conditions become true at the same boundary.

- [ ] **Step 5: Add red EPM total-contract cases**

Mock the dot-sourced `Invoke-EndpointOpsRequest` directly in `tests/contract/Invoke-EpmRequest.Tests.ps1` so each failure is deterministic and does not require new mock routes. Feed responses from a per-test queue and add cases for:

```powershell
@{
    Name = 'rejects more collected items than TotalCount'
    Pages = @(
        [pscustomobject]@{ events = @(@{ id = 'a' }, @{ id = 'b' }); TotalCount = 1 }
    )
    Message = '*TotalCount*collected*'
}
@{
    Name = 'rejects TotalCount changes between pages'
    Pages = @(
        [pscustomobject]@{ events = @(@{ id = 'a' }); TotalCount = 3 }
        [pscustomobject]@{ events = @(@{ id = 'b' }); TotalCount = 2 }
    )
    Message = '*TotalCount*changed*'
}
@{
    Name = 'rejects an empty page before TotalCount is reached'
    Pages = @(
        [pscustomobject]@{ events = @(@{ id = 'a' }); TotalCount = 3 }
        [pscustomobject]@{ events = @(); TotalCount = 3 }
    )
    Message = '*TotalCount*incomplete*'
}
@{
    Name = 'rejects TotalCount disappearing between pages'
    Pages = @(
        [pscustomobject]@{ events = @(@{ id = 'a' }); TotalCount = 3 }
        [pscustomobject]@{ events = @(@{ id = 'b' }) }
    )
    Message = '*TotalCount*disappeared*'
}
```

Also add malformed values `-1`, `1.5`, and `'not-a-number'`. Assert each throws a sanitized contract error and does not leak headers or request bodies. Keep the existing `offset-no-total` test green.

- [ ] **Step 6: Prove the EPM total-contract tests are red for the reproduced reasons**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Invoke-EpmRequest.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the current implementation accepts at least the two-items-with-total-one response and either returns incomplete results or throws a different incidental conversion error for malformed totals.

- [ ] **Step 7: Implement one stable EPM total contract per request**

Before the pagination loop, add:

```powershell
$expectedTotalCount = $null
$hasTotalContract = $false
```

After reading `$pageItems` and before accepting termination, detect the property without conflating absent and null:

```powershell
$hasPageTotal = $page.PSObject.Properties.Name -contains 'TotalCount'
if ($hasPageTotal) {
    $rawTotal = $page.TotalCount
    $parsedTotal = 0L
    $isInteger = [long]::TryParse(
        [string]$rawTotal,
        [System.Globalization.NumberStyles]::Integer,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$parsedTotal)

    if (-not $isInteger -or $parsedTotal -lt 0) {
        throw "EndpointOps: invalid EPM TotalCount on $Path"
    }
    if (-not $hasTotalContract) {
        $expectedTotalCount = $parsedTotal
        $hasTotalContract = $true
    }
    elseif ($parsedTotal -ne $expectedTotalCount) {
        throw "EndpointOps: EPM TotalCount changed during pagination on $Path"
    }
}
elseif ($hasTotalContract) {
    throw "EndpointOps: EPM TotalCount disappeared during pagination on $Path"
}

if ($hasTotalContract -and $items.Count -gt $expectedTotalCount) {
    throw "EndpointOps: collected EPM item count exceeds TotalCount on $Path"
}
if ($pageItems.Count -eq 0) {
    if ($hasTotalContract -and $items.Count -lt $expectedTotalCount) {
        throw "EndpointOps: incomplete EPM pagination before TotalCount on $Path"
    }
    break
}
if ($hasTotalContract -and $items.Count -eq $expectedTotalCount) { break }
```

If a real existing fixture exposes a numeric JSON value as another integral CLR type, normalize it without accepting decimals. Do not use a plain `[int]` cast as validation because it can truncate or throw an unsanitized error. Preserve offset advancement by the requested limit.

- [ ] **Step 8: Add red unit-style tests for hostile Retry-After values**

In `tests/contract/Transport.RateLimit.Tests.ps1`, add an `InModuleScope EndpointOps` context that mocks `Invoke-WebRequest` and `Start-Sleep`. Use a helper response object with status 429 and parameterize:

```powershell
@(
    @{ Header = 'NaN';    Max = 60; Message = '*invalid Retry-After*' }
    @{ Header = '-1';     Max = 60; Message = '*invalid Retry-After*' }
    @{ Header = '1.5';    Max = 60; Message = '*invalid Retry-After*' }
    @{ Header = '999999'; Max = 60; Message = '*exceeds*60*' }
    @{ Header = 'later';  Max = 60; Message = '*invalid Retry-After*' }
)
```

For each case, call `Invoke-EndpointOpsHttpRequest -MaxAttempts 2 -MaxRetryAfterSec <Max>`, assert the expected throw, `Should -Invoke Start-Sleep -Times 0 -Exactly`, and `Should -Invoke Invoke-WebRequest -Times 1 -Exactly`.

Add green-intent cases that are red until the new parameter exists:

- delta-seconds `1` sleeps once for one second and the second request succeeds;
- a future HTTP date inside the bound sleeps once with a non-negative delay no greater than the bound;
- a past HTTP date sleeps with zero and immediately performs the second attempt;
- an exponential delay exceeding `MaxRetryAfterSec` is also rejected before sleeping, so the cap applies to all retry delays rather than only server-provided values.

- [ ] **Step 9: Prove the hostile Retry-After tests are red**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Transport.RateLimit.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the current direct `[double]` conversion either accepts non-finite/excessive values, throws an unsanitized conversion error, or lacks `MaxRetryAfterSec`.

- [ ] **Step 10: Implement bounded Retry-After parsing**

Add the validated policy parameter to `Invoke-EndpointOpsHttpRequest` and `Invoke-EndpointOpsRequest`, and include it in `$callArgs`:

```powershell
[ValidateRange(1, 3600)][double]$MaxRetryAfterSec = 60
```

Parse the first header value as an invariant-culture non-negative integer because RFC `Retry-After` delta-seconds do not permit fractions. Only if integer parsing fails, parse an HTTP date with invariant culture and `DateTimeStyles.AssumeUniversal`; clamp a past date to zero. Values such as `1.5`, `NaN`, and negative integers are invalid rather than HTTP dates. Then enforce the policy bound for either the parsed server delay or exponential backoff:

```powershell
if ([double]::IsNaN($wait) -or [double]::IsInfinity($wait) -or $wait -lt 0) {
    throw "EndpointOps: invalid Retry-After value returned by $Uri"
}
if ($wait -gt $MaxRetryAfterSec) {
    throw "EndpointOps: retry delay exceeds the $MaxRetryAfterSec second policy limit for $Uri"
}
```

Do not include the raw header value in the error. Do not silently cap an excessive server value: throwing makes the contract violation visible and avoids pretending to honor server pacing.

- [ ] **Step 11: Run the complete targeted transport suite**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/contract/Transport.Tests.ps1","tests/contract/Transport.Pagination.Tests.ps1","tests/contract/Transport.RateLimit.Tests.ps1","tests/contract/Transport.Timeout.Tests.ps1","tests/contract/Invoke-EpmRequest.Tests.ps1","tests/security/RedirectSecretHandling.Tests.ps1","tests/security/EpmSecretHandling.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
```

Expected: all targeted tests pass with zero failed containers.

- [ ] **Step 12: Prove all three guards with reversible fault injections**

Save a patch before each mutation and restore it immediately afterward.

1. Remove the shared `$pageCount -ge $MaxPages` check. The unique-cursor test must fail because a fourth request occurs or the mock sequence is exhausted.
2. Replace the EPM total-contract block with the previous `if ($items.Count -ge [int]$totalCount) { break }`. The two-items-with-total-one test must fail.
3. Remove the non-finite and maximum-delay checks. The hostile Retry-After tests must fail because `Start-Sleep` is reached or the expected sanitized error disappears.

Perform each mutation in a disposable worktree created from the task commit, or with a precisely scoped `apply_patch` that is immediately reversed. Never use a broad checkout, reset, or reverse patch that could discard task work. After each mutation, inspect the exact diff, require the named test to fail for the intended assertion, restore only that mutation, and rerun the targeted green test.

- [ ] **Step 13: Update public documentation and decision records**

- `README.md`: state that pagination and retry waits are bounded by local policy.
- `docs/decisions.md`: record why excessive `Retry-After` is rejected rather than silently capped, and why inconsistent EPM totals fail closed.
- `docs/api-notes.md`: document shared `MaxPages`, `MaxRetryAfterSec`, supported header forms, and sanitized failure semantics.
- `docs/api-notes-epm.md`: document the stable-total contract and retain the existing note that some routes omit `TotalCount`.

Do not claim that all vendor pagination formats were verified against a real tenant.

- [ ] **Step 14: Run the complete repository validation gate**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests -PassThru -Output None; "Result: $($r.Result) | $($r.PassedCount)/$($r.TotalCount) | conteneursKO: $($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
pwsh -NoProfile -Command '$l=[System.Collections.Generic.List[object]]::new(); foreach ($p in @("./src","./tests")) { foreach ($d in (Invoke-ScriptAnalyzer -Path $p -Recurse -Settings ./PSScriptAnalyzerSettings.psd1)) { $l.Add($d) } }; "diagnostics: " + $l.Count; if ($l.Count -ne 0) { $l | Format-Table -AutoSize; exit 1 }'
pwsh -NoProfile -Command '$manifest=Import-PowerShellDataFile ./src/EndpointOps/EndpointOps.psd1; $public=@(Get-ChildItem ./src/EndpointOps/Public -Filter *.ps1 | ForEach-Object BaseName | Sort-Object); $exports=@($manifest.FunctionsToExport | Sort-Object); "Public=$($public.Count) Exports=$($exports.Count) Diff=$(@(Compare-Object $public $exports).Count)"; if (@(Compare-Object $public $exports).Count -ne 0) { exit 1 }'
git diff --check
gitleaks detect --source . --no-banner --redact
```

- [ ] **Step 15: Commit, obtain two independent reviews, open the PR, and merge only after CI**

```bash
git add src/EndpointOps/Public/Invoke-EndpointOpsRequest.ps1 \
  src/EndpointOps/Private/Invoke-EpmRequest.ps1 \
  src/EndpointOps/Private/Invoke-EndpointOpsHttpRequest.ps1 \
  tests/contract/Transport.Pagination.Tests.ps1 \
  tests/contract/Invoke-EpmRequest.Tests.ps1 \
  tests/contract/Transport.RateLimit.Tests.ps1 \
  tests/mock/MockApiServer.ps1 README.md docs/decisions.md docs/api-notes.md docs/api-notes-epm.md
git diff --cached --check
git commit -m "fix: bound pagination and retry delays"
```

Request one plan-compliance reviewer and one separate transport/security-quality reviewer. Both must run the relevant tests; the quality reviewer must replay the unique-cursor, contradictory-total, and excessive-delay injections. Resolve findings and rerun validation before publishing the task branch. Then:

```bash
git push -u origin fix/transport-pagination-retry-bounds
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "Bound pagination and retry delays" \
  --body "Closes #${issue_number}. Adds a shared page bound, validates stable EPM totals, and rejects invalid or excessive retry delays. Includes red-green tests and reversible fault-injection evidence.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

Rerun the complete gate on the merge commit.

---

### Task 10.2: Detect and redact literal secrets at dynamic invocation sinks

**Issue title:** `Security tests: detect and redact dynamic secret literals`

**Branch:** `test/dynamic-secret-sink-detection`

**Files:**
- Modify: `tests/security/ReputationSecretHandling.Tests.ps1:286-380,572-587`
- Modify: `docs/decisions.md`

**Interfaces:**
- Keeps `Find-ReputationHardcodedSecret -Files <FileInfo[]>` local to the security test suite.
- Resolved `Connect-VirusTotal -ApiKey`, `Connect-MalwareBazaar -AuthKey`, and `Connect-HybridAnalysis -ApiKey` calls retain their current command-specific checks.
- An unresolved command invoked with PowerShell's call operator is a finding only when `-ApiKey` or `-AuthKey` binds a literal non-empty string.
- Every textual and AST finding contains only the file path, line number, and a stable finding category or parameter name; it never includes the matched literal.
- Variable, expression, secure-string, splatted, and runtime-computed arguments remain outside this narrow rule; Gitleaks and the existing textual patterns remain independent layers.
- Exact allow-listed synthetic values are exempt only when the file is under `tests/`; variants or source-tree copies remain findings.

- [ ] **Step 1: Create the issue and fresh task branch from merged main**

```bash
git switch main
git fetch origin
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "Security tests: detect and redact dynamic secret literals" \
  --body "The repository AST scanner resolves direct, module-qualified, and statically parenthesized connection commands, but skips an unresolved dynamic invocation even when a literal is bound to -ApiKey or -AuthKey. Its findings also include the matched value, so detecting a real secret could echo it into Pester or CI output. Treat the narrow dynamic-literal pattern as a finding and redact every textual and AST diagnostic to file, line, and category or parameter only. Keep variable and runtime-computed arguments out of scope, preserve exact test-fixture exemptions, and retain Gitleaks as independent protection. This issue implements Task 10.2 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c test/dynamic-secret-sink-detection
```

- [ ] **Step 2: Convert the existing dynamic-literal fixture into a red positive test**

Replace `leaves dynamic command expressions unresolved without parser failures` with:

```powershell
It 'flags an ApiKey literal passed through a dynamic invocation' {
    $testPath = Join-Path $TestDrive 'scanner-dynamic-command.ps1'
    Set-Content -LiteralPath $testPath -Value @(
        '$commandName = "EndpointOps\Connect-VirusTotal"'
        "& `$commandName -ApiKey 'DYNAMIC-VT-LITERAL'"
    ) -Encoding utf8NoBOM

    $findings = Find-ReputationHardcodedSecret -Files @([System.IO.FileInfo]$testPath)
    $findingText = $findings -join "`n"

    $findings.Count | Should -Be 1
    $findingText | Should -Match 'scanner-dynamic-command.ps1.*ApiKeyLiteral'
    $findingText | Should -Not -Match 'DYNAMIC-VT-LITERAL'
}
```

Add the parallel `-AuthKey 'DYNAMIC-MB-LITERAL'` case so both sensitive parameter names are covered independently. It must report `AuthKeyLiteral` without containing `DYNAMIC-MB-LITERAL`.

- [ ] **Step 3: Add negative tests that define the deliberate static-analysis boundary**

Use separate TestDrive files and assert no findings for:

```powershell
$commandName = 'EndpointOps\Connect-VirusTotal'
$apiKey = Read-Host -AsSecureString
& $commandName -ApiKey $apiKey
```

and:

```powershell
$commandName = 'EndpointOps\Connect-MalwareBazaar'
& $commandName -AuthKey (Get-SecretFromApprovedRuntimeSource)
```

Also prove that an unrelated direct command with `-ApiKey 'NOT-A-CONNECTION-SECRET'` is not flagged by the AST sink rule. The generic textual scanners can still flag strings that match their provider-key patterns; use values that deliberately do not match those patterns for this structural test.

- [ ] **Step 4: Prove red for the existing unresolved-command skip**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/security/ReputationSecretHandling.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the two dynamic-literal tests fail because the scanner reaches `continue` when `GetCommandName()` cannot resolve `$commandName`; the variable and expression cases remain green.

- [ ] **Step 5: Implement literal inspection for unresolved call-operator commands**

Refactor the command loop so it computes whether the target is resolved and whether the invocation uses the call operator:

```powershell
$isDynamicInvocation = [string]::IsNullOrWhiteSpace($commandName) -and
    $command.InvocationOperator -eq
        [System.Management.Automation.Language.TokenKind]::Ampersand
```

For a resolved known connection command, keep the current single expected parameter. For an unresolved call-operator invocation, inspect both known secret parameter names:

```powershell
$parameterNames = if ($isDynamicInvocation) {
    @('ApiKey', 'AuthKey')
}
elseif (-not [string]::IsNullOrWhiteSpace($commandName)) {
    $terminalCommandName = $commandName.Substring($commandName.LastIndexOf([char]92) + 1)
    if ($script:ConnectSecretParameters.ContainsKey($terminalCommandName)) {
        @($script:ConnectSecretParameters[$terminalCommandName])
    }
    else {
        @()
    }
}
else {
    @()
}
```

Reuse the existing `CommandParameterAst.Argument` lookup and literal extraction for every name in `$parameterNames`. Do not flag a resolved unrelated command. Do not try to resolve variable contents or follow assignments; the rule is intentionally based on a literal at a sensitive dynamic sink.

Replace both existing finding formats so values are used only for validation and exact fixture exemptions, never for output:

```powershell
# Text-pattern finding
$findings.Add("$($file.FullName):${lineNumber}:ProviderKeyPattern")

# AST literal finding
$findings.Add(
    "$($file.FullName):$($argument.Extent.StartLineNumber):$($parameterName)Literal")
```

Update all existing positive scanner assertions to match the file name and stable category instead of the synthetic literal. Add one source-tree text-pattern fixture and one resolved-command AST fixture, serialize the returned findings, and assert that neither synthetic value appears. This proves redaction for both scanner paths rather than only the new dynamic branch.

- [ ] **Step 6: Verify exact fixture exemptions still have their original scope**

Add two assertions:

- dynamic `-ApiKey 'MOCK-VT-KEY'` under TestDrive is exempt because TestDrive is part of the Pester test path only if the scanner's existing `$isTest` logic classifies it that way; if it does not, create the exemption fixture under a temporary `tests/` child of TestDrive and pass that file;
- dynamic `-ApiKey 'MOCK-VT-KEY-LEAK'` under that same test path is a finding, and `MOCK-VT-KEY` copied under a temporary `src/` path is a finding; assertions use file/category metadata and explicitly prove that neither literal occurs in the finding text.

Do not broaden `$script:AllowedTestLiterals` and do not use prefix matching.

- [ ] **Step 7: Run targeted security tests and Gitleaks**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/security/ReputationSecretHandling.Tests.ps1","tests/security/VtSecretHandling.Tests.ps1","tests/security/EpmSecretHandling.Tests.ps1","tests/security/RedirectSecretHandling.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
gitleaks detect --source . --no-banner --redact
```

- [ ] **Step 8: Kill the original dynamic-skip mutation**

Replay two mutations separately in a disposable worktree. First, restore this behavior immediately before the unresolved-command branch:

```powershell
if ([string]::IsNullOrWhiteSpace($commandName)) {
    continue
}
```

Run `tests/security/ReputationSecretHandling.Tests.ps1`. Require `Result` not equal to `Passed` and confirm that both dynamic literal tests fail while the parser itself remains healthy. Restore the implementation. Second, append `$value` to either finding format and require the corresponding non-disclosure assertion to fail. Restore the implementation exactly, rerun the targeted security suite, and inspect `git diff` before proceeding.

- [ ] **Step 9: Document the prevention boundary**

In `docs/decisions.md`, record:

- why unresolved call-operator invocations with literal `ApiKey` or `AuthKey` arguments fail the repository scanner;
- why scanner diagnostics never echo the value that triggered a finding;
- why variable and runtime-computed values are not treated as proof of a committed secret;
- why this does not replace Gitleaks or claim complete PowerShell data-flow analysis.

No README capability claim is needed because this change strengthens repository assurance rather than the module's public runtime behavior.

- [ ] **Step 10: Run the complete cycle-exit validation**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests -PassThru -Output None; "Result: $($r.Result) | $($r.PassedCount)/$($r.TotalCount) | conteneursKO: $($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
pwsh -NoProfile -Command '$l=[System.Collections.Generic.List[object]]::new(); foreach ($p in @("./src","./tests")) { foreach ($d in (Invoke-ScriptAnalyzer -Path $p -Recurse -Settings ./PSScriptAnalyzerSettings.psd1)) { $l.Add($d) } }; "diagnostics: " + $l.Count; if ($l.Count -ne 0) { $l | Format-Table -AutoSize; exit 1 }'
pwsh -NoProfile -Command '$manifest=Import-PowerShellDataFile ./src/EndpointOps/EndpointOps.psd1; $public=@(Get-ChildItem ./src/EndpointOps/Public -Filter *.ps1 | ForEach-Object BaseName | Sort-Object); $exports=@($manifest.FunctionsToExport | Sort-Object); "Public=$($public.Count) Exports=$($exports.Count) Diff=$(@(Compare-Object $public $exports).Count)"; if (@(Compare-Object $public $exports).Count -ne 0) { exit 1 }'
git diff --check
gitleaks detect --source . --no-banner --redact
```

Record the exact passed/total test count, failed-container count, analyzer diagnostic count, public/export counts, Gitleaks result, branch SHA, and worktree status.

- [ ] **Step 11: Commit, obtain independent reviews, open the PR, and merge only after CI**

```bash
git add tests/security/ReputationSecretHandling.Tests.ps1 docs/decisions.md
git diff --cached --check
git commit -m "test: detect dynamic secret sink literals"
```

Request one plan-compliance reviewer and one separate security-test-quality reviewer. Both must run the scanner tests; the second reviewer must replay both the dynamic-skip and diagnostic-disclosure mutations. Resolve all findings and rerun the complete gate before publishing the task branch. Then:

```bash
git push -u origin test/dynamic-secret-sink-detection
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "Detect and redact dynamic secret literals" \
  --body "Closes #${issue_number}. Extends the repository AST scanner to flag literal ApiKey or AuthKey arguments at unresolved call-operator invocations, redacts every finding value, and preserves the documented runtime-expression boundary. Includes mutation proof and full security validation.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

Validate the resulting `main` commit.

## Lot 10 and Full Hardening Cycle Exit

- [ ] Confirm Tasks 10.1 and 10.2 were each merged by their own issue and PR.
- [ ] Confirm all seven Lot 8-10 issues are closed by seven merged pull requests.
- [ ] Run the complete Pester suite on current `main` and require `Result = Passed` plus `FailedContainersCount = 0`.
- [ ] Run PSScriptAnalyzer through a typed list and require zero diagnostics.
- [ ] Require exact synchronization between `Public/*.ps1` and `FunctionsToExport`.
- [ ] Run `git diff --check` and Gitleaks.
- [ ] Recheck every review mutation: unsafe manager destination, EPM fail-soft, stale session cache, interrupted/concurrent persistent cache, provider identity mismatch, shared pagination overflow, contradictory EPM total, excessive retry delay, and dynamic secret literal.
- [ ] Request a final independent security review of the seven-task diff against the approved design.
- [ ] Verify GitHub CI on the final merge SHA, a clean worktree, and synchronization with `origin/main`.
- [ ] Keep Device Control issues #11 and #12 open and explicitly blocked; do not substitute an invented tenant contract.
- [ ] Update public counters and mock-backed limitations with exact fresh evidence.
