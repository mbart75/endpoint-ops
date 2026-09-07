# Lot 8 Security and Behavioral Blockers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three independently reproduced defects that prevent EndpointOps from being described as production-ready: an unchecked EPM manager destination, reputation preflight blocking base EPM output, and an unbounded VirusTotal session cache.

**Architecture:** Validate the dispatcher-provided EPM destination before token state exists, preserve EPM collection when optional reputation is unavailable, and wrap VirusTotal session-cache values with retrieval timestamps while preserving the public report shape. Each task is delivered through its own English issue and pull request and is merged before the next task starts.

**Tech Stack:** PowerShell 7.2+, Pester 6, PSScriptAnalyzer, local `HttpListener` mock server, GitHub CLI, Gitleaks.

**Spec:** `docs/superpowers/specs/2026-09-07-independent-review-hardening-design.md`

## Global Constraints

- Work only in the public `mbart75/endpoint-ops` repository.
- Start every task from freshly fetched `origin/main`; never stack task branches.
- Use one GitHub issue, one branch, and one pull request per task.
- Keep every public file and GitHub artifact in English.
- Preserve PowerShell files as UTF-8 without BOM and do not add accented characters to `.ps1` files.
- Use synthetic fixture credentials only; never add a real token, tenant name, internal hostname, endpoint, user, or enterprise hash.
- External reputation may reject or weaken a proposal, never authorize one.
- Do not upload files or add an automatic security authorization or destructive remediation path.
- The mock proves a simulated contract, not compatibility with a real SentinelOne or CyberArk EPM tenant.
- A task is complete only after targeted red-green proof, relevant fault injection, full Pester with `Result = Passed` and `FailedContainersCount = 0`, typed-list PSScriptAnalyzer count zero, manifest/export synchronization, `git diff --check`, Gitleaks, two independent reviews, PR CI, merge, and fresh validation on `main`.

---

### Task 8.1: Reject unsafe EPM manager destinations

**Issue title:** `EPM: validate the dispatcher-provided manager destination`

**Branch:** `fix/epm-manager-destination-validation`

**Files:**
- Modify: `src/EndpointOps/Public/Connect-EpmTenant.ps1:33-40,72-117`
- Modify: `tests/contract/Connect-EpmTenant.Tests.ps1`
- Modify: `tests/security/EpmSecretHandling.Tests.ps1`
- Modify: `docs/decisions.md`
- Modify: `docs/api-notes-epm.md`

**Interfaces:**
- Consumes: `Connect-EpmTenant -DispatcherUri <string> -Credential <pscredential> [-ApplicationId <string>] [-SkipValidation]`.
- Produces: the same `EndpointOps.Epm.Connection` object for valid destinations; unsafe `ManagerURL` values throw before `$script:EpmConnection` is populated or `Invoke-EpmRequest` is called.
- Preserves: exact loopback HTTP support for the local mock, HTTPS support for real dispatchers and managers, sanitized errors, and the existing public return shape.

- [ ] **Step 1: Create the issue and task branch from current main**

```bash
git switch main
git fetch origin
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "EPM: validate the dispatcher-provided manager destination" \
  --body "The dispatcher-provided ManagerURL is currently accepted without URI or transport validation, then receives the EPM authorization token. Reject unsafe manager destinations before connection state exists. Accept absolute HTTPS destinations and exact loopback HTTP destinations used by the mock. Add red-green security tests proving that non-loopback HTTP never receives the token. This issue implements Task 8.1 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c fix/epm-manager-destination-validation
```

- [ ] **Step 2: Add a red security test for non-loopback HTTP token forwarding**

Add an `InModuleScope EndpointOps` test to `tests/security/EpmSecretHandling.Tests.ps1` that stubs dispatcher calls, returns an HTTP manager, and records every unexpected manager request:

```powershell
It 'rejects a non-loopback HTTP ManagerURL before forwarding the token' {
    $result = InModuleScope EndpointOps -Parameters @{ Credential = $script:ValidCases } {
        param($Credential)
        $script:ManagerRequestObserved = $false

        Mock Invoke-EndpointOpsRequest {
            param($Uri, $Method, $Body, $Headers)
            if ($Uri -like '*/EPM/API/Server/Version') {
                return [pscustomobject]@{ Version = 'review' }
            }
            if ($Uri -like '*/EPM/API/Auth/EPM/Logon') {
                return [pscustomobject]@{
                    ManagerURL = 'http://manager.example.invalid'
                    EPMAuthenticationResult = 'SYNTHETIC-EPM-TOKEN'
                    IsPasswordExpired = $false
                }
            }

            $script:ManagerRequestObserved = -not [string]::IsNullOrEmpty(
                [string]$Headers.Authorization)
        }

        $message = $null
        try {
            Connect-EpmTenant -DispatcherUri 'https://dispatcher.example.invalid' `
                -Credential $Credential | Out-Null
        }
        catch {
            $message = $_.Exception.Message
        }

        [pscustomobject]@{
            ManagerRequestObserved = $script:ManagerRequestObserved
            ErrorMessage           = $message
        }
    }

    $result.ManagerRequestObserved | Should -BeFalse
    $result.ErrorMessage | Should -BeLike '*ManagerURL*HTTPS*'
}
```

- [ ] **Step 3: Run the security test and prove the current code fails for the reproduced reason**

Run:

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/security/EpmSecretHandling.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the first assertion fails because the current code sends an authorization header to the injected HTTP manager. The result records only a boolean and never copies the token into test output. After the correction, the separate error assertion proves that rejection names the safe transport requirement.

- [ ] **Step 4: Add contract cases for malformed manager destinations**

In `tests/contract/Connect-EpmTenant.Tests.ps1`, add parameterized cases for:

```powershell
@(
    @{ ManagerURL = 'http://manager.example.invalid'; Reason = 'non-loopback HTTP' }
    @{ ManagerURL = 'http://127.0.0.2:8080'; Reason = 'unapproved loopback address' }
    @{ ManagerURL = 'http://127.1:8080'; Reason = 'abbreviated loopback spelling' }
    @{ ManagerURL = '/relative/manager'; Reason = 'relative URI' }
    @{ ManagerURL = 'ftp://manager.example.invalid'; Reason = 'unsupported scheme' }
    @{ ManagerURL = 'https://user:password@manager.example.invalid'; Reason = 'embedded credentials' }
    @{ ManagerURL = 'https://manager.example.invalid/#fragment'; Reason = 'fragment' }
)
```

For each case, mock the version and logon responses, call `Connect-EpmTenant`, require an error naming `ManagerURL`, and assert that `Get-EpmConnectionState` still throws `*Connect-EpmTenant*`.

- [ ] **Step 5: Implement manager URI validation before secure-token construction**

Immediately after checking that `ManagerURL` is non-empty and before building `$secureToken`, replace string trimming with an absolute `System.Uri` validation:

```powershell
$rawManagerUri = ([string]$managerUrl).Trim()
$managerUriObject = $null
$hasAbsoluteManagerUri = [uri]::TryCreate(
    $rawManagerUri,
    [System.UriKind]::Absolute,
    [ref]$managerUriObject)
$hasEmbeddedCredentials = $hasAbsoluteManagerUri -and
    -not [string]::IsNullOrEmpty($managerUriObject.UserInfo)
$hasFragment = $hasAbsoluteManagerUri -and
    -not [string]::IsNullOrEmpty($managerUriObject.Fragment)
$hasAllowedLoopbackAuthority = $hasAbsoluteManagerUri -and
    $rawManagerUri -match '^http://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/|$)'
$hasSafeScheme = $hasAbsoluteManagerUri -and (
    $managerUriObject.Scheme -ceq [System.Uri]::UriSchemeHttps -or
    ($managerUriObject.Scheme -ceq [System.Uri]::UriSchemeHttp -and
        $hasAllowedLoopbackAuthority))

if (-not $hasAbsoluteManagerUri -or -not $hasSafeScheme -or
    $hasEmbeddedCredentials -or $hasFragment) {
    $script:EpmConnection = $null
    throw 'EndpointOps: ManagerURL must be an absolute HTTPS URI. HTTP is allowed only for an exact loopback host used by local tests; embedded credentials and fragments are rejected.'
}

$managerUri = $managerUriObject.AbsoluteUri.TrimEnd('/')
```

Evaluate the HTTP allowlist against the original trimmed spelling, not normalized `Uri.Host`: URI normalization turns `127.1` into `127.0.0.1`. Do not use `Uri.IsLoopback`, which accepts additional loopback addresses. IPv6 loopback is intentionally absent because the current mock does not use it. Do not add same-host or same-domain pinning: that relationship is not confirmed against a real tenant.

- [ ] **Step 6: Prove valid HTTPS and loopback destinations remain supported**

Add or retain assertions showing:

```powershell
$result.ManagerUri | Should -BeExactly $expectedManagerUri
$result.Validated | Should -BeTrue
```

Use the existing mock for loopback and an `InModuleScope` transport mock for HTTPS. Require that automatic validation sends one manager request only after validation succeeds.

- [ ] **Step 7: Run targeted EPM contract and security tests**

Run:

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/contract/Connect-EpmTenant.Tests.ps1","tests/contract/EpmMockAuth.Tests.ps1","tests/security/EpmSecretHandling.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
```

Expected: `Result=Passed` and `ContainersFailed=0`.

- [ ] **Step 8: Replay the token-forwarding fault injection**

In a disposable worktree, temporarily replace the new `$hasSafeScheme` result with `$true`, run only the new HTTP-manager security test, and require it to fail because a manager request is observed. Restore the file and require `git diff --exit-code` in the disposable worktree.

- [ ] **Step 9: Document the trust boundary**

Add a decision explaining that the dispatcher remains trusted to select the manager host, while EndpointOps independently enforces an absolute safe transport URI. Update the EPM API note to state that same-domain pinning is intentionally absent until validated against an authorized tenant.

- [ ] **Step 10: Commit, independently review, and merge the task**

```bash
git add src/EndpointOps/Public/Connect-EpmTenant.ps1 \
  tests/contract/Connect-EpmTenant.Tests.ps1 \
  tests/security/EpmSecretHandling.Tests.ps1 \
  docs/decisions.md docs/api-notes-epm.md
git diff --cached --check
git commit -m "fix: validate EPM manager destinations"
```

Run the global validation commands, request separate plan-compliance and security-quality reviews, resolve every finding, then:

```bash
git push -u origin fix/epm-manager-destination-validation
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "fix: validate EPM manager destinations" \
  --body "Closes #$issue_number

Rejects unsafe dispatcher-provided manager destinations before EPM connection state or token forwarding. Preserves HTTPS and explicit local-mock hosts and adds adversarial secret-boundary coverage.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

Rerun the complete validation on the merge commit before Task 8.2.

---

### Task 8.2: Keep base EPM summaries available without VirusTotal

**Issue title:** `EPM: preserve elevation summaries when reputation is unavailable`

**Branch:** `fix/epm-reputation-failure-isolation`

**Files:**
- Modify: `src/EndpointOps/Public/Get-EpmElevationSummary.ps1:78-96,243-257`
- Modify: `tests/contract/Get-EpmElevationSummary.Reputation.Tests.ps1:207-245`
- Modify: `docs/backlog-detections.md`
- Modify: `docs/decisions.md`

**Interfaces:**
- Consumes: `Get-EpmElevationSummary -SetId <string> -IncludeReputation [-MinIntervalMs <int>]`.
- Produces: every base binary grouping even when all reputation providers are disconnected; each affected grouping exposes `Reputation = 'Unavailable'` and retains its base proposal level.
- Preserves: early rejection of `-GroupBy User -IncludeReputation`, malicious-only degradation, output ordering, and the existing output property set.

- [ ] **Step 1: Create the issue and branch from freshly validated main**

```bash
git switch main
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "EPM: preserve elevation summaries when reputation is unavailable" \
  --body "Get-EpmElevationSummary currently aborts before querying EPM when VirusTotal is disconnected, contradicting the documented fail-soft enrichment contract. Return all base EPM groupings with Unavailable reputation and unchanged proposals. This issue implements Task 8.2 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c fix/epm-reputation-failure-isolation
```

- [ ] **Step 2: Replace the contradictory test with a red fail-soft contract test**

Replace the test beginning `Throws before querying EPM when VirusTotal is disconnected` with:

```powershell
It 'returns every EPM grouping when VirusTotal is disconnected' {
    Disconnect-VirusTotal
    $before = Measure-EpmRequestLog

    try {
        $summary = @(
            Get-EpmElevationSummary -SetId $script:Production `
                -IncludeReputation -MinIntervalMs 0
        )

        $summary.Count | Should -Be 5
        @($summary.Reputation | Select-Object -Unique) | Should -Be @('Unavailable')
        (Measure-EpmRequestLog) | Should -BeGreaterThan $before

        $contoso = Get-GroupedSummary -Summary $summary -Hash $script:HContoso
        $contoso.ProposalLevel | Should -BeExactly 'Strong'
    }
    finally {
        Connect-VirusTotal -BaseUri $script:Server.BaseUrl -ApiKey $script:VtKey | Out-Null
    }
}
```

- [ ] **Step 3: Run the new test and prove the preflight causes red**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Get-EpmElevationSummary.Reputation.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the new test fails with an error naming `Connect-VirusTotal` before its count assertions execute.

- [ ] **Step 4: Remove only the report-level VirusTotal preflight**

Delete this block from `Get-EpmElevationSummary.ps1`:

```powershell
if ($IncludeReputation) {
    $null = Get-VtConnectionState
}
```

Keep the `GroupBy User` parameter guard before EPM collection and keep the existing per-group `try/catch` around `Get-FileReputation`.

- [ ] **Step 5: Add a test proving malicious evidence still only degrades**

Use `InModuleScope EndpointOps` to mock `Get-FileReputation` as malicious for one known group and unavailable for the others. Assert that the malicious group becomes `ProposalLevel = 'None'`, unavailable groups retain their base level, and no group is promoted.

- [ ] **Step 6: Run all EPM summary tests**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/contract/Get-EpmElevationSummary.Tests.ps1","tests/contract/Get-EpmElevationSummary.Reputation.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
```

- [ ] **Step 7: Replay the failure-isolation mutation**

In a disposable worktree, restore the deleted `Get-VtConnectionState` preflight, run the new disconnected-provider test, and require red with `Connect-VirusTotal`. Restore the file and prove the disposable worktree is clean.

- [ ] **Step 8: Reconcile public documentation**

Keep the existing backlog invariant and add a decision that mandatory-first provider ordering does not make provider availability mandatory for the base EPM report. State that unavailable evidence leaves proposals unchanged.

- [ ] **Step 9: Commit, review, and merge**

```bash
git add src/EndpointOps/Public/Get-EpmElevationSummary.ps1 \
  tests/contract/Get-EpmElevationSummary.Reputation.Tests.ps1 \
  docs/backlog-detections.md docs/decisions.md
git diff --cached --check
git commit -m "fix: isolate EPM reports from reputation failures"
```

Run the global validation and independent two-stage review, then:

```bash
git push -u origin fix/epm-reputation-failure-isolation
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "fix: isolate EPM reports from reputation failures" \
  --body "Closes #$issue_number

Keeps base EPM elevation groupings available when optional reputation providers are disconnected or unavailable. Malicious evidence can still degrade a proposal, while unavailable evidence never promotes or suppresses it.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

Freshly validate the merge commit before Task 8.3.

---

### Task 8.3: Expire VirusTotal session-cache evidence

**Issue title:** `VirusTotal: enforce session-cache freshness`

**Branch:** `fix/virustotal-session-cache-freshness`

**Files:**
- Modify: `src/EndpointOps/Public/Get-VtFileReport.ps1:1-5,39-65,123-151`
- Modify: `tests/contract/Get-VtFileReport.Tests.ps1`
- Modify: `tests/contract/ReputationCache.Tests.ps1`
- Modify: `docs/api-notes-reputation.md`
- Modify: `docs/decisions.md`

**Interfaces:**
- Consumes: `Get-VtUtcNow` as the injectable UTC clock and the existing case-insensitive `$script:VtFileReportCache` dictionary.
- Produces: internal cache entries with exact properties `Report` (`pscustomobject`) and `CachedAtUtc` (`datetime`).
- Preserves: the public `EndpointOps.VirusTotal.FileReport` property set and defensive-copy behavior.

- [ ] **Step 1: Create the issue and fresh task branch**

```bash
git switch main
git fetch origin
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "VirusTotal: enforce session-cache freshness" \
  --body "The process-lifetime VirusTotal cache currently has no retrieval timestamp. Stale clean or unknown evidence can bypass the seven-day policy, stale malicious evidence can outlive 90 days, and a transient Unavailable result can remain stuck for the session. Add timestamped internal envelopes, evict stale entries, never cache Unavailable, and preserve the public report shape and defensive-copy behavior. This issue implements Task 8.3 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c fix/virustotal-session-cache-freshness
```

- [ ] **Step 2: Add red tests for stale clean evidence and transient unavailable recovery**

Add `InModuleScope` tests using the existing `Get-VtUtcNow` injection point:

```powershell
It 'requeries a Clean session entry after seven days' {
    $hash = $script:KnownHash
    $now = [datetime]'2026-09-07T12:00:00Z'

    InModuleScope EndpointOps -Parameters @{ Hash = $hash; Now = $now } {
        param($Hash, $Now)
        $script:VtFileReportCache.Clear()
        Mock Get-VtUtcNow { $Now }
        Mock Invoke-VtRequest {
            [pscustomobject]@{ data = [pscustomobject]@{ attributes = [pscustomobject]@{
                last_analysis_stats = [pscustomobject]@{ malicious = 0; harmless = 10 }
                sha1 = $Hash
                sha256 = ('A' * 64)
                md5 = ('A' * 32)
            } } }
        }

        Get-VtFileReport -Hash $Hash -MinIntervalMs 0 | Out-Null
        Mock Get-VtUtcNow { $Now.AddDays(8) }
        Get-VtFileReport -Hash $Hash -MinIntervalMs 0 | Out-Null

        Should -Invoke Invoke-VtRequest -Times 2 -Exactly
    }
}
```

For unavailable recovery, mock `Invoke-VtRequest` to throw on the first call and return a clean response on the second. Call twice and require `Unavailable` then `Clean`, with two provider calls.

- [ ] **Step 3: Run the new tests and prove both are red**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Get-VtFileReport.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected current behavior: stale clean evidence produces only one provider call, and the transient unavailable result remains unavailable with only one provider call.

- [ ] **Step 4: Store timestamped internal cache envelopes**

Keep the dictionary type but store this private shape:

```powershell
[pscustomobject]@{
    Report      = $report.PSObject.Copy()
    CachedAtUtc = (Get-VtUtcNow)
}
```

At lookup, calculate lifetime from `entry.Report.Verdict`:

```powershell
$validityDays = if ($entry.Report.Verdict -eq 'Malicious') { 90 } else { 7 }
$age = (Get-VtUtcNow) - $entry.CachedAtUtc
if ($age -ge [timespan]::Zero -and
    $age -le [timespan]::FromDays($validityDays)) {
    Copy-VtReport -Report $entry.Report
    return
}
$null = $script:VtFileReportCache.Remove($Hash)
```

Do not change the report returned to callers.

- [ ] **Step 5: Never cache unavailable reports**

In both transport-error and malformed-response paths, only add a cache envelope when:

```powershell
if ($report.Verdict -ne 'Unavailable') {
    $script:VtFileReportCache[$Hash] = [pscustomobject]@{
        Report      = $report.PSObject.Copy()
        CachedAtUtc = (Get-VtUtcNow)
    }
}
```

Unknown remains cacheable for seven days because repeated 400/404 requests waste provider quota without adding evidence.

- [ ] **Step 6: Add malicious and clock-skew boundary tests**

Seed internal envelopes through `InModuleScope` and prove:

- malicious at exactly 90 days is served;
- malicious older than 90 days is requeried;
- a future `CachedAtUtc` is evicted and requeried;
- upper/lowercase SHA-1 lookups share one valid envelope;
- caller mutation still cannot change the cached report.

- [ ] **Step 7: Run VirusTotal and persistent-cache contract tests**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/contract/Get-VtFileReport.Tests.ps1","tests/contract/ReputationCache.Tests.ps1","tests/security/VtSecretHandling.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
```

- [ ] **Step 8: Replay cache fault injections**

Run two disposable mutations separately:

1. remove the age check and require the stale-clean test to fail;
2. cache `Unavailable` and require the recovery test to fail.

Restore each mutation independently and prove a clean disposable worktree after each run.

- [ ] **Step 9: Document session-cache semantics**

State the exact 7/90-day in-memory lifetimes, the reason unknown is cached, why unavailable is not cached, and that the persistent cache remains opt-in while the session cache remains memory-only.

- [ ] **Step 10: Commit, review, merge, and run the Lot 8 security gate**

```bash
git add src/EndpointOps/Public/Get-VtFileReport.ps1 \
  tests/contract/Get-VtFileReport.Tests.ps1 \
  tests/contract/ReputationCache.Tests.ps1 \
  docs/api-notes-reputation.md docs/decisions.md
git diff --cached --check
git commit -m "fix: expire VirusTotal session evidence"
```

Run the standard independent reviews and complete validation. Resolve all findings before publishing the task branch. Then:

```bash
git push -u origin fix/virustotal-session-cache-freshness
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "fix: expire VirusTotal session evidence" \
  --body "Closes #$issue_number

Applies seven-day clean and unknown freshness, 90-day malicious freshness, and no session caching for unavailable VirusTotal results while preserving the public report shape.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

After the merge, rerun validation and dispatch a separate read-only security reviewer for the complete Lot 8 diff. Require it to replay the HTTP manager, disconnected-provider, stale-cache, unavailable-recovery, redirect-secret, and caller-cache-poisoning tests. Do not begin Lot 9 until that gate is clean.

## Global validation commands

Run after every task immediately before review, immediately before PR merge, and again on merged `main`:

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests -PassThru -Output None; "Result: $($r.Result) | $($r.PassedCount)/$($r.TotalCount) | containersFailed: $($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
pwsh -NoProfile -Command '$l=[System.Collections.Generic.List[object]]::new(); foreach ($p in @("./src","./tests")) { foreach ($d in (Invoke-ScriptAnalyzer -Path $p -Recurse -Settings ./PSScriptAnalyzerSettings.psd1)) { $l.Add($d) } }; "diagnostics: $($l.Count)"; if ($l.Count -ne 0) { $l | Format-Table -AutoSize; exit 1 }'
pwsh -NoProfile -Command '$m=Test-ModuleManifest ./src/EndpointOps/EndpointOps.psd1 -ErrorAction Stop; $public=@(Get-ChildItem ./src/EndpointOps/Public -Filter *.ps1 | ForEach-Object BaseName | Sort-Object); $exported=@($m.ExportedFunctions.Keys | Sort-Object); $diff=@(Compare-Object $public $exported); "Public=$($public.Count) Exported=$($exported.Count) Diff=$($diff.Count)"; if ($diff.Count -ne 0) { exit 1 }'
git diff --check
gitleaks detect --source . --no-banner --redact
git status --short
```
