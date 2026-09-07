# Lot 9 Evidence and Cache Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make persistent reputation evidence recoverable under concurrent access and enforce one unambiguous SHA-1 identity through EPM grouping, provider responses, and canonical VirusTotal pivots.

**Architecture:** Serialize cache mutations with a data-free sidecar lock, write complete JSON through a flushed sibling temporary file and atomic replacement, and coordinate clearing through the same lock. Narrow the multi-provider cascade to its actual EPM SHA-1 contract, validate returned provider identity, and normalize grouping identity without changing direct VirusTotal lookup support.

**Tech Stack:** PowerShell 7.2+, .NET `FileStream`, Pester 6, PSScriptAnalyzer, local `HttpListener` mock server, GitHub CLI, Gitleaks.

**Spec:** `docs/superpowers/specs/2026-09-07-independent-review-hardening-design.md`

## Global Constraints

- Begin only after the Lot 8 security gate is clean and merged `main` has fresh passing evidence.
- Work only in the public repository and keep every public artifact in English.
- Deliver each task through its own issue, fresh branch, pull request, CI run, merge, and post-merge validation.
- Preserve legacy and version-2 cache compatibility unless the task explicitly rejects an unsafe envelope.
- Never persist provider credentials, endpoint names, machine names, user names, or provider response details in the cache.
- Malicious evidence is monotonic within its valid lifetime and cannot be replaced by clean, unknown, unavailable, malformed, or mismatched evidence.
- `Get-FileReputation` is the EPM cascade and accepts SHA-1 only; direct `Get-VtFileReport` lookups continue to accept MD5, SHA-1, and SHA-256.
- Use case-insensitive hexadecimal identity comparisons and retain deterministic public output.
- A task is complete only after targeted red-green proof, deterministic fault injection, full Pester result checks, typed-list analyzer count zero, manifest/export synchronization, `git diff --check`, Gitleaks, independent compliance and quality reviews, CI, merge, and fresh validation of `main`.

---

### Task 9.1: Make persistent cache mutation atomic and concurrent-safe

**Issue title:** `Cache: make persistent reputation updates atomic`

**Branch:** `fix/reputation-cache-atomic-writes`

**Files:**
- Create: `src/EndpointOps/Private/Invoke-WithReputationCacheLock.ps1`
- Create: `src/EndpointOps/Private/Move-ReputationCacheFile.ps1`
- Create: `src/EndpointOps/Private/Write-ReputationCacheFile.ps1`
- Create: `src/EndpointOps/Private/Test-ReputationCacheFile.ps1`
- Modify: `src/EndpointOps/Private/Write-ReputationCacheEntry.ps1:54-225`
- Modify: `src/EndpointOps/Public/Clear-ReputationCache.ps1`
- Modify: `tests/contract/ReputationCache.Tests.ps1`
- Create: `tests/unit/ReputationCacheFile.Tests.ps1`
- Modify: `README.md`
- Modify: `docs/decisions.md`

**Interfaces:**
- Produces: `Invoke-WithReputationCacheLock -CachePath <string> -ScriptBlock <scriptblock> [-LockTimeoutMs <int>]` with a default 5000 ms timeout.
- Produces: `Write-ReputationCacheFile -CachePath <string> -Entries <object[]>`, which flushes a complete sibling temporary file and calls `Move-ReputationCacheFile` only after serialization succeeds.
- Produces: `Move-ReputationCacheFile -SourcePath <string> -DestinationPath <string>`, the mockable wrapper around `[System.IO.File]::Move(..., $true)`.
- Produces: `Test-ReputationCacheFile -CachePath <string>` returning one object with `Exists`, `IsValid`, and `Entries`.
- Preserves: `Write-ReputationCacheEntry` remains private and non-throwing to public enrichment callers; `Clear-ReputationCache` remains public and idempotent for an absent path.

- [ ] **Step 1: Create the issue and fresh task branch**

```bash
git switch main
git fetch origin
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "Cache: make persistent reputation updates atomic" \
  --body "Persistent reputation cache updates currently use an unlocked read-modify-write and replace the live file in place. Concurrent processes can lose evidence, including a malicious verdict, and interruption can leave truncated JSON. Clear-ReputationCache also deletes a supplied leaf without ShouldProcess. Add a bounded per-cache sidecar lock, same-filesystem temporary write plus atomic replacement, monotonic malicious evidence, strict cache recognition, and ShouldProcess-guarded clearing. This issue implements Task 9.1 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c fix/reputation-cache-atomic-writes
```

- [ ] **Step 2: Write red unit tests for cross-process exclusion**

In `tests/unit/ReputationCacheFile.Tests.ps1`, use a deterministic two-job handshake rather than timing overlap. Job A imports the module, acquires the lock through the module's session state, creates an `entered-a` signal file, waits for a `release-a` file, then exits. Start job B only after `entered-a` exists; its critical section creates `entered-b`. Assert `entered-b` cannot appear while A is held, create `release-a`, then require both jobs to complete and `entered-b` to appear. Invoke the private helper inside each job with:

```powershell
$module = Get-Module EndpointOps
& $module {
    param($Path, $EnteredPath, $ReleasePath)
    Invoke-WithReputationCacheLock -CachePath $Path -ScriptBlock {
        [System.IO.File]::WriteAllText($EnteredPath, '', [System.Text.UTF8Encoding]::new($false))
        if ($ReleasePath) {
            while (-not [System.IO.File]::Exists($ReleasePath)) {
                Start-Sleep -Milliseconds 20
            }
        }
    }
} $cachePath $enteredPath $releasePath
```

For the different-path control, hold cache A with the same handshake and assert a job locking cache B creates its signal before A is released. Give every signal wait a bounded five-second timeout and stop failed jobs in `finally` so a broken test cannot hang the suite.

- [ ] **Step 3: Run the lock tests and prove red because the helper does not exist**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/unit/ReputationCacheFile.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: failure naming `Invoke-WithReputationCacheLock` as unknown.

- [ ] **Step 4: Implement the bounded sidecar lock helper**

Create `Invoke-WithReputationCacheLock.ps1` with this contract:

```powershell
function Invoke-WithReputationCacheLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CachePath,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [ValidateRange(100, 60000)][int]$LockTimeoutMs = 5000
    )

    $lockPath = "$CachePath.lock"
    [System.IO.Directory]::CreateDirectory((Split-Path $lockPath -Parent)) | Out-Null
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $lockStream = $null
    try {
        while ($null -eq $lockStream) {
            try {
                $lockStream = [System.IO.FileStream]::new(
                    $lockPath,
                    [System.IO.FileMode]::OpenOrCreate,
                    [System.IO.FileAccess]::ReadWrite,
                    [System.IO.FileShare]::None)
            }
            catch [System.IO.IOException] {
                if ($timer.ElapsedMilliseconds -ge $LockTimeoutMs) {
                    throw "EndpointOps: timed out waiting for the reputation cache lock at $CachePath"
                }
                Start-Sleep -Milliseconds 50
            }
        }
        & $ScriptBlock
    }
    finally {
        if ($null -ne $lockStream) { $lockStream.Dispose() }
    }
}
```

Canonicalize the cache path before calling this helper with `[System.IO.Path]::GetFullPath(...)`; relative paths are resolved against `(Get-Location).Path`. Add a test that one worker uses the direct path and the other an equivalent path containing `..`, and prove they still serialize on one lock. If the canonical path has no parent, use the current location. Keep the empty lock file; deleting it after release can create an inode race with a waiter.

- [ ] **Step 5: Add red tests for atomic replacement and interruption**

Seed a valid cache file, mock `Move-ReputationCacheFile` to throw, call `Write-ReputationCacheFile`, and assert:

```powershell
(Get-Content -LiteralPath $cachePath -Raw) | Should -BeExactly $originalContent
@(Get-ChildItem -LiteralPath (Split-Path $cachePath -Parent) -Filter '*.tmp.*').Count |
    Should -Be 0
```

Add a success test that parses the replacement JSON and checks UTF-8 without BOM.

Run and require red because `Write-ReputationCacheFile` and `Move-ReputationCacheFile` do not exist:

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/unit/ReputationCacheFile.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

- [ ] **Step 6: Implement flushed temporary writing and mockable atomic move**

`Move-ReputationCacheFile.ps1` contains only:

```powershell
function Move-ReputationCacheFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    [System.IO.File]::Move($SourcePath, $DestinationPath, $true)
}
```

`Write-ReputationCacheFile` must create a sibling path named with process ID and GUID, serialize with `ConvertTo-Json -Depth 4`, write with `UTF8Encoding($false)`, call `Flush()` and `BaseStream.Flush($true)`, dispose the writer, then call `Move-ReputationCacheFile`. Its `finally` block removes a remaining temporary file only.

- [ ] **Step 7: Add red concurrent-write and evidence-monotonicity tests**

First add a deterministic integration assertion: mock `Invoke-WithReputationCacheLock` to execute its script block, call private `Write-ReputationCacheEntry`, and require `Should -Invoke Invoke-WithReputationCacheLock -Times 1 -Exactly`. This is red on the current writer because it never calls the lock helper.

Launch two jobs against one empty canonical cache path. Each imports the module and invokes private `Write-ReputationCacheEntry` through `& (Get-Module EndpointOps) { ... }`. One writes a synthetic clean VirusTotal entry and the other writes a synthetic malicious MalwareBazaar entry with the same lookup identity. Wait for both jobs, require both to exit successfully, parse the final cache, and assert both sources exist exactly once.

Seed a fresh malicious VirusTotal entry and submit, separately, a clean VirusTotal update with the same binding, a weaker update with a different non-empty canonical SHA-256, and a weaker update with a null canonical binding. The first must retain the malicious verdict; the latter two must leave the cache byte-for-byte unchanged. Add separate cases proving an expired malicious entry and a future-dated malicious entry do not suppress a current clean replacement.

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/ReputationCache.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the lock-integration assertion and monotonicity cases fail deterministically on the baseline. The real concurrent-writer case is retained as an integration stress check but is not the sole red proof because process scheduling could serialize one isolated run by chance.

- [ ] **Step 8: Move cache parsing and mutation behind the acquired lock**

Wrap the complete existing read-normalize-add-write body of `Write-ReputationCacheEntry` in:

```powershell
Invoke-WithReputationCacheLock -CachePath $resolvedCachePath -ScriptBlock {
    # Re-read the live cache here, preserve validation, apply the new binding and monotonicity rules,
    # add the candidate only when accepted, then call Write-ReputationCacheFile.
}
```

Do not read the cache before acquiring the lock. While normalizing existing entries, parse each date and compute `$age = [datetime]::UtcNow - $entryDate.UtcDateTime`; only an age from zero through 90 days can trigger malicious monotonic retention. Future and expired entries do not block replacement and receive explicit tests.

Before removing or adding entries, collect every non-empty valid `CanonicalSha256` for the candidate `LookupHash`. If an established non-empty binding exists, require the candidate `CanonicalSha256` to be non-empty and equal case-insensitively; a missing or different candidate binding returns from the locked mutation without changing the live file. This is a contradictory or unbound evidence update, not a normal refresh. The tests written in Step 7 prove both rejection paths byte-for-byte.

For the same binding and source, when a current entry is `Malicious` and the candidate is `Clean` or `Unknown`, retain the existing entry and set a flag that suppresses appending the weaker candidate. Replace the final `File.WriteAllText` call with:

```powershell
Write-ReputationCacheFile -CachePath $resolvedCachePath -Entries $entries.ToArray()
```

Keep the public enrichment path fail-soft by retaining the outer catch. Lock timeout and write failure must not turn unavailable enrichment into an authorization.

- [ ] **Step 9: Add red `ShouldProcess` and unrelated-file tests**

In `ReputationCache.Tests.ps1`, assert:

```powershell
Clear-ReputationCache -CachePath $cachePath -WhatIf
(Test-Path -LiteralPath $cachePath) | Should -BeTrue
(Test-Path -LiteralPath "$cachePath.lock") | Should -BeFalse
```

Create an unrelated valid JSON file such as `[{"project":"not-endpoint-ops"}]`; require normal clearing to throw a cache-envelope error and preserve the file. Require `-Force -Confirm:$false` to remove an intentionally corrupt cache. Keep absent-path clearing idempotent and assert it creates neither the cache directory nor a sidecar lock.

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/ReputationCache.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the baseline rejects `-WhatIf`, deletes unrelated JSON, and has no `-Force` recovery path.

- [ ] **Step 10: Implement strict recognition and coordinated clearing**

`Test-ReputationCacheFile` returns `Exists = $false`, `IsValid = $true`, and an empty `Entries` array for an absent file. For an existing file, require a top-level JSON array and require every element to match exactly one supported legacy or version-2 property set and allowed source/verdict/hash/date rules already enforced by the reader. On any contradiction, return `Exists = $true`, `IsValid = $false`, and no entries.

Change the declaration to:

```powershell
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'EndpointOps/reputation-cache.json'),
    [switch]$Force
)
```

Canonicalize the path. Return immediately when the cache file is absent. Call `ShouldProcess` before acquiring the lock so `-WhatIf` does not create a directory or retained sidecar file. Only when it returns true, acquire `Invoke-WithReputationCacheLock`, re-run `Test-ReputationCacheFile` under the lock, return if another process already cleared it, reject an invalid envelope unless `-Force`, and remove the file:

```powershell
if (-not (Test-Path -LiteralPath $resolvedCachePath -PathType Leaf)) { return }
if ($PSCmdlet.ShouldProcess($resolvedCachePath, 'Remove the EndpointOps reputation cache')) {
    Invoke-WithReputationCacheLock -CachePath $resolvedCachePath -ScriptBlock {
        $cache = Test-ReputationCacheFile -CachePath $resolvedCachePath
        if (-not $cache.Exists) { return }
        if (-not $cache.IsValid -and -not $Force) {
            throw 'EndpointOps: the supplied path is not a recognized reputation cache.'
        }
        Remove-Item -LiteralPath $resolvedCachePath -Force -ErrorAction Stop
    }
}
```

- [ ] **Step 11: Run cache unit, contract, security, and module tests**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/unit/ReputationCacheFile.Tests.ps1","tests/contract/ReputationCache.Tests.ps1","tests/security/ReputationSecretHandling.Tests.ps1","tests/unit/Module.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
```

- [ ] **Step 12: Replay deterministic lock and atomicity mutations**

In separate disposable worktrees:

1. replace the exclusive-lock body with direct `& $ScriptBlock`; require the held-lock signal test to fail because worker B enters before worker A is released;
2. replace `Move-ReputationCacheFile` with direct overwrite of the destination before the injected failure; require the interruption test to show that the original content was lost.
3. remove canonical path normalization; require the direct-versus-`..` alias test to show simultaneous entry.
4. allow a null or different canonical binding to replace an established binding; require the byte-identity tests to fail.
5. move `ShouldProcess` inside the lock; require the `-WhatIf` sidecar test to fail.

Restore after each mutation and require no disposable diff.

- [ ] **Step 13: Reconcile documentation and commit**

Change README claims from “only state-changing command” to “only remote product write command” and document `Clear-ReputationCache` as a local `ShouldProcess` operation. Record why the sidecar lock is retained and why the temporary file must share the target filesystem.

```bash
git add src/EndpointOps/Private/Invoke-WithReputationCacheLock.ps1 \
  src/EndpointOps/Private/Move-ReputationCacheFile.ps1 \
  src/EndpointOps/Private/Write-ReputationCacheFile.ps1 \
  src/EndpointOps/Private/Test-ReputationCacheFile.ps1 \
  src/EndpointOps/Private/Write-ReputationCacheEntry.ps1 \
  src/EndpointOps/Public/Clear-ReputationCache.ps1 \
  tests/unit/ReputationCacheFile.Tests.ps1 \
  tests/contract/ReputationCache.Tests.ps1 README.md docs/decisions.md
git diff --cached --check
git commit -m "fix: make reputation cache updates atomic"
```

Run the complete validation commands and obtain separate compliance and security-quality reviews. Resolve all findings before publishing the task branch. Then:

```bash
git push -u origin fix/reputation-cache-atomic-writes
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "fix: make persistent reputation updates atomic" \
  --body "Closes #$issue_number

Serializes cache mutation, preserves established evidence bindings, atomically replaces complete JSON, and makes local cache clearing recognizable and ShouldProcess-aware.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

Freshly validate the merge commit before Task 9.2.

---

### Task 9.2: Enforce SHA-1 identity across the reputation cascade

**Issue title:** `Reputation: enforce hash identity across providers`

**Branch:** `fix/reputation-hash-identity`

**Files:**
- Modify: `src/EndpointOps/Public/Get-FileReputation.ps1:11-39,141-199`
- Modify: `src/EndpointOps/Private/Get-MbFileVerdict.ps1:24-49`
- Modify: `src/EndpointOps/Public/Get-EpmElevationSummary.ps1:101-175`
- Modify: `tests/mock/MockApiServer.ps1:130-180,208-310`
- Modify: `tests/contract/Get-FileReputation.Tests.ps1`
- Modify: `tests/contract/MalwareBazaarConnection.Tests.ps1`
- Modify: `tests/contract/Get-EpmElevationSummary.Tests.ps1`
- Modify: `tests/contract/ReputationCache.Tests.ps1`
- Modify: `docs/api-notes-reputation.md`
- Modify: `docs/decisions.md`

**Interfaces:**
- Consumes: EPM SHA-1 hashes through `Get-FileReputation -Hash <40 hex characters>`.
- Produces: local parameter rejection for MD5, SHA-256, malformed, or non-hex cascade values before any provider call.
- Preserves: direct `Get-VtFileReport` support for 32-, 40-, and 64-character hashes.
- Produces: MalwareBazaar malicious evidence only for one unambiguous case-insensitive SHA-1 match.
- Produces: one EPM binary group for case variants of the same SHA-1.

- [ ] **Step 1: Create the issue and branch from current main**

```bash
git switch main
git fetch origin
git pull --ff-only origin main
issue_url=$(gh issue create --repo mbart75/endpoint-ops \
  --title "Reputation: enforce hash identity across providers" \
  --body "The EPM reputation cascade accepts hash lengths that later fail at its SHA-1-only MalwareBazaar stage, accepts MalwareBazaar evidence without binding the returned SHA-1 to the lookup, and can split one EPM binary when hash casing differs. A VirusTotal alias-check mutation also survives the current suite. Make the cascade SHA-1-only before network access, bind provider evidence to exact case-insensitive identity, normalize grouping identity, and add a mismatched-alias fixture that kills the mutation. Direct Get-VtFileReport MD5/SHA-1/SHA-256 support remains unchanged. This issue implements Task 9.2 of the independent-review hardening design.")
issue_number=${issue_url##*/}
git switch -c fix/reputation-hash-identity
```

- [ ] **Step 2: Add red public-boundary tests for cascade hash formats**

In `Get-FileReputation.Tests.ps1`, add cases for 32 and 64 hexadecimal characters and a 40-character value containing `G`. Measure the reputation request journal before and after each call, require a `ParameterBindingException`, and require zero network requests.

Use this command metadata assertion:

```powershell
$parameter = (Get-Command Get-FileReputation).Parameters['Hash']
$pattern = @($parameter.Attributes | Where-Object { $_ -is [ValidatePattern] })[0]
$pattern.RegexPattern | Should -BeExactly '^[0-9A-Fa-f]{40}$'
```

- [ ] **Step 3: Prove the current public boundary tests are red**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Get-FileReputation.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: MD5 reaches VirusTotal and later fails at MalwareBazaar, SHA-256 behaves inconsistently by VirusTotal verdict, and the malformed SHA-1 is not rejected by `Get-FileReputation` itself.

- [ ] **Step 4: Narrow `Get-FileReputation` to SHA-1 before any provider call**

Change the public parameter to:

```powershell
[Parameter(Mandatory, ValueFromPipeline)]
[ValidatePattern('^[0-9A-Fa-f]{40}$')]
[string]$Hash
```

Update help to state that this is the EPM multi-provider cascade. Do not narrow the `Get-VtFileReport` parameter.

- [ ] **Step 5: Add red MalwareBazaar identity tests**

Mock `Invoke-MbRequest` with `QueryStatus = 'ok'` for:

1. one record whose `sha1` differs from the requested hash;
2. no record containing `sha1`;
3. two matching records;
4. exactly one matching record with a case variant.

Require `Unavailable` for the first three and `Malicious` only for the fourth. Require the detail to contain no unrelated hash or raw response.

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/MalwareBazaarConnection.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the mismatched, missing, and ambiguous cases fail because the current implementation accepts the first `ok` record without binding its SHA-1.

- [ ] **Step 6: Bind MalwareBazaar evidence to one matching record**

Replace first-record selection with:

```powershell
$matchingRecords = @($response.Data | Where-Object {
        $_.PSObject.Properties.Name -contains 'sha1' -and
        [string]::Equals([string]$_.sha1, $Hash,
            [System.StringComparison]::OrdinalIgnoreCase)
    })
if ($matchingRecords.Count -ne 1) {
    throw [System.IO.InvalidDataException]::new(
        'MalwareBazaar: response does not contain one unambiguous SHA-1 match.')
}
$record = $matchingRecords[0]
```

The existing catch converts the invalid response to `Unavailable`.

- [ ] **Step 7: Add a red EPM grouping case-identity test**

Mock `Get-EpmElevationEvent` to return two otherwise compatible records with hashes `('A' * 40)` and `('a' * 40)`, different users, and different endpoints. Require one output group with `EventCount = 2`, `DistinctUserCount = 2`, and `ComputerCount = 2`.

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path tests/contract/Get-EpmElevationSummary.Tests.ps1 -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -eq "Passed") { exit 1 }'
```

Expected: the new test fails with two groups because the baseline grouping key preserves hash casing.

- [ ] **Step 8: Normalize only the grouping hash identity**

Build the binary component as:

```powershell
$normalizedHash = ([string]$eventRecord.Hash).ToUpperInvariant()
$groupingKey = "$($eventRecord.Publisher)$([char]0x1F)$normalizedHash"
```

Store `Hash = $normalizedHash` in new binary groups so output and later reputation lookups are deterministic. Apply the same normalization to the `GroupBy User` distinct-binary key. Do not change publisher casing in this task.

- [ ] **Step 9: Add a mismatched VirusTotal alias fixture and red cascade test**

Add a synthetic 40-character lookup hash `('4' * 38) + '11'` to the mock. Return a valid SHA-256 but a different valid SHA-1 alias. Make MalwareBazaar report malicious so the cascade reaches the malicious stage. Assert that Hybrid Analysis may use the EPM SHA-1 but ThreatFox is never queried because the SHA-256 pivot is not bound to the requested SHA-1.

- [ ] **Step 10: Prove the canonical identity mutation is now killed**

In a disposable worktree, replace the first condition of `$validatedCanonicalSha256` with `$true`, run the new mismatched-alias test, and require it to fail because ThreatFox was queried. Restore and prove the worktree is clean.

- [ ] **Step 11: Run all identity, grouping, cache, and provider tests**

```bash
pwsh -NoProfile -Command '$r=Invoke-Pester -Path @("tests/contract/Get-FileReputation.Tests.ps1","tests/contract/MalwareBazaarConnection.Tests.ps1","tests/contract/Get-EpmElevationSummary.Tests.ps1","tests/contract/Get-EpmElevationSummary.Reputation.Tests.ps1","tests/contract/ReputationCache.Tests.ps1","tests/contract/ThreatFox.Tests.ps1") -PassThru -Output Detailed; "Result=$($r.Result) Passed=$($r.PassedCount)/$($r.TotalCount) ContainersFailed=$($r.FailedContainersCount)"; if ($r.Result -ne "Passed" -or $r.FailedContainersCount -ne 0) { exit 1 }'
```

- [ ] **Step 12: Reconcile documentation and commit**

Document the deliberate distinction between direct VirusTotal identifiers and the EPM SHA-1 cascade. Record MalwareBazaar response binding and case-normalized grouping as evidence-identity decisions.

```bash
git add src/EndpointOps/Public/Get-FileReputation.ps1 \
  src/EndpointOps/Private/Get-MbFileVerdict.ps1 \
  src/EndpointOps/Public/Get-EpmElevationSummary.ps1 \
  tests/mock/MockApiServer.ps1 \
  tests/contract/Get-FileReputation.Tests.ps1 \
  tests/contract/MalwareBazaarConnection.Tests.ps1 \
  tests/contract/Get-EpmElevationSummary.Tests.ps1 \
  tests/contract/ReputationCache.Tests.ps1 \
  docs/api-notes-reputation.md docs/decisions.md
git diff --cached --check
git commit -m "fix: enforce reputation hash identity"
```

Run the complete validation commands below and obtain separate compliance and security-quality reviews. Resolve all findings before publishing the task branch. Then:

```bash
git push -u origin fix/reputation-hash-identity
pr_url=$(gh pr create --repo mbart75/endpoint-ops \
  --title "fix: enforce reputation hash identity" \
  --body "Closes #$issue_number

Makes the EPM multi-provider cascade SHA-1-only, binds MalwareBazaar and VirusTotal pivots to the requested identity, and groups hash case variants deterministically.")
gh pr checks "$pr_url" --watch --required
gh pr merge "$pr_url" --merge --delete-branch
git switch main
git pull --ff-only origin main
```

Freshly validate the merge commit before Lot 10.

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
