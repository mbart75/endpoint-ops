# PowerShell 7.6 and Windows ACL CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce a supported PowerShell 7.6 LTS baseline and prove the existing cache ACL preservation test on native Windows CI.

**Architecture:** Keep the current Ubuntu validation pipeline intact, but make its runtime version explicit. Add a separate Windows job that runs the existing ACL test and fails if it is skipped or not selected. The module manifest, source/test requirements, and README must agree on the new floor; no product behavior or tenant integration changes.

**Tech Stack:** PowerShell 7.6 LTS, Pester 6.0.1, GitHub Actions, PSScriptAnalyzer 1.25.0.

**Spec:** [GitHub issue #39](https://github.com/mbart75/endpoint-ops/issues/39).

## Global Constraints

- Minimum documented and enforced PowerShell version: 7.6 LTS.
- CI must assert the actual `pwsh` major/minor version; a runner label alone is not evidence.
- Windows ACL assurance requires the native Windows test to run, not be skipped.
- Keep synthetic fixtures and product behavior unchanged; do not use a real tenant or credential.
- A Pester pass requires `Result -eq 'Passed'` and `FailedContainersCount -eq 0`.

## Review Focus

- A runner silently downgrades `pwsh`: version gate must fail before test/tool installation (Task 1).
- A Windows-labelled job runs a non-Windows shell: explicit `$IsWindows` gate must fail (Task 2).
- Pester selects no ACL test: `TotalCount - NotRunCount -eq 1` must be asserted (Task 2).
- Pester skips the ACL test: `SkippedCount -eq 0` and `PassedCount -eq 1` must be asserted (Task 2).
- Windows ACL assertion fails in practice: PR CI is the required native execution proof; do not claim local macOS validation covers it (Task 2).

---

### Task 1: Raise and enforce the PowerShell support floor

**Files:**
- Modify: `tests/unit/Module.Tests.ps1` (manifest floor test)
- Modify: `src/EndpointOps/EndpointOps.psd1`, `src/EndpointOps/EndpointOps.psm1` (module floor)
- Modify: existing `#Requires -Version 7.2` files under `tests/` (consistent test floor)
- Modify: `.github/workflows/ci.yml` (Ubuntu runtime assertion)
- Modify: `README.md` and the obsolete 7.2 explanation in `src/EndpointOps/Private/Write-ReputationCacheFile.ps1`

**Interfaces:** The manifest property `PowerShellVersion` is the declared minimum; the CI gate reads `$PSVersionTable.PSVersion` and accepts major 7, minor 6 only for the validated baseline.

- [x] Add a unit assertion that the imported manifest declares `PowerShellVersion = '7.6'`.
- [x] Run that test against the current manifest and observe a failure on `7.2`.
- [x] Update the manifest and all existing `#Requires -Version 7.2` directives to `7.6`; update README and the obsolete source comment without changing cache logic.
- [x] Add an Ubuntu CI gate before tooling that prints and asserts actual PowerShell 7.6.x; show it rejects a deliberately wrong expected minor version locally.
- [x] Run the unit test, then all local Pester tests and PSScriptAnalyzer; commit the scoped changes.

### Task 2: Exercise the Windows ACL test natively

**Files:**
- Modify: `.github/workflows/ci.yml` (separate Windows ACL job)
- Modify: `README.md` (describe native Windows CI evidence)
- Reuse unchanged: `tests/unit/ReputationCacheFile.Tests.ps1` (existing ACL test)

**Interfaces:** The Windows job uses `windows-2025`, `shell: pwsh`, PowerShell 7.6.x, Pester 6.0.1, and a `FullNameFilter` selecting exactly the existing ACL test.

- [x] Add the Windows job with a runtime/OS gate before installing Pester.
- [x] Run the filtered ACL test on macOS with `Result`, `FailedContainersCount`, `TotalCount - NotRunCount`, `PassedCount`, and `SkippedCount` checks; confirm it fails because the test is skipped.
- [x] Validate workflow syntax and run the full local Pester suite plus PSScriptAnalyzer; commit this independently testable CI step.
- [ ] Open the issue-linked PR; require both Ubuntu and Windows CI jobs to pass before claiming native ACL evidence.

## Final Review

- [ ] Inspect the final diff for unrelated changes, secrets, and non-ASCII PowerShell files.
- [ ] Confirm module exports still match `Public/` and `FunctionsToExport`.
- [ ] Obtain independent review and report exact local and GitHub CI results.
