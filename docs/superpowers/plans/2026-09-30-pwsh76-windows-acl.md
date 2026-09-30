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
- Pester selects no Windows cache test: `TotalCount - NotRunCount -eq 2` must be asserted after the recovery test was added (Task 2).
- Pester skips a Windows cache test: `SkippedCount -eq 0` and `PassedCount -eq 2` must be asserted (Task 2).
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
- Modify: `tests/unit/ReputationCacheFile.Tests.ps1` (the native run exposed inherited-ACL SDDL reification; test an explicit restrictive ACL and partial-failure recovery)
- If native CI reveals the existing ACL invariant is broken, minimally modify `src/EndpointOps/Private/Move-ReputationCacheFile.ps1` and document the verified cause in `docs/decisions.md`.

**Interfaces:** The Windows job uses `windows-2025`, `shell: pwsh`, PowerShell 7.6.x, Pester 6.0.1, and a `FullNameFilter` selecting exactly the existing ACL and new partial-failure recovery tests.

- [x] Add the Windows job with a runtime/OS gate before installing Pester.
- [x] Run the filtered ACL test on macOS with `Result`, `FailedContainersCount`, `TotalCount - NotRunCount`, `PassedCount`, and `SkippedCount` checks; confirm it fails because the test is skipped.
- [x] Validate workflow syntax and run the full local Pester suite plus PSScriptAnalyzer; commit this independently testable CI step.
- [x] Resolve the native Windows ACL failure shown by the PR check, then require a green rerun before claiming preservation. The recovery test first failed when an injected replacement failure moved the original to its backup; run 36750890976 then passed both native Windows tests.
- [x] Open the issue-linked PR; both Ubuntu and Windows CI jobs passed on run 36750890976.

## Final Review

- [x] Inspect the final diff for unrelated changes, secrets, and non-ASCII PowerShell files.
- [x] Confirm module exports still match `Public/` and `FunctionsToExport` (31 each).
- [x] Obtain independent review and report exact local and GitHub CI results.

The independent review found no blocking issue. A non-blocking follow-up is to inject restoration-denied through the entire writer path and assert warning plus protected backup retention; native byte-for-byte proof here covers a protected ACL, not every inherited-ACL layout.
