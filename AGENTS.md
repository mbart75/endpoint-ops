# AGENTS.md

Briefing for coding agents (Codex, Claude Code, and others) and human contributors. `CLAUDE.md` is a symbolic link to this file: edit `AGENTS.md` only.

## What this repository is

`EndpointOps` is a PowerShell 7.6 module that reads documented SentinelOne, CyberArk EPM, VirusTotal, MalwareBazaar, Hybrid Analysis, and ThreatFox APIs and turns the responses into explainable review findings. Start with [README.md](README.md) for the user view and [docs/decisions.md](docs/decisions.md) for the reasons behind non-obvious choices.

**Validation boundary.** Everything is implemented from public documentation and tested only against the local mock server. Never describe a contract as validated against a real tenant or provider account, never invent an undocumented schema, and never add tenant data, tenant addresses, tokens, or production credentials. Work that needs real-service evidence stays blocked until that evidence exists.

## Layout

```
src/EndpointOps/EndpointOps.psd1   Module manifest; FunctionsToExport must match Public/ exactly
src/EndpointOps/EndpointOps.psm1   Loader (StrictMode 3.0); dot-sources Private/ then Public/
src/EndpointOps/Public/            One exported command per file, flat, file name = command name
src/EndpointOps/Private/           Helpers, product request wrappers, cache internals
tests/unit|contract|security/      Pester 6 suites
tests/mock/MockApiServer.ps1       Local HttpListener mock of every product API
docs/decisions.md                  Numbered design decisions (append, never renumber)
docs/api-notes*.md                 API research with sources
docs/superpowers/                  Versioned specs and plans of past work cycles
```

Four layers, each calling only the one below: workflows (`Get-*Report`, `Invoke-S1FleetRemediation`) → product queries (`Get-S1*`, `Get-Epm*`, `Get-Vt*`, `Get-FileReputation`) → connections (`Connect-*`/`Disconnect-*`) → transport (`Invoke-EndpointOpsRequest`). Product queries return observations; scoring and judgment live in workflows.

## Commands

Use the versions CI pins: PowerShell 7.6.x, Pester 6.0.1, PSScriptAnalyzer 1.25.0.

```bash
pwsh -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./tests -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"
pwsh -NoProfile -Command "Test-ModuleManifest ./src/EndpointOps/EndpointOps.psd1"
gitleaks git .
```

On macOS and Linux three Windows-only ACL tests are skipped. A local skip is not a Windows result: only the `windows-acl` CI job proves that path.

## Rules that are not obvious from the code

- **Credentials.** Tokens and API keys stay in `SecureString` in memory, are converted to plaintext only to build an authorization header, and are never written to disk, logs, verbose or debug output, or error messages. Do not retain raw HTTP responses, headers, bodies, or inner exceptions to recover a status code: use `Get-HttpStatusFromError`. Security tests assert at the output sinks; keep them that way.
- **Evidence semantics.** Absence of data is not absence of usage, `Unknown` is never safe, and reputation can only weaken or reject an EPM proposal, never authorize one.
- **Writes.** `Invoke-S1FleetRemediation` is the only remote write command and only moves endpoints to a tracking group. Anything that writes uses `SupportsShouldProcess` and honours `-WhatIf` without skipping connection validation.
- **Public surface.** Adding or removing a file in `Public/` requires the same change in `FunctionsToExport`; `tests/unit/Module.Tests.ps1` enforces it.
- **Tests first.** A fix starts with a test that fails for the right reason. Prefer the mock server over function mocks for anything that crosses HTTP. Control time through the private clock helpers rather than waiting for the wall clock.
- **Decisions.** A non-obvious trade-off gets a new numbered entry in `docs/decisions.md`.

## Git and pull requests

- `main` is protected: changes land through a pull request, and the `validate` (Linux) and `windows-acl` (Windows) checks must pass on an up-to-date branch. There is no bypass.
- Commit messages are in English and follow `type(scope): summary` (`feat`, `fix`, `test`, `docs`, `ci`, `chore`).
- To mention an issue without closing it, write `Related to #N`. A closing keyword (`fixes`, `closes`, `resolves`) in front of an issue number closes it on merge, even inside a negative sentence.
- Issues #11 and #12 are blocked on authorized real-tenant evidence. Do not work around them with assumed schemas.

## Local architecture graph (optional)

A [Graphify](https://pypi.org/project/graphifyy/) knowledge graph helps navigate the code without rereading it. It is local only: `graphify-out/` is ignored and must never be committed (see decision 62).

```bash
graphify update .                                      # build or refresh the code graph, no LLM, a few seconds
graphify query "how are HTTP statuses exposed?"        # breadth-first answer with source files
graphify explain "Invoke-EndpointOpsRequest"           # a node and its neighbours
graphify god-nodes --top 10                            # most connected components
```

Read `graphify-out/GRAPH_REPORT.md` for an overview. The graph is a map, not evidence: confirm every claim in the source before acting on it, and refresh it after pulling changes. Saved query results in `graphify-out/memory/` are fed back into the graph on the next update, so never save secrets or tenant data there.
