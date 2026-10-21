# Security policy

## Supported versions

Only the latest commit on `main` is supported. There are no maintained release branches.

## Reporting a vulnerability

Please do not open a public issue, discussion, or pull request for a suspected vulnerability.

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability reporting). Include the affected file or command, the impact, and the smallest reproduction you can share. Use placeholder values: never send real tokens, API keys, tenant addresses, or tenant data.

This is a personal project maintained on a best-effort basis. You should receive an acknowledgement within 7 days. Confirmed issues are fixed on `main` and disclosed through a GitHub security advisory once a fix is available, with credit if you want it.

## Scope

In scope:

- credential handling: token or API key exposure in output, errors, logs, files, or memory longer than needed;
- the reputation cache: file permissions, integrity, and evidence provenance;
- the HTTP transport: TLS enforcement, redirects, retry and pagination bounds;
- the remediation command and anything that bypasses `-WhatIf` or confirmation;
- the CI workflows and their supply chain.

Out of scope:

- vulnerabilities in SentinelOne, CyberArk EPM, VirusTotal, MalwareBazaar, Hybrid Analysis, or ThreatFox themselves; report those to the vendor;
- differences between the mocked contracts and a real tenant; the [README](README.md) states that the integrations are tested only against a local mock server. These are welcome as regular issues when they contain no sensitive data.
