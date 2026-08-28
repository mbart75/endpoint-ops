# Reputation-service API notes

This document compares public API characteristics relevant to optional reputation enrichment. It records the contracts implemented by the module and their validation limits; it is not an endorsement of any service.

## Decision table

| Service | Hash support used here | URL lookup | Rate-limit position | Privacy implication | Selected |
|---|---|---:|---|---|---:|
| VirusTotal | MD5, SHA-1, SHA-256 | Yes | Public API: four requests per minute and 500 per day | Hashes and reversible URL identifiers are disclosed | Yes |
| MalwareBazaar | SHA-1 accepted | No | Public quota and abuse controls apply | Hash disclosure | Yes |
| Hybrid Analysis | Hash search | Not used | API key required; quota metadata is treated as opaque and may be absent | Hash disclosure | Yes, for third-stage context |
| ThreatFox | No direct SHA-1 path in this workflow | No | Shared abuse.ch authentication; no quota semantics are inferred | VirusTotal-derived SHA-256 disclosure | Yes, only through the SHA-256 pivot |
| AlienVault OTX | Hash and URL capabilities | Yes | API key and service quota apply | Hash or URL disclosure | No |

## Cascade and reconciliation

`Get-FileReputation` always queries VirusTotal first. A `Clean` VirusTotal result stops the cascade. A `Malicious`, `Unknown`, or `Unavailable` result continues to MalwareBazaar. Hybrid Analysis is queried only after the aggregate contains malicious evidence; ThreatFox is queried at that stage only when VirusTotal returned a valid SHA-256 pivot.

Sources add evidence, not votes. Any malicious evidence makes the aggregate `Malicious`; no `Clean`, `Unknown`, or `Unavailable` response can erase it, authorize software, or promote an elevation proposal. Absence has source-specific meaning and must not be presented as clean.

## VirusTotal

Sources: [Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api), [file report](https://docs.virustotal.com/reference/file-info), and [URL report](https://docs.virustotal.com/reference/url-info).

- Endpoint: `https://www.virustotal.com/api/v3`.
- Authentication: `x-apikey: <API key>`.
- File report: `GET /files/{hash}` for MD5, SHA-1, or SHA-256. The module submits a hash only and has no file-upload path.
- URL report: `GET /urls/{id}`, where `id` is the URL encoded as base64url.
- Public quota: four requests per minute and 500 requests per day.

A missing report is `Unknown`, not clean. A malicious file verdict requires the configured minimum number of malicious engines. For a matched EPM SHA-1, the returned SHA-256 may become the ThreatFox pivot.

## MalwareBazaar (abuse.ch)

Source: [MalwareBazaar API](https://bazaar.abuse.ch/api/).

- Request: `POST /api/v1/`.
- Authentication: exact `Auth-Key` header.
- Body: `application/x-www-form-urlencoded` with `query=get_info&hash=<hash>`.
- Absence: HTTP 200 with `query_status=hash_not_found`.

The service accepts the SHA-1 exposed by EPM. A matching record is malicious evidence; `hash_not_found` means absence from this source, not `Clean`.

## Hybrid Analysis (Falcon Sandbox)

Source: [Falcon Sandbox API v2](https://www.hybrid-analysis.com/docs/api/v2).

- Request: `GET /api/v2/search/hash` with the hash query parameter.
- Authentication: exact `api-key` header.
- Hash search supports the documented MD5, SHA-1, and SHA-256 forms.
- Quota headers are preserved as opaque provider data and may be absent. The module does not invent quota semantics or a public quota value.

Hybrid Analysis is a third-stage source: it adds sandbox context after malicious evidence already exists. A missing report remains `Unknown`.

## ThreatFox (abuse.ch)

- Mocked request contract: `POST /api/v1/`.
- Authentication: the shared abuse.ch `Auth-Key`.
- Body: JSON with `query=search_hash` and the VirusTotal-derived SHA-256.
- Provenance: the EPM SHA-1 is never silently relabelled as SHA-256; the source result records the pivot hash and VirusTotal provenance.

**Validation boundary:** the ThreatFox route and absence-status contract are exercised only by the local mock server. They were not attested against a real ThreatFox service during this implementation and require real-service confirmation before operational use.

## AlienVault OTX

Source: [OTX API](https://otx.alienvault.com/assets/static/external_api.html).

OTX offers reputation and threat-intelligence queries but is not selected for this bounded workflow. Adding another source would expand disclosure, credential handling, and failure semantics without closing the documented SHA-1 coverage gap more directly than MalwareBazaar.

## Cost and safety boundary

Multiple providers add outbound disclosure, credentials, rate limits, transient failures, and different silence semantics. Every queried provider learns a hash; ThreatFox receives the VirusTotal-derived SHA-256. No provider receives file contents.

Enrichment and persistent caching are opt-in. A malicious match may only reject or weaken a proposal. Missing evidence, provider failure, and clean evidence never create or strengthen an authorization.
