# Reputation-service API notes

This document compares public API characteristics relevant to optional reputation enrichment. It is an evidence record, not an endorsement of any service.

## Decision table

| Service | Public API | Hash lookup | URL lookup | Rate-limit position | Privacy implication | Selected |
|---|---|---:|---:|---|---|---:|
| VirusTotal | Yes | Yes | Yes | Four requests per minute on the public API | Hashes and reversible URL identifiers are disclosed to a third party | Yes |
| MalwareBazaar | Yes | Yes | No | Public quota and abuse controls apply | Hash disclosure | No |
| Hybrid Analysis | Yes | Yes | Yes | API key and quota required | Hash or URL disclosure | No |
| AlienVault OTX | Yes | Yes | Yes | API key and quota required | Hash or URL disclosure | No |

The module deliberately supports a single enrichment source. Adding multiple engines would increase API-key handling, outbound disclosure, failure modes, and contradictory verdict handling without changing the core rule: external reputation can only downgrade a proposal, never approve one.

## VirusTotal

Sources: [Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api), [file report](https://docs.virustotal.com/reference/file-info), and [URL report](https://docs.virustotal.com/reference/url-info).

- Endpoint: `https://www.virustotal.com/api/v3`.
- Authentication: `x-apikey: <API key>`.
- File report: `GET /files/{hash}` for MD5, SHA-1, or SHA-256. The module submits a hash only; it contains no file-upload path.
- URL report: `GET /urls/{id}`, where `id` is the URL encoded as base64url.
- Public quota: four requests per minute and 500 requests per day.

A hash with no report is `Unknown`, not clean. The module records four source-defined states: `Malicious`, `Clean`, `Unknown`, and `Unavailable`. A malicious result requires the configured minimum number of engines; a clean result never promotes an EPM elevation proposal.

## MalwareBazaar (abuse.ch)

Source: [MalwareBazaar API](https://bazaar.abuse.ch/api/).

MalwareBazaar can look up a file hash and is useful for malware-intelligence investigations. It does not provide the URL-reputation symmetry needed here and was not selected. Its use would still disclose a hash to an external service.

## Hybrid Analysis (Falcon Sandbox)

Source: [Falcon Sandbox API v2](https://www.hybrid-analysis.com/docs/api/v2).

Hybrid Analysis provides hash and URL capabilities, but adds API-key, quota, and service-specific verdict semantics. Supporting it alongside VirusTotal would require reconciliation logic rather than a simple second HTTP request. It is not selected.

## AlienVault OTX

Source: [OTX API](https://otx.alienvault.com/assets/static/external_api.html).

OTX supports reputation and threat-intelligence queries but has different coverage and response semantics. It is not selected because an additional source does not justify the added disclosure, key management, and conflicting-result complexity for this bounded workflow.

## Cost of multiplying sources

Multiple reputation sources do not create a reliable automatic verdict. They multiply outbound data sharing, credentials, quotas, transient failures, inconsistent categories, and the risk that a caller mistakes “more data” for authorization. The implementation keeps the safety boundary simple: enrichment is explicitly requested, one source is consulted, and no reputation response can create or elevate a proposed privilege rule.
