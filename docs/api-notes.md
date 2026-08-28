# API research notes

**Verification date:** 2026-07-24, with the VirusTotal update dated 2026-08-20 and Device Control update dated 2026-07-28.

**Purpose:** record what public sources support before implementation, distinguish confirmed behaviour from assumptions, and preserve the items that require real-tenant validation.

**Evidence key:** ✅ confirmed by a public source · ⚠️ plausible but requires tenant confirmation · ❌ cannot be verified without access.

## SentinelOne Management API

| Topic | Status | Notes |
|---|---|---|
| Base URL | ✅ | `https://<console-hostname>/web/api/v2.1`; each customer has its own console hostname. |
| Authentication | ✅ | `Authorization: ApiToken <token>`. |
| Agent collection | ✅ | `GET /web/api/v2.1/agents`. |
| Pagination | ✅ | Cursor based: responses contain `pagination.totalItems` and `pagination.nextCursor`; send the cursor as the next request’s `cursor` parameter. |
| Offset pagination | ✅ | `skip`/`limit` are deprecated from 2.1.2 and are not used. |
| Response shape | ✅ | `{ data: [...], pagination: { totalItems, nextCursor } }`. |
| Exclusions | ⚠️ | `/web/api/v2.1/exclusions` is implemented but not confirmed by official public documentation. |
| Device Control rules | ⚠️ | `/web/api/v2.1/restrictions` is implemented but not confirmed by official public documentation. |
| Move an agent to a group | ⚠️ | `POST /web/api/v2.1/agents/actions/move-to-group` with `{ agentIds, groupId }` is the only module write path and needs real-tenant validation. |

The mock server exercises both plausible terminal-page forms: a missing `pagination` property and `nextCursor: null`. This defensive handling is intentional; it is not evidence that either form is the product’s confirmed behaviour.

The module consumes agent fields including `id`, `computerName`, `osName`, `osRevision`, `isActive`, `isDecommissioned`, and `lastActiveDate`; exclusion fields including `id`, `type`, `value`, `description`, `scope`, `createdBy`, and `updatedBy`; and Device Control fields including `id`, `ruleName`, `action`, `matchBy`, `vendorId`, `productId`, `deviceClass`, and provenance properties. Defensive property access allows an absent optional field to degrade output instead of terminating the module.

## CyberArk EPM Web Services SDK

The detailed [EPM API notes](api-notes-epm.md) are the primary record. EPM authentication is a two-stage dispatcher flow: the dispatcher returns both a session token and `ManagerURL`; all later requests target that `ManagerURL`.

The first public API research noted a historical `Bearer`-token interpretation and uncertain pagination. Later official documentation research supersedes it for the implemented path: authentication uses `Authorization: basic <Token>`; EPM lists use `offset`/`limit`; and event APIs use `nextCursor`. The repository does not claim real-tenant validation.

## VirusTotal API v3

| Topic | Status | Notes |
|---|---|---|
| Base URL | ✅ | `https://www.virustotal.com/api/v3`. |
| Authentication | ✅ | `x-apikey: <API key>`; the key stays in memory for the active VirusTotal session. |
| File report | ✅ | `GET /files/{hash}`; MD5, SHA-1, and SHA-256 hashes are accepted. The module never uploads a file. |
| URL report | ✅ | `GET /urls/{id}`; `id` is the URL’s base64url form. |
| Public quota | ✅ | Four requests per minute and 500 requests per day. |
| Unknown hashes | ⚠️ | Documentation shows 400 while common practice reports 404. Both are handled as `Unknown`, never as safe. |

Reputation enrichment is opt-in. A hash lookup discloses that a hash was observed; a base64url URL identifier is reversible and therefore discloses the URL itself. The in-memory counter paces the current process only and does not claim cross-process or daily accounting accuracy.

## Device Control research for W4.7

### Device Control events

The Device Control event collection is publicly described as Windows and macOS Device Control events. It supports `agentIds`, `groupIds`, `siteIds`, event-time filters, `cursor`, `limit`, `skip`, `deviceClasses`, `vendorIds`, `productIds`, `interfaces`, `countOnly`, and `skipCount`.

`countOnly` makes “was any device connected?” a count request rather than a full pagination walk. Its exact response shape is not documented. The mock contract assumes an empty `data` array and a count in `pagination.totalItems`; `Get-S1DeviceControlEvent -CountOnly` refuses missing or non-numeric counts rather than silently returning zero.

Device Control requires the Control SKU and does not support Linux. Because SKU availability is not in agent data, `Get-S1UnusedAuthorizationReport` requires `-ControlSkuAvailable`. Without it, potentially permissive agents are classified `OutOfScope` and no Device Control event query runs.

### Group-membership history

Third-party sources corroborate an activities endpoint, but no public source maps activity-type numbers to “agent moved between groups.” The code therefore does not invent that mapping. A real tenant or authenticated API Hub documentation is required before using that signal.

### Retention is an input

SentinelOne retention varies by subscribed SKU. An absence of events beyond the retention window is not evidence of non-use. The report therefore requires a retention input and distinguishes: no observed use within a reliable window, an indeterminate window longer than retention, and an endpoint outside Device Control scope. `AlertAfterDays` must remain strictly lower than `RemoveAfterDays`.

## Sources

- [SentinelOne Management API, OpenAPI](https://apis.io/apis/sentinelone/management-api/)
- [SentinelOne Device Control Events, Postman collection](https://www.postman.com/api-evangelist/sentinelone/request/l9g5krz/get-device-control-events)
- [SentinelOne logs, Panther](https://docs.panther.com/data-onboarding/supported-logs/sentinel-one)
- [SentinelOne v2 integration, Cortex XSOAR](https://xsoar.pan.dev/docs/reference/integrations/sentinel-one-v2)
- [SentinelOne integration, Elastic](https://www.elastic.co/docs/reference/integrations/sentinel_one)
- [CyberArk EPM web services](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm)
- [CyberArk EPM server authentication](https://docs.cyberark.com/epm/latest/en/content/webservices/serverauthentication.htm)
- [CyberArk EPM policy APIs](https://docs.cyberark.com/epm/latest/en/content/webservices/policyapis.htm)
