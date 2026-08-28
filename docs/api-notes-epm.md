# CyberArk EPM API notes

Research date: 2026-07-27. This document is based on public documentation from `docs.cyberark.com`, without real-tenant access.

**Source status:** each confirmed statement is tied to public vendor documentation. Public documentation describes paths and field names, but does not prove every edge-case response shape. Ambiguities remain explicit and require real-tenant validation.

## 1. Authentication: the dispatcher model

Source: [EPM authentication](https://docs.cyberark.com/epm/latest/en/content/webservices/serverauthentication.htm)

```
POST https://<dispatcher>/EPM/API/<Version>/Auth/EPM/Logon
Content-Type: application/json
```

The body requires `Username`, `Password`, and `ApplicationID`. `ApplicationID` is an arbitrary caller-selected identifier, such as `EndpointOps`.

| Response field | Meaning |
|---|---|
| `EPMAuthenticationResult` | Base64-encoded session token |
| `ManagerURL` | **EPM server URL for every subsequent request** |
| `IsPasswordExpired` | Boolean |

The structural point is the dispatcher: authenticate against it, then send all subsequent calls to the returned `ManagerURL`, not the dispatcher. Authentication uses `Authorization: basic <Token>`; this is the returned token value, not HTTP Basic user/password construction.

Regional dispatchers are documented at [Automate tasks with EPM web services](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm), including `login.epm.cyberark.com/login`, regional prefixes, and `login.epm.cyberarkgov.cloud/login`.

There is no fixed token lifetime. It depends on the tenant’s “Timeout for inactive session” setting. A 401 must therefore be treated as an expected reconnect condition, not as proof of a code defect. The documentation allows only one API login per minute per user, so blind automatic retry of a login can fail.

## 2. URL versioning

Source: [Automate tasks with EPM web services](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm)

A version segment is optional, for example `/EPM/API/23.6.0.1/Sets/...`. When omitted, the latest version applies; the documentation recommends omitting it. The module constructs unversioned URLs while preserving a way to force a version if necessary.

## 3. Pagination

EPM uses two distinct pagination mechanisms.

### Numeric offset: `offset` / `limit`

Used for sets and policies. Source: [Get sets list](https://docs.cyberark.com/epm/latest/en/content/webservices/getsetslist.htm).

`limit` is 1–1000 with a default of 50; `offset` begins at 0. The documentation explicitly requires `offset` to be a whole-number multiple of `limit`. Increment offsets by `limit`; arbitrary increments can be rejected.

### Opaque cursor: `nextCursor`

Used for events. Source: [Get policy audit raw event details](https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicyauditraweventdetails.htm).

- The first request is `?nextCursor=start&limit=100`; `start` is literal.
- `nextCursor` is returned only when supplied as input. Omitting it caps results at 1000 records.
- The documentation says the final cursor is an empty string, while its example shows `"nextCursor": null`. The mock server covers both; the code treats both as terminal. This is defensive compatibility, not resolved vendor behaviour.

## 4. Sets

Source: [Get sets list](https://docs.cyberark.com/epm/latest/en/content/webservices/getsetslist.htm)

```
GET https://<ManagerURL>/EPM/API/Sets?offset=<n>&limit=<n>
```

The response contains `SetsCount` and `Sets[]`. The JSON example uses `Id`, `Name`, `Description`, and `IsNPVDI`, while the descriptive table calls them `SetId`, `SetName`, and `SetDescription`. The module reads defensively because public documentation is internally inconsistent; a real response is needed to resolve the canonical names.

## 5. Application policies

### List policies

Source: [Get policies](https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicies.htm)

```
POST https://<ManagerURL>/EPM/API/Sets/<SetId>/Policies/Server/Search?limit=&offset=&sortBy=&sortDir=
```

This is a read performed with POST. The body carries a filter such as `{"filter": "..."}`, using EPM’s query language (`CONTAINS`, `EQ`, `IN`, and `AND`). Responses provide `Policies[]`, `ActiveCount`, `TotalCount`, and `FilteredCount`; list entries do not include `Description` or policy-author identity.

### Policy details

Sources: [Get policy details](https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicydetails.htm) and [Application policy](https://docs.cyberark.com/epm/latest/en/content/webservices/applicationpolicydefinitions.htm).

```
GET https://<ManagerURL>/EPM/API/Sets/<SetId>/Policies/Server/<PolicyId>
```

`Description` exists only in the detail response, is optional, and has a 2048-character maximum. A policy-hygiene review consequently needs one detail request per policy. Policy APIs are limited to 30 calls per minute; 200 policies take more than six minutes of pacing before other work. The implementation surfaces progress rather than presenting the wait as a hang.

## 6. Elevation events

Sources: [Get detailed raw events](https://docs.cyberark.com/epm/latest/en/content/webservices/getdetailedrawevents.htm) and [Get policy audit raw event details](https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicyauditraweventdetails.htm).

```
POST https://<ManagerURL>/EPM/API/Sets/<setId>/Events/Search
POST https://<ManagerURL>/EPM/API/Sets/<setId>/policyaudits/search
```

Both use filtered POST requests with cursor pagination. Confirmed useful fields include `hash` (SHA-1), `publisher`, `userName`, `userIsAdmin`, `computerName`, `agentId`, `fileName`, `filePath`, `fileDescription`, `productName`, `company`, `firstEventDate`, `lastEventDate`, `arrivalTime`, `policyName`, and `policyAction`.

## 7. Status handling and rate limiting

Source: [Automate tasks with EPM web services](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm).

The public documentation documents 30 API calls per minute for policy APIs but does not document an EPM equivalent of SentinelOne’s `Retry-After` behaviour. The module paces policy-detail calls proactively using `-MinIntervalMs` instead of relying on post-failure recovery. A 401 is detected as expired-session guidance; the current shared transport’s string-based error signalling is a known technical debt recorded in [technical decisions](decisions.md).

## 8. Hashes and download URLs

EPM documentation confirms only SHA-1 for event and raw-file hash fields:

| Source | Field | Documented meaning |
|---|---|---|
| [Policy audit raw event details](https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicyauditraweventdetails.htm) | `hash` | SHA-1 hash of the application that triggered the event |
| [Raw file details](https://docs.cyberark.com/epm/latest/en/content/webservices/getrawfiledetails.htm) | `hash` | SHA-1 hash of the application file |

A download URL is not guaranteed for every event. Treat it as optional and do not reject an event because it has no URL. `sourceType` is a useful provenance discriminator, but event values and raw-file-instance values differ; normalise them explicitly rather than assuming a common enumeration. Email and removable-media origins warrant the same review attention as downloaded binaries.

The SHA-1-only EPM event contract constrains complementary reputation coverage:

- A provider that does not accept SHA-1 cannot cover EPM events directly.
- ThreatFox is queried only when a VirusTotal match supplies the file's SHA-256.
- That pivot does not close the blind spot when VirusTotal does not know the EPM SHA-1.
- MalwareBazaar remains the complementary service for that blind spot because it accepts SHA-1.

These consequences follow from the public field documentation and the local mock contract; they do not claim that a real tenant confirmed every field shape.

## 9. Items not confirmed by public documentation

| Question | Status |
|---|---|
| Who created or modified a policy? | Not exposed. `Get policies` gives dates but no identity; `policyaudits` returns application events, not administration history. |
| Exact difference between `/Events/Search` and `/policyaudits/search` | Not explained. |
| Actual set field names: `Id` or `SetId` | Public-documentation contradiction. |
| Set identifier type | Not stated. |
| Terminal cursor form: `""` or `null` | Public-documentation contradiction. |
| Empty-list response shape | Not documented. |
| Behaviour after quota exhaustion | No status code or response header documented. |

EPM reporting must not fabricate accountability. When no policy author can be identified from the API, the report explicitly says that contact information is unavailable through the EPM API instead of leaving a misleading blank field.
