# Device Control rule-usage inventory roadmap

**Status:** design only; no rule-level correlation is implemented.

**Evidence access date:** 2026-08-30.

**Validation boundary:** this roadmap uses public product material, public API mirrors, third-party integration schemas, and the repository's synthetic tests. It has not been validated against a SentinelOne tenant. No production data or credential was used.

## Outcome

Add a rule-centric, read-only view over Device Control activity collected across eligible endpoints. The view should turn a noisy tenant-wide event stream into evidence that reviewers can sort by rule, device identifiers, endpoint, scope, date, and outcome.

This capability is additive. It does not replace or change either existing workflow:

| Existing workflow | Current question | Preserved boundary |
|---|---|---|
| `Get-S1DeviceControlRiskReport` | Is a rule structurally broad or risky? | Scores rule breadth without claiming that the rule was used. |
| `Get-S1UnusedAuthorizationReport` | Did an eligible endpoint in a caller-selected permissive group produce any Device Control event during a reliable window? | Remains a machine/group-level report. It does not identify the rule responsible for an event. |

The proposed inventory asks a different question: **which individual rules have qualifying observed usage, and what evidence supports that conclusion?**

## Operational scenario

A project may authorize smartphones or other USB devices by VID/PID, serial identifier, or a broader criterion. If a rule is later removed, inconsistent naming or incomplete ticket references can make the affected population difficult to reconstruct. The need may become visible only when endpoints produce blocked-device events or users open new support tickets.

The design therefore covers two related review needs:

1. measure observed use of rules that are currently active;
2. retain enough read-only rule history to interpret blocked demand after a rule disappears.

A blocked event is evidence of demand or impact. It is not proof that an active allow rule was used.

## Evidence confidence

| Label | Meaning |
|---|---|
| **Official** | Supported by SentinelOne-owned public product material. |
| **Secondary** | Described by a public API mirror or integration, but not guaranteed by SentinelOne-owned API documentation. |
| **Inferred** | A proposed relationship derived from documented fields; tenant validation is still required. |
| **Unverified** | No adequate public evidence was found. The implementation must not assume the behaviour. |

## Evidence table

| Topic | Public evidence | Confidence | Design consequence |
|---|---|---|---|
| Rule criteria and scope | [SentinelOne](https://www.sentinelone.com/blog/feature-spotlight-enhanced-usb-bluetooth-device-control/) describes USB rules using Vendor ID, Class, Serial ID, and Product ID, with Enterprise, Site, or Group scope and allow/read-only/block actions. | Official | Preserve rule identity, match criteria, action, and scope in each snapshot. |
| Allowed and blocked activity | [SentinelOne](https://www.sentinelone.com/blog/feature-spotlight-device-control/) states that administrators can configure approved and blocked devices to be reported to Activity logs. | Official | Logging coverage is a prerequisite. Do not treat the absence of events as non-use until allowed-device reporting is established. |
| Events endpoint | A [public Postman mirror](https://www.postman.com/api-evangelist/sentinelone/request/l9g5krz/get-device-control-events) describes `GET /web/api/v2.1/device-control/events` for eligible Windows and macOS agents with a Control subscription. | Secondary | Keep the implemented endpoint behind the repository's mock-backed validation boundary. Confirm it against an authorized tenant before claiming compatibility. |
| Event filters | The [public Postman mirror](https://www.postman.com/api-evangelist/sentinelone/request/l9g5krz/get-device-control-events) lists time, agent, site, group, interface, vendor, product, class, event-type, permission, cursor, and count filters. | Secondary | Prefer bounded windows and server-side narrowing where confirmed. Preserve client-side sorting for review fields not supported by the service. |
| Pagination | The [public Postman mirror](https://www.postman.com/api-evangelist/sentinelone/request/l9g5krz/get-device-control-events) documents offsets up to 1,000 and cursor pagination beyond that point. | Secondary | A tenant-wide collector must walk cursors and detect incomplete or repeated pagination. It must not rely on offset-only retrieval. |
| Rules endpoint | A [public Postman mirror](https://www.postman.com/api-evangelist/sentinelone/request/wo0p1wr/get-device-rules) describes rule listing under `GET /web/api/v2.1/device-control`. The current module uses the unconfirmed `/web/api/v2.1/restrictions` path. | Secondary and conflicting | Do not silently replace the current path. Resolve the endpoint and response contract through a sanctioned schema-validation task. |
| Event rule-identity field | The [Splunk SOAR connector schema](https://github.com/splunk-soar-connectors/sentinelone/blob/main/README.md) exposes an event `ruleId` alongside endpoint, time, and device fields. Permission is documented separately as a Postman event filter, not as a field in this schema. | Secondary | Field presence in a third-party integration does not establish its meaning or availability in the target console version. |
| Direct rule/event join | Matching a tenant-validated `event.ruleId` to `rule.id` is the preferred proposed relationship. | Inferred | The join cannot become a production contract until both identifiers and their semantics are confirmed. |
| Device serial in events | [Official material](https://www.sentinelone.com/blog/feature-spotlight-enhanced-usb-bluetooth-device-control/) documents Serial ID as a rule criterion. The [Splunk schema](https://github.com/splunk-soar-connectors/sentinelone/blob/main/README.md) exposes `uId`, but does not authoritatively define it as the serial number. | Unverified | Never relabel `uId` or another device identifier as a serial number without schema evidence. |
| Device Control event retention | [Public retention material](https://www.sentinelone.com/resources/datasheets/data-retention-solution-brief/) does not establish the retention or purge semantics of the Device Control Events endpoint. | Unverified | Require an explicit effective retention boundary and its provenance. A requested window that reaches or exceeds retention cannot support `NoObservedUsage`. |
| Rule precedence and historical scope | No adequate public source establishes how inherited rules, precedence, or historical group membership map to an event. | Unverified | A VID/PID match alone is not authoritative rule attribution. Historical scope and precedence must remain explicit unknowns. |

### Sources

- [SentinelOne: Enhanced USB and Bluetooth Device Control](https://www.sentinelone.com/blog/feature-spotlight-enhanced-usb-bluetooth-device-control/)
- [SentinelOne: Device Control](https://www.sentinelone.com/blog/feature-spotlight-device-control/)
- [SentinelOne: Singularity Control](https://www.sentinelone.com/platform/singularity-control/)
- [SentinelOne: Data Retention solution brief](https://www.sentinelone.com/resources/datasheets/data-retention-solution-brief/)
- [Public Postman mirror: Device Control events](https://www.postman.com/api-evangelist/sentinelone/request/l9g5krz/get-device-control-events)
- [Public Postman mirror: Device rules](https://www.postman.com/api-evangelist/sentinelone/request/wo0p1wr/get-device-rules)
- [Splunk SOAR SentinelOne connector schema](https://github.com/splunk-soar-connectors/sentinelone/blob/main/README.md)

## Proposed traceability model

The future workflow should preserve three independently reviewable records:

```text
Versioned rule snapshot     Device Control event             Review record
-----------------------     --------------------             -------------
Rule identity        <----  confirmed RuleId          ---->  correlation method
configuration hash          device identifiers               coverage and confidence
action and scope            endpoint and event time           observation window
observed interval           allowed/blocked outcome           separate usage/demand evidence
lifecycle evidence                                           rationale and next action
```

A versioned rule snapshot prevents a rule that is no longer observed from disappearing from later analysis. Each configuration hash has an observed interval; an event can be aligned with that version only when the event time falls inside a gap-free interval. A complete inventory can establish only that a previously visible rule is `NoLongerObserved`. `ConfirmedDeleted` requires an authoritative deletion state or activity whose semantics have been validated. Snapshots are evidence, not backups that the module may restore.

### Correlation levels

1. **Direct:** a tenant-validated event rule identifier matches a snapshot rule identifier.
2. **Candidate:** device identifiers and scope appear compatible, but direct rule identity is absent. This is useful for investigation, not sufficient for `ObservedUsage`.
3. **Unresolved:** identifiers, scope history, temporal alignment, precedence, or schema are insufficient. The evidence remains unevaluated rather than being promoted to usage.

## Proposed review record

The names below define the module-owned output contract proposed for future implementation. They do not claim to be vendor response fields.

| Field | Purpose |
|---|---|
| `RuleId`, `RuleName` | Stable authorization identity and reviewer-facing label. |
| `RuleVersionHash`, `ObservedFrom`, `ObservedUntil` | Versioned configuration and the gap-free interval in which it was observed. |
| `LifecycleState`, `LastSeenInInventoryAt` | `Current` or `NoLongerObserved` inventory evidence. Absence from a complete inventory does not by itself prove deletion. |
| `DeletionObservedAt`, `LifecycleEvidenceSource` | Optional `ConfirmedDeleted` evidence, populated only from an authoritative deletion state or activity with validated semantics. |
| `Action`, `MatchBy`, `VendorId`, `ProductId`, `SerialId` | Normalized rule intent and device criteria when available. |
| `ScopeLevel`, `ScopeId`, `ScopeName` | Scope evidence without pretending current membership proves historical membership. |
| `ObservationStart`, `ObservationEnd` | Requested evidence window. |
| `RetentionDays`, `RetentionSource`, `RetentionVerifiedAt` | Retention boundary and its provenance. |
| `AllowedLoggingState`, `AllowedLoggingFrom`, `AllowedLoggingUntil`, `AllowedLoggingSource` | Evidence that allowed-device logging covered the requested scope and window. |
| `BlockedLoggingState`, `BlockedLoggingFrom`, `BlockedLoggingUntil`, `BlockedLoggingSource` | Independent evidence that blocked-device logging covered the requested scope and window. |
| `AllowedCollectionState`, `AllowedCheckpoint`, `AllowedCollectionError` | Completeness and failure evidence for allowed-event collection. |
| `BlockedCollectionState`, `BlockedCheckpoint`, `BlockedCollectionError` | Completeness and failure evidence for blocked-event collection. |
| `AllowedCoverageState`, `BlockedCoverageState` | Independent `Complete`, `Partial`, `Indeterminate`, or `OutOfScope` coverage for each outcome stream. |
| `UsageState` | `ObservedUsage`, `CandidateUsage`, `NoObservedUsage`, or `NotEvaluated`. |
| `BlockedDemandState` | `BlockedDemandObserved`, `BlockedDemandCandidate`, `NoBlockedDemandObserved`, or `NotEvaluated`. |
| `AllowedEventCount`, `BlockedEventCount` | Separate evidence; allowed usage and blocked demand may coexist. |
| `DistinctAgentCount`, `LastAllowedAt`, `LastBlockedAt` | Tenant-wide activity summary without collapsing two timelines. |
| `CorrelationMethod`, `CorrelationConfidence` | Direct, candidate, or unresolved attribution and its evidence quality. |
| `Rationale` | Plain-language explanation of the conclusion and limitations. |
| `NextAction` | Human-owned review step, never an executable rule change. |

### Human-owned actions

Examples include retaining a used rule, reviewing whether a broad VID/PID rule can be narrowed, locating an accountable ticket or owner, extending collection, or investigating blocked demand. `NextAction` must never authorize automatic deletion, restoration, or creation of a rule.

### Fail-safe decision table

The coverage and outcome dimensions are independent. A rule may have both `ObservedUsage` and `BlockedDemandObserved` in the same window, and one stream may be complete while the other is indeterminate.

| Evidence condition | Allowed result | Blocked result |
|---|---|---|
| Platform or entitlement cannot expose Device Control evidence | `AllowedCoverageState=OutOfScope`; `UsageState=NotEvaluated` | `BlockedCoverageState=OutOfScope`; `BlockedDemandState=NotEvaluated` |
| Directly correlated allowed event exists | Preserve actual allowed coverage; `UsageState=ObservedUsage` | Evaluate independently |
| Only a heuristic allowed-event match exists | Preserve actual allowed coverage; `UsageState=CandidateUsage` | Evaluate independently |
| Directly correlated blocked event exists | Evaluate independently | Preserve actual blocked coverage; `BlockedDemandState=BlockedDemandObserved` |
| Only a heuristic blocked-event match exists | Evaluate independently | Preserve actual blocked coverage; `BlockedDemandState=BlockedDemandCandidate` |
| No allowed event; allowed logging, retention, temporal rule version, correlation, scope, and allowed cursor collection are all complete | `AllowedCoverageState=Complete`; `UsageState=NoObservedUsage` | Evaluate independently |
| No blocked event; blocked logging, retention, temporal rule version, correlation, scope, and blocked cursor collection are all complete | Evaluate independently | `BlockedCoverageState=Complete`; `BlockedDemandState=NoBlockedDemandObserved` |
| Allowed logging is unconfirmed or does not cover the full window | `AllowedCoverageState=Indeterminate`; `UsageState=NotEvaluated` unless positive direct evidence exists | No effect on independently evaluated blocked evidence |
| Blocked logging is unconfirmed or does not cover the full window | No effect on independently evaluated allowed evidence | `BlockedCoverageState=Indeterminate`; `BlockedDemandState=NotEvaluated` unless positive direct evidence exists |
| Requested window reaches/exceeds retention, or retention provenance is missing | `AllowedCoverageState=Indeterminate`; `UsageState=NotEvaluated` unless positive direct evidence exists | `BlockedCoverageState=Indeterminate`; `BlockedDemandState=NotEvaluated` unless positive direct evidence exists |
| A cursor repeats, a page fails, or collection stops early | Set the affected stream to `Partial`; do not infer negative evidence | Set the affected stream to `Partial`; do not infer negative evidence |
| Rule version, historical scope, precedence, or direct identity cannot be aligned | `AllowedCoverageState=Indeterminate`; `UsageState=NotEvaluated` unless positive direct evidence exists | `BlockedCoverageState=Indeterminate`; `BlockedDemandState=NotEvaluated` unless positive direct evidence exists |

## Event exploration

The future command should accept bounded filters and return sortable data rather than an unbounded in-memory dump. Required review dimensions are:

- rule identity and name;
- VID/PID and other confirmed device identifiers;
- endpoint;
- site and group;
- observation period;
- event type;
- allowed or blocked outcome.

Cursor pagination remains mandatory for complete collection. Incremental collection and persistent snapshots require a separate storage and privacy design; this roadmap does not choose a storage backend.

## Existing synthetic coverage

The current suite already proves the safe boundaries that do not depend on an invented rule/event schema:

| Boundary | Existing evidence |
|---|---|
| Cursor pagination | `tests/contract/S1DeviceControlEventsMock.Tests.ps1` and the pagination cases in `tests/contract/Get-S1DeviceControlEvent.Tests.ps1`. |
| No-event response | `tests/contract/Get-S1DeviceControlEvent.Tests.ps1` returns an empty collection without fabricating an event. |
| Malformed count and limited responses | `tests/contract/Get-S1DeviceControlEvent.Tests.ps1` rejects missing, non-numeric, contradictory, or primitive response shapes. |
| Retention equality and excess | `tests/contract/Get-S1UnusedAuthorizationReport.Tests.ps1` keeps windows equal to or longer than retention out of `NoUsage`. |
| Unsupported platform | `tests/contract/Get-S1UnusedAuthorizationReport.Tests.ps1` classifies Linux and caller-excluded platforms as `OutOfScope`. |
| Unconfirmed entitlement | `tests/contract/Get-S1UnusedAuthorizationReport.Tests.ps1` produces no `NoUsage` result and makes no event request without explicit Control SKU confirmation. |
| No write path | The same report test confirms that the workflow performs no group move. |

No synthetic rule-level fixture should be added until the rule endpoint, event identity fields, allowed/blocked values, and direct-join semantics are confirmed. Freezing guessed vendor fields in tests would make an unsupported assumption look like a contract.

## Open validation questions

1. What are the exact rule and event response schemas for the authorized console version?
2. Does the event schema expose a stable `ruleId`, and under which event types?
3. Which field, if any, is the device serial identifier?
4. Which event values distinguish allowed use, read-only use, and blocking?
5. Is approved-device logging enabled and complete for the intended scopes?
6. What is the effective Device Control event retention and late-arrival behaviour?
7. Are cursor checkpoints stable enough for lossless incremental collection?
8. How are Enterprise, Site, and Group inheritance and precedence represented?
9. Can historical endpoint scope be established without collecting unnecessary personal data?
10. Do Bluetooth and BLE events expose equivalent identifiers and rule relationships?

## Follow-up delivery split

1. [**Validate the rule/event contract (#11):**](https://github.com/mbart75/endpoint-ops/issues/11) use a sanctioned non-production tenant, record only sanitized schema metadata, confirm endpoint paths, logging coverage, event outcomes, identity fields, pagination, retention, and precedence. Do not add tenant payloads to the repository.
2. [**Implement the read-only inventory (#12):**](https://github.com/mbart75/endpoint-ops/issues/12) after the contract is confirmed, use TDD to add synthetic fixtures, normalized rule/event identity, tenant-wide aggregation, bounded exploration, snapshots, evidence states, and human-review output. Preserve all existing reports and prohibit automatic rule changes.
