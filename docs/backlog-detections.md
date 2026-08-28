# Detection backlog

This backlog describes the review signals implemented or planned for endpoint-operations workflows. Each signal should return evidence and a reason, not an unexplained score.

## W1 — SentinelOne fleet hygiene

Identify endpoints that are inactive, decommissioned but recently active, below the target agent version, on an unsupported operating-system branch, or below the required revision for their branch.

### Comparing an operating-system build

An `osRevision` value such as `22631.4890` cannot be compared numerically with `19044.1288`: they belong to different operating-system branches. The input build map identifies the branch and its minimum revision. A missing branch is `Unsupported`, not merely out of date; an empty map produces `Unknown`, not `Current`.

### Graduated response

- Stage 0: collect and report only. A silent endpoint cannot be remediated remotely by this module.
- Stage 1: move an endpoint to a tracking group using `Invoke-S1FleetRemediation`.
- Stage 2: emit a human-reviewed proposal for further action; the module does not execute it.

Only Stage 1 is implemented as a write operation, and it is gated by `ShouldProcess`.

## W2 — EPM events to policy proposals

Aggregate elevation events by publisher and file hash, then propose policy treatment from explainable inputs such as signature state and distinct-user count. An unsigned binary remains a weak or no proposal regardless of frequency: prevalence measures distribution, not legitimacy.

Optional VirusTotal enrichment can reject or weaken a proposal. It cannot promote one. EPM reports state `Contact` as unavailable through the API when public API data cannot identify a policy author.

## W3 — SentinelOne exclusion review

Highlight broad exclusions, especially root paths, wide scope, and entries without a usable justification. Results include the available creation or update provenance so a reviewer can identify an accountable contact when one exists. A service account is not presented as a human contact.

## W4 — Device Control review

Highlight permissive device-control rules, including vendor-wide matching where evidence supports concern. Findings expose their reasons and severity rather than a single opaque risk number.

### W4.7 — unused authorization review

Unused authorization is a three-state question:

1. `NoUsage`: no relevant usage was observed in a reliable window.
2. `Indeterminate`: the requested window reaches or exceeds the stated retention period.
3. `OutOfScope`: Device Control coverage cannot be established, including Linux or an unconfirmed Control SKU.

The report requires `RetentionDays` and explicit `-ControlSkuAvailable`. It rejects `AlertAfterDays -ge RemoveAfterDays`; an alert and removal workflow must be a genuine progression.

## Cross-cutting requirements

- Reports expose their reasons in plain text and severity is the strongest reason, not a black-box score.
- Collection minimises personal data. The “last logged-on user” field is intentionally not collected because no current signal needs it.
- Missing data must remain missing or indeterminate; it must not become a reassuring default.
- Read commands report observations. Scoring belongs to workflow commands, separate from product-query commands.

## Extending the backlog

Add a signal only after documenting: its evidence source, the trust and retention boundary, false-positive behaviour, minimum data required to decide, output reasons, and whether it can ever trigger a write. A new signal must not silently widen the module’s current authorization boundary.
