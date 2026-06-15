# Vela protocol specification v0.105.0

> **CLI-surface note (v0.700).** The command surface was cut to a ~70-command
> core in v0.700. Event kinds and reducer semantics in this spec remain
> normative — the reducer still replays every historical event — but some CLI
> invocations referenced below (`vela trace`, `vela bridge`, `vela federation`,
> `vela discord`, `vela impact`) describe commands that were removed from the
> binary. The events they minted are still valid state.

> **Version-scheme note.** Two numbering schemes appear in this repository.
> Markers of the form `v0.X` or `v0.X.Y` (v0.32, v0.78, v0.105, v0.262, …)
> are the original micro-version stamps: each names the working cycle that
> introduced a feature, kept as historical provenance in comments, doc
> strings, and this spec's section headings. The workspace release version
> (`0.700.0`, reported by `vela version`) is a separate, later scheme that
> began at 0.700 with the consolidated substrate. The two do not compare:
> v0.78 is *older* than 0.700, not newer. Micro-version markers are never
> bumped retroactively; new work cites the release scheme.


This document defines the shipped v0 language kernel for portable,
correctable frontier state. It is normative for finding bundles, typed links,
proposal records, canonical events, proof freshness, content addressing,
frontier epistemic confidence, entity resolution, content-addressed artifacts,
proof packets, and Git-compatible storage.

Runtime objects, federation, and dedicated constellation interfaces are not part
of the v0 protocol contract.

The Carina kernel name is reserved for the primitive object and event model
inside this protocol. See [`CARINA.md`](CARINA.md) for the kernel vocabulary;
the external-artifact adapter ships as the `vela artifact-to-state` command
(section 6's event kinds cover the records it mints).

The protocol boundary is the invariant this spec enforces throughout:
scientific activity is source material until it enters the proposal -> diff ->
review -> accepted event -> deterministic replay path. Derived answer pages,
graph views, benchmark tables, and source dashboards are projections over
replayed frontier state, not separate truth stores.

## 1. design principles

1. **Narrow waist.** The substrate solves persistent, correctable scientific
   state.
2. **Finding first.** The paper is a source artifact. The finding bundle is the
   primary state object.
3. **State transition first.** Truth-changing writes become proposals and then
   canonical events.
4. **Disagreement is structural.** Contradictions and contested claims remain
   inspectable instead of being flattened.
5. **Git-compatible.** Frontiers can be versioned with normal files, commits,
   branches, and diffs. Network propagation remains outside v0.
6. **Content-addressed.** Stable content produces stable IDs.
7. **Correction over deletion.** Corrections preserve history.
8. **Agent output is source, not truth.** Agent traces, synthetic reports, and
   benchmark outputs require source/evidence/condition grounding and review.

## 2. primitive set

Vela v0 has three protocol-level primitives:

- **Object:** finding bundles are primary. Supporting kernel objects include
  artifacts, negative results, trajectories, datasets, code artifacts,
  replications, predictions, and resolutions.
- **Link:** typed relationships between findings.
- **Event:** the authoritative state-transition record.

A frontier snapshot is a bounded, reviewable frontier state over a scientific
question. It is not a claim of final truth. ("Belief state" is the theory-side
nomenclature for the same object. See `docs/MATH.md` and `docs/THEORY.md`.)

### 2.1 finding bundle

A finding bundle is one assertion plus its evidence, conditions, entities,
confidence, provenance, flags, annotations, attachments, and links.

Required fields:

| Field | Meaning |
|-------|---------|
| `id` | `vf_...` content address |
| `version` | Finding schema version |
| `previous_version` | Previous finding ID if corrected |
| `assertion` | The bounded claim text and type |
| `evidence` | Evidence class, method, spans, model system, and statistics |
| `conditions` | Scope boundaries such as species, assay, comparator, endpoint |
| `confidence` | Frontier epistemic support and components |
| `provenance` | Source and extraction metadata |
| `flags` | Review-relevant state such as gap, contested, retracted |
| `links` | Typed relationships to other findings |
| `annotations` | Lightweight notes or caveats |
| `created` / `updated` | Timestamps |

### 2.2 source, evidence, and condition projections

Frontier snapshots may carry derived projections:

- `sources`: source artifacts such as papers, PDFs, JATS files, CSV rows,
  notes, agent traces, research traces, benchmark outputs, notebook entries,
  experiment logs, and synthetic reports.
- `evidence_atoms`: exact source-grounded units bearing on one finding.
- `condition_records`: materialized condition boundaries for one finding.
- `artifacts`: content-addressed protocols, trial registry records, supplements,
  notebooks, tables, figures, model outputs, dataset manifests, and files.

These projections support proof and review. They are not authoritative
transition logs. Older frontiers may omit them; the reference implementation can
derive them for check/export/proof and materialize them during normalize without
rewriting canonical events. In v0, writable normalization is a pre-transition
repair step: once canonical events exist, further durable changes should be
represented as reviewed state transitions instead of post hoc normalization.

### 2.3 artifact object

An artifact is a durable byte or pointer commitment:

| Field | Meaning |
|-------|---------|
| `id` | `va_...` content address |
| `kind` | `dataset`, `clinical_trial_record`, `protocol`, `supplement`, `notebook`, `code`, `model_output`, `table`, `figure`, `registry_record`, `lab_file`, `source_file`, or `other` |
| `content_hash` | `sha256:<64hex>` commitment |
| `storage_mode` | `local_blob`, `local_file`, `remote`, or `pointer` |
| `locator` | local path, blob path, remote URL, or accession |
| `source_url` | original upstream page or record |
| `target_findings` | findings the artifact bears on |
| `metadata` | adapter-specific structured fields |
| `access_tier` | public, restricted, or classified |

`artifact.asserted` carries the full artifact inline. Replay reconstructs the
artifact table from events. `artifacts/artifacts.json`,
`artifacts/artifact-audit.json`, and `artifacts/blob-map.json` are canonical
proof packet files. When a license-compatible local artifact can be checked,
`vela proof` copies the bytes into `artifacts/blobs/sha256/<hash>` and validates
them against the recorded content hash.

### 2.4 reserved concepts

Future layers may add `ProtocolRecord`, `ExperimentRecord`, `ResultRecord`,
first-class `Observation`, runtime writeback, network propagation, and dedicated
constellation interfaces. They are outside v0 until they have replay, writeback,
proof/export, and review/merge semantics.

Research traces are currently represented as source artifacts, not as a new
authority primitive. A trace may summarize an agent run, proof search, benchmark
run, notebook session, or lab execution. It can carry verifier attachments and
formalization-fidelity questions, but it cannot mutate frontier state without a
proposal and accepted canonical event. The reference CLI validates traces with
`vela trace validate` and compiles them into pending `research_trace.review`
proposals with `vela trace propose`. Proof packets include validated trace
projections at `research-traces/research-traces.json` and
`research-traces/verifier-attachments.json`.

The `Trajectory` (v0.50) and `NegativeResult` (v0.49) primitives map
to what AI-research-runtime systems call workstreams and failed
explorations respectively. See `docs/RESEARCH_RUNTIME.md` for the
runtime-side concept mapping and §6.1 / §6.3 below for the kernel
event surface.

### 2.5 artifact packet

`carina.artifact_packet.v0.1` is an interchange packet for external runtimes
that produce provenance-bearing artifacts.

The packet contains a producer, topic, created time, immutable artifacts with
`sha256:*` hashes and parent lineage, candidate claims linked to packet
artifacts, and open needs that become gap-style proposals.

Import rules:

- packet artifacts map to `artifact.assert` proposals
- candidate claims map to `finding.add` proposals
- open needs map to gap-style `finding.add` proposals
- packet artifact ids and parent ids stay in proposal provenance
- `--apply-artifacts` may accept artifact records immediately
- truth-changing findings and gaps remain pending review

No external runtime receives automatic authority. The accepted event is the
state transition.

### 2.6 scientific diff pack

A Scientific Diff Pack (`vsd_...`) is the reviewable unit for a proposed set of
frontier state changes. It aggregates one or more proposal records and exposes
the review grammar a human needs before accepting, rejecting, or requesting
revision:

- source artifacts
- proposed operations
- affected findings
- evidence deltas
- confidence deltas
- contradiction effects
- downstream impacts
- validation results
- required reviewers
- exact CLI equivalents

Each member proposal is also classified into one operation class:
`add_finding`, `add_evidence_atom`, `repair_locator`, `repair_span`,
`resolve_entity`, `add_link`, `add_caveat`, `revise_confidence`,
`mark_contradiction`, `open_gap`, or `request_downstream_review`. Pack
inspection reports operation counts, non-mutating preview counts when a member
proposal is canonical in the local frontier, and whether accepting the pack
would make proof state stale. Confidence-changing operations must carry a
review reason plus at least one source or evidence reference; missing fields are
reported as validation results rather than silently accepted.

A pack is not a truth object and does not bypass the event log. Agent-produced
packs remain source material until local review records a verdict and accepted
member proposals become canonical frontier events. Pack inspection can be
rendered in Workbench or as JSON with `vela diff-pack inspect <frontier>
<pack-id> --json`.

The boundary is explicit:

- **Pack:** groups proposed work into a reviewer-facing unit.
- **Member proposal:** describes the concrete local state transition.
- **Reviewed event:** records the verdict, reviewer, reason, member counts, and
  proof freshness impact.
- **Accepted member event:** mutates frontier state through the existing
  proposal reducer.

### 2.7 scoped scientific attestation

A scoped scientific attestation (`vatt_...`) is a local reviewer statement
about one target:

- `vsd_*` Scientific Diff Pack
- `vrp_*` review packet
- `vpf_*` proof packet
- `vev_*` canonical event

The record names the reviewer id, optional ORCID, optional ROR affiliation,
reviewer role, declared scope, reason, and timestamp. Supported scopes are
`source_extraction`, `method_review`, `statistical_review`,
`domain_relevance`, `translation_clarity`, and `policy_approval`.

For `vev_*` targets, Vela also appends a canonical `attestation.recorded`
event that points at the target event. For other targets, the attestation is a
local review artifact under `.vela/attestations/`.

This primitive separates expert scope from global agreement. It does not imply
institutional consensus, multi-actor signing, or clinical actionability.

### 2.8 protocol ingestion source material

Protocol ingestion accepts structured material from tools, notebooks, agents,
and reviewers without granting authority to that material.

Supported source contracts include:

- research traces
- score returns
- notebook outputs

Notebook outputs use `vela.notebook_output.v0.1`. A valid notebook output names
the objective, inputs, code hash, environment, outputs, metrics, verifier
attachments, and review boundary. It is source material. It does not write
frontier state, create review events, or claim accepted findings.

Score returns can compile into `vela.return_to_draft_events.v2`. The compiled
artifact contains draft review events with source-return paths, source hashes,
case ids, task ids, arm scores, and authority boundaries. These draft events
are not canonical events. They require explicit maintainer review before any
accepted event can mutate frontier state.

The boundary is explicit:

- **Source material:** a returned file, trace, or notebook output submitted for
  review.
- **Draft event:** a previewable candidate event compiled from source material.
- **Reviewed event:** the only layer that can accept, reject, revise, or caveat
  trusted frontier state.

## 3. content addressing

Finding IDs are computed from content:

```text
SHA-256(normalize(assertion.text) + "|" + assertion.type + "|" + provenance_id)
```

`provenance_id` is `doi`, then `pmid`, then source title. The ID is `vf_` plus
the first 16 hex characters of the hash.

Source records use `vs_...`, evidence atoms use `vea_...`, condition records use
`vcnd_...`, artifacts use `va_...`, proposals use `vpr_...`, and canonical
events use `vev_...`. The full prefix registry — the authoritative meaning of
every live `v*_` prefix, including the known `vat_` and `vtr_` collisions —
lives in [`PREFIXES.md`](PREFIXES.md).

## 4. confidence

`confidence.score` means bounded frontier epistemic support for the finding as
currently represented. It is not extraction accuracy, not truth probability, and
not review consensus by itself.

Vela keeps three notions separate:

- `confidence.score`: frontier epistemic support.
- `confidence.extraction_confidence`: extraction accuracy confidence.
- review state: proposals, canonical events, contestation flags, and signals.

The computed score uses:

```text
score = evidence_strength * replication_strength * model_relevance * sample_strength
        - review_penalty + calibration_adjustment
```

The normalized component names are `evidence_strength`,
`replication_strength`, `sample_strength`, `model_relevance`, `review_penalty`,
and `calibration_adjustment`. Legacy component names may be accepted on input
for compatibility.

## 5. links

Core v0 link types:

| Type | Meaning |
|------|---------|
| `supports` | Source finding provides evidence for target |
| `contradicts` | Findings oppose each other under comparable or overlapping conditions |
| `extends` | Source builds on or broadens target |
| `depends` | Source validity depends on target |
| `replicates` | Source independently reproduces target |
| `supersedes` | Source replaces target |
| `synthesized_from` | Source was compiled from one or more targets |

Links may include confidence, notes, evidence spans, conditional text, and
inference provenance. Link-derived outputs are review surfaces unless accepted
through normal frontier review.

### v0.10 — domain-neutral enum extensions

The first non-bio frontier published to the public hub (a particle-astrophysics
WIMP direct-detection frontier) surfaced that the v0 enum sets were
biology-leaning. v0.10 added domain-neutral entries — additively — without
changing content addressing for pre-v0.10 frontiers:

- **Entity type:** `particle` (WIMPs, photons), `instrument` (XENONnT, JWST —
  capital objects that run measurements), `dataset` (instrument data releases
  distinct from the paper that reports them), `quantity` (named numerical
  values with units, e.g. `28 GeV/c^2`). The pre-v0.10 entries (`gene`,
  `protein`, …) and the `other` escape valve remain.
- **Assertion type:** `measurement` (numerical-quantity reports), `exclusion`
  (upper/lower bound at a confidence level). Pre-v0.10 entries unchanged.
- **Provenance source type:** `data_release` (instrument runs, observation
  campaigns, dataset versions that are themselves the substantive object).
  Pre-v0.10 entries unchanged.

Schema URL bumps `v0.8.0 → v0.10.0` for new frontiers; the validator accepts
both URLs so pre-v0.10 frontiers (BBB, BBB-extension, the v0.8 cross-frontier
conformance vector) replay byte-identically under a v0.10 binary.

### v0.8 — cross-frontier link targets

`Link.target` may take two shapes:

- `vf_<16hex>` — references a finding in this same frontier.
- `vf_<16hex>@vfr_<16hex>` — references a finding in a different frontier
  (the trailing `vfr_` is the target frontier's content-addressed id).

Cross-frontier targets are valid only if the dependent frontier declares a
matching `vfr_id` in `frontier.dependencies` with both a `locator` and a
`pinned_snapshot_hash`. Strict validation refuses cross-frontier targets
without a declared dep.

`vela registry pull <vfr> --transitive` walks the dependency graph and
verifies that every fetched dep's actual snapshot matches the dependent's
pinned hash. The pin is the integrity guarantee; partial trust is not a
state v0.8 supports.

## 6. proposal and event protocol

The public write boundary is a `vela.proposal.v0.1` proposal. Truth-changing
commands create pending proposals by default. `--apply` accepts and applies the
proposal locally in one step.

Accepted proposals append a canonical `StateEvent`, apply the reducer,
recompute derived state, and mark proof stale when appropriate.

Core proposal kinds:

| Kind | CLI surface |
|------|-------------|
| `finding.add` | `vela finding add` |
| `finding.review` | `vela review` |
| `finding.note` | `vela note` |
| `finding.caveat` | `vela caveat` |
| `finding.confidence_revise` | `vela revise` |
| `finding.reject` | `vela reject` |
| `finding.retract` | `vela retract` |

Core event kinds:

| Kind | Meaning |
|------|---------|
| `finding.asserted` | Add a finding |
| `finding.reviewed` | Record review judgment |
| `finding.noted` | Attach a note |
| `finding.caveated` | Attach a caveat |
| `finding.confidence_revised` | Revise confidence interpretation |
| `finding.rejected` | Mark a finding rejected |
| `finding.retracted` | Mark retraction state |
| `finding.dependency_invalidated` | Per-dependent cascade event from an upstream retraction |
| `negative_result.asserted` | Deposit a NegativeResult (`vnr_*`) — see §6.1 |
| `negative_result.reviewed` | Record review verdict on a NegativeResult |
| `negative_result.retracted` | Mark a NegativeResult retracted |
| `trajectory.created` | Open a Trajectory (`vtr_*`) — see §6.2 |
| `trajectory.step_appended` | Append a step (`vts_*`) to an existing Trajectory |
| `trajectory.reviewed` | Record review verdict on a Trajectory |
| `trajectory.retracted` | Mark a Trajectory retracted |
| `tier.set` | Re-classify a kernel object's read-side access tier — see §13 |
| `frontier.conflict_detected` | Federation observation: peer view of a finding diverges from ours; see §6.4 |
| `frontier.conflict_resolved` | Reviewer verdict paired with a prior `frontier.conflict_detected`; see §6.4 |
| `bridge.reviewed` | Reviewer verdict on a `vbr_*` cross-frontier bridge (v0.67); reducer arm is a no-op on findings, the verdict projects onto `Bridge.status` on read. Required payload: `bridge_id`, `status` (one of `confirmed` or `refuted`), optional `note`. Constructor at `crates/vela-protocol/src/events.rs:386-420`; validator arm at `crates/vela-protocol/src/events.rs:869-895`; constant `EVENT_KIND_BRIDGE_REVIEWED` at `events.rs:125`. |
| `replication.deposited` | Append a `Replication` record to `Project.replications` (v0.70); idempotent on the `vrep_*` id. Required payload: `replication` (the full record). Validator arm at `crates/vela-protocol/src/events.rs:829-849`; reducer arm at `crates/vela-protocol/src/reducer.rs:830-848`; state helper `state::deposit_replication` at `crates/vela-protocol/src/state.rs:610-657`. |
| `prediction.deposited` | Append a `Prediction` record to `Project.predictions` (v0.70); idempotent on the `vpred_*` id. Required payload: `prediction` (the full record). Validator arm at `crates/vela-protocol/src/events.rs:850-868`; reducer arm at `crates/vela-protocol/src/reducer.rs:850-868`; state helper `state::deposit_prediction` at `crates/vela-protocol/src/state.rs:661-700`. |
| `review.accepted` / `review.rejected` / `review.revision_requested` | A reviewer's decision on a proposal, recorded as a signed, append-only event targeting the proposal (`target.type = "proposal"`, `target.id = vpr_*`). Side-table events (`before_hash = after_hash = NULL_HASH`), transparent to the per-finding hash chain; audit-only on the finding projection. Required payload: `proposal_id` (`vpr_*`), `proposal_kind`, `verdict` (must agree with the kind), optional `applied_event_id` (`vev_*`, accepts only), optional `legacy_backfill` (true for migration-synthesized unsigned events). Signed under the reviewer key (key custody, like accept). Proposal `status` is a PROJECTION of these events (plus, for an accept, the domain event it produced); the projection is verified against the stored field by `proposals::verify_proposal_decision_parity` — the gate that closes the silent-reject vector (THREAT_MODEL A11). Constructor `new_review_decision_event` + `ReviewDecisionPayload` in `events.rs`; emitted by `reject_proposal_in_frontier_signed` / `request_revision_in_frontier_signed` in `proposals.rs`. A reject is therefore now as accountable as an accept: same key custody, same signed log event, same replayability. Accepts continue to record their decision via the domain event they produce (`finding.asserted`, …), so no separate `review.accepted` is emitted on the standard accept path; the parity check recognizes an `applied` proposal's `applied_event_id` as its decision trace. |

Canonical `events` are the authoritative write log. Legacy `review_events` and
`confidence_updates` fields may be read for compatibility, but new v0 writes
should not rely on them as state authority.

### 6.0.1 Event-first hub projection

Network hubs preserve the canonical event array as ordered
`frontier_events` rows. The `(vfr_id, seq)` order must reproduce the
same `latest_event_log_hash` as the signed manifest. Query endpoints may
filter by kind or target, but the unfiltered cursor order is the
authoritative replay order.

Materialized frontier objects such as findings, sources, evidence atoms,
condition records, actors, negative results, trajectories, links, and
proposals are projections from a verified snapshot or from a replayed
event log. Snapshot JSON is a pull/export shape. It is not the network
authority source after promotion.

Historical backfills may use `authority_mode = "manifest_snapshot"`
when older events do not carry enough payload to replay genesis. In
that mode the signed manifest plus verified snapshot hash is the
authority bridge. New direct event writes must carry the full payload
needed for replay. In particular, `finding.asserted` must include
`payload.finding`.

### 6.1 NegativeResult lifecycle (v0.49)

A `NegativeResult` is a first-class kernel object parallel to
`FindingBundle`, identified by `vnr_<16hex>`. It records what was
tried and observed without flipping the confidence of any `Finding`
on its own; downstream confidence math reads the deposit and decides
what to revise. Two variants are discriminated by `kind.kind`:

- `registered_trial`: `endpoint`, `intervention`, `comparator`,
  `population`, `n_enrolled`, `power`, `effect_size_ci` (a 2-element
  `[lower, upper]` array), optional `effect_size_threshold` (the
  pre-registered MCID), optional `registry_id`.
- `exploratory`: `reagent`, `observation`, `attempts`.

Top-level NegativeResult fields: `id`, `kind`, `target_findings`
(optional `vf_*` ids the null bears against; cross-frontier
`vf_<id>@vfr_<id>` allowed), `deposited_by`, `conditions`
(reuses the `Conditions` shape), `provenance` (reuses the
`Provenance` shape), `created`, `notes`, optional `review_state`,
`retracted: bool`. Full schema: [`schema/negative-result.v0.1.0.json`](../schema/negative-result.v0.1.0.json).

**`negative_result.asserted` payload**:

```json
{
  "proposal_id": "vpr_<hex>",
  "negative_result": { "id": "vnr_<hex>", "kind": { ... }, "..." }
}
```

The full inline NegativeResult is carried on
`payload.negative_result` so a fresh `replay_from_genesis`
reconstructs `state.negative_results` from the canonical event log
alone. The reducer is idempotent on duplicate `vnr_id`s.

**`negative_result.reviewed` payload**:

```json
{
  "proposal_id": "vpr_<hex>",
  "status": "accepted" | "contested" | "needs_revision" | "rejected"
}
```

Targets a `vnr_*` via `event.target.id`. The reducer sets the
NegativeResult's `review_state` field; v0.49 does not flip a
`contested` flag the way `finding.reviewed` does because
NegativeResults don't carry the legacy `flags.contested` shim.

**`negative_result.retracted` payload**:

```json
{
  "proposal_id": "vpr_<hex>"
}
```

Targets a `vnr_*` and sets `retracted: true`. Replay of a frontier
with a later `negative_result.retracted` event reproduces the same
state regardless of how the live frontier reached it.

**Cross-implementation coverage.** The Rust, Python, and TypeScript
reducers all dispatch on these kinds. The cross-impl post-replay
digest (`fixture_coverage_includes_every_reducer_arm`) covers
finding-state only in v0.49, so TS and Python reducers may treat
the three `negative_result.*` kinds as no-ops on `Finding[]` state
without breaking the byte-equivalence promise. v0.50 tightens the
digest to include `negative_results` and requires all three
implementations to mirror the Rust apply functions.

**CLI**: `vela negative-result-add` deposits in one shot. Required
flags differ by `--kind`: `registered_trial` requires
`--endpoint`, `--intervention`, `--comparator`, `--population`,
`--n-enrolled`, `--power`, `--ci-lower`, `--ci-upper`;
`exploratory` requires `--reagent`, `--observation`, `--attempts`.
`vela negative-results <frontier>` lists deposits, optionally
filtered by `--target <vf_id>`.

### 6.2 Artifact lifecycle

`artifact.asserted` deposits a generic content-addressed artifact.

```json
{
  "proposal_id": "vpr_<hex>",
  "artifact": {
    "id": "va_<hex>",
    "kind": "clinical_trial_record",
    "name": "AHEAD 3-45 Study",
    "content_hash": "sha256:<64hex>",
    "storage_mode": "local_blob",
    "locator": ".vela/artifact-blobs/sha256/<hash>",
    "source_url": "https://clinicaltrials.gov/study/NCT04468659",
    "target_findings": ["vf_<hex>"],
    "metadata": {
      "nct_id": "NCT04468659",
      "overall_status": "ACTIVE_NOT_RECRUITING"
    },
    "access_tier": "public"
  }
}
```

Targets a `va_*` object and appends it to `Project.artifacts`.
`artifact.reviewed` sets `review_state`; `artifact.retracted` sets
`retracted: true`. `tier.set` may also target artifacts.

**CLI**: `vela artifact-add` records a local or remote artifact.
`vela clinical-trial-import <frontier> <NCT_ID>` fetches a ClinicalTrials.gov v2
study record, stores a canonical JSON blob in `.vela/artifact-blobs/sha256/`
when the target is a `.vela` repo, and emits `artifact.asserted`.
`vela artifacts <frontier>` lists records, optionally filtered by
`--target <vf_id>`. `vela artifact-audit <frontier>` checks artifact
hashes, local blob sizes, target finding references, source locators,
access terms, and profile fields such as NCT ids for trial records.
The same report is exposed by `vela serve` at `/api/artifact-audit`.

`vela artifact-to-state <frontier> <packet.json> --actor <actor>` validates a
`carina.artifact_packet.v0.1` packet and writes reviewable proposals. Use
`--apply-artifacts` to accept only the content-addressed artifact records while
leaving candidate findings and gaps in the proposal inbox. `vela proposals
preview <frontier> <vpr_id>` applies one proposal to an in-memory clone and
reports count deltas without mutating the frontier.

`vela runtime-adapter run <frontier> <adapter> --input <file-or-dir>` is the
external-runtime bridge. It normalizes supported runtime exports into the same
artifact packet boundary, then reuses artifact-to-state review semantics.
`scienceclaw-artifact-v1` maps artifact DAG exports to artifact, finding, and
gap proposals. `agent-discourse-v1` maps post/comment/review exports to
artifact, finding, and review-note proposals.

### 6.3 Trajectory lifecycle (v0.50)

A `Trajectory` is the search path that produced (or did not
produce) a finding — hypotheses considered, branches tried,
branches ruled out and why. Identified by `vtr_<16hex>`, with steps
identified by `vts_<16hex>`. Steps are append-only, idempotent on
content-address. Full schema: [`schema/trajectory.v0.1.0.json`](../schema/trajectory.v0.1.0.json).

Top-level Trajectory fields: `id`, `target_findings` (optional
`vf_*` ids the search aimed at), `deposited_by`, `created`,
`steps`, `notes`, optional `review_state`, `retracted: bool`. The
trajectory id is fixed at creation
(`SHA-256(sorted_target_findings.join(",") | deposited_by | created)`)
so appending steps does not mint a new id.

Step fields: `id` (content-addressed
`SHA-256(parent_trajectory_id | kind.canonical() | normalize(description) | at | actor)`),
`kind` (`hypothesis | tried | ruled_out | observed | refined`),
`description`, `at`, `actor`, optional `references` (any kernel id
— `vf_*`, `vnr_*`, `vrep_*`, `vpred_*`, `vd_*`, `vc_*`).

**`trajectory.created` payload**:

```json
{
  "proposal_id": "vpr_<hex>",
  "trajectory": { "id": "vtr_<hex>", "target_findings": [...], "...": "..." }
}
```

The full inline Trajectory (with empty `steps`) is carried on
`payload.trajectory`. Idempotent on duplicate `vtr_id`.

**`trajectory.step_appended` payload**:

```json
{
  "proposal_id": "vpr_<hex>",
  "parent_trajectory_id": "vtr_<hex>",
  "step": { "id": "vts_<hex>", "kind": "ruled_out", "...": "..." }
}
```

Targets the parent trajectory's `vtr_id` via `event.target.id`.
Idempotent on duplicate `vts_id` so a replay of a partially-applied
log doesn't double-append.

**`trajectory.reviewed` payload** mirrors `negative_result.reviewed`:
`{ proposal_id, status: "accepted"|"contested"|"needs_revision"|"rejected" }`.

**`trajectory.retracted` payload**: `{ proposal_id }`. Sets
`retracted: true`.

**CLI**:
- `vela trajectory-create <frontier> --deposited-by ID --reason "…"
  [--target vf_…]* [--notes "…"]` opens a trajectory.
- `vela trajectory-step <frontier> <vtr_id> --kind hypothesis|tried|ruled_out|observed|refined
  --description "…" --actor ID --reason "…" [--reference vf_…|vnr_…|…]*`
  appends a step.
- `vela trajectories <frontier> [--target vf_id]` lists.

**Cross-implementation coverage**: same v0.49 → future digest
tightening pattern as NegativeResult. v0.50 ships the four kinds in
`REDUCER_MUTATION_KINDS` with Rust apply functions; cross-impl
fixture 06 exercises `created`, `step_appended`, `reviewed`, and
`retracted`.

### 6.4 Federation observation events

Frontier-level observations record what happened between hubs without
mutating finding state. Two kinds ship in v0.39 / v0.59:

- `frontier.conflict_detected` (v0.39): emitted per finding when a
  peer's view of the same `vf_*` diverges from ours. Required payload:
  `peer_id`, `finding_id`, `kind`. Validator arm at
  `crates/vela-protocol/src/events.rs::validate_payload` ("frontier.conflict_detected").
- `frontier.conflict_resolved` (v0.59): paired resolution event for an
  existing `frontier.conflict_detected`. Required payload:
  `conflict_event_id`, `resolved_by`, `resolution_note`. Optional:
  `winning_proposal_id`. The conflict event itself is never modified;
  the resolution is appended as a separate canonical event and paired
  on read by `conflict_event_id`. The proposal validator at
  `crates/vela-protocol/src/proposals.rs::validate` ("frontier.conflict_resolve")
  refuses a second resolution for an already-resolved conflict; the
  event-payload validator at `crates/vela-protocol/src/events.rs`
  enforces the required fields. The reducer arm at
  `crates/vela-protocol/src/reducer.rs` is a no-op on `Project.findings`
  for both kinds; consumers (Workbench inbox, audit scripts, hub
  mirrors) walk the event log to project paired status.

### 6.5 Bridge review (v0.67)

A `Bridge` (`vbr_*`) is a candidate cross-frontier link that a derive
pass identifies and a reviewer confirms or refutes. Pre-v0.67 the
status field was mutated by direct file write. v0.67 makes the verdict
a canonical event so federation sync can carry it.

`bridge.reviewed` payload:

```json
{
  "bridge_id": "vbr_<hex>",
  "status": "confirmed" | "refuted",
  "note": "optional reviewer note"
}
```

`event.target` is `{type: "bridge", id: "vbr_<hex>"}`. The reducer arm
is a no-op on `Project.findings`; the verdict projects onto
`Bridge.status` on read so the existing bridges projection picks it up
without additional state. `bridges derive` remains the path that mints
the original `derived` record; `bridge.reviewed` only records
`confirmed` or `refuted`. The CLI surface is `vela bridge confirm` and
`vela bridge refute`.

The signature-pure validator at
`crates/vela-protocol/src/events.rs:869-895` enforces `bridge_id`
prefix (`vbr_*`), `status` membership, and the optional `note` type. As
of v0.73 a state-aware second pass at
`validate_bridge_reviewed_against_state` (same module) rejects events
whose `bridge_id` is not present on the local frontier's bridge table.
The CLI emission path calls it before writing the event, so a
`bridges confirm` or `bridges refute` against a missing id fails fast
rather than landing an event nothing can project. Federation intake
paths that ingest `bridge.reviewed` events from peers should call the
state-aware validator with their local bridge id list before storing.

### 6.6 Replication and Prediction deposits (v0.70)

`Replication` (`vrep_*`) and `Prediction` (`vpred_*`) have been
first-class kernel objects on `Project.replications` and
`Project.predictions` since earlier releases, but the deposit was a
file-write side-table mutation. v0.70 makes both deposits
event-driven so federation sync can propagate them.

`replication.deposited` payload:

```json
{
  "replication": {
    "id": "vrep_<hex>",
    "...": "..."
  }
}
```

The reducer arm pushes the record onto `Project.replications` only if
the `vrep_*` id is not already present, so re-application of the same
event is a no-op. Pre-v0.70 frontiers with raw `vrep_*` entries on
`Project.replications` continue to load without an event.

`prediction.deposited` mirrors the shape against `Project.predictions`
and the `vpred_*` id space. Both deposits are reachable from the
Workbench review pages: `/review/replication-add/{finding_id}` and
`/review/prediction-add/{finding_id}` (added v0.71).

### 6.7 Proposal `drafted_at` (v0.67)

`StateProposal` carries an optional `drafted_at: Option<String>` field
documented at `crates/vela-protocol/src/proposals.rs:29-38`. When an
agent drafts a proposal long before the reviewer accepts it,
`drafted_at` records the draft moment and `created_at` records the
moment the proposal entered the canonical store. Throughput dashboards
read against `drafted_at` when present, falling back to `created_at`,
so the median proposal-to-event latency surfaces real reviewer queue
time rather than zero. The field is additive: pre-v0.67 proposals load
with `drafted_at: None` and round-trip byte-identically (the field is
serialized only when present).

### 6.8 Federation push-resolution (v0.70)

`vela federation push-resolution` is the cross-hub propagation path
for `frontier.conflict_resolved` events. The CLI loads the paired
event from the local frontier, signs the canonical preimage with the
reviewer's Ed25519 key, and POSTs it to the peer hub at
`POST /entries/<vfr_id>/events`. The protocol-level wire surface
follows.

Auth headers (the body omits the `signature` field so the bytes the
hub canonicalizes match the bytes the reviewer signed):

```
X-Vela-Signer-Pubkey: <64-hex-char Ed25519 pubkey>
X-Vela-Signature:     <128-hex-char Ed25519 signature>
```

Verification rules, applied in order, fail fast on the first
violation:

1. Headers present and well-formed (64 hex pubkey, 128 hex signature).
2. Body parses as a `StateEvent`.
3. The `vfr_id` in the URL resolves to a `live` frontier on this hub.
4. The pubkey resolves to a registered actor on the frontier.
5. `event.actor.id` matches the resolved actor.
6. Ed25519 signature verifies against the canonical preimage.
7. `event.kind` is `frontier.conflict_resolved`.
8. The paired `frontier.conflict_detected` event named by
   `payload.conflict_event_id` is already on the hub's log for this
   `vfr_id`.
9. No prior resolution exists for the same `conflict_event_id` under
   a different event id.

Response codes:

| Code | Meaning |
|------|---------|
| `202 Accepted` | Event appended; response body carries the assigned `seq`. |
| `200 OK` | Idempotent re-push: same canonical event id already on the log; response carries `duplicate=true`. |
| `401 Unauthorized` | Pubkey not registered as an actor, or signature does not verify. |
| `403 Forbidden` | Event kind is not `frontier.conflict_resolved`. |
| `409 Conflict` | A different resolution event already pairs with the same `conflict_event_id`. |
| `422 Unprocessable Entity` | Paired `frontier.conflict_detected` not found on this hub. |

v0 remains proposal/event/finding centered.

### 6.9 Release history

This list tracks protocol-surface additions across recent releases.
Earlier releases are documented inline in the sections above.

- **v0.67**: `bridge.reviewed` event (§6.5); `StateProposal.drafted_at` optional field (§6.7).
- **v0.68**: internal hardening; no new event kinds or schema fields.
- **v0.69**: internal hardening; no new event kinds or schema fields.
- **v0.70**: `replication.deposited` and `prediction.deposited` events (§6.6); `vela federation push-resolution` cross-hub path (§6.8).
- **v0.71**: Workbench review surfaces `/review/replication-add/{finding_id}` and `/review/prediction-add/{finding_id}` for the v0.70 deposit events.
- **v0.72**: cross-impl fixture coverage for v0.67 to v0.71 events; `docs/PROTOCOL.md` backfill; `CONTRIBUTING.md` and `clients/python/README.md` added.
- **v0.73**: `bridge.reviewed` validator gains `validate_bridge_reviewed_against_state` for state-aware tightening (§6.5); cross-impl JSON fixture export extended to cover v0.67 to v0.71 event kinds; `docs/EVENT_LOG.md` developer walkthrough.

## 7. storage layout

The portable baseline remains monolithic `frontier.json`.

The default cloneable frontier repository format is:

```text
my-frontier/
├── README.md
├── SCOPE.md
├── frontier.yaml
├── frontier.json
├── vela.lock
├── sources/
├── artifacts/
├── review/
├── proof/
├── exports/
└── .vela/
```

In split frontier repos, `.vela/events/` is the append-only machine authority.
`frontier.json` is the materialized clone/read entrypoint. `proof/` is the
visible verification surface. `vela.lock` records the snapshot, event-log,
proposal-state, kernel, reducer, source, artifact, review, and proof hashes
that prove the visible state matches the event history.

### 7.1 Manifest dependencies (v0.59)

`frontier.yaml::dependencies` carries the durable cross-frontier
dependency declarations for split repos. The pre-v0.59 shape kept three
flat string lists (`frontiers`, `packages`, `adapters`); the v0.59
addition is `frontiers_v2: Vec<ProjectDependency>`, which records full
`ProjectDependency` entries (vfr id, locator, pinned snapshot hash, kind)
inline in the manifest. See `crates/vela-protocol/src/frontier_repo.rs`
(`ManifestDependencies::frontiers_v2`).

The field closes a split-repo loader gap: pre-v0.59, `vela frontier
add-dep` writes landed in the rendered `frontier.json` only, and
`vela frontier materialize` regenerated that file without them.
`frontiers_v2` is the durable source of truth in the yaml manifest and
is rehydrated into `Project.dependencies` on load. The field is
additive: pre-v0.59 manifests load with `frontiers_v2: []` and round-trip
unchanged; the renderer skips serialization when the list is empty.

A `.vela` repository may also store frontier state as files:

```text
.vela/
  config.toml
  findings/
    vf_{hash}.json
  events/
    vev_{hash}.json
  proposals/
    vpr_{hash}.json
  proof-state.json
```

Older repositories may include split link manifests, review projection files,
confidence-update projection files, runs, or trails. Those are compatibility or
roadmap artifacts, not required v0 public storage.

## 8. proof packet contract

`vela proof` exports a review packet from frontier state without modifying the
input frontier by default. `--record-proof-state` may be used for local
bookkeeping after successful packet validation. Required packet families
include:

- manifest, overview, scope, packet lock, and RO-Crate metadata
- full findings
- source registry, evidence atoms, and source/evidence map
- condition records and condition matrix
- candidate gaps, bridges, tensions, review queue, and signals
- canonical events and replay report
- proposals
- artifact manifest, artifact audit, and checked local artifact blob map
- proof trace

`packet validate` checks packet integrity, artifact audit status, and packet
local artifact blob hashes. Proof freshness relative to later accepted frontier
writes is tracked in frontier state when proof state has been recorded.

## 9. derived signals

Signals are recomputed from frontier state. They include proof readiness, review
queues, candidate gaps, candidate bridges, candidate tensions, observer-policy
rerankings, and simulated retraction impact over declared dependency links.

Signals are not standalone scientific facts.

## 10. conformance

> The guarantee ⇄ proof ⇄ conformance triangle — every load-bearing invariant mapped to its
> normative clause here, its machine-checked Lean theorem, and its conformance vector — is in
> [`docs/PROTOCOL_GUARANTEES.md`](PROTOCOL_GUARANTEES.md). Two interoperating implementations
> (Rust reference + Python reducer) agree on the vectors.

A conforming v0 implementation must:

1. Read and write finding bundles matching `finding-bundle.v0.2.0.json`.
2. Generate content-addressed IDs using the v0 pre-image rules.
3. Compute confidence from structured evidence fields.
4. Preserve source/evidence/condition boundaries.
5. Preserve disagreement through typed links and review state.
6. Use proposal-first writes for truth-changing state changes.
7. Store canonical events as the authoritative transition log.
8. Validate replay and proof freshness for proof-facing output.
9. Support monolithic frontier JSON and Git-compatible `.vela` layout.
10. Preserve read compatibility for legacy review/confidence fields where
    practical.

A conforming implementation should expose machine-readable check/proof/serve
contracts and keep candidate signals caveated.

## 11. Non-Normative roadmap boundary

The larger theory includes runtime, network propagation, and constellated
coordination. Vela v0 only standardizes the state kernel. Future object families
or network behavior must be promoted through the same discipline: replay,
writeback, proof/export, review, and merge semantics first.

## 13. Access tiers (v0.51)

The dual-use deposition channel. Three read-side tiers, ordered by
sensitivity:

- `public` (default) — open read.
- `restricted` — readers need an `ActorRecord` with
  `access_clearance >= restricted`. The IBC review level: dual-use
  research that the host institution has declared subject to
  incident-response review but not capability-gated.
- `classified` — readers need
  `access_clearance == classified`. Aligned with the federal DURC
  framework and the capability gates frontier AI labs already
  publish under their own safety frameworks (Anthropic's Responsible
  Scaling Policy, OpenAI's Preparedness Framework, Google
  DeepMind's Frontier Safety Framework). Content above those
  internal thresholds is excluded from public deposit entirely; the
  substrate's openness default fails closed on ambiguous cases,
  with the operational cost borne by depositors.

The composition risk — capability uplift from aggregation across the
dependency graph rather than any single deposit — is the harder
problem and v0.51 does not claim to solve it. Treating it as solved
would be the wrong move. v0.51 carries the per-object tier; the
composition graph is a follow-up.

### 13.1 Where the tier lives

Each of the three load-bearing claim objects carries an
`access_tier` field:

- `FindingBundle.access_tier`
- `NegativeResult.access_tier`
- `Trajectory.access_tier`

Default is `public`. The field is **NOT** part of the
content-address preimage — re-classifying an object does not mint
a new id. Pre-v0.51 frontiers load with the default and round-trip
byte-identically (skip-if-public).

`ActorRecord` carries an `access_clearance: Option<AccessTier>`.
Pre-v0.51 actors load with `None`, equivalent to public-only access.

### 13.2 `tier.set` lifecycle event

Re-classification is replay-deterministic. Payload:

```json
{
  "proposal_id": "vpr_<hex>",
  "object_type": "finding" | "negative_result" | "trajectory",
  "object_id": "vf_<hex>" | "vnr_<hex>" | "vtr_<hex>",
  "previous_tier": "public" | "restricted" | "classified",
  "new_tier":      "public" | "restricted" | "classified"
}
```

`event.target.{type,id}` mirrors `payload.{object_type, object_id}`.
The reducer locates the matched object and mutates its
`access_tier`. `previous_tier` is recorded in the payload so a
downstream auditor reading the event log can reconstruct the full
classification history without re-deriving it from prior state.

### 13.3 Read gating in `vela serve`

The Rust HTTP/MCP server resolves the requesting actor's clearance
from an `X-Vela-Actor` request header, looks the actor up in
`Project.actors`, and applies `access_tier::redact_for_actor`
before serializing.

- Anonymous reads (header absent) get `None`, equivalent to
  public-only.
- `GET /api/finding/<id>` returns `404` when the finding's tier
  exceeds the actor's clearance — the existence of the object is
  itself part of the tiered content.
- `GET /api/frontier` and `GET /api/findings` return a redacted
  `Project` view: above-clearance findings, negative_results,
  trajectories, and any events targeting them are dropped from the
  response.

This is a deliberately thin authentication surface for v0.51 — a
real deployment terminates TLS and validates actor signatures at a
reverse proxy, then forwards `X-Vela-Actor` only when verified.
v0.52+ can tighten this to require a signed bearer token end-to-end.

### 13.4 CLI

```bash
# Register an actor with read-side clearance
vela actor add my-frontier.json reviewer:ibc \
  --pubkey "$(cat keys/public.key)" \
  --clearance restricted

# Re-classify an existing finding
vela tier-set my-frontier.json \
  --object-type finding \
  --object-id  vf_<hex> \
  --tier       restricted \
  --actor      reviewer:ibc \
  --reason     "Subject to IBC review; gain-of-function adjacent."
```

### 13.5 What v0.51 does NOT solve

- **Composition risk.** The per-object tier protects single
  deposits. Aggregation across the dependency graph could leak
  capability uplift even when each individual object is below the
  classification threshold. v0.51.x will model this; today the
  substrate flags the gap rather than papering over it.
- **Federation propagation.** When a frontier with restricted
  objects syncs to a peer hub, what happens to the redaction is
  not yet specified. v0.51 ships with the local read gate only.
- **Audit-trail tiering.** The `tier.set` event itself is currently
  public. A future revision can elevate the event payload to the
  same tier as the object it reclassifies if the act of
  classification is itself sensitive.

---

## 14. Changelog from v0.73.0

v0.73.0 was the substrate-completeness cut. The kernel below
that mark stayed shape-stable; the cycles that landed since
add primitives, surfaces, and machine-checked guarantees
without changing the canonical-event preimage or replay
rules. Material additions, in cycle order:

- v0.74: top-level alias verbs (`init / ingest / propose /
  diff / accept / attest / log / lineage / serve`) and the
  README six-step demo.
- v0.75: Carina v0.3 spec deliverable plus the `Proof`
  primitive; bundled JSON Schemas at
  `examples/carina-kernel/schemas/`; new `vela carina
  list / schema / validate` CLI.
- v0.78: `Atlas` (`vat_<id>`) primitive in Carina v0.4.
- v0.80: `Constellation` (`vco_<id>`) primitive in Carina
  v0.5; per-event `attestation.recorded` event kind.
- v0.83: discord detectors (`evidence_gap`,
  `provenance_fragile`, `status_divergent`) over the live
  event log.
- v0.85: BelnapStatus surfaced in the Workbench. Per-finding
  Belnap letter (N / T / F / B) derived deterministically
  from the support set.
- v0.86: ancestor_closure primitive wired into federation
  divergence reports.
- v0.88: provenance polynomial structure in the API.
- v0.89: `schema_artifact_id` additive on `StateEvent`.
- v0.90: five substrate theorems machine-checked in Lean 4
  (Theorems 1 to 5, replay convergence + provenance
  retraction monotonicity + status-provenance soundness +
  detector monotonicity to frontier upward closure +
  hash-DAG log integrity). See `lean/Vela/`.
- v0.91: README-demo gate scripts/test-readme-demo.sh.
- v0.92: `POST /api/proposals/from-carina` agent
  write-target.
- v0.94: public conformance contract at `conformance/`.
- v0.95: `vela discord` aggregate CLI.
- v0.96: replay perf characterized at O(N^2); deferred to
  v0.105.
- v0.97: `/api/discord` HTTP endpoint mirroring CLI.
- v0.99: mixed-folder ingest dispatches every content type
  in stable order (notes / scout / data) with an unhandled-
  extension warn line.
- v0.100: publish-pull round-trip exercised end-to-end
  against the live hub.
- v0.101: `vela registry publish` auto-registers the owner
  actor when the actors set is empty.
- v0.102: ingest-doi hint plus README path-precedence note;
  full crates.io + PyPI publish round (v0.102 is the first
  published binary that matches repo state since v0.77).
- v0.103: `vela quickstart` wizard composes init + sign +
  actor add + finding add in one shot.
- v0.104: multi-sig kernel correctness fix.
  `sign::canonical_json` strips
  `flags.jointly_accepted` from the signing preimage so
  the v0.37 threshold flow is verifiable end-to-end;
  `verify_frontier_data` iterates every signed envelope
  individually so multi-sig findings report all distinct
  signers. Byte-compatible with every existing on-disk
  signature because `jointly_accepted=false` was already
  skip-serialized.
- v0.105: O(N) replay via per-replay finding-id index in
  the reducer. The v0.96-deferred optimization landed.
  Public `apply_event` signature unchanged; replay loop
  uses the new `apply_event_indexed`.

For per-cycle release notes (started, ended, baseline,
result, gates, notes), see
`docs/SESSION_LOG_2026-05-08.md`.

## State integrity and impact

Vela separates structural correctness from scientific incompleteness.

Accepted events are the append-only authority. Materialized frontier JSON is the
replay output. A proposal can be pending, accepted, rejected, or held for
revision, but it does not become trusted frontier state until an accepted event
exists and replay agrees with the materialized state.

The protocol exposes two read-only checks:

```bash
vela integrity <FRONTIER> [--json]
vela impact <FRONTIER> <vf_id> [--depth N] [--json]
```

`vela integrity` reports duplicate event ids, orphan event targets, replay
conflicts, accepted proposals without applied events, accepted events without
proposal ids, stale proof state, and accepted artifact proposals that lack a
source locator or content hash.

`vela impact` reports declared downstream dependents for a finding across
`supports`, `depends`, `contradicts`, and cross-frontier targets. It is
non-mutating and does not change confidence.

*Vela Protocol Specification v0.105.0 - May 2026*
