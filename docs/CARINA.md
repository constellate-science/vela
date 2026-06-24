# Carina kernel

Carina is the technical kernel under Vela. It defines the primitive
objects, events, provenance fields, and review boundaries that make a
scientific frontier replayable.

Vela is the product and state substrate. Carina is the object and event
model. Relay is the adapter layer that turns outside activity into
Carina packets and Vela proposals.

The split is:

```text
Carina defines the primitives.
Vela makes them compound.
Relay brings outside activity to the review boundary.
Navigator is the Workbench interface over the state.
```

Carina is not a separate app, social network, hub, or runtime. It is the
kernel spec that lets other systems emit scientific objects Vela can
validate, preview, review, and record.

In a frontier repository, Carina appears as a dependency declared in
`frontier.yaml` and pinned in `vela.lock`. There is no top-level `carina/`
folder in the default repo shape. The frontier repo stores Vela state,
review material, sources, artifacts, proof, and exports.

## v0.2 scope

Carina v0.2 is a reconciliation cut over v0.1. It does not change the
primitive set or the kernel boundary. It closes two gaps the v0.66
coverage agent surfaced:

1. The Proposal primitive now carries a top-level `actor` block in the
   canonical sample, matching the validation rule that every proposal
   preserves an actor id. v0.1 left the actor implicit in provenance.
2. The lift between the kernel interchange shapes and the heavier
   typed-pole shapes inside the protocol crate is now documented as a
   deliberate two-tier split rather than a silent divergence. See
   "Two-tier shape: kernel interchange vs typed pole" below.

The v0.1 example bundle stays in place at
`examples/carina-kernel/primitives.v0.1.json` for backward-compat
replay. The v0.2 sample lives at
`examples/carina-kernel/primitives.v0.2.json`. Both are pinned by the
integration test in `crates/vela-protocol/tests/carina_examples.rs`.

## v0.1 scope

Carina v0.1 covers the minimum object and event model needed for
artifact-to-state review.

| Primitive | Role |
| --- | --- |
| `Finding` | A scoped scientific claim with conditions, evidence, confidence, provenance, and links. |
| `Evidence` | A source span, table, measurement, artifact, dataset row, registry field, or observation supporting or constraining a finding. |
| `Artifact` | A content-addressed file, source record, code object, protocol, label, dataset, table, or agent output. |
| `Proposal` | A proposed frontier state change. Agent output and source updates stay here until review. |
| `Diff` | The before and after shape of accepting a proposal. |
| `Event` | An append-only accepted or rejected state transition. Replay uses events in order. |
| `Attestation` | A signed review, validation, replication, rejection, or judgment by an actor. |
| `Question` | An explicit uncertainty or missing-evidence target. |
| `Protocol` | A method for producing evidence. |
| `Experiment` | A test intended to update frontier state. |
| `Mechanism` | A causal or structural annotation over finding links. |
| `Lineage` | Parentage and provenance across artifacts, evidence, findings, proposals, and events. |
| `Confidence` | A bounded belief score plus method, scope, and review history. |

## Minimal object shapes

These are examples, not a complete wire schema for every Vela object.
They show the fields another system must preserve if it wants its output
to cross the review boundary cleanly.

```json
{
  "schema": "carina.finding.v0.1",
  "id": "vf_example",
  "assertion": {
    "text": "APOE4 carriers show accelerated BBB dysfunction in a bounded early-AD cohort.",
    "type": "mechanistic"
  },
  "conditions": {
    "text": "Human cohort; early symptomatic or cognitively at-risk Alzheimer's disease; assay and genotype boundary required."
  },
  "evidence_ids": ["ve_example"],
  "confidence": {
    "score": 0.72,
    "method": "reviewer_estimated",
    "scope": "bounded human biomarker evidence"
  },
  "lineage": {
    "source_ids": ["src_example"],
    "artifact_ids": ["va_example"]
  },
  "status": "proposed"
}
```

```json
{
  "schema": "carina.evidence.v0.1",
  "id": "ve_example",
  "source_id": "src_example",
  "artifact_id": "va_example",
  "locator": "doi:10.1038/s41586-020-2247-3",
  "span": "figure/table/registry field or quoted source span",
  "supports": ["vf_example"],
  "limitations": ["Does not establish treatment benefit."]
}
```

```json
{
  "schema": "carina.event.v0.1",
  "id": "vev_example",
  "kind": "finding.reviewed",
  "target": { "type": "finding", "id": "vf_example" },
  "actor": { "id": "reviewer:demo", "type": "human" },
  "timestamp": "2026-05-07T00:00:00Z",
  "reason": "Accepted as bounded human BBB-biomarker evidence. It does not settle treatment effect.",
  "payload": {
    "proposal_id": "vpr_example",
    "status": "accepted"
  }
}
```

Full examples for all v0.1 primitives live in
`examples/carina-kernel/primitives.v0.1.json`. The file is the
canonical sample bundle: thirteen entries, one per primitive,
covering Finding, Evidence, Artifact, Proposal, Diff, Event,
Attestation, Question, Protocol, Experiment, Mechanism, Lineage, and
Confidence. The integration test
`crates/vela-protocol/tests/carina_examples.rs` keeps the example
file aligned with this spec: every documented primitive has a
matching entry, every entry declares the right `carina.<kind>.v0.1`
schema, and the Finding entry's confidence score stays inside
`[0.0, 1.0]`.

## State rule

Artifacts are not truth by default.

An agent report, dataset export, ScienceClaw-shaped artifact, lab file,
registry record, paper, or platform comment can enter Vela as source
material. It becomes frontier state only when a proposal is reviewed and
accepted into an event.

```text
artifact
  -> evidence or artifact proposal
  -> finding, gap, caveat, or review-note proposal
  -> reviewer diff
  -> accepted or rejected event
  -> updated frontier and proof packet
```

This is the difference between an artifact DAG and a scientific state
substrate. Carina preserves lineage. Vela records epistemic change.

## Artifact packet boundary

`carina.artifact_packet.v0.1` is the interchange object for external
systems. It is intentionally local and dependency-free.

Required fields:

- `schema`: `carina.artifact_packet.v0.1`
- `packet_id`: stable `cap_*` packet id
- `producer`: source system, runtime, agent, lab, or reviewer identity
- `topic`: bounded frontier topic
- `created_at`: ISO timestamp
- `artifacts[]`: immutable artifacts with locator, content hash, and
  parent ids
- `candidate_claims[]`: proposed claims linked to packet artifacts
- `open_needs[]`: questions or missing-evidence records that should
  become gap proposals
- `caveats[]`: optional source-scope warnings
- `source_refs[]`: optional upstream source locators

The schema is in `schema/carina.artifact-packet.v0.1.json`. A minimal
valid packet is in `examples/bridge-kit/packet.json`.

## Review contract

`artifact.assert` proposals can be applied during import when a reviewer
chooses `--apply-artifacts`. Truth-changing findings, gaps,
contradiction notes, and attestations remain review-gated.

```bash
vela ingest <frontier> packet.json --actor agent:demo --json
vela ingest <frontier> packet.json --actor agent:demo --apply-artifacts
vela runtime-adapter run <frontier> scienceclaw-artifact-v1 --input export.json --actor reviewer:demo --json
vela proposals preview <frontier> vpr_... --json
vela proposals accept <frontier> vpr_... --reviewer reviewer:demo --reason "Accepted bounded update"
```

External comments, votes, agent confidence, and platform reputation are
stored as source context. They do not become canonical truth directly.

## Adapter mappings

| External surface | Carina mapping | Review rule |
| --- | --- | --- |
| ScienceClaw-shaped artifact DAG | `Artifact`, `Lineage`, candidate `Finding`, `Question` | Artifacts may be accepted; findings and gaps need review. |
| Science Beach-style hypothesis thread | post artifact, candidate `Finding`, comments as source context | Social signals stay context; only reviewed proposals become events. |
| Agent4Science-style review | review artifact, `Attestation` candidate, contradiction or note proposal | Review text can propose an attestation, but signer and scope must be explicit. |
| ClinicalTrials.gov record | source `Artifact`, registry-field `Evidence`, optional review-note proposal | Registry metadata can trigger review; it does not settle interpretation. |
| Paper or dataset | source `Artifact`, source-span `Evidence`, candidate `Finding` | Accepted state must preserve locator, span, conditions, and caveats. |

## Validation rules

Carina v0.1 requires the following before source material can create a
reviewable Vela proposal:

- Every artifact has an id, kind, locator, content hash, and parent ids.
- Every parent id references an artifact in the same packet.
- Every candidate claim references at least one artifact id.
- Every open need has a stable id and question text.
- Every proposal preserves packet id, external object ids, actor id, and
  source locators.
- Every accepted event names its target, actor, timestamp, proposal id,
  status, and reason.
- Every confidence value has scope and method when it is promoted into a
  finding.
- Retractions, rejections, and request-revision decisions preserve
  history. They do not delete the source object.

## Python loader

A Python mirror of the split-repo loader lives at
`clients/python/vela_loader.py`. The function
`load_frontier_repo(path)` walks `.vela/findings/`, `.vela/events/`,
`.vela/proposals/`, `.vela/reviews/`, and `.vela/confidence-updates/`,
parses `frontier.yaml`, and rehydrates the
`dependencies.frontiers_v2` block into `project.dependencies` so a
Python replay can resolve cross-frontier link references the same way
the Rust loader does on every load. The reducer arms in
`vela_reducer.py` apply the event log on top of genesis findings. The
yaml parsing prefers `pyyaml` if it is installed and falls back to a
small stdlib parser that handles the manifest's known shape, so no
third-party dependency is required. The loader does not yet hydrate
`vela.lock`, signatures, replications, datasets, predictions,
resolutions, or the v0.55/v0.56 trajectory and evidence-atom
materializers; those remain Rust-only for now.

## Two-tier shape: kernel interchange vs typed pole

Carina has two shapes for several primitives, and they are deliberately
different. The kernel layer is the lightweight interchange shape that
external systems emit and that the canonical example file documents.
The typed pole is the heavier in-bundle and replay shape that lives as
Rust structs inside `crates/vela-protocol/src/bundle.rs` and
`crates/vela-protocol/src/events.rs`.

The split is real. `vela_protocol::bundle::Evidence` carries
`type`, `model_system`, `method`, `sample_size`, and an
`extraction_confidence` field. The Carina v0.1 interchange Evidence
carries `source_id`, `artifact_id`, `locator`, `span`, `supports`,
and `limitations`. `vela_protocol::bundle::Artifact` carries `name`,
`storage_mode`, `provenance`, `created`, and a content-hash block.
The Carina interchange Artifact carries `id`, `kind`, `locator`,
`content_hash`, and `parents`. `vela_protocol::events::StateEvent`
carries `before_hash`, `after_hash`, and a typed payload. The Carina
interchange Event carries `target`, `actor`, `timestamp`, `reason`,
and an open `payload` object.

The lift from kernel to typed pole happens through the
artifact-to-state pipeline at
`crates/vela-protocol/src/artifact_to_state.rs`. That pipeline takes a
`carina.artifact_packet.v0.1` packet plus its candidate claims and
produces typed `StateProposal`, `StateEvent`, and bundle entries.
Replay reconstructs the typed pole from the event log without
re-reading the kernel packet, which is why the heavier hash and
provenance fields belong on the typed side.

Both poles are byte-deterministic. The cross-impl reducer fixtures
in the protocol crate's test suite confirm that the lift produces the
same bytes on every run. External adapters target the kernel shape.
Internal replay and review use the typed shape. Neither side hides
the other.

## v0.6 scope (Trial primitive)

Carina v0.6 (shipped at substrate v0.113) adds the seventeenth
primitive, `Trial`. A `Trial` (`vtri_<id>`) carries the long-
lived metadata of a single clinical trial (phase, status,
registry id, intervention, indication, primary and secondary
endpoints, sponsor, frontier pointer) so the Vela frontier
that holds the trial's findings, evidence, and proposal stream
can also surface the trial-shape attributes that don't change
between events. The shape aligns with the
`examples/trial-evidence-packet` reference frontier shipped at
v0.112.0; pre-v0.6, that frontier had to encode trial metadata
ad-hoc on its seed finding. v0.6 makes the shape first-class
in Carina without introducing a new event kind in the
substrate kernel (Trial is metadata, not state).

`Trial` fields:

- `id` (`vtri_<id>`).
- `title` (free-form display label).
- `phase` (one of `preclinical`, `phase_0`, `phase_1`,
  `phase_2`, `phase_3`, `phase_4`, `observational`).
- `status` (one of `planned`, `recruiting`, `active`,
  `completed`, `suspended`, `terminated`, `withdrawn`).
- `registry_id` (optional; ClinicalTrials.gov NCT, EudraCT,
  ISRCTN, or sponsor protocol number).
- `intervention` (optional; short prose).
- `indication` (target condition).
- `primary_endpoint` (optional).
- `secondary_endpoints` (optional array).
- `arms` (optional array of arm descriptions).
- `sponsor` (optional).
- `start_date` / `end_date` (optional ISO date strings).
- `frontier_id` (optional `vfr_<id>` pointer to the Vela
  frontier carrying the trial's findings and proposals).

The bundled v0.6 example is at
`examples/carina-kernel/primitives.v0.6.json`. It carries all
17 primitives.

### v0.6 changelog

- New `Trial` primitive at
  `examples/carina-kernel/schemas/trial.schema.json`.
- v0.5 and earlier example bundles preserved untouched. v0.6
  bundle added at
  `examples/carina-kernel/primitives.v0.6.json`.
- The bundled Carina schema set now covers 17 primitives.
- No new event kinds; trial state transitions remain
  expressible through existing finding / proposal / event
  primitives on the trial's frontier.

## v0.5 scope (Constellation primitive)

Carina v0.5 (shipped at substrate v0.80) adds the sixteenth
primitive, `Constellation`, completing the ecosystem-layer
shape. A `Constellation` (`vco_<id>`) is a network of
connected Atlases across scientific domains. It composes one
or more Atlas references plus inter-Atlas bridge declarations,
which the substrate's cross-Atlas bridge auto-discovery walks
when a Constellation is materialized.

`Constellation` fields:

- `id` (`vco_<id>`).
- `name` (free-form display label).
- `atlas_ids` (array of `vat_<id>` references; declares
  composition).
- `bridges` (array of cross-Atlas bridge declarations; each
  carries an endpoint pair plus a confirmation status from
  the auto-discovery primitive).
- `created_at` (RFC3339).

The bundled v0.5 example is at
`examples/carina-kernel/primitives.v0.5.json`. It carries all
16 primitives.

### v0.5 changelog

- New `Constellation` primitive at
  `examples/carina-kernel/schemas/constellation.schema.json`.
- v0.4 and earlier example bundles preserved untouched. v0.5
  bundle added at
  `examples/carina-kernel/primitives.v0.5.json`.

## v0.4 scope (Atlas primitive)

Carina v0.4 (shipped at substrate v0.78) adds the fifteenth
primitive, `Atlas`. An `Atlas` (`vat_<id>`) is a living,
versioned map of a scientific domain composed of one or more
frontiers. It pairs a domain scope-note with a list of
composing-frontier references plus declared intra-Atlas
bridges (entity overlaps that span composing frontiers).

`Atlas` fields:

- `id` (`vat_<id>`).
- `name` (free-form display label).
- `domain` (short scope tag; e.g. `"oncology translation"`).
- `scope_note` (longer prose framing).
- `frontier_ids` (array of `vfr_<id>` references).
- `bridges` (array of intra-Atlas bridge declarations).
- `created_at` (RFC3339).

The bundled v0.4 example is at
`examples/carina-kernel/primitives.v0.4.json`.

### v0.4 changelog

- New `Atlas` primitive at
  `examples/carina-kernel/schemas/atlas.schema.json`.
- v0.3 example bundle preserved at
  `examples/carina-kernel/primitives.v0.3.json`. v0.4 bundle
  added at `examples/carina-kernel/primitives.v0.4.json`.

## v0.3 scope (Gowers-shaped + spec deliverable)

The 2026-05-08 Gowers post on ChatGPT-5.5-Pro doing PhD-level
research argues for two things Vela's substrate already supports
informally and now ships explicitly:

1. **A different repository where AI-produced results can live**,
   moderated by human certification of correctness.
2. Stronger: results "formalized by a proof assistant," with the
   verifier output as the certificate.

Vela has always carried `actor.type: "human" | "agent"` on every
event and proposal. v0.3 extends Carina with a fourteenth
primitive, `Proof`, so AI-produced or human-produced findings can
carry a first-class slot for proof-assistant verifier output.

`Proof` fields:

- `id` (`vpf_<id>`).
- `tool` (one of `lean4`, `coq`, `isabelle`, `agda`, `metamath`,
  `rocq`, `other`).
- `tool_version` (free string, e.g. `"4.7.0"`).
- `script_locator` (content-addressed pointer; `sha256:<64hex>`,
  URL, `doi:`, or `git+commit`).
- `verifier_output_hash` (`sha256:<64hex>`).
- `verified_at` (RFC3339).
- `target_finding_id` (`vf_<id>`).
- Optional `scope_note` for what stays informal vs. formal.

The bundled v0.3 example is at
`examples/carina-kernel/primitives.v0.3.json`. It carries all 14
primitives, including `proof` formalizing the example finding
under Lean 4.

### Spec deliverable: 14 hand-authored JSON Schemas

v0.3 ships `*.schema.json` files for every primitive at
`examples/carina-kernel/schemas/` (public source-of-truth) and a
mirrored copy at `crates/vela-protocol/embedded/carina-schemas/`
(for `cargo publish`). Schemas are JSON Schema draft-07,
hand-authored to match the v0.3 example shapes.

The bundled JSON Schemas at `examples/carina-kernel/schemas/` are the public
contract for validating any Carina-shaped JSON against the primitive set.

The substrate's signature-pure event-payload validator at
`crates/vela-protocol/src/events.rs::validate_event_payload`
remains authoritative for replay. The schemas are the public
contract. The conformance test
`crates/vela-protocol/tests/carina_examples.rs::carina_event_payload_validator_agrees_with_schema`
cross-checks the two.

### v0.3 changelog

- New `Proof` primitive (Gowers-shaped) at
  `examples/carina-kernel/schemas/proof.schema.json`.
- Hand-authored schemas for all 14 primitives at
  `examples/carina-kernel/schemas/`.
- Bundled schema mirror at
  `crates/vela-protocol/embedded/carina-schemas/` so the crate
  publishes them.

- Three new conformance round-trip tests in
  `tests/carina_examples.rs`. Test count rises 599 to 602.
- `Artifact.kind` documents `proof_script` as a recognized kind
  for proof artifacts that back a `Proof` primitive.
- v0.1 and v0.2 example bundles preserved untouched. v0.3 bundle
  added at `examples/carina-kernel/primitives.v0.3.json`.

## v0.2 changelog

- Proposal primitive now carries a top-level `actor` block in the
  canonical example, satisfying the validation rule that every proposal
  preserves an actor id. The substrate convention is
  `{"id": "<reviewer-or-agent-id>", "type": "human" | "agent"}`.
- Two-tier shape documented as a deliberate split between kernel
  interchange shapes and the typed pole inside `vela-protocol`. The
  lift point is named (`artifact_to_state.rs`) and the replay
  determinism guarantee is stated.
- v0.1 example bundle preserved at
  `examples/carina-kernel/primitives.v0.1.json`. v0.2 bundle added at
  `examples/carina-kernel/primitives.v0.2.json`.
- No Rust struct definitions changed. No new primitives. No new
  validation rules beyond the proposal-actor one already in v0.1.

## Outside this release

Carina v0.1 does not define a live lab runtime, Atlas capability graph,
Registry federation protocol, multi-actor joint signatures, or a universal
ontology for all of science. Those are later layers. The current cut is
the kernel needed to move from source activity to reviewed frontier state.
