# Atlas: a living, versioned map of a scientific domain

This doc introduces **Atlas** as the next-layer-up construct above
Vela's existing `frontier` primitive. The ten-year roadmap doc
(internal, May 2026) names Atlas as the unit a non-substrate user
thinks about: "every disease has an Atlas; every Atlas has
frontiers; every frontier has open questions." This file says what
that means concretely, what is shipped today, and what lands in
v0.78+.

## Definitions

- **Frontier** (`vfr_*`). The substrate primitive: a bounded,
  reviewable state over one scientific question. Findings,
  evidence, proposals, events, attestations all live inside one
  frontier. Replay is per-frontier. The substrate has shipped
  this since v0.55; nothing in v0.78+ changes the frontier
  primitive.
- **Atlas**. A living, versioned map of a scientific domain
  composed of one or more frontiers. An Atlas carries:
  - **Composition rules**: which frontiers compose, with what
    cross-frontier dependencies (already represented in
    `frontier.yaml::dependencies.frontiers_v2`).
  - **Bridges**: cross-frontier connections through shared
    entities, mechanisms, or claims (already represented in
    `.vela/bridges/<vbr_*>.json` and the v0.46 Bridge primitive).
  - **Persistent accepted-core**: the union of accepted findings
    across composing frontiers, durable across rounds of review.
  - **Domain-level metadata**: what the Atlas is named, who
    maintains it, what its scope rules are, what is in scope and
    what is not.
- **Constellation**. A network of connected Atlases across
  domains. The doc names this; the substrate does not yet
  represent it. v0.79+.

## Why frontier stays primitive

The temptation when growing the model is to make Atlas the unit
of replay. Don't. The frontier-level invariants (per-frontier
event log, replay determinism, content-addressed identity) are
load-bearing for the substrate's correctness guarantees:

- **Replay determinism**. Given the same event log + same Carina
  kernel digest, Rust + Python reducers produce byte-identical
  finding-state digests. This is per-frontier.
- **Append-only chain**. Each event's `before_hash` welds against
  the previous event's `after_hash` for the same target finding.
  This works because a target finding is in one frontier.
- **Federation**. Two-hub conflict drills move state at the
  frontier granularity. An Atlas-level conflict is decomposed
  into per-frontier conflicts.
- **Proof packets**. A proof packet seals one frontier's state
  at one point in time. An Atlas-level proof is the union of
  its constituent frontier proofs.

An Atlas is therefore a **composition** over frontiers, not a
replacement for them. The doc's ontology is consistent with this.

## What is shipped today (v0.77)

Vela already has the building blocks an Atlas needs:

1. **Multi-frontier projects** under `projects/`. The substrate has
   five today: `anti-amyloid-translation`, `early-ad-biomarker-calibration`,
   `alzheimers-bbb-dysfunction-delivery`, `perturbation-response`,
   and the v0.78-seeded `brain-tumor-translation`.
2. **Cross-frontier dependencies** at the manifest level. The
   `frontier.yaml::dependencies.frontiers_v2` block (v0.67+) names
   downstream frontiers by name, source, vfr_id, and locator.
   `projects/brain-tumor-translation/frontier.yaml` declares
   anti-amyloid as a dependency for the BBB physiology question.
3. **Cross-frontier bridges**. The Bridge primitive (`vbr_*`,
   v0.46) records candidate cross-frontier hypotheses through
   shared entities. The CLI surface is `vela bridge <a> <b>`. The
   bridge.reviewed event (v0.67) makes confirmation a signed
   canonical event.
4. **Cross-frontier impact reports**. `scripts/build-cross-frontier-impact.sh`
   (v0.69) rolls up impact across all reviewed frontiers, scoped
   to accepted-core.

The pattern that emerges: an Atlas in v0.77 is **a curated
collection of project frontiers + their declared cross-frontier
dependencies + their bridges + their cross-frontier impact rollup**.
There is no "Atlas object" yet, but the data is composable.

## Honest limit: bridge detector filter

The substrate's bridge detector at
`crates/vela-protocol/src/bridge.rs::detect_bridges` filters out
**too-generic biological terms** as bridge candidates via
`is_obvious()` at `bridge.rs:153`. Filtered terms include
"blood-brain barrier", "neuron", "DNA", and similar ubiquitous
entities. The motivation is correct: a generic term that appears
in every biology frontier produces noise, not signal.

The consequence is that **the brain-tumor-translation and
anti-amyloid-translation frontiers do not auto-bridge** even
though they share the BBB physiology question, because the only
shared entity is "blood-brain barrier" itself. The substantive
bridge candidates are pericyte loss, claudin-5 / occludin
downregulation, and BBB efflux transporter biology, but the
anti-amyloid frontier's findings are not tagged with the
specific molecular entities that would surface those bridges.

This is solvable two ways:

- **Reviewer-curated bridges**: file an explicit `vela bridge confirm`
  on a `vbr_*` candidate the reviewer cares about, recording the
  bridge as a signed canonical event regardless of automated
  detection.
- **Tag richer entities at finding-add time**: when seeding a
  frontier, include specific molecular entities (pericyte,
  claudin-5, P-glycoprotein) so the auto-detector finds substantive
  candidates.

Both land as v0.78 reviewer-wave work.

## What an Atlas surface would look like (v0.78+)

The roadmap doc names the Atlas-layer surfaces. Concretely:

1. **`vela atlas init <atlas-name>`**. Scaffolds an
   `atlases/<name>/` directory with a `manifest.yaml` listing
   composing frontiers, an `overview.md`, and a per-Atlas review
   policy.
2. **`vela atlas materialize <atlas-name>`**. Builds an
   Atlas-level snapshot: union of accepted-core findings,
   declared bridges, cross-frontier dependency graph, hash digest.
3. **`vela atlas serve <atlas-name>`**. The Atlas-level Workbench
   page: domain overview, per-frontier inboxes, cross-frontier
   bridges, replication queue, decision-brief view.
4. **`vela-atlas` crate** (already namespace-reserved at
   crates.io 0.0.0). Carries the typed Atlas struct, manifest
   parser, and materialization pipeline. The current bridge.rs
   primitives move into this crate when carved out.
5. **`atlas.yaml` schema** (Carina v0.4). New primitive declaring:
   - `atlas_id` (`vat_*`)
   - `name`, `domain`, `scope`
   - `composing_frontiers[]` with vfr_id pointers
   - `bridges[]` with vbr_id pointers
   - `maintainers[]`
   - `review_policy_locator`

Until these ship, an Atlas is a collection of project frontiers
under `projects/<atlas-name>-*/`. The brain-tumor-translation
frontier today is one frontier; "Brain Tumor Translation Atlas"
in the v0.78+ surface will be the Atlas-level wrapper that
composes brain-tumor-translation, anti-amyloid-translation
(via shared BBB physiology), and any future glioma-specific
frontiers (e.g., DIPG, IDH-mutant low-grade glioma) into one
domain map.

## Five candidate first Atlases

The roadmap names "Brain Tumor Translation" as the
recommended first Atlas demonstration. Below the substrate
already supports composing one. Other natural first-Atlas
candidates from the existing project frontiers:

| Atlas (proposed) | Composing frontiers | Status |
|---|---|---|
| Brain Tumor Translation | brain-tumor-translation, (future) DIPG, (future) IDH-mutant glioma | seeded v0.78 |
| Anti-amyloid Translation | anti-amyloid-translation, alzheimers-bbb-dysfunction-delivery | exists at frontier level |
| Early-AD Calibration | early-ad-biomarker-calibration | one frontier; would compose with anti-amyloid for the Atlas-level view |
| Perturbation Biology | perturbation-response, (future) Arc State VCM-derived frontiers | exists at frontier level |
| Math: Additive Combinatorics | examples/sidon-sets/ + future arithmetic-progression frontier | one frontier today |

The brain-tumor Atlas is the smallest demonstrable Atlas because it
already declares a cross-frontier dependency in its manifest (to
anti-amyloid) and carries one explicit reviewer verdict that names
the cross-frontier bridge. The Atlas-level surface in v0.78 should
take this frontier as its first-class demo.

## Atlas vs frontier: which user thinks about which

- **Reviewers** think in frontiers (a bounded question they
  adjudicate).
- **Maintainers** think in Atlases (a domain they curate).
- **Funders, foundations, policy** think in Constellations
  (cross-domain landscapes).
- **The substrate** stays at the frontier granularity.

This is the same pattern as Git: developers think in commits,
release managers think in branches, organizations think in
repositories. The atomic unit (commit / event) doesn't change as
the conceptual layer rises.

## Doctrine

- An Atlas does not rewrite frontier history. Composing two
  frontiers into an Atlas is read-only over their event logs.
- An Atlas does not auto-resolve cross-frontier conflicts. A
  conflict between frontiers is a `frontier.conflict_detected`
  event in each, resolved per the v0.62 conflict-drill pattern.
- An Atlas can declare a maintainer per the doc's roadmap, but
  the maintainer's authority is per-frontier (signing accept
  events) plus Atlas-level (composition decisions). The
  substrate's signing model (Ed25519 per actor) carries through.
- Atlas-level proof packets are the concatenated proof packets
  of composing frontiers + the Atlas-level bridge attestations.
  No new proof primitive needed.

## See also

- `docs/PROTOCOL.md` for the frontier-level normative semantics.
- `docs/CARINA.md` for the kernel primitives. Atlas will land
  as Carina v0.4 with a fourteenth primitive (after Proof in
  v0.3).
- `docs/EVENT_LOG.md` for the canonical event chain at the
  frontier level.
- `docs/AI_ATTRIBUTION.md` for the agent-vs-human-reviewer
  doctrine that scales unchanged from frontier to Atlas.
- `docs/RELAY.md` for the adapter shapes that produce
  proposals; relays write at the frontier level, an Atlas
  reads across them.
- `projects/brain-tumor-translation/` for the v0.78-seeded
  first-Atlas demo target.
- `namespace-stubs/vela-atlas/` for the reserved crates.io
  name carrying the v0.78+ Atlas-level Rust implementation.
