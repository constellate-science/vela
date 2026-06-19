# The Minimal Core: six primitives of mathematical state change

> Doc of record for Workstream 0 (the aggressive minimal core). This names the six generic
> primitives that constitute "the mechanics of accepted mathematical state," states the identity
> and wire contract each is frozen to, and points at the conformance test that pins it. A second
> producer reads exactly these. Everything else, including the domain vocabulary (Problem,
> StatementVariant, Obstruction, Bridge), is deliberately NOT promoted; see the last section.
>
> Freeze means two things only: a stable identity + wire contract, and a conformance test that
> fails if the contract moves. It does not mean new abstraction. Promotion of a domain noun to a
> generic type happens when a live consumer forces it, never speculatively. The Attempt Packet and
> ProducerRef below were promoted because the H1 ablation (Workstream A) needed a producer-agnostic
> attempt; that is the pattern.

## The six

### 1. Frontier
- **Is:** a unit of governed accepted state, identified by `frontier_id`, whose accepted content
  is a pure function of its signed event log. `roots` / `snapshot_hash` address the materialized
  view. (`project.rs`, `frontier_repo.rs`.)
- **Frozen contract:** the `frontier_id` and the genesis-rooted log identify the frontier; the
  materialized view is reproducible from the log alone; no field of the accepted view is authored
  out of band.
- **Pinned by:** `vela reproduce` + `vela frontier materialize` byte-identical on every committed
  frontier; the executable no-hidden-state law (`conformance/vela_no_hidden_state_check.py`); the
  finite-ranked kernel fixture (`conformance/vela_v09_sidon_kernel_fixture.py`).

### 2. StateTransition
- **Is:** a single signed event appended to a frontier's log and applied by the reducer. This is
  the ONLY way accepted state changes. (`events.rs`, `reducer.rs`.)
- **Frozen contract:** the reducer is a pure left fold over the event sequence; an event's `id`
  hashes its `after_hash`; canonical JSON is presence-sensitive, so the wire shape is part of the
  contract. Two independent reducer implementations must agree bit-for-bit on the derived state.
- **Pinned by:** the cross-implementation reducer fixtures (`conformance/fixtures/`, Rust ==
  Python finding-state digest, gate step `gate-conformance-py-rust`); canonical hashing vectors
  (`conformance/canonical-hashing.json`, `verify_canonical_hashing.py`).

### 3. Receipt
- **Is:** a content-addressed witness that a verification or retrieval happened: a
  `VerifierAttachment`, a signed manifest, a witness blob under `vela-verify`. Provenance, not a
  verdict; registering a receipt never accepts a claim.
- **Frozen contract:** a receipt addresses exact bytes (the witness / manifest), and re-checking
  those bytes under the frozen verifier reproduces the same pass/fail. A receipt carries no trust
  weight on its own; acceptance is a separate key-custody event.
- **Pinned by:** `vela reproduce` (every witness re-checks under the frozen `vela-verify`);
  canonical hashing vectors for the content addresses.

### 4. Replay
- **Is:** loading a frontier IS replaying its log IS reducing it. `reducer::replay_from_genesis`
  + `verify_replay`. (`reducer.rs`.)
- **Frozen contract:** loader == reducer (no separate read path that could drop state);
  deterministic across runs and implementations; the determinism guarantee is the frozen one the
  rest of the core rests on.
- **Pinned by:** `conformance/vela_no_hidden_state_check.py` (the executable Conformance Law);
  `vela reproduce`; `verify_replay` tests.

### 5. Task
- **Is:** a unit of producible work: a target obligation on a base frontier root. Today it is
  realized for one profile (`vtk_` in `sidon_profile/producer.rs`); the Attempt Packet (below)
  carries `target_obligation_id`, `statement_variant_id`, `base_frontier_root` generically.
- **Frozen contract (for the Sidon profile; generic Task packet promotion deferred to Workstream
  B):** a task names a target on a specific base frontier root, so what a producer is asked to do
  is pinned to the state it consumed.
- **Pinned by:** the Sidon producer profile + kernel fixture. The generic Task type is promoted
  when a second producer class needs it (the forcing-function discipline), not before.

### 6. Producer
- **Is:** the agent that reads a frontier root and emits an Attempt. Identified by
  `ProducerRef { system, version, config_digest }`. The Attempt Packet (`base_frontier_root`,
  `target_obligation_id`, `statement_variant_id`, `method_families`, `remaining_obligations`,
  `named_obstructions`, `producer`) is the normalized output. (`attempt.rs`, promoted in WS-A1.)
- **Frozen contract:** an Attempt is content-addressed (`vat_`) and key-independent (the id does
  not depend on who signed it); the packet fields are additive and `skip_serializing_if` empty, so
  a legacy attempt's `vat_` is unchanged (byte-safe promotion); `base_frontier_root` pins the
  attempt to the state it consumed, which is the spine of the retained-producer loop and the H1
  ablation.
- **Pinned by:** `conformance/attempt-id.json` + `verify_attempt_id.py` (cross-impl `vat_`);
  the `packet_fields_round_trip_and_legacy_id_is_stable` unit test.

## Deliberately NOT promoted (domain vocabulary stays local)

`Problem`, `StatementVariant`, `Formalization`, `Obstruction`, `Bridge` remain domain nouns in
the Sidon profile and the Erdős data. They are promoted to generic types only when the ablation
or a second producer forces it (Workstream B/C). Promoting them now would be the founder
abstraction trap: refining the description ahead of a consumer. The bar for promotion is a live
second consumer, the same bar that promoted ProducerRef and the Attempt Packet.

## Why this is enough

The six primitives are what a producer must understand to read state, do work, and submit it:
a Frontier to read, a Task to attempt, a Producer identity to attempt as, an Attempt that becomes
a StateTransition once accepted, a Receipt as the evidence, and Replay as the guarantee that what
they read is exactly what is true. Each is pinned by a test that fails if its contract moves. No
AI sits in any trust path: a Receipt is provenance, acceptance of a StateTransition is a
key-custody human decision, and replay determinism is what makes both checkable by anyone.
