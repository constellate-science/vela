# Vela Conformance

This directory ships the public conformance contract for any
implementation that claims to be Vela-compatible.

A Vela-compatible implementation must agree with the canonical Rust
reducer on per-kind mutation rules across findings, negative results,
trajectories, and artifacts. The fixtures here are the test vectors that
prove that agreement.

## Contract

Given any fixture file `cascade-fixture-NN.json`:

1. Parse the JSON. It contains:
   - `genesis_findings`: the initial finding bundles, plus initial
     negative results, trajectories, and artifacts.
   - `event_log`: the canonical event log (an ordered array of
     `StateEvent` records).
   - `expected_states`: the post-replay reducer-effects array, sorted by
     finding id, capturing only the fields the reducer mutates
     (`retracted`, `contested`, `review_state`, `confidence_score`,
     `annotation_ids`, plus the analogous projections for negative
     results, trajectories, and artifacts).

2. Apply your reducer to `(genesis_findings, event_log)` to produce a
   post-state.

3. Compute the same effect-row shape from your post-state. The shape is
   defined in `crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs`.

4. Assert deep equality with `expected_states`.

If your implementation passes all 9 fixtures, you have shown agreement
with the canonical reducer on every event kind currently in the
substrate.

## Event kinds covered

The fixtures collectively exercise every event kind in the v0.93
substrate:

```
finding.asserted
finding.reviewed         (statuses: accepted, contested, needs_revision, rejected)
finding.noted
finding.caveated
finding.confidence_revised
finding.rejected
finding.retracted
finding.dependency_invalidated
finding.span_repaired
finding.entity_resolved
finding.entity_added
negative_result.asserted
negative_result.reviewed
negative_result.retracted
trajectory.created
trajectory.step_appended
trajectory.reviewed
trajectory.retracted
artifact.asserted
artifact.reviewed
artifact.retracted
tier.set
attestation.recorded
bridge.reviewed
replication.deposited
prediction.deposited
evidence_atom.locator_repaired
```

Fixture 08 specifically exercises the v0.73+ event kinds
(`bridge.reviewed`, `replication.deposited`, `prediction.deposited`)
that have historically been the boundary of cross-impl coverage. A
fully conformant implementation handles them as no-ops on the
finding-effect-row digest if it does not yet implement the underlying
side-table mutations.

## Reference implementations

Three reducers run these fixtures green today:

- `crates/vela-protocol/src/reducer.rs` (Rust, canonical).
- `clients/python/vela_reducer.py` (Python, second implementation).
- `clients/typescript/vela_reducer.ts` (TypeScript, third implementation
  with v0.82 no-op handlers for newer event kinds).

To verify a fourth implementation, walk the fixtures with your reducer
and run the four-step contract above.

## Running the canonical regression

The Rust regression runs as part of the workspace test suite:

```bash
cargo test -p vela-protocol --test cross_impl_reducer_fixtures
```

The Python regression runs from `release-check.sh`:

```bash
./scripts/release-check.sh
```

Both compare against the same fixtures shipped here.

## Extending the conformance set

When a new event kind lands in the substrate, the conformance fixtures
need a new vector that exercises it. The pattern is:

1. Update `crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs` to
   produce a fixture covering the new kind.
2. Run the test; it regenerates the corresponding JSON file in
   `crates/vela-protocol/tests/fixtures/`.
3. Copy the regenerated fixture(s) to `conformance/fixtures/`.
4. Update this README's "Event kinds covered" list.

Any implementation that has not yet implemented the new event kind must
either add a handler or return a no-op-on-digest result for it; the
fixture pins the expected reducer-effect shape so silent disagreement
becomes a failing test.

## License

These fixtures are part of the Vela project and are licensed under the
same terms as the rest of the repository (Apache 2.0 or MIT, dual).

## Status

This conformance contract is at v0.94. The fixture set will grow as the
substrate grows; the contract shape (parse, replay, compare effect
rows) is stable and is the point at which an external implementation
declares Vela-compatibility.

For the formal substrate properties these fixtures empirically test,
see `docs/THEORY.md` and the machine-checked theorems in `lean/`.
