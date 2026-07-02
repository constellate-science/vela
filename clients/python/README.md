# Vela Python client

> **Not distributed on PyPI.** The historical `vela-state` package is
> frozen at a pre-consolidation version and deprecated — do not install
> it. This module lives HERE, in the repo, as the second conformance
> implementation; the distribution channel for Vela is GitHub releases
> (`install.sh`). See THREAT_MODEL.md A9/A10.

Cross-implementation reducer + loader for the Vela protocol. The
authoritative implementation is the Rust workspace under
`crates/vela-protocol/`; this Python module mirrors the kernel
behavior so a third-party Python tool can replay a frontier's
event log and load a split-repo without depending on the Rust
binary.

The cross-impl invariant is: given the same canonical event log
and the same Carina kernel digest, the Rust reducer and the
Python reducer produce byte-equivalent finding-state digests.
This is the load-bearing property that lets Vela claim "the
protocol is implementation-portable."

## What's here

- `vela_reducer.py`: the reducer dispatch. Accepts a canonical
  `StateEvent` JSON dict + a Project state dict, applies the
  reducer arm for the event's `kind`, mutates state in place.
  Mirrors `crates/vela-protocol/src/reducer.rs::apply_event`.

- `vela_loader.py`: the split-repo loader. Reads
  `.vela/findings/`, `.vela/events/`, `.vela/proposals/`, plus
  `frontier.yaml`, populates `project.dependencies` from the v0.59
  `frontiers_v2` schema, replays events through the reducer.
  Mirrors `crates/vela-protocol/src/repo.rs::load_vela_repo`.
  Yaml is parsed via `pyyaml` if present; otherwise a
  hand-rolled parser narrow to the manifest's exact shape.

- `tests/test_loader_frontiers_v2.py`: integration test
  asserting the loader produces the same dependency state +
  finding state the Rust loader does on a real frontier
  (`projects/early-ad-biomarker-calibration`).

## Usage

```python
from vela_loader import load_frontier_repo

project = load_frontier_repo("/path/to/projects/early-ad-biomarker-calibration")

# project is a dict with keys:
#   project: { name, description, dependencies }
#   frontier_id, findings, events, proposals
#   review_events, confidence_updates, manifest
#   negative_results, trajectories, artifacts, evidence_atoms

print(f"frontier: {project['project']['name']} ({project['frontier_id']})")
print(f"findings: {len(project['findings'])}")
print(f"events:   {len(project['events'])}")
print(f"deps:     {len(project['project']['dependencies'])}")
```

## What's NOT here (honest gaps)

The Python loader does not currently rehydrate every field the
Rust loader does. Specifically missing:

- `vela.lock` (lockfile parsing).
- `actors.json`, `peers.json` (federation surfaces).
- `proof-state.json`.
- `signatures/`, `replications/`, `datasets/`, `code-artifacts/`,
  `predictions/`, `resolutions/`, `artifacts/`.
- The v0.55 trajectories+nulls materialization.
- The v0.56 evidence-atom locator materialization.
- `.vela/links/manifest.json` redistribution.
- `project::recompute_stats`.

These are real gaps. The cross-impl invariant currently holds at
the finding-state-digest level only; full Project parity is a
follow-on cycle. Anyone implementing a third Vela language
binding should target the same subset first and document their
gaps as honestly.

## Running the test

The test runs without pytest if needed:

```bash
python3 clients/python/tests/test_loader_frontiers_v2.py
```

Or with pytest:

```bash
python3 -m pytest clients/python/tests/
```

## Cross-impl correctness

The fixture harness is Rust-side at
`crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs`.
Each fixture builder generates an event log; the test exports
the same logs to JSON for the Python reducer to replay; the
finding-state digests must match byte-for-byte. The test file's
`fixture_coverage_includes_every_reducer_arm` assertion
verifies every kind in `REDUCER_MUTATION_KINDS` has a fixture
builder. New kinds added to the Rust reducer must be reflected
in this Python module (a no-op match arm is sufficient if the
kind doesn't mutate finding state) and in the fixture builders.

## Doctrine

The Python loader is a mirror, not the spec. When the Rust and
Python reducers disagree, the Rust implementation is
authoritative; the Python side is the bug. The cross-impl test
catches the disagreement; the spec at `docs/PROTOCOL.md`
documents the canonical behavior.

No silent edits. No event-log mutation. No version-skew
silently glossed; if a new kind appears in the event log that
the Python dispatch doesn't know, the loader raises rather
than silently dropping the event.
