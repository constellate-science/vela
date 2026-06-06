# Vela protocol guarantees: spec ⇄ proof ⇄ conformance

What makes a protocol *real* (git, TCP/IP) is not one document but a closed triangle: a normative
spec clause, a machine-checked guarantee, and an executable conformance test for every load-bearing
invariant — and two interoperating implementations that agree on the vectors. This file is that map
for Vela. Every row cites a concrete artifact; if a row's three cells disagree, that is a bug.

Two interoperating implementations today: the Rust reference (`crates/vela-protocol/`, conformance
runner `conformance.rs`) and the Python reducer (`clients/python/vela_reducer.py`). `conformance/verify.py`
replays the 12 canonical fixtures through the Python reducer (currently 12/12, integrity preflight green).

## The triangle

| Invariant | Normative spec (PROTOCOL.md) | Machine-checked theorem (`lean/Vela/`) | Conformance vector |
|---|---|---|---|
| **Content addressing** `id = vf_/vev_… + H(canon(o))` | §3 content addressing | `CanonicalEventId.lean` (T9, serialize-then-hash determinism); `Log.lean` T5 (hash injectivity model) | `tests/conformance/id-generation.json` |
| **Canonical bytes** (sorted keys, compact, RFC-8785-style) | §3 + `canonical.rs` header | `CanonicalEventId.lean`; `ScientificDiffPackId.lean` | `tests/conformance/id-generation.json` |
| **Replay determinism** `S_F = R(E)` is a pure function of `E` | §6 proposal/event protocol | `Log.lean` T1 (canonical-order convergence); `ReducerModel.lean` `replay_deterministic` | the 12 `conformance/fixtures/cascade-*.json` |
| **Incremental replay** `R(E++F) = R_{R(E)}(F)` | §6 (append + reduce) | `ReducerModel.lean` `replay_append`; `ReplayAppend.lean` | cascade fixtures (event-prefix replays) |
| **Append-only log** | §6, §7 storage | `ReducerModel.lean` `step_log_grows` | fixtures (event arrays are ordered, append-only) |
| **Concurrent-event commutativity** (disjoint) | §6 federation/merge | `ConcurrentReplay.lean` T12 | `tests/conformance/` merge cases |
| **Retraction monotonicity** (support can only shrink) | §6 retraction | `Provenance.lean` `retraction_monotone` (T2) | `tests/conformance/retraction-propagation.json` |
| **No zombie findings** (T-support killed ⇒ status ≠ T) | §6 + §4 confidence | `Provenance.lean` `status_provenance_sound_t` (T3) | `tests/conformance/retraction-propagation.json` |
| **Frontier upward closure** (sub-context discord ⇒ super-context discord) | §5 links / discord | `Provenance.lean` `frontier_upward_closed` (T4) | `tests/conformance/` discord cases |
| **Descriptor preservation** under accept/eval/replay | §6 (reducer arms) | `ReducerModel.lean` `acceptPack_preserves_descriptors`, `eval_then_pack_preserves`, `replay_preserves_descriptors` (de-hollowed T28/T34, now proven) | `tests/conformance/` descriptor cases |
| **Cross-frontier transfer soundness** (verified transports) | §9.1 constellation (THEORY.md) | `Transfer.lean` `transfer_sound` (T23) + concrete `translateTransfer`/`sidon_translate_sound` | the certified-frontier transfers (Sidon→B_h, code→E8) |
| **Signature stability / uniqueness** | §6 signing | `Signing.lean` (T6), `SignatureUniqueness.lean` (T10), `MultiSigThreshold.lean` (T11) | `tests/conformance/` signing cases |
| **Spec-surface freeze** (event/proposal kinds frozen per version) | `SPEC_VERSION.md` | — (hash discipline) | `conformance/spec-surface.v1.json` `surface_sha256` |

## Honesty notes (from `docs/THEORY_AUDIT.md`)

- No theorem uses `sorry`. `hash_injective` / `canonicalBytes_injective` are standard cryptographic /
  serialization idealizations (you cannot prove SHA-256 injective), clearly labeled, not hollow.
- The descriptor-composition theorems T28/T34 *were* hollow (assume-guarantee axioms over an `opaque`
  reducer). They are now backed by `ReducerModel.lean`, which proves the same invariants over a
  concrete reducer — the axioms are realized by a real model.
- `Transfer.transfer_sound` is the *contract* (definitional); `translateTransfer` is the worked
  instance whose `sound` field is a genuinely proven theorem, so the constellation layer carries
  content, not just a signature.

## What "conformant" means (MUST)

An implementation is Vela-v1-conformant iff it: (1) derives every `id` as `prefix + H(canon(o))` with
canonical bytes per `canonical.rs`; (2) reproduces every `tests/conformance/*.json` and `conformance/`
fixture byte-identically; (3) reduces the frozen event/proposal kinds in `spec-surface.v1.json` and no
others (silently); (4) treats retractions as appended events, never deletions; (5) represents genuine
scientific disagreement as Belnap `B` / discord, never as a forced merge. The Rust reference and the
Python reducer both satisfy (1)–(5); a third implementation is conformant exactly when it joins them on
the vectors.
