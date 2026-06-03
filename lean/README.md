# Vela Lean theorem formalization

This is a minimal Lean 4 / Mathlib project for the Vela substrate theorem bundle. Thirty-four theorems are machine-checked in this directory.

## Contents

- `Vela/Provenance.lean`
  - Theorem 2: provenance retraction monotonicity
  - Theorem 3: status-provenance soundness, T-side
  - Theorem 4: detector monotonicity implies frontier support upward closure
- `Vela/Log.lean`
  - Theorem 1: replay convergence for deterministic replay over the same finite canonical log
  - Theorem 5: structural hash-DAG log integrity under an abstract injective hash assumption
- `Vela/Signing.lean`
  - Theorem 6: signature stability under cache-flag flips (v0.104 multi-sig canonical-bytes fix)
- `Vela/ReplayIndex.lean`
  - Theorem 7: replay-index correctness under append (v0.105 O(N) replay optimization)
- `Vela/EGZ.lean`
  - Theorem 8: Erdős-Ginzburg-Ziv (1961), n = 2 case (v0.113 substrate-honesty wedge)
- `Vela/CanonicalEventId.lean`
  - Theorem 9: canonical-event-id determinism (serialize then hash; injectivity composes)
- `Vela/SignatureUniqueness.lean`
  - Theorem 10: signature uniqueness under canonical bytes (signing pipeline injective on (event_core, signing_key) pairs)
- `Vela/MultiSigThreshold.lean`
  - Theorem 11: multi-sig threshold soundness (distinct-valid-signer counting rule: distinctness, monotonicity, registration-bound)
- `Vela/ConcurrentReplay.lean`
  - Theorem 12: concurrent-replay commutativity for disjoint events (the reducer's local commutativity assumption made explicit)
- `Vela/FrontierIdDeterminism.lean`
  - Theorem 13: frontier-id determinism (`vfr_*` ids inherit injectivity from canonical event-log bytes + abstract hash; Theorem 9 lifted to the event-log layer)
- `Vela/ProposalIdempotency.lean`
  - Theorem 14: proposal-acceptance idempotency (under the substrate's deduplication policy, accepting the same proposal twice is a no-op)
- `Vela/ConfidenceUpdate.lean`
  - Theorem 15: confidence-update bounds (under the reviewer-policy cap, a single `finding.confidence_revise` event cannot move confidence by more than the declared cap)
- `Vela/GovernedQuorumSoundness.lean`
  - Theorem 16: governed-quorum soundness (a governed owner-rotation accepted by `verify_quorum` is witnessed by `≥ threshold` distinct eligible non-revoked signers; pins v0.145 multi-sig governance)
- `Vela/CoreTheorems.lean`
  - Aggregator import for all theorem modules
- `Vela/Theorems.lean`, `Vela/LogTheorems.lean`, `Vela/CanonicalOrder.lean`
  - Compatibility imports for earlier module paths
- `Vela.lean`
  - Project root import

## Theorem-to-substrate cross-reference

| Theorem | Substrate role | Cross-reference |
|---|---|---|
| 1 | Replay convergence under deterministic replay | `crates/vela-protocol/src/replay.rs`, `tests/replay_*.rs` |
| 2 | Provenance retraction monotonicity | `events.rs::apply_finding_retracted` |
| 3 | Status-provenance soundness | `events.rs::apply_finding_reviewed` |
| 4 | Detector monotonicity implies frontier support upward closure | `lint::analyze`, `signals::analyze` |
| 5 | Hash-DAG log integrity (structural) | `events.rs::canonical_event_id`, `EVENT_LOG.md` |
| 6 | Signature stability under cache-flag flips | `sign.rs::canonical_bytes_for_signing` |
| 7 | Replay-index correctness under append | `replay.rs::build_finding_index`, `tests/replay_perf.rs` |
| 8 | Erdős-Ginzburg-Ziv n = 2 case | external math; targets the EGZ assertion in `examples/erdos-problems` proposal `vpr_933b01bcb2066d02` |
| 9 | Canonical-event-id determinism (serialize then hash) | `events.rs::canonical_event_id` (composes `canonical_bytes` then sha256) |
| 10 | Signature uniqueness under canonical bytes | `sign.rs::canonical_bytes_for_signing` + `ed25519_dalek::SigningKey::sign` |
| 11 | Multi-sig threshold soundness | `sign.rs::verify_multisig_threshold` (distinct-signer counting rule) |
| 12 | Concurrent-replay commutativity for disjoint events | `reducer.rs::apply_event` (commutativity on disjoint target ids; conformance suite at `conformance/`) |
| 13 | Frontier-id determinism | `repo.rs::frontier_id` (sha256 of canonical event-log bytes; underlies `vela registry witness-check` from v0.129) |
| 14 | Proposal-acceptance idempotency | `reducer.rs::apply_event` proposal.accepted arm; deduplication on `applied_event_id` |
| 15 | Confidence-update bounds | `state::revise_confidence` reviewer-policy cap enforcement |
| 16 | Governed-quorum soundness | `governance::verify_quorum` (distinct-signer counting + eligibility + non-revocation + Ed25519 signature check) |
| 17 | Search-index determinism | `vela_search::build_index` (same inputs → same vsi_* under canonical-bytes + abstract hash injectivity) |
| 18 | Owner-epoch chain monotone-by-one | `governance::OwnerEpochChain::append` (strictly increasing by 1, starts at 1) |
| 19 | Registry checkpoint root injectivity | `checkpoint::compute_registry_root` (same canonical summary → same root; equal roots imply equal summaries) |

Theorems 1–7 are substrate-internal: they pin algebraic guarantees of the kernel (replay determinism, hash-DAG integrity, sound signing, sound index maintenance). Theorem 8 is the bundle's first external mathematical fact: a non-trivial number-theoretic claim (the n = 2 case of Erdős-Ginzburg-Ziv 1961) carried alongside the substrate's own correctness theorems. It demonstrates that the Lean bundle can grow with the same tooling that pins kernel guarantees, and provides a worked example for future formalized findings on substrate frontiers.

## Build

This project is pinned to Lean `v4.29.1` and Mathlib `v4.29.1`.

```bash
./scripts/verify.sh
```

or manually:

```bash
lake update
lake exe cache get
lake build Vela.CoreTheorems
```

## Dependency-free nucleus (verify in seconds, no Mathlib)

World-class infrastructure should let anyone check its core in seconds without a 5 GB dependency
(the git/Linux property). These three modules import **nothing** beyond the Lean prelude and compile
standalone — `lean Vela/Core.lean` (and likewise `Transfer`, `ReducerModel`), no library required:

- `Vela/Core.lean` — substrate Theorems 2, 3, 4 re-proven over plain `List` (retraction monotonicity,
  no-zombie status, frontier upward closure): the dependency-free heart of the substrate.
- `Vela/TransferCWCtoDNA.lean` — a concrete cross-frontier transfer `ConstantWeightCode(n,d,w) →
  DNACode(n,d,w)` (identity on the symbol list under `0=A, 1=C`), with a genuine `sound` proof
  (Mathlib-free; build via `lake build Vela.TransferCWCtoDNA` since it imports `Vela.Transfer`). The
  highest-leverage bridge from a compute-model research pass: GC content equals the binary weight, and
  the reverse complement of an `{A,C}` word lies in `{G,T}` so reverse-complement distance is the full
  length. `scripts/transfer_cwc_to_dna_demo.py` exhibits the operational chain
  `Steiner S(2,3,7) → CWC(7,4,3) → DNA(7,4,GC=3)` through the frozen Python verifiers (not a record claim).
- `Vela/TransferPackingToCWC.lean` — the pro model's #2 transfer (core): `Packing(v,k,s) → CWC(v,2(k−s),k)`
  via `Ham x y + 2·|x∩y| = wt x + wt y` (proved subtraction-free), so weight-`k` words with pairwise
  support-intersection `≤ s` have minimum distance `2(k−s)`; with `s=t−1` this is the Steiner bound
  `2(k−t+1)`. It **composes** with `cwcToDna` through `Transfer.comp` to give a single proven
  `packing → CWC → DNA` bridge (`packingToDNA`). Mathlib-free; build via `lake`.
- `Vela/TransferBinaryCodeToCWC.lean` — the pro model's #3 (no linearity needed): `BinaryCode(n,d) →
  CWC(n,d,w)` via the *fixed-weight filter* (keep weight-`w` codewords) — a genuine non-identity
  transfer map, proven sound (filtering preserves length/binariness/distance, enforces weight). Composes
  to `binCodeToDNA`. The famous instance — extended Golay `[24,12,8]` → its 759 weight-8 octads =
  `CWC(24,8,8)` → DNA — is run end-to-end through the frozen verifiers in
  `scripts/transfer_golay_to_dna_demo.py` (reproduces `A(24,8,8)=759`; calibration, not a record claim).
- `Vela/Transfer.lean` — Theorem 23: cross-frontier transfer soundness (a verifier-homomorphism
  transports verified status) + the category structure on frontiers, plus a *concrete* worked transfer
  (`translateTransfer` / `sidon_translate_sound`: translation preserves the Sidon property) whose
  soundness is genuinely proven, not just a contract.
- `Vela/PoVD.lean` — Proof-of-Verified-Delta: a permissionless accumulation mechanism for the
  verifiable slice, with machine-checked anti-gaming properties (no credit without verification,
  monotone state, no double-spend, Sybil/duplication resistance, authority-free determinism). See
  `docs/POVD.md` for the thesis and the honest limits.
- `Vela/Accumulation.lean` — the scaling core of PoVD (the "Bitcoin headers/SPV" property for science):
  a constant-size accumulator (running state + one integrity bit) whose single bit certifies an
  *unbounded* accepted-delta history. Proves succinct-accumulation soundness (`globalCheck_sound`:
  the bit ⇒ every delta in the whole history verified), irreversible tamper-evidence, state
  monotonicity, and authority-free determinism. The abstract soundness a real recursive-SNARK / PCD
  instantiation must preserve. See `docs/PCK.md` (Proof-Carrying Knowledge) for the full candidate and
  its honest limits.
- `Vela/ProtocolKeystone.lean` — **the protocol keystone**: one machine-checked theorem composing the
  two central guarantees. `protocol_keystone` shows that if the accumulator's single constant-size
  integrity bit is true, then (1) *every* delta in the unbounded history was accepted — the bit
  certifies a clean, fully-accepted history (succinct/light-client verification), and (2) *every* claim
  in the resulting state is genuinely `Verified`, grounded through sound cross-frontier transfers in
  native verifier acceptances, with nothing laundered. So checking one constant-size object certifies
  the entire cross-frontier knowledge DAG. The central protocol claim, as a checked theorem.
- `Vela/HeteroAccumulation.lean` — the **moat**: accumulation across *heterogeneous* frontiers, where a
  delta may be justified either natively or by importing another frontier's verified best through a
  sound transfer (Theorem 23). Proves `accumulate_state_verified`: every nonzero entry of the
  accumulated state is genuinely `Verified` for *any* history of native-or-transfer deltas — so
  cross-frontier credit is exactly as sound as native credit and never launders an unverified claim.
  This is the property the folding/PCD literature does not provide. Includes a concrete worked import
  (frontier 1 verified purely by transfer from frontier 0, no native witness).
- `Vela/FoldingSoundness.lean` — machine-checks the cryptographic core of `scripts/pck_fold.py`: the
  Nova relaxed-R1CS folding step. `fold_complete` (folding two satisfied rows yields a satisfied folded
  row) and `fold_sound` (over `Int`, with the challenge `r ≠ 0`, a forged/unsatisfied row cannot be
  folded into a satisfied accumulator without breaking the folded check). Turns the identity the demo
  verifies numerically into a checked theorem. Mathlib-free (subtraction-free equational statements +
  `Int` integral-domain cancellation).
- `Vela/ReducerModel.lean` — a concrete event-sourced reducer with PROVEN invariants: replay
  determinism, the incremental replay law `R(E++F)=R_{R(E)}(F)`, append-only log, and descriptor
  preservation under step/composition/replay. De-hollows the assume-guarantee descriptor theorems
  (T28, T34): what they asserted as an axiom over an `opaque` reducer is here proven over a concrete one.

A Mathlib-dependent companion (needs the build cache, not part of the seconds-to-verify nucleus):

- `Vela/SumcheckSoundness.lean` — the soundness core of `scripts/pck_spartan.py`: single-variable
  Schwartz–Zippel. `sumcheck_round_sound` (a cheating round polynomial agrees with the honest one at
  `≤ d` of `|F|` challenges, so a cheat survives a round with probability `≤ d/|F|`) and
  `sumcheck_round_catches` (`≥ |F| − d` challenges expose it). Built on Mathlib's `Polynomial.card_roots'`.
  Together with `FoldingSoundness.lean`, the two crypto facts the nucleus cannot express — folding's
  cross-term cancellation and the decider's random-challenge soundness — are machine-checked.

The richer `Finset`/`Multiset` versions of 2–4 remain in `Vela/Provenance.lean`. The spec ⇄ proof ⇄
conformance map for every protocol invariant is `docs/PROTOCOL_GUARANTEES.md`; the honest
classification of proven vs assumed vs de-hollowed is `docs/THEORY_AUDIT.md`.

## Verifying

- **Nucleus (no dependencies, seconds):** `lean Vela/Core.lean && lean Vela/Transfer.lean && lean Vela/ReducerModel.lean && lean Vela/PoVD.lean && lean Vela/Accumulation.lean && lean Vela/HeteroAccumulation.lean && lean Vela/FoldingSoundness.lean`
- **Full bundle (needs the Mathlib build cache):** `lake exe cache get && lake build`

## Carina Proof primitive (content-addressed locator)

The Carina kernel's `Proof` primitive (v0.3) carries a content-addressed locator pointing at the proof script plus a verifier-output hash. For Theorem 8 (`Vela/EGZ.lean`), the locator at v0.113 is:

```
sha256:58dec20d4f8c474d222009c9d3b7cae2ef010bfac48fd5c2ad7c9c8d894428ec
```

Re-hash on update with `shasum -a 256 lean/Vela/EGZ.lean`. A future cycle can ship a real `vpf_*` Carina Proof artifact registered against the EGZ proposal once it is reviewed and accepted onto the `examples/erdos-problems` frontier.

## Scope and honesty notes

The formalization is intentionally substrate-level.

The provenance module uses a finite-support representation of `N[X]`: a coefficient map on finite multiset monomials, a finite set of nonzero monomials, and an invariant tying them together. The current theorems use only variable support, but the representation keeps coefficients and exponent multiplicity in the object model.

The log module models event ids as `Nat` to obtain a simple total order for canonical replay. The Rust substrate uses content hashes with lexicographic ordering. The formal theorem proves replay convergence for logs with the same finite event-id set and core map, where canonical sequence is determined by sorting ids. The validity predicate includes causal down-closure and a sufficient condition that parent ids are smaller than child ids. A future stronger formalization should replace this with a true canonical topological sort over finite DAGs.

The hash-DAG integrity theorem is structural. It assumes an injective abstract hash function. It does not prove cryptographic collision resistance or Merkle security.

The replay-index theorem (Theorem 7) is a structural guarantee under an abstract key function. It proves the load-bearing semantic properties of the substrate's index-maintenance rule (insert on append agrees with rebuild from scratch). It does not prove the runtime complexity (Lean does not model HashMap costs); the perf test at `crates/vela-protocol/tests/replay_perf.rs` is the implementation gate.

The EGZ n = 2 theorem (Theorem 8) covers only the n = 2 case via pigeonhole on parity. The general Erdős-Ginzburg-Ziv theorem (arbitrary n) requires the Chevalley-Warning machinery from combinatorics and is named explicitly out of scope for this cycle. A future cycle may extend the bundle with the general case via the Chevalley-Warning route or import an existing mathlib formalization if one lands.
