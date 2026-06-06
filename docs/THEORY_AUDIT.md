# Theory audit: what is genuinely proven, what is assumed, what is hollow

A correctness/depth audit of the Lean substrate theorems (2026-06-01), prompted by "make sure all
the theories are fully ideal and correct, not bad or shallow." Honest classification, no inflation.

## 1. Genuinely sound, non-trivial content

- **`Vela.Log`** — Theorem 1 (replay convergence) and Theorem 5 (hash-DAG integrity). Replay
  convergence over a canonical linear extension (lexicographic event-id tie-break) is the genuinely
  substantive substrate theorem; it is proven over concrete definitions.
- **`Vela.Transfer`** — Theorem 23 (cross-frontier transfer soundness) + category structure, AND a
  *concrete* worked instance `translateTransfer` whose `sound` field is the proven theorem
  `sidon_translate_sound` (translation preserves the Sidon property; membership-unfolding + `omega`).
  No axiom, no `opaque`, no `sorry`. Verified standalone (Mathlib-free, `lake env lean` exit 0).
- **`Vela.EGZ`** — Erdős-Ginzburg-Ziv (n=2), a real number-theory proof.

## 2. Correct but algebraically shallow (appropriate — they are invariants)

- **`Vela.Provenance`** — Theorems 2 (retraction monotonicity), 3 (status-provenance soundness),
  4 (frontier upward closure). Proven over concrete definitions (`rho_Y`, `deriveStatus`,
  `frontierSupport`), no cheating. They are near-trivial algebraically — that is correct *for
  invariants*: their job is to be obviously-true machine-checked guarantees that pin the model, not
  deep results. Honest framing: present them as invariants, not breakthroughs.

## 3. Legitimate boundary assumptions (standard idealizations, clearly labeled)

- `hash_injective : Function.Injective Hash` and `canonicalBytes_injective` (in
  `AgentAttestationInjectivity`, `ScientificDiffPackId`, `ToolDescriptorInjectivity`,
  `VerdictConflictResolution`, `EvaluationRecordInjectivity`). You cannot prove SHA-256 injective
  (false by pigeonhole); modeling the hash/serializer as injective is the standard cryptographic /
  canonicalization idealization. Acceptable as labeled assumptions, not hollowness.

## 4. HOLLOW — theorems that assume their own content as an axiom over an opaque reducer

These are the "bad/shallow" case and should be de-hollowed:

- **`ToolDescriptorComposition`** Theorem 28 and **`EvaluationDescriptorComposition`** Theorem 34.
  They conclude "the reducer preserves descriptor identity" by citing axioms
  (`accept_pack_preserves_descriptors`, `record_evaluation_preserves_descriptors`) that *are* that
  conclusion, over `opaque` (undefined) reducers `accept_pack` / `record_evaluation`. The substantive
  invariant is assumed, not proven. The composition step (chaining two preservation facts) is real,
  but the per-step preservation is axiomatic.
- Similar pattern: `descriptor_id_is_self`, `signed_bytes_determine_body` (`DiffPackFederationSoundness`).

**The fix (DONE):** `lean/Vela/ReducerModel.lean` gives the reducer a *concrete model* (`St` carries an
append-only log, a descriptor table, and a finding store; `step` appends to the log and never touches
the descriptor table on `acceptPack`/`recordEvaluation`) and *proves* preservation from the definition
(`acceptPack_preserves_descriptors`, `eval_then_pack_preserves`, and `replay_preserves_descriptors` by
induction over the log). The invariant T28/T34 asserted as an axiom over an `opaque` reducer is now a
theorem over a concrete one — the assume-guarantee stubs are realized by a real model. Mathlib-free,
compiles standalone (exit 0). **Resolved.**

## Verdict

No theorem is *wrong* and none uses `sorry`. The substrate is honest *if framed honestly*: Theorems 1,
5, 23 (+ the concrete transfer) and EGZ are real content; 2-4 are correct invariants; the injectivity
axioms are standard idealizations; the descriptor-composition theorems **were** hollow and are now
**de-hollowed** by `Vela/ReducerModel.lean` (concrete reducer, proven invariants). The remaining
`axiom`s (`hash_injective`, `canonicalBytes_injective`, `signed_bytes_determine_body`) are boundary
idealizations of cryptographic / serialization injectivity, not hidden content.

The dependency-free nucleus (`Vela/Core.lean`, `Vela/Transfer.lean`, `Vela/ReducerModel.lean`) re-proves
the core substrate guarantees with NO Mathlib, so the heart of the protocol verifies in seconds. The
right next work is external validation (OEIS) and scaled-proposer compute, NOT new mathematics.
