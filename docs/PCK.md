
# Proof-Carrying Knowledge (PCK): the Bitcoin-scale candidate for Vela

> **Implementation note.** The Python crypto/protocol prototypes cited below (`scripts/pck_*.py`,
> `scripts/povd_node.py`) lived in the consuming workspace and were retired in the verifier
> cut-over; they are not part of this substrate. The proven core is canonical and lives here in
> `lean/Vela/` (`ProtocolKeystone`, `HeteroAccumulation`, `Accumulation`, `FoldingSoundness`,
> `SumcheckSoundness`, `PoVD`); build it with `lake build`. The `scripts/*.py` references below are
> historical.

This document names the one mechanism that could be to *cumulative knowledge* what Bitcoin was to
*money* — same shape, different substrate — and is blunt about which parts are proven, which are
buildable, and which cannot be willed. It is a research direction with a proven first stone, not a
claim of achievement.

## What Bitcoin's "scale" actually was

Bitcoin's breakthrough was not money. It was a *shape*: **trustless agreement on the state of an
append-only DAG, where any party verifies the whole structure's integrity without a central authority,
and verifies it cheaply relative to the work that built it.** Light clients (SPV) check a constant-ish
chain of headers, not the entire transaction history. Verification cost decoupled from production cost.
That decoupling is what let a global, permissionless ledger exist.

## The matching gap in Vela

`PoVD` (`lean/Vela/Accumulation/PoVD.lean`; the mechanism is detailed in the PoVD section below) gives us the consensus + anti-fraud + Sybil-resistance
core on the frozen-verifiable slice: the shared state grows only by verifier-accepted, strictly
improving deltas, by a pure function with no adjudicator. Proven and running (`scripts/povd_node.py`).

But PoVD's `replay()` is **O(history)** — to learn "this is the true verified frontier," you re-run
every verifier. That is exactly the gap Bitcoin's headers closed. Without decoupling verification cost
from production cost, PoVD is a correct mechanism that does not yet *scale* like the thing it is modelled
on.

## The candidate: Proof-Carrying Knowledge

> A single constant-size, recursively-composed proof attesting that the **entire** cross-frontier
> knowledge-DAG was assembled only from frozen-verifier-accepted, strictly-improving deltas —
> verifiable by anyone in milliseconds, foldable as new deltas arrive, and composing **heterogeneous**
> verifiers across frontiers via the soundness-preserving transfer maps of Theorem 23.

Bitcoin = a succinctly-verifiable trustless **money** DAG. PCK = a succinctly-verifiable trustless
**knowledge** DAG. The open problem it cracks: *how does cumulative science verify its own global
integrity without a central authority and without anyone redoing all the work.*

## Why now — three real 2023–2025 lines that supply the pieces

1. **Folding / accumulation schemes** — Nova → HyperNova (CRYPTO 2024) → MicroNova (IEEE S&P 2025).
   Defining property: the verifier's work does **not** grow with the number of steps. The object for
   "verify unbounded history in constant time."
2. **Proof-Carrying Data** (Bünz, Chiesa, Tromer, et al.; *PCD from multi-folding schemes*, 2023–24):
   mutually distrustful parties run an indefinite distributed computation in which **every intermediate
   state is succinctly verifiable** — almost verbatim a distributed scientific-knowledge ledger.
3. **The formal-math supply explosion** — the Polynomial Freiman–Ruzsa conjecture formalized in Lean in
   three weeks (Tao/Dillies/Mehta, 2023); AlphaProof at IMO silver→gold (Nature, 2025); the **Equational
   Theories Project** settling all 22,028,942 implications among 4,694 magma laws, every edge
   Lean-validated (Tao et al., 2025). That last is a hand-built proto-Vela: distributed knowledge
   accumulation gated by a frozen verifier (the Lean kernel). The supply of machine-checkable knowledge
   is now industrial — the demand-side substrate (PCK) is the missing half.

## What is genuinely new in the combination (the moat, not a reuse)

Folding schemes fold **one machine's repeated step**. PCD handles a DAG but under **one fixed**
compliance predicate. PCK's compliance predicate is a **heterogeneous** set of frozen verifiers linked
by **verified transfer-homomorphisms** (`lean/Vela/Transfer/Transfer.lean`, Theorem 23): a Sidon record
importable into a B_h proof via a soundness-preserving map, a `[8,4,4]` code into an E8 kissing bound —
all composed inside one accumulator. Cross-frontier composition inside a single succinct proof is the
part not present in the cryptographic literature, and it is precisely where Vela's constellation thesis
already lives.

## The moat, now proven (not just specified)

The cross-frontier composition above is the novel part, and `lean/Vela/Accumulation/HeteroAccumulation.lean`
(Mathlib-free, standalone) now proves its soundness. The accumulator there folds a *heterogeneous*
history: each delta is justified either natively (its frontier's own verifier accepts a witness) or
**by transfer** — importing another frontier's current verified best through a registered sound map,
which is the encoding of Theorem 23 (`Verified.transfer`). The headline result:

| Property | Theorem | Meaning |
|---|---|---|
| Cross-frontier credit is as sound as native credit | `accumulate_state_verified` | for ANY history of native-or-transfer deltas, every nonzero entry of the accumulated state is genuinely `Verified` — transfers never launder an unverified claim across a frontier boundary |
| Imports preserve verification step-by-step | `accept_preserves_verified` | one accepted delta (including a transfer) keeps every state entry verified |

It also ships a concrete worked import: frontier 1 is `Verified` at a level with **no native witness of
its own**, purely by importing frontier 0's verified result through a sound transfer — a discovery
single-frontier search cannot see, made sound by the transfer. This is the constellation thesis,
machine-checked.

## The succinct stack, instantiated (real field + real curve, not modelled)

Three runnable scripts now carry PCK from *modelled* toward *cryptographic*, each reusing the same real
field and R1CS arithmetization:

1. **`scripts/pck_fold.py` — arithmetization + folding (7/7).** The Sidon verifier as a real R1CS over
   the BN254 scalar field (pairwise sums distinct, via inverse-witness non-equality gadgets), and the
   actual Nova folding scheme (relaxed R1CS, cross-term, Fiat-Shamir). Folds a delta history into one
   accumulator; the single relaxed check attests all of them; a forged delta breaks it; and the exact
   identity `folded_residual = residual_acc + r²·residual_forge` is verified numerically — *why*
   accumulation attests an unbounded history at constant marginal cost.
2. **`scripts/pck_pedersen.py` — constant-size commitment (6/6).** A real Pedersen vector commitment on
   the BN254 G1 curve (`y²=x³+3`) with nothing-up-my-sleeve hash-to-curve generators. A witness of any
   length commits to **one** group point; folding is homomorphic
   (`Comm(W1)+r·Comm(W2)=Comm(W1+r·W2)`, verified), so the folding verifier does a constant number of
   point operations regardless of witness size — shown identical at m=4 and m=6. Binding is real
   (flipping one coordinate changes the commitment).
3. **`scripts/pck_spartan.py` — the compressing decider (4/4).** The real sum-check protocol (the core
   of Spartan): R1CS satisfiability as a sum over the boolean hypercube, verified in O(log n) rounds
   plus one random-point evaluation instead of recomputing all n constraints. Accepts the honest folded
   instance and rejects a forged one (false satisfiability caught with probability `1 − deg/|F|`),
   at m=4 (6 rounds vs 45 constraints) and m=6 (8 rounds vs 210).

4. **`scripts/pck_ipa.py` — the polynomial-commitment opening (6/6).** A real Bulletproofs
   inner-product argument over BN254 G1. The key fact: a multilinear extension evaluated at `rho` is an
   inner product `f~(rho) = <z, eq(rho)>`, so "open the MLE at `rho`" = "prove `<committed z, public b> =
   v`". The proof is `2·log₂(n)` group elements + one scalar; the verifier checks it against the
   commitment alone (witness-free), and a wrong claimed value or tampered proof is rejected.
5. **`scripts/pck_snark.py` — the witness-free decider, end to end (8/8).** Composes all of the above:
   fold → commit `z` and `E` to two G1 points → sum-check → open `A~(rho), B~(rho), C~(rho), E~(rho)`
   via IPA (each an inner product of a committed vector with a public vector `Aᵀeq(rho)`, etc.) → final
   check from the opened values. **The verifier's entire input is two commitments, the O(log n)
   sum-check transcript, and four log-size IPA openings — it never reads the witness.** A lie about any
   opened value breaks the check (and its IPA would fail).

Together these are the pieces a Nova+Spartan-with-IPA IVC pipeline composes: fold (constant marginal
cost) → commit (constant-size instance) → sum-check decide (logarithmic verification) → IPA-open
(witness-free evaluations). The seam between commitment and decider — the part that was missing — is
now closed and runnable.

What this is **not**, stated plainly: not yet a *production* SNARK. It is binding-sound but not
zero-knowledge (no blinding term yet — an orthogonal add). The IPA proof is O(log n) but its verifier
does O(n) group work; an O(1)-time verifier needs a pairing-based PCS (KZG) or FRI in place of the IPA —
a PCS swap, not an architecture change. And it runs on small `m` because the EC is pure-Python for
fidelity. Those are engineering, ZK, and a PCS choice — not a missing piece of the architecture, which
is complete and demonstrated. Production hardening (a real curve library, ZK, an O(1)-verifier PCS,
scale) and — above all — adoption are what remain.

## Two axes of scale (do not conflate them)

PCK has two independent scaling questions, and it is honest to separate them:

1. **History length** — how many verified deltas the system can accumulate. This is what folding
   addresses, and `scripts/pck_scale.py` demonstrates it directly: folding N verified Sidon records for
   N up to 64 keeps the accumulator at a **constant** size (96 field elements) and the per-delta cost
   **flat** (~5 ms), and a **single** decision attests the entire history at cost **independent of N**
   (~3.4 ms whether N=4 or N=64). A forged delta hidden anywhere in the history is caught by that one
   decision. This is the Bitcoin light-client property — verify an unbounded history cheaply — and it
   holds.
2. **Per-delta circuit size** — how large a single record's verifier circuit is. This is a separate
   *arithmetization* problem. The naive gadget (a non-equality constraint for every pair of pairwise
   sums) is **O(K²)** in the number of sums K — fine for small records, infeasible at record sizes
   (a(16)=503 → K≈127k → ~8×10⁹). `scripts/pck_arith.py` now implements the **O(K log m)** gadget: a
   **permutation / grand-product argument** (the prover supplies the sums in sorted order; running
   products with a Fiat-Shamir challenge `gamma` prove it is a permutation of the actual sums) plus
   **range-proof comparison gadgets** (bit-decomposed differences prove the sort is strictly
   increasing). A multiset has a strictly-increasing arrangement iff it has no duplicates, so the system
   is satisfiable **iff the set is Sidon**; non-Sidon sets are rejected *deterministically* (the zero
   gap has no valid range proof). `gamma` lives in the witness, so the matrices stay uniform and v2
   instances fold like any other. The printed crossover is real (6.2× fewer constraints at m=16, growing
   with m); reaching a(16)=503 from here is a fast prover/curve, i.e. engineering, not a missing gadget.

## The proven first stone (in hand today)

`lean/Vela/Accumulation/Accumulation.lean` (Mathlib-free, compiles standalone) models the accumulator as a
constant-size object — running `state` plus one integrity bit `ok` — and proves the load-bearing
scaling property:

| Property | Theorem | Meaning |
|---|---|---|
| Succinct-accumulation soundness | `accumulate_sound` / `globalCheck_sound` | checking the single constant-size bit certifies that **every** delta in the unbounded history passed its verifier |
| Tamper-evidence is irreversible | `fold_preserves_false` | one forged delta clears the bit, and it never resurrects |
| Per-step inversion | `fold_ok_inv` | a set bit after a fold implies the prior bit was set *and* this delta verified |
| State never regresses | `fold_state_monotone` | the accumulated frontier only rises |
| Authority-free determinism | `accumulate_deterministic` | the constant-size summary is a pure function of (verifier, history) |

`scripts/povd_node.py` exhibits this operationally on real A309370 records: one bit certifies a
multi-delta history, and the bit flips the instant any delta in the history is forged (9/9 properties
observed in running code).

## Honest limits (the parts a proof cannot grant)

1. **Constant-size + witness-free: the cryptographic architecture is now complete and runnable.**
   Folding (constant marginal cost), a real BN254 Pedersen commitment, the O(log n) sum-check decider,
   and the IPA polynomial-commitment opening that connects them are each implemented; `pck_snark.py`
   composes them into a decider whose verifier reads only two commitments + an O(log n) transcript +
   four log-size openings, never the witness. What remains is *not a missing primitive*: zero-knowledge
   (a blinding term), an O(1)-verifier PCS (KZG/FRI) in place of the O(n)-verifier IPA, a production
   curve library, and a better per-delta arithmetization (O(K log m); see "Two axes of scale").
   Engineering, ZK, and a PCS choice — not architecture.
2. **Heterogeneous folding is proven *abstractly*, not yet in-circuit.** `HeteroAccumulation.lean`
   proves transfer-linked folding preserves verification (`accumulate_state_verified`), but over an
   abstract sound-transfer registry. The remaining work is the same as for the single-verifier case:
   carrying that soundness in a real recursive proof, and discharging each concrete transfer's
   soundness in `Transfer.lean` (done for Sidon translation; open for the rest).
3. **Most current verifiers are still Python, not circuits — but the first one is now arithmetized.**
   `scripts/pck_fold.py` expresses the Sidon B_2 verifier as a real R1CS over the BN254 scalar field
   and runs the actual Nova folding scheme on it (see "The folding core, instantiated" below). The
   remaining verifiers still need arithmetizing, and the folding core still needs a commitment scheme
   and a final compressing SNARK to become deployable.
4. **Novelty is still bounded by the substrate**, and **adoption is still unwillable.** As with PoVD,
   mechanism + proof is necessary, not sufficient, for a breakthrough. The status comes only from people
   who are not us relying on it, and from surviving adversarial reality over years.

## Roadmap (cost-honest)

- **Done:** PoVD core (proven + running); succinct-accumulation soundness (proven + running, single
  verifier); heterogeneous transfer-linked accumulation soundness (`accumulate_state_verified`, proven).
- **Done:** concrete transfer soundnesses now include the cross-frontier Sidon ⇄ Golomb bridge
  (`Transfer.lean`, both directions proven, identity on objects) alongside Sidon translation — the
  abstract registry is backed by real proven homomorphisms between *distinct* frontiers.
- **Done:** the full cryptographic architecture is instantiated and runnable — Nova folding
  (`pck_fold.py`, 7/7), a real BN254 Pedersen constant-size commitment with homomorphic folding
  (`pck_pedersen.py`, 6/6), the Spartan sum-check decider with O(log n) verification (`pck_spartan.py`,
  4/4), the Bulletproofs IPA polynomial-commitment opening (`pck_ipa.py`, 6/6), and the end-to-end
  witness-free decider composing all of them (`pck_snark.py`, 8/8). The seam is closed.
- **Done:** the scaling property in history length — `pck_scale.py` folds up to 64 verified records at
  constant accumulator size and flat per-delta + per-decision cost, with forgery detection (5/5).
- **Done:** the O(K log m) per-delta arithmetization — `pck_arith.py` (permutation grand-product +
  range-proof comparison), satisfiable iff Sidon, foldable, with a real constraint-count crossover (6/6).
- **Done / scoped honestly:** zero-knowledge. For PCK's domain, witness-hiding is usually *not wanted* —
  scientific records are meant to be public and reproducible. ZK matters only for **priority/embargo**
  (prove you hold a record before disclosing it), which `pck_zk.py` implements as a complete, sound,
  simulator-demonstrated Okamoto Σ-protocol (6/6). A full zk-*evaluation* proof (zk-IPA) is deliberately
  not built, as permanently-secret records are contrary to the public-record norm.
- **Next (engineering, not architecture):** an O(1)-verifier PCS (KZG needs a pairing — no pairing
  library is available here, so it is a real-curve-library task; FRI is the transparent alternative and
  avoids KZG's trusted setup) swapped in for the O(n)-verifier IPA; a fast prover/curve library to run
  the O(K log m) circuit at record sizes (a(16)=503); and on the Lean side, discharging more concrete
  transfer soundnesses (e.g. code → kissing).
- **The unwillable part:** one external participant submits a verified delta and relies on the succinct
  proof. That experiment, not more theory, decides whether PCK is a breakthrough or an elegant dead end.

---

## The PoVD mechanism (the anti-gaming core)

*Folded from the former POVD.md.*
# Proof-of-Verified-Delta (PoVD)

A candidate mechanism for the one honest analogue of Bitcoin's breakthrough, applied to the
**frozen-verifiable slice of science**. This document specifies the mechanism, states the thesis,
cites the machine-checked properties, and is blunt about the limits. It is the *design and proof* of
the inventive core. It is **not** a claim that the breakthrough is achieved: that status, like
Bitcoin's, is earned only through adoption and surviving reality, which no specification or proof can
grant.

## The thesis

Bitcoin needed three separate mechanisms: proof-of-work (Sybil resistance), longest-chain (consensus),
and transaction validation (fraud prevention). The PoVD claim is that **a frozen verifier collapses all
three into a single primitive** — but only on the slice of science where a claim ships with a witness a
verifier can re-check cheaply (combinatorics, codes, algorithms, formal proofs). On that slice:

- **Anti-fraud** = the verifier. You cannot earn standing without a witness it accepts.
- **Sybil resistance** = content-addressing + strict improvement. Duplicate or stale contributions are
  rejected, so extra identities buy nothing; the cost is doing real verifiable work, not owning keys.
- **Consensus** = deterministic replay. "What is verified" is a pure function of the accepted-delta set
  and the frozen verifier; every party computes the identical state with no trusted adjudicator.

This is mechanism design, not new mathematics — exactly the register Bitcoin was in (hashcash, Merkle
trees, and public-key crypto all predated it; the invention was the *mechanism*).

## The mechanism

- **Shared state** `S : Frontier → Level`: the best verified level recorded for each frontier.
- **Delta** `(frontier, level, witness)`: a proposed improvement, backed by a witness.
- **Acceptance** (`accept`): a delta is accepted iff `verify(witness)` AND `level > S[frontier]`
  (it strictly improves the current best). On acceptance the state rises at exactly that frontier.
- **Credit**: one non-forgeable, content-addressed unit accrues to the producer of each accepted delta.
- **Replay**: the shared state is the deterministic fold of all accepted deltas — no authority.

## Proven properties (machine-checked, `lean/Vela/Accumulation/PoVD.lean`, Mathlib-free, compiles standalone)

| Property | Theorem | Meaning |
|---|---|---|
| No credit without verification | `accept_implies_verified` | accepted ⇒ the verifier passed |
| Monotone state, no zombies | `accept_monotone` | acceptance never lowers any frontier's level |
| No double-spend / known-result rejected | `stale_rejected` | a non-improving delta is rejected |
| Sybil / duplication resistance | `duplicate_rejected` | resubmitting an accepted delta earns nothing |
| Authority-free consensus | `accept_deterministic` | acceptance is a pure function — same verdict for all |
| Credited ⇒ real | `credited_is_real` | every credited delta is verified AND strictly advanced its frontier |

Together: the shared state grows **only** by genuine, re-checkable improvements, and credit is
impossible without doing real verification work. That is the anti-gaming core, proven.

## Why this is not "blockchain for science"

Those efforts failed by bolting a speculative token onto **unverifiable** peer-review trust — the token
secured nothing because the underlying claims weren't checkable. PoVD inverts this: it admits **only**
claims with a frozen verifier, so the "proof" is a real re-checkable certificate, not a token standing
in for trust. Credit is non-forgeable provenance, not a tradeable coin. The restriction to the
verifiable slice is both the source of integrity and the ceiling.

## Honest limits (the parts a proof cannot fix)

1. **Verifiable slice only.** Most empirical/wet-lab science has no frozen verifier — you cannot
   re-check "this drug works" from the ledger. Such claims enter as *proposals/predictions*, never as
   credited deltas, until a verifier exists. Bitcoin's domain (money) was fully digital; science is not.
   This is a hard boundary, not a temporary gap.
2. **Credit, not money.** Bitcoin bootstrapped security with a token that had monetary value from day
   one. PoVD's incentive is non-forgeable credit/standing. Whether reputational credit alone drives a
   real community of scientists and agents is an **unproven empirical bet**, and it is the part most
   likely not to land.
3. **Novelty is bounded by the substrate.** "Strict improvement" is measured against the shared state,
   not all of human knowledge. A delta can be new to the substrate yet already known externally
   (exactly the AI-math-discovery failure mode: retrieval mistaken for discovery). Completeness of the
   substrate bounds the novelty guarantee.
4. **No economic security model.** There is no 51%-style cost-of-attack analysis, because there is no
   economic stake. The "security" rests entirely on the verifier being un-foolable on its slice.

## What would make it a breakthrough

Not more theory and not a better spec. Adoption by people who are not us; surviving contact with real,
adversarial, messy contributions; one frontier a working scientist actually relies on; and enough
accumulated, externally-accepted verified state that trust compounds. Those are years-long and cannot
be willed. What is in hand today is the mechanism and its proven anti-gaming core — the design, stated
honestly, with its boundary drawn where integrity requires.
