# Vela: The Formal Core and the Frontier Calculus

*The single canonical statement of the mathematics under Vela and Constellate.
**Part I** is the protocol formal core: the substrate is sound (replay,
hash-DAG integrity, signatures, deterministic merge). **Part II** is the
frontier calculus: the state the substrate carries is meaningful (provenance,
graded status, κ, the bilattice, the verification-cost admission boundary). The
machine-checked ground truth is `lean/Vela/*.lean`; the executable reference is
`research/frontier-calculus/frontier_calculus_kernel.py` (25/25 checks, wired
into the conformance gate via `scripts/full-conformance.sh`).*

## How to read this document

| You want | Read |
|---|---|
| The protocol-correctness guarantees (replay, hash-DAG, signatures, merge, quorum) | **Part I**, §1–§16 |
| The epistemic calculus (provenance algebra, Belnap/bilattice status, κ, admission, transfers) | **Part II**, §17–§39 |
| The narrative companion | `docs/THEORY_NARRATIVE.md` |
| The implementation-facing invariants that must survive product changes | `docs/INVARIANTS.md` |

Citation convention: Part I theorems are **Core Theorem N**, Part II's are
**Calculus Theorem N**. Where the two coincide (replay convergence, retraction
monotonicity, no-zombie status), Part I is the canonical statement and Part II
cross-references it rather than restating it. This document supersedes the
former `docs/MATH.md` and the working spec at
`research/frontier-calculus/frontier_calculus.md`; both are folded in here. The
executable kernel (`frontier_calculus_kernel.py`) and the paper draft remain in
`research/frontier-calculus/`.

---

# Part I — The Formal Core

*The substrate is sound: deterministic, auditable, contradiction-preserving,
content-addressed. These are protocol-correctness results, not adjudications of
scientific truth.*

## Abstract

We define a formal core for Vela, a substrate for scientific state. The
central object is an **Atlas**, a formal context-indexed state object modeled
as a typed presheaf of scientific state over a category of contexts. Public
product language should usually say frontier state; this document uses Atlas
only for the mathematical object. The target category, **CarinaState**,
contains typed bundles of content-addressed objects, hyperrelations,
contextual Belnap status, Bayesian confidence state, and provenance
polynomials. Vela itself is modeled as an operation-based replicated
datatype: a content-addressed hash-DAG of signed, attested events whose
deterministic replay constructs context-indexed frontier state.

The core results are replay convergence, provenance retraction
monotonicity, status-provenance soundness, discord support
monotonicity, and hash-DAG log integrity. These results do not
adjudicate scientific truth. They establish substrate properties:
determinism, auditability, contradiction preservation, provenance
propagation, and computable frontier support.

This document is a formal substrate specification with provable
implementation properties. It is not a novel mathematical theory of
science. The mathematics it uses (presheaves, semirings, four-valued
logic, hash-DAGs, Bayesian decision theory) is standard. The
contribution is the specific stack of well-known math, applied to
scientific state, in a configuration that produces a buildable system
with stated guarantees.

The operational primitive is a reviewed, provenance-bearing state transition
over scoped frontier state. Papers, datasets, lab logs, benchmark outputs,
agent traces, and reviews are source activity until they become proposals,
diffs, accepted events, and replayed state.

For the narrative companion to this document, see
`docs/THEORY_NARRATIVE.md`. For the implementation-facing invariants that must
survive product and protocol changes, see `docs/INVARIANTS.md`. The frontier
calculus that this formal core carries is Part II below.

---

# 1. Preliminaries

Let `C` be a small category of scientific contexts.

A context may encode:

```text
species
disease subtype
cell type
model system
assay
dose
timepoint
method
dataset
lab condition
patient subgroup
intervention
```

A morphism `u : c' -> c` means that `c'` is a refinement, restriction,
or scoped subcontext of `c`.

Example:

```text
recurrent IDH-wildtype GBM under assay A
  -> recurrent IDH-wildtype GBM
  -> human glioma
```

For the support monotonicity theorem in Section 10, we assume `C` is
thin, or work in the preorder reflection of `C`, so that context
refinement can be read as an order relation.

Let `X` be the set of source and event identifiers.

Let `N[X]` be the semiring of finite polynomials over `X` with
natural-number coefficients.

Let `B4 = {N, T, F, B}` be the Belnap status set:

```text
N = neither supported nor refuted
T = supported
F = refuted
B = both supported and refuted
```

Status is not truth. It is substrate-visible evidence polarity under
a review policy.

---

# 2. CarinaState

A **Carina bundle** is a tuple

```text
B = (O, R, sigma, kappa, pi)
```

where

```text
O     = finite set of content-addressed Carina objects
R     = finite set of typed hyperrelations among objects in O
sigma = contextual Belnap status map
kappa = Bayesian confidence / posterior state
pi    = provenance annotation in N[X]
```

Carina object types include:

```text
Context
Claim
Finding
Evidence
Mechanism
Method
Dataset
Protocol
Experiment
Proposal
Diff
Event
Attestation
Lineage
Confidence
Status
```

## 2.1 Claim-context pairs

Let `P_B` be the finite set of claim-context pairs represented inside
`B`. Then

```text
sigma_B : P_B -> B4
kappa_B : P_B -> K
```

where `K` is a chosen space of posterior or confidence objects.

Examples of `kappa`:

```text
posterior distribution
credible interval
Bayes factor
calibrated score
model-weight vector
evidence-weighted uncertainty state
```

Status and confidence are orthogonal:

```text
sigma says which directions of accepted evidence exist.
kappa says how strong or uncertain that evidence is.
```

A claim can be `B with high confidence`, meaning there is strong
accepted evidence both for and against the claim in the given
context.

## 2.2 Provenance

Each object or derived relation has a provenance polynomial

```text
pi(o) in N[X]
```

Example:

```text
pi(F) = p1 * d3 + r7 * e2
```

This means: finding `F` is supported either by paper `p1` and dataset
`d3`, or by review `r7` and experiment `e2`. Multiplication
represents joint dependence. Addition represents alternative
derivation paths.

Coefficients count distinct derivation events. For example,
`2 * p1 * d3` means the substrate observed two distinct derivations
of the same object through the same source combination `p1 * d3`,
such as two independent reviewers, extraction pipelines, or attested
derivation events. Idempotent collapse is not assumed in `N[X]`. If
an implementation wants lineage-only semantics, it can quotient to
the Boolean semiring; Vela's default provenance semiring preserves
multiplicity.

## 2.3 Morphisms in CarinaState

A morphism `f : B -> B'` is a tuple

```text
f = (f_O, f_R, f_sigma, f_kappa, f_pi)
```

satisfying the following.

**Object map.** `f_O : O -> O'` is a partial function preserving
content identity. An object either maps to itself by content hash or
is dropped. It is never silently rewritten.

**Hyperrelation map.** `f_R` restricts hyperrelations along `f_O`. A
hyperrelation survives only if all required participating objects
survive.

**Status map.** `f_sigma` restricts `sigma` to surviving
claim-context pairs.

**Confidence map.** `f_kappa` restricts or marginalizes `kappa` to
surviving claim-context pairs.

**Provenance map.** `f_pi : N[X] -> N[X]` is a semiring homomorphism
that cannot invent provenance support. For restriction maps,
variables map as `x -> x` or `x -> 0`. Thus

```text
supp(f_pi(p)) is a subset of supp(p)
```

for all provenance polynomials `p`. Provenance may narrow. It may not
create new support.

These morphisms form the category `CarinaState` with identities and
composition defined componentwise.

---

# 3. Atlas

An **Atlas** is a presheaf

```text
A : C^op -> CarinaState
```

For every context `c`, the Atlas assigns local scientific state
`A(c)`. For every refinement morphism `u : c' -> c`, the Atlas gives
a restriction map

```text
A(u) : A(c) -> A(c')
```

This restriction drops or narrows what does not apply to the refined
context. It does not invent new scientific claims.

Thus an Atlas is not a wiki, a graph, a database, or a literature
review. It is context-indexed scientific state.

**Implementation status.** This formal presheaf definition is target
v0.8. The current substrate has typed state, scoped objects,
content-addressed objects, append-only events, and partial context
structure, but it does not yet implement the full
`C^op -> CarinaState` Atlas model. Sections using the presheaf
formalism describe the target formal substrate, not the complete
current implementation. See Section 13.

---

# 4. Discord and frontiers

Let `K` be a finite set of discord kinds:

```text
K = {
  Conflict,
  ConflictingConfidence,
  MissingOverlap,
  TranslationFail,
  EvidenceGap,
  ReplicationFail,
  ProvenanceFragile,
  StatusDivergent,
  MethodMismatch
}
```

Let `L = P(K)` ordered by subset inclusion.

The powerset lattice is chosen because discord kinds are initially
treated as independent. A context can have `Conflict` without
`TranslationFail`, or both. The lattice can be refined later if some
discord kinds are operationally known to subsume others.

A **discord assignment** for Atlas `A` is a monotone map
`D_A : C -> L`, where `D_A(c)` is the set of discord kinds detected
at context `c`.

The intended monotonicity is upward propagation:

```text
c' -> c  and  D_A(c') is nonempty  =>  D_A(c) is nonempty
```

A refined-context conflict makes the broader context unstable unless
resolved or scoped away.

The **frontier** of an Atlas is

```text
Frontier(A) = supp(D_A) = { c in C | D_A(c) is nonempty }
```

A frontier is the support of unresolved discord in an Atlas. Not
every unknown is a frontier. A frontier is an actionable instability
in scientific state.

---

# 5. Vela event log

Vela is an operation-based replicated datatype with causal delivery
through a content-addressed hash-DAG. It is not a pure state-based
CRDT. Operations are events. State is computed by deterministic
replay.

## 5.1 Events

An event is

```text
e = (id, parents, payload, attestations, policy, schema, timestamp, signature)
```

where

```text
id           = H(canonical(e without id))
parents      = finite set of parent event ids
payload      = typed Carina transition
attestations = signed review objects
policy       = review or merge policy
schema       = content-addressed schema and reducer reference
timestamp    = declared event timestamp
signature    = actor signature
```

The hash function `H` is assumed collision-resistant. Schema and
reducer artifacts are content-addressed and may themselves be
introduced or updated by governance events. Therefore the event set
commits to its replay semantics.

## 5.2 Valid event sets

An event set `E` is **causally down-closed** if

```text
e in E  =>  parents(e) is a subset of E
```

Only down-closed event sets are valid replay inputs.

If a hub receives an event without ancestors, merge is undefined
until missing ancestors are fetched or an explicit fork policy is
invoked.

## 5.3 Merge

For valid down-closed event sets

```text
E1 join E2 = E1 union E2
```

Since both sets are down-closed, their union is down-closed. For
incomplete received sets, merge is undefined until ancestor closure
is restored.

## 5.4 Canonical replay order

The event DAG induces a partial order

```text
e_i < e_j   if   e_i is an ancestor of e_j
```

Replay uses the canonical topological ordering of this DAG, with
ties in causal antichains broken lexicographically by event id.
Since event ids are content hashes, this tie-break is deterministic
across hubs.

## 5.5 Replay

Let `R(E)` be the Atlas state obtained by folding the deterministic
reducer over the canonical order of `E`. Thus

```text
A = R(E)
```

## 5.6 Concurrent payload interactions

Suppose two events `e1, e2` are causally concurrent. Replay does not
resolve payload interactions by arrival order. It classifies the
interaction and derives state deterministically.

### 5.6.1 Polarity disagreement

If `e1` contributes supporting provenance and `e2` contributes
refuting provenance for the same claim-context pair `(q, c)`, replay
derives

```text
sigma(q, c) = B
```

and creates derived discord state:

```text
discord(
  kind   = Conflict,
  target = (q, c),
  causes = [e1.id, e2.id]
)
```

Belnap `B` is the deterministic resolution rule for polarity
disagreement.

### 5.6.2 Confidence disagreement

If `e1` and `e2` update `kappa(q, c)` incompatibly without changing
evidence polarity, replay does not promote `sigma(q, c)` to `B`.
Instead, replay creates derived discord:

```text
discord(
  kind   = ConflictingConfidence,
  target = (q, c),
  causes = [e1.id, e2.id]
)
```

The confidence state `kappa(q, c)` is then handled by the
schema-specific reducer: mixture, interval widening, model-set
expansion, or policy-required review. The formal core only requires
deterministic handling.

### 5.6.3 Commuting field updates

If `e1` and `e2` affect disjoint fields, or one changes provenance
while the other adds unrelated metadata, replay applies both in
canonical order and does not create discord.

### 5.6.4 Policy-level resolution

A derived discord object is computed state, not a new log event. A
policy layer may later append:

```text
contest event
fork event
resolution event
supersession event
```

The formal core remains deterministic.

---

# 6. Retraction

For a set `Y` that is a subset of `X` of retracted sources or events,
define the retraction homomorphism

```text
rho_Y : N[X] -> N[X]
```

by

```text
rho_Y(x) = 0   if x in Y
rho_Y(x) = x   if x not in Y
```

extended homomorphically over addition and multiplication.

Retraction is not deletion. Retraction is a state-changing event
that changes how provenance evaluates.

---

# 7. Status derivation from provenance

For each claim-context pair `(q, c)`, maintain two provenance
polynomials

```text
pi_T(q, c)  in N[X]   = supporting derivation provenance
pi_F(q, c)  in N[X]   = refuting derivation provenance
```

The Belnap status is derived from nonempty support:

```text
T  if  supp(pi_T) is nonempty  and  supp(pi_F) is empty
F  if  supp(pi_T) is empty     and  supp(pi_F) is nonempty
B  if  supp(pi_T) is nonempty  and  supp(pi_F) is nonempty
N  if  supp(pi_T) is empty     and  supp(pi_F) is empty
```

This derivation is the substrate status rule. Review policy
determines which evidence is admitted into `pi_T` and `pi_F`. The
substrate then propagates consequences.

---

# 8. Frontier ranking

Frontier support is structural. Frontier ranking is decision-theoretic.

For a candidate action, review, or experiment `e`, define

```text
Rank(e | A) = E_{theta, y ~ p(theta, y | A, e)} [ U(A, e, y, theta) ]
```

where

```text
theta        = latent scientific state
y            = possible outcome of e
kappa(q, c)  = current Atlas posterior used as prior for affected
               claim-context pairs
U            = explicit utility function
```

Utility may include:

```text
expected information gain
practical relevance
translation value
tractability
review burden
cost
risk
redundancy
ethical constraint
time
```

Any product score such as `information_gain * tractability - cost`
is only a UI approximation to `U`, not the theory.

---

# 9. Constellation

Given Atlases `A_i : C_i^op -> CarinaState`, a **Constellation** is a
bridge-augmented Atlas over a combined context category.

Start with the disjoint union

```text
C_star = C_1 + C_2 + ... + C_n
```

Then add bridge spans `c_i <- b_ij -> c_j` where `b_ij` is a typed,
provenance-bearing bridge context.

Examples:

```text
BBB delivery context      <-> Alzheimer's neurovascular context
GBM tumor microenvironment <-> neuroinflammation context
protein stability context  <-> materials stability context
```

A Constellation is

```text
Const : C_star^op -> CarinaState
```

with the condition that restriction to each `C_i` recovers the
corresponding Atlas `A_i`, up to bridge policy.

A bridge is not an equivalence. It is a reviewable, typed,
provenance-bearing cross-context relation. A Constellation is a
network of Atlases connected by explicit cross-context bridges.

## 9.1 Transfers: the constructive side of a bridge

A bridge above is an *epistemic* link between context categories. When
both frontiers are *directly verifiable* (each carries a frozen verifier
on candidate objects), a bridge has a constructive counterpart: a
**transfer**, a map of candidate objects that *preserves verification*.

Model a verifiable frontier as a pair `F = (Obj, verified)` where `Obj`
is the type of candidate objects and `verified : Obj -> Prop` is the
frozen verifier. A **transfer** `T : F_A -> F_B` is a verifier-homomorphism:

```text
T = (toFun : Obj_A -> Obj_B,
     sound : forall o, verified_A o -> verified_B (toFun o))
```

Transfers carry an identity and compose (Section 10, Theorem 23), so
verifiable frontiers and transfers form a category; a path of bridges
composes into a single transfer. The payoff is that a *verified* result
in one frontier becomes a *verified* result in a connected one with no
new search, and a transferred witness can *close* a discord point in the
target (Theorem 23, `transfer_closes`). This is the formal statement of
the cross-frontier moat: discoveries that live in the morphisms between
frontiers, invisible to single-frontier search.

Real instances (re-checkable, not metaphor):

```text
Sidon (B_2) sets {0,1}^n  ->  B_h sets        (packed encoding; verifier verify_bh)
[8,4,4] Hamming code      ->  E8 kissing config (Construction A; verifier verify_kissing)
```

The second constructs the 240-point E8 kissing configuration from the code side,
a verified *witness* matching the known optimum `K(8) = 240` (the matching upper
bound is Odlyzko-Sloane / Levenshtein, not part of the transfer).
Both are verifier-homomorphisms in the sense above.

---

# 10. Theorems

## Theorem 1: Replay convergence

**Statement.** Let `E` be a finite, valid, causally down-closed
event set. Assume all schema and reducer artifacts referenced by `E`
are content-addressed and included in the dependency closure of `E`.
Let `R` be deterministic replay using canonical topological order
with lexicographic event-id tie-breaking. Then any two hubs with the
same `E` compute byte-identical Atlas state:

```text
R_1(E) = R_2(E)
```

**Proof sketch.** Event ids are content hashes of canonical event
content. Validity depends only on ancestors in `E`. The event DAG
defines a partial causal order. The replay order is the unique
canonical topological order induced by lexicographic event-id
tie-breaking. The reducer is deterministic and schema/reducer
artifacts are fixed by content hash. Concurrent conflicting events
are represented as derived discord and Belnap `B`, not resolved by
arrival order. Therefore replay is a pure function of `E`.

**Implementation requirements.**

```text
canonical event serialization
content-addressed schema and reducer artifacts
causally down-closed event sets
canonical topological replay order
lexicographic event-id tie-break
deterministic reducer
canonical byte serialization of final Atlas state
```

---

## Theorem 2: Provenance retraction monotonicity

**Statement.** Let `p in N[X]` be a provenance polynomial. Let
`rho_Y` be the retraction homomorphism for `Y subset X`. Then

```text
supp(rho_Y(p))  is a subset of  supp(p)
```

**Proof sketch.** `rho_Y` maps variables in `Y` to `0` and all other
variables to themselves. Therefore any monomial containing a
retracted variable is deleted. Monomials not containing retracted
variables remain unchanged. No new monomial can be introduced by
substitution. Hence support can only shrink or remain constant.

**Implementation requirements.**

```text
normalized provenance polynomials
explicit source/event identifiers
retraction represented as substitution
support recomputation after retraction
no implicit provenance creation
```

---

## Theorem 3: Status-provenance soundness

**Statement.** Let `(q, c)` be a claim-context pair with
`sigma(q, c) = T` under the status derivation rule in Section 7. Let
`Y subset X` be a retracted source/event set. If

```text
supp(rho_Y(pi_T(q, c)))  is empty
```

then after deterministic replay of the retraction effect, before any
new support-producing event is added,

```text
sigma(q, c) is not T
```

**Proof sketch.** By Section 7, `T`-status requires nonempty support
in `pi_T(q, c)` and empty support in `pi_F(q, c)`. If
`rho_Y(pi_T(q, c))` has empty support, no supporting derivation
remains. Replay derives status from remaining supporting and
refuting support. Therefore the status cannot remain `T`. It becomes
`N` if no refuting support remains, `F` if refuting support exists,
or another non-`T` state if policy adds further derived status. It
cannot remain simply supported.

**Implementation requirements.**

```text
separate supporting and refuting provenance polynomials
status derived from support sets
retraction events trigger provenance reevaluation
status recomputed after provenance change
no manual status persistence after support disappears
```

Operational meaning: no zombie findings.

---

## Theorem 4: Detector monotonicity implies frontier support monotonicity

For each discord kind `k in K`, let `D_k : C -> 2` be a detector for
discord kind `k`.

Define

```text
D_A(c) = { k in K | D_k(c) = 1 }
```

so `D_A : C -> P(K)`.

**Detector-design obligation.** The monotonicity of `D_A` is not
automatic. It is a detector-design obligation.

A detector `D_k` is monotone if

```text
c' -> c  and  D_k(c') = 1  =>  D_k(c) = 1
```

Operationally: if a refined context contains discord of kind `k`,
the broader context cannot be treated as globally stable with
respect to `k` unless the discord is resolved or explicitly scoped
away.

**Statement.** If every detector `D_k` is monotone, then `D_A` is
monotone under pointwise union, and

```text
supp(D_A) = { c in C | D_A(c) is nonempty }
```

is upward closed. That is

```text
c' -> c  and  c' in supp(D_A)  =>  c in supp(D_A)
```

**Proof sketch.** If `c' in supp(D_A)`, then there exists some
`k in K` such that `D_k(c') = 1`. Since `D_k` is monotone and
`c' -> c`, we have `D_k(c) = 1`. Therefore `k in D_A(c)`, so
`D_A(c)` is nonempty. Hence `c in supp(D_A)`.

**Implementation requirements.**

```text
explicit context refinement relation
detectors assigned to discord kinds
monotone discord propagation rule
local detector outputs aggregated upward
frontier support computed from D_A
```

Operational meaning: frontier computation can be local and
aggregated upward. Narrow discord cannot be hidden by broader
labels. The theorem is only as strong as the detector family;
missing detector kinds produce missing frontier support.

---

## Theorem 5: Hash-DAG log integrity

**Statement.** Assume `H` is collision-resistant and
second-preimage-resistant. If an event `e` in a committed hash-DAG
log is tampered with, then the event id changes and all descendant
commitments depending on `e` are invalidated, except with negligible
probability in the security parameter.

**Proof sketch.** The event id is

```text
id(e) = H(canonical(e without id))
```

Changing event content changes the hash unless a collision or
second preimage is found. Descendant events include parent ids, so
any changed ancestor id changes descendant commitments. Merkle or
hash-DAG inclusion proofs verify membership against committed roots.
Preserving the same committed root after tampering would require
breaking the hash assumption.

**Implementation requirements.**

```text
canonical event serialization
collision-resistant hash function
parent ids included in event content
Merkle or hash-DAG root commitments
signed roots or signed checkpoints
inclusion and consistency proofs
```

---

## Theorem 6: Signature stability under cache-flag flips

**Statement.** Let `canonicalJson` denote the v0.104 finding signing
preimage, defined to exclude `flags.jointly_accepted` from
serialization. For any finding `f` and any signature scheme that
verifies by recomputing `canonicalJson` against current finding
bytes, flipping `f.flags.jointly_accepted` does not invalidate
existing signatures over `f`.

**Proof sketch.** `canonicalJson(f)` is independent of
`f.flags.jointly_accepted` by construction; therefore
`canonicalJson(f with jointlyAccepted := ¬b) = canonicalJson(f)` for
every Boolean `b`. A verifier consulting only `canonicalJson` returns
the same accept/reject for any signature against the same key
regardless of the flag state. The companion property
(`signature_threshold` IS in the preimage) keeps the threshold
cryptographically locked: an attacker who lowers the threshold
invalidates every existing signature over the finding, which is
the right behavior.

**Why this matters.** The v0.37 multi-actor joint-signature flow
flips `jointly_accepted` from false to true once `k` distinct
registered actors have each signed the finding. Pre-v0.104 the
flip mutated the canonical bytes and invalidated every signature
that had just made the threshold; the substrate could record
`jointly_accepted = true` on disk but no signature
cryptographically validated against current bytes. Theorem 6 is the
algebraic guarantee that the v0.104 fix actually closes that gap:
under the new `canonicalJson` rule, signatures remain stable
across the flip, so the substrate's joint-acceptance claim has
verifiable cryptographic backing.

**Implementation requirements.**

```text
canonical_json must exclude flags.jointly_accepted
signature_threshold must remain in canonical_json
verifier must recompute canonical_json against current bytes
```

**Formalization.** Lean module: `lean/Vela/Signing.lean`. The
companion theorem `theorem6_pre_vs_post_fix_distinction` proves
the structural difference is real: the pre-fix preimage was
demonstrably flip-sensitive on a concrete finding, while the
post-fix preimage is provably flip-invariant on every finding.
`canonicalJson_threshold_locked` proves the dual property: the
threshold field IS sensitive to changes, so an attacker cannot
silently lower it.

**Implementation gate.** `scripts/test-multisig-threshold.sh`
exercises the post-fix happy path end-to-end: two distinct actors
sign a threshold-2 finding, verify reports `valid=2 signers=2
jointly_accepted=1`. The Rust unit tests in
`crates/vela-protocol/src/sign.rs` cover the invariant directly.

---

## Theorem 7: Replay-index correctness under append

**Statement.** Let `lookup` denote the function that walks a
list of findings and returns the position of the first
element with a given id. Let `xs` be a list of findings whose
ids are pairwise distinct, and let `x` be a finding whose id
does not appear in `xs`. Then for every key `k`,

```text
lookup (xs ++ [x]) k =
    if k = id(x) then some xs.length
                 else lookup xs k
```

**Why this matters.** v0.105 introduced an O(N) replay
optimization: `replay_from_genesis` builds a
`HashMap<finding_id, usize>` once at the start and updates it
in lockstep with `finding.asserted` pushes. Per-kind apply
functions look up their target via `idx.get(id)` instead of
linear-scanning `state.findings`. Theorem 7 is the algebraic
guarantee that the in-place index maintenance is sound:
inserting `(id(x), xs.length)` after a push agrees with
rebuilding the index from the new list.

**Proof sketch.** By induction on `xs`. The base case is
direct: lookup over `[x]` for `id(x)` returns `some 0` =
`some [].length`, and lookup for any other key returns
`none`. The inductive case splits on whether the head's id
matches the target key. If it matches, both sides return
`some 0`. If it doesn't match, both sides recurse to the
tail; the inductive hypothesis closes the gap. The
freshness assumption (`x`'s id not in `xs`) is consumed in
the head-mismatch branch of `lookup_append_hit`.

**Implementation requirements.**

```text
findings are append-only (no removals)
ids are content-addressed (pairwise distinct)
build_finding_index iterates the list and inserts each (id, position)
apply_finding_asserted inserts (finding.id, position) after push
no other reducer arm mutates state.findings positions
```

The substrate's reducer satisfies all five conditions. The
v0.105 commit comment states "findings are append-only in the
substrate, so the index never goes stale; positions remain
valid for the life of a replay." Theorem 7 is that statement
as a Lean-checked theorem.

**Formalization.** Lean module: `lean/Vela/ReplayIndex.lean`.
The companion lemmas `lookup_append_miss` (appending a fresh
key doesn't change other lookups) and `lookup_append_hit`
(the appended key's lookup returns the new last position) are
fully proved by induction; Theorem 7 combines them.

**Implementation gate.** `crates/vela-protocol/tests/replay_perf.rs`
exercises the optimized replay against the v0.96 baseline; the
substrate's correctness is also pinned via the cross-impl
conformance suite at `conformance/`, which runs the same
event log through the Rust and Python reducers and compares
the resulting frontier state byte-for-byte.

## Theorem 8: Erdős-Ginzburg-Ziv (1961), n = 2 case

**Statement.** For any three integers `a, b, c`, at least one
of the three pairwise sums is divisible by 2:

```text
∀ a b c : ℤ. (a + b) % 2 = 0 ∨ (a + c) % 2 = 0 ∨ (b + c) % 2 = 0.
```

**Why this matters.** The Erdős-Ginzburg-Ziv theorem (1961)
asserts that among any `2n - 1` integers, some `n` of them sum
to a multiple of `n`. The general theorem requires the
Chevalley-Warning machinery from combinatorics. The `n = 2`
case is provable directly by pigeonhole on parity, and gives
the substrate's machine-checked theorem bundle a non-trivial
external mathematical claim alongside the substrate's own
correctness theorems. This demonstrates that Vela can carry
formalized claims for findings that ride on its frontiers
(e.g. the agent-drafted Erdős proposals shipped with
`examples/erdos-problems/` at v0.111) without leaving
substrate concerns.

**Proof sketch.** Every integer satisfies `x % 2 ∈ {0, 1}`,
so three integers map into two parity classes; by
pigeonhole, at least two share a class. Two integers with
the same parity have an even sum:
`(a + b) % 2 = (a % 2 + b % 2) % 2 = 2 * (a % 2) % 2 = 0`.
The Lean proof walks all 2³ = 8 parity patterns explicitly
and selects which pair-sum is even in each.

**Formalization.** Lean module: `lean/Vela/EGZ.lean`. The
helper lemma `int_emod_two` proves `x % 2 ∈ {0, 1}` via
`Int.emod_nonneg` + `Int.emod_lt_of_pos`. The helper lemma
`sum_even_of_same_parity` proves that integers with equal
mod-2 residue sum to zero mod 2. `theorem8_egz_two` combines
them with a case split on the eight residue patterns. No
`sorry` anywhere; verify with
`lake build Vela.EGZ` from `lean/`.

**Out of scope.** The general EGZ theorem (arbitrary `n`) is
not formalized here. The substrate-relevant work is to keep
formalized claims discoverable; future cycles may extend the
bundle with the general case via the Chevalley-Warning route
or import an existing mathlib formalization if one lands.

## Theorem 9: Canonical event-id determinism (serialize then hash)

**Statement.** Let `canonicalBytes : EventCore → ByteString`
be the substrate's canonical-bytes serializer and let
`H : ByteString → EventId` be its abstract hash. If both are
injective on their respective domains, then the composed
canonical-event-id function

```text
canonicalEventId(core) := H(canonicalBytes(core))
```

is itself injective on event cores. Distinct event cores
produce distinct canonical event ids.

**Why this matters.** The substrate's canonical event id is a
two-stage pipeline: serialize the event core to canonical
bytes (canonical JSON with sorted keys, fixed numeric
formatting, explicit field order), then hash the bytes with
sha256. Theorem 5 already pins the abstract version of this
guarantee at the level of an `EventCore → EventId` map.
Theorem 9 names the intermediate `canonical_bytes` layer
explicitly so the substrate's design choice (serialize first,
hash second) is checked end-to-end. The substrate-honest
reading: the serialization step does real work, not just
sitting between two abstractions, and its injectivity composes
cleanly with the abstract-hash injectivity that Theorem 5
assumes.

**Proof sketch.** By `Function.Injective.comp` from Mathlib:
if `g : A → B` is injective and `f : B → C` is injective, then
`f ∘ g : A → C` is injective. Setting `g := canonicalBytes`
and `f := H`, the composition `H ∘ canonicalBytes` is
injective. The Lean proof is one line.

**Formalization.** Lean module: `lean/Vela/CanonicalEventId.lean`.
The `canonicalEventId` definition makes the composed pipeline
explicit; `theorem9_canonical_event_id_injective` is the main
result; `theorem9_same_id_implies_same_core` is the
contrapositive form the substrate's replay-index correctness
argument (Theorem 7) uses implicitly. Verifies with
`lake build Vela.CanonicalEventId`.

**Out of scope.** This is a structural theorem under an
abstract-injectivity assumption on the hash. It does not
prove cryptographic collision resistance of sha256; that is
an algorithmic property Lean cannot address. It does prove
that the substrate's two-stage pipeline does not introduce
its own collisions, which is the load-bearing question for
canonical event ids.

## Theorem 10: Signature uniqueness under canonical bytes

**Statement.** Let `canonicalBytes : EventCore → ByteString`
be the substrate's canonical-bytes serializer (per Theorem 9)
and let `sign : ByteString × SigningKey → Signature` be an
abstract sign function. If both are injective on their
respective inputs, then the substrate's signing pipeline

```text
signPipeline(c, k) := sign(canonicalBytes(c), k)
```

is itself injective on `(event_core, signing_key)` pairs.
Equivalently: distinct `(event_core, signing_key)` inputs
produce distinct signatures.

**Why this matters.** Theorem 6 proved that toggling
cache-only fields on a `Finding` does not change the
canonical bytes it signs (signature stability). Theorem 9
proved canonical-bytes injectivity. Theorem 10 closes the
final layer of the substrate's signing record: the
serialization step plus the keying step are both
load-bearing in the signing pipeline, and they compose
cleanly. An attacker cannot construct two distinct
`(event_core, signing_key)` pairs that share a signature.

**Proof sketch.** Unfold the pipeline to expose the
`(canonicalBytes(c), k)` pair, apply `sign`'s injectivity to
recover equality of the pairs, then apply `canonicalBytes`'s
injectivity to the first component. The Lean proof is six
lines; the contrapositive form is given as
`theorem10_distinct_core_or_key_implies_distinct_sig`.

**Formalization.** Lean module:
`lean/Vela/SignatureUniqueness.lean`. The main result is
`theorem10_signature_uniqueness_under_canonical`. Verifies
with `lake build Vela.SignatureUniqueness`.

**Out of scope.** This is a structural theorem under an
abstract-injectivity assumption on `sign`. The substrate's
actual signing function is
`ed25519_dalek::SigningKey::sign(canonical_bytes)`, which is
cryptographically EUF-CMA-secure under standard assumptions.
The injectivity assumption here is weaker than full EUF-CMA;
Lean does not prove cryptographic forgery resistance, only
that the substrate's pipeline composes injective layers
into an injective whole.

## Theorem 11: Multi-sig threshold soundness

**Statement.** Let `sigs : List (SignerKey × Signature)` be
the signatures attached to a finding, `validate` an abstract
signature-verification predicate over `(signature pair,
canonical bytes)`, and define

```text
distinctValidSigners(validate, sigs, canonical) :=
  ((sigs.filter validate).map fst).toFinset
```

Then three properties hold:

- **Distinctness (11.a)**: `sk ∈ distinctValidSigners ↔ ∃ sig, (sk, sig) ∈ sigs ∧ validate (sk, sig) canonical`.
- **Monotonicity (11.b)**: appending a signature to `sigs` never
  decreases `distinctValidSigners.card`.
- **Registration-bound (11.c)**: `distinctValidSigners.card ≤
  (sigs.map fst).toFinset.card`.

**Why this matters.** The substrate's v0.37 multi-sig kernel
rule says a finding is "jointly accepted" iff the count of
distinct keys with valid signatures meets or exceeds a
threshold `k`. The v0.104 canonical-bytes fix kept that rule
intact under cache-flag flips. Theorem 11 pins the rule's
algebraic shape: counting distinct valid signers and
comparing to `k` is sound under monotonicity, distinctness,
and registration-bound. An attacker cannot lower the
effective threshold by inserting duplicate-key signatures
(distinctness collapses them) or unregistered-key signatures
(registration-bound caps the count at the registered set).

**Proof sketch.** The three properties are direct corollaries
of `Finset.card_le_card` plus the definitional unfolding of
`toFinset` and `List.mem_filter`. Each is six to ten lines of
Lean.

**Formalization.** Lean module:
`lean/Vela/MultiSigThreshold.lean`. Three theorems:
`theorem11a_distinctness`, `theorem11b_monotone_under_append`,
`theorem11c_registration_bound`. Verifies with
`lake build Vela.MultiSigThreshold`.

**Out of scope.** Cryptographic strength of the underlying
signature scheme; implementation correctness of
`canonical_json` (Theorem 6 handles canonical-bytes
stability; the substrate's
`scripts/test-multisig-threshold.sh` regression gate covers
the Rust implementation).

## Theorem 12: Concurrent-replay commutativity for disjoint events

**Statement.** Let `apply : AtlasState × Event → AtlasState` be
the reducer's apply function and `disjoint : Event × Event →
Prop` the substrate's predicate naming when two events target
different findings. If `apply` is locally commutative on
disjoint events:

```text
∀ s e₁ e₂. disjoint(e₁, e₂) ⇒ apply(apply(s, e₁), e₂)
                              = apply(apply(s, e₂), e₁)
```

then for any two canonical events `e₁, e₂` with disjoint
targets, the final state is independent of application order:
`apply(apply(s₀, e₁), e₂) = apply(apply(s₀, e₂), e₁)`.

**Why this matters.** The substrate's canonical-order doctrine
(Theorem 1) pins replay determinism under a *single* canonical
order. Theorem 12 closes the symmetric claim: events that affect
*disjoint* state (different `target.id` fields) commute, so the
canonical order is load-bearing only for events that share a
target. The substrate's parallel-ingest path (two reviewers
asserting different findings concurrently) is sound iff the
reducer is locally commutative on disjoint events. Theorem 12
makes that assumption explicit.

**Proof sketch.** The proof is one line: under the local-
commutativity hypothesis, the theorem is exactly the predicate
instantiated at the given pair. The substrate value is naming
`LocallyCommutative` as a hypothesis rather than letting it
remain implicit in the Rust code.

**Formalization.** Lean module:
`lean/Vela/ConcurrentReplay.lean`. Two theorems:
`theorem12_concurrent_replay_commutes` (main statement) and
`theorem12b_two_event_swap` (named base case for the n-event
permutation extension). Verifies with
`lake build Vela.ConcurrentReplay`.

**Out of scope.** The n-event permutation extension (any
permutation of pairwise-disjoint events produces the same
state) reduces to repeated adjacent swaps of Theorem 12; the
formal proof of the n-event case is deferred. Events that share
a target finding do not commute in general; the substrate's
canonical order remains load-bearing for those. The
implementation-correctness of the Rust reducer's locally-
commutative-on-disjoint behavior is covered by the cross-impl
conformance suite at `conformance/`, which the substrate
runs at every release cut.

## Theorem 13: Frontier-id determinism

**Statement.** Let `canonicalEventLog : EventLog → ByteString` be
the substrate's serializer over a frontier's canonical event log,
and let `H : ByteString → FrontierId` be the hash function used to
produce `vfr_*` ids. If `canonicalEventLog` is injective on event
logs and `H` is injective on byte strings, then the composed
frontier-id function `frontierId = H ∘ canonicalEventLog` is
injective on event logs: distinct event logs produce distinct
`vfr_*` ids.

**Why this matters.** The substrate's `vfr_*` ids are
content-addressed: a frontier id is
`sha256(canonical_bytes(event_log))`. Two hubs that return
byte-identical canonical bytes for a shared `vfr_*` necessarily
agree on the underlying event log. Theorem 13 pins this end-to-end
at the algebraic level. It composes Theorem 9 (per-event
canonical-bytes injectivity) one layer up to the *event-log*
layer, closing the substrate's content-addressing record with
proven injectivity at both layers: per event and per frontier.

**Proof sketch.** Function composition preserves injectivity. The
Lean proof is one line via `Function.Injective.comp`, mirroring
the structure of Theorem 9 at the event-log layer rather than the
per-event layer.

**Formalization.** Lean module:
`lean/Vela/FrontierIdDeterminism.lean`. Two theorems:
`theorem13_frontier_id_injective` (main statement) and
`theorem13_same_id_implies_same_log` (the contrapositive form
used directly in the witness-check argument). Verifies with
`lake build Vela.FrontierIdDeterminism`.

**Substrate role.** This is the substrate-side guarantee that the
v0.129 `vela registry witness-check` primitive (A11 cross-hub
divergence detector) implicitly assumes: when two hubs agree on
the canonical bytes for a given `vfr_*`, they agree on the
frontier's underlying state. The Rust implementation lives at
`crates/vela-protocol/src/repo.rs::frontier_id`, which composes
canonical-bytes with sha256.

**Out of scope.** Cryptographic collision resistance of sha256 is
abstracted as an injective-hash assumption, consistent with the
structural model of Theorem 5. The implementation correctness of
`canonicalEventLog` over the Rust event-log type is covered by
the canonical-bytes round-trip tests in
`crates/vela-protocol/tests/canonical_*.rs`.

## Theorem 14: Proposal-acceptance idempotency

**Statement.** Let `accept : S × P → S` be the substrate's
reducer arm for `proposal.accepted` events and let
`DedupedOn accept s p` denote the substrate's "this proposal is
already in `s`'s accepted-set" predicate (concretely: the
post-acceptance state's defining property under the dedup
rule). If `DedupedOn accept (accept s p) p` holds, then:

```text
accept (accept s p) p = accept s p
```

The reducer is idempotent on repeated acceptance of the same
proposal.

**Why this matters.** The substrate's `proposal.accepted` event
carries an `applied_event_id`. The reducer maintains an
accepted-set on the frontier; the dedup rule states that an
acceptance event whose `applied_event_id` is already in the set
produces no further projection-state change. Theorem 14 pins
this algebraically. The substrate-honest consequence: a replay
or federation re-sync that re-emits the same accepted-proposal
event can not diverge from the canonical state, even if the
event arrives many times in succession.

**Proof sketch.** One line: the deduplication hypothesis says
`accept (accept s p) p = accept s p` directly, which is the
substrate's dedup rule applied at the post-acceptance state.
The Lean proof is `exact hDedup`. A threefold corollary
(`accept (accept (accept s p) p) p = accept s p`) verifies by
rewriting twice.

**Formalization.** Lean module:
`lean/Vela/ProposalIdempotency.lean`. Two theorems:
`theorem14_accept_idempotent` (main statement) and
`theorem14_accept_threefold` (named corollary for the
three-in-a-row case used directly in the federation re-sync
argument). Verifies with `lake build Vela.ProposalIdempotency`.

**Substrate role.** Pins the substrate's dedup guarantee at the
algebraic level. The Rust implementation lives at
`crates/vela-protocol/src/reducer.rs::apply_event` in the
`proposal.accepted` arm, which checks `applied_event_id`
against the frontier's accepted-set before applying the
projection delta.

**Out of scope.** The implementation correctness of the
accepted-set lookup over the Rust state type is covered by the
reducer's cross-impl conformance suite at `conformance/`. The
Lean theorem abstracts the dedup predicate so that any future
substrate implementation that satisfies `DedupedOn` inherits
the idempotency guarantee.

## Theorem 15: Confidence-update bounds

**Statement.** Let `revise : ℝ × ℝ → ℝ` be the reviewer-policy
confidence-revision step (input current confidence `c` and
proposed delta `δ`; output new confidence). Let `cap` be the
per-event delta cap declared by the reviewer policy. If the
substrate enforces the bounded-update rule:

```text
∀ c δ. |revise c δ - c| ≤ cap
```

then for any single `finding.confidence_revise` event, the
magnitude of the actual confidence change is at most `cap`.

**Why this matters.** This pins the substrate's defense against
confidence drift under reviewer compromise. An attacker who
controls a single reviewer key can move a finding's confidence
by at most `cap` per event. The cap is the load-bearing
parameter: a small cap bounds short-horizon damage tightly; a
large cap admits faster legitimate updates but admits faster
attacker drift too. Defending against long-horizon multi-event
drift requires multi-reviewer attestation, which is a separate
threat surface; the cap alone bounds drift linearly in event
count.

**Proof sketch.** One line via the bounded-update hypothesis.
A symmetric corollary restates the bound in two-sided form:
`revise c δ ≤ c + cap` and `c - cap ≤ revise c δ`. The Lean
proof reuses Mathlib's `abs_le` to discharge the half-bounds.

**Formalization.** Lean module:
`lean/Vela/ConfidenceUpdate.lean`. Two theorems:
`theorem15_confidence_update_bounded` (main statement) and
`theorem15_two_sided_bound` (symmetric corollary for use in
policy-monitoring reasoning where one wants to bound the
upper or lower confidence independently). Verifies with
`lake build Vela.ConfidenceUpdate`.

**Substrate role.** The Rust substrate's
`crates/vela-protocol/src/state.rs::revise_confidence`
implements the bounded-update rule: a
`finding.confidence_revise` event whose proposed delta
magnitude exceeds the reviewer-policy cap is either rejected
at the apply step or saturated at the cap. Theorem 15 names
that bound algebraically.

**Out of scope.** The N-event drift bound (linear in event
count) follows from Theorem 15 by induction; the substrate
records the per-event delta on the canonical event so audits
can reconstruct the cumulative move. The Lean module proves
the single-event bound; the inductive extension is left as a
substrate-side reasoning step rather than a separate theorem.
Multi-reviewer attestation as a long-horizon defense against
cumulative drift is a separate threat surface.

## Theorem 16: Governed-quorum soundness

**Statement.** Let `attestations : List Actor` be the list of
governance attestations on an owner-rotation proposal, and let
`eligible, revoked, signed : Actor → Bool` denote membership
in the active policy's `rotate_quorum.eligible_actors`,
revocation at-or-before the attestation timestamp, and
production of a valid Ed25519 signature over the canonical
proposal preimage respectively. If
`AccGoverned attestations eligible revoked signed threshold`
holds (the count of distinct actors satisfying
`eligible ∧ ¬revoked ∧ signed` is at least `threshold`), then
there exists a sublist of length `≥ threshold` whose every
element satisfies all three predicates simultaneously.

**Why this matters.** This is the algebraic guarantee
underlying v0.145 governed owner-rotate. A compromised current
owner cannot satisfy the predicate without compromising the
threshold authority set: the count is over distinct eligible
non-revoked signers, so the v0.144 validator's rejection of
non-bootstrap policies with `current_owner_counts: true` lifts
to a hard guarantee that single-key compromise is insufficient
for non-bootstrap rotations.

**Proof sketch.** The witnessing sublist is exactly the dedup
+ filter applied to `attestations`. The length lower bound is
the hypothesis. The `Nodup` follows from
`List.Nodup.filter` over `List.nodup_dedup`. The pointwise
predicate split follows from Boolean conjunction unfolding.

**Formalization.** Lean module:
`lean/Vela/GovernedQuorumSoundness.lean`. One theorem:
`theorem16_governed_quorum_sound`. Verifies with
`lake build Vela.GovernedQuorumSoundness`. Composes Theorem 11
(multi-sig threshold counting), Theorem 10 (signature
uniqueness), and Theorem 13 (frontier-id determinism — gives a
unique proposal preimage per frontier + epoch).

**Substrate role.** The Rust substrate's
`crates/vela-protocol/src/governance.rs::verify_quorum`
implements the same rule: distinct-signer counting, eligibility
check, revocation check, Ed25519 signature check. Theorem 16
makes the rule algebraic.

**Out of scope.** The full security argument against an
attacker who controls the *threshold* set of governance keys
(rather than just the current owner) is not formalized — no
protocol survives compromise of the authority set, and the
defense lives in policy design (larger quorum, role diversity,
institutional stewards) rather than in the algebra. The
mathlib proof models attestations as a Boolean predicate
satisfying-set; the substrate's Ed25519 signature check is the
operational realization.

---

## Theorem 23: Cross-frontier transfer soundness (constellation layer)

**Statement.** Model a verifiable frontier as `F = (Obj, verified)` with
a frozen verifier `verified : Obj -> Prop`. A **transfer**
`T : F_A -> F_B` is a verifier-homomorphism `(toFun, sound)` where
`sound : forall o, verified_A o -> verified_B (toFun o)`. Then for any
verified `o` in `A`,

```text
verified_A o  =>  verified_B (T.toFun o)
```

Moreover verifiable frontiers and transfers form a category: there is an
identity transfer, and transfers compose (`(S.comp T).toFun = T.toFun ∘
S.toFun`) with the identity as unit and associative composition.
Frontier reduction: if a verified `A`-object transfers to a `B`-object
satisfying a target predicate `q`, then `q` has a verified witness in `B`
(`transfer_closes`), i.e. a resolved finding in one frontier can remove a
discord point in a connected one.

**Proof.** Immediate from the homomorphism field `sound`; composition is
function composition with the soundness fields chained; unit and
associativity hold definitionally (`rfl`). Fully proved, Mathlib-free,
in `lean/Vela/Transfer.lean` (`transfer_sound`, `Transfer.id`,
`Transfer.comp`, `transfer_closes`).

**Why this matters.** This is the formal core of the constellation
(Section 9.1) and of Vela's distinctive edge. The substrate Theorems
1-5 are single-frontier; Theorem 23 is the inter-frontier guarantee that
*verification transports*. It is not new mathematics (a category of
objects-with-verifiers and verification-preserving maps); the
contribution is that it specifies the cross-frontier moat and is
machine-checked. Empirical instances: the Sidon (B_2) -> B_h transfer
and the `[8,4,4]` code -> E8 kissing transfer (which reproduced the
240-point `K(8) = 240` kissing configuration, matching the known optimum). Honest scope: a transfer only earns this
guarantee once `sound` is discharged for the specific map; the theorem
is the contract, the per-bridge `sound` proof is the obligation.

---

# 11. Counterexamples to stronger claims

## 11.1 Atlas is not a sheaf in general

A presheaf becomes a sheaf only when compatible local sections glue
uniquely to a global section. This fails for scientific state.

Construct a simple case. Let `X` be a broad context covered by
subcontexts `U, V` with overlap `W`. Let

```text
A(U) = A(V) = A(W) = {*}
```

but

```text
A(X) = {g_1, g_2}
```

with both `g_1` and `g_2` restricting to `*` on `U, V, W`. Then the
local sections agree on the overlap but admit two possible global
sections. Uniqueness fails.

Scientific interpretation: two local experimental domains agree on
all shared observations, but two incompatible broader mechanisms
explain them.

Thus an Atlas is generally a presheaf with discord tracking, not a
sheaf.

## 11.2 Vela is not a pure state-based CRDT

A pure state-based CRDT requires a state lattice with a commutative,
associative, idempotent join such that merging states alone yields
convergence. Vela uses operation history.

Example:

```text
accept claim C
retract support for claim C
```

and

```text
retract support for claim C
accept claim C
```

are not semantically interchangeable without causal structure. The
hash-DAG records causality. Replay interprets operations under
causal dependencies and policy. Therefore Vela is better modeled as
an operation-based replicated datatype with causal delivery, not as
a pure state-based CRDT.

## 11.3 Frontier detection is complete only relative to the detector family

Let `K = {Conflict, EvidenceGap}`. Suppose a context has a severe
`MethodMismatch`, but `MethodMismatch` is not in `K` and no detector
emits it. Then `D_A(c)` is empty even though a domain expert would
regard `c` as frontier-relevant.

Thus frontier detection is complete only relative to the chosen
detector family. Detector design is part of the science.

## 11.4 Bayesian confidence and Belnap status cannot be collapsed into one scalar without losing structure

Consider two claim-context pairs.

Pair 1:

```text
sigma = B
kappa = high confidence
```

meaning strong accepted evidence exists both for and against the
claim.

Pair 2:

```text
sigma = T
kappa = low confidence
```

meaning weak support exists and no accepted refutation exists.

Any single scalar that ranks Pair 1 above Pair 2 or Pair 2 above
Pair 1 loses an essential distinction: evidence polarity, or
evidence strength. The substrate needs both axes. Status is
categorical. Confidence is quantitative. They are not one field.

---

# 12. Doctrine

## Negative-space laws

1. The substrate records judgments; it does not become the judge.
2. Activity is not state.
3. Truth is not a field; accepted state is a governed event history.

## Structural laws

4. Same valid event set, same replay function, same Atlas state.
5. Every object is content-addressed.
6. No claim without context.
7. No evidence without provenance.
8. No accepted transition without review policy and attestation.
9. Contradiction is first-class.
10. Retractions are events, not erasures.
11. Frontiers are computed, not declared.
12. Federation must converge or explicitly fork.
13. Reviewer attention is scarce and must be allocated by mechanism,
    not vibes.
14. The system must be useful before it is complete.

Mechanism design is important, but it is outside this formal core
until review allocation is implemented.

---

# 13. Current and target primitives

| Primitive | Status | Home |
|---|---|---|
| Append-only typed event log | Current | `VELA_PROTOCOL.md` |
| Content-addressed objects | Current | `CONTENT_ADDRESSING.md` |
| Replay-deterministic state | Current | `THEORY.md`, Theorem 1 |
| Canonical causal replay order | Current / must be explicit | `VELA_PROTOCOL.md` |
| Carina type kernel | Current | `CARINA.md` |
| Signed attestations | Current / partial | `ATTESTATIONS.md` |
| Schema/reducer artifacts as content-addressed deps | Target v0.7 | `VELA_PROTOCOL.md` |
| Federated hubs with deterministic merge | Partial | `FEDERATION.md` |
| Missing ancestor fetch/fork policy | Target v0.7 | `FEDERATION.md` |
| Formal context category C | Partial | `ATLAS_CONTEXTS.md` |
| `CarinaState` morphisms | Target v0.75 | `THEORY.md` |
| Atlas as `C^op -> CarinaState` | Target v0.8 | `THEORY.md` |
| Discord assignment `D_A` | Target v0.9 | `FRONTIERS.md` |
| Provenance semiring `N[X]` | Target v0.85 | `PROVENANCE.md` |
| Belnap contextual status | Target v0.8 | `STATUS_LOGIC.md` |
| Bayesian frontier ranking | Target v1.0 | `FRONTIER_RANKING.md` |
| Constellation bridge category | Target v0.9 | `CONSTELLATIONS.md` |
| Mechanism-design review allocation | Target v1.2 | `REVIEW_ALLOCATION.md` |
| Theorem 1 (replay convergence) Lean-checked | Current (v0.90) | `lean/Vela/Log.lean` |
| Theorem 2 (retraction monotonicity) Lean-checked | Current (v0.90) | `lean/Vela/Provenance.lean` |
| Theorem 3 (status-provenance soundness) Lean-checked | Current (v0.90) | `lean/Vela/Provenance.lean` |
| Theorem 4 (frontier upward closure) Lean-checked | Current (v0.90) | `lean/Vela/Provenance.lean` |
| Theorem 5 (hash-DAG log integrity, structural) Lean-checked | Current (v0.90) | `lean/Vela/Log.lean` |

---

# 14. Implementation obligations by theorem

## Replay convergence

Required:

```text
canonical serialization
content-addressed event ids
content-addressed schemas and reducers
down-closed event validation
canonical topological order
lexicographic event-id tie-break
deterministic reducer
byte-identical state serialization
```

Tests:

```text
same event set, randomized input order, same output hash
two hubs, different arrival order, same Atlas hash
concurrent conflict, deterministic Belnap B and discord output
```

## Provenance retraction monotonicity

Required:

```text
polynomial provenance representation
normal form for N[X]
retraction as substitution
support computation
no implicit evidence creation
```

Tests:

```text
retract p, all monomials containing p disappear
monomials not containing p remain
no new monomials appear
```

## Status-provenance soundness

Required:

```text
separate supporting and refuting provenance
status derived from support
status recomputation after retraction
review policy controls evidence admission
```

Tests:

```text
supported claim loses all support and cannot remain T
supported claim with alternate support remains T
supported claim with only refutation remaining becomes F
support and refutation together become B
```

## Discord support monotonicity

Required:

```text
context refinement relation
monotone detectors
upward discord propagation
frontier computed from supp(D_A)
```

Tests:

```text
discord in narrow context propagates to broad context
removing narrow discord removes propagated broad discord if no
  other source remains
detector family omissions are visible as missing kinds, not hidden
  truth
```

## Hash-DAG log integrity

Required:

```text
content hash ids
parent hash references
Merkle or DAG root commitments
signed roots/checkpoints
inclusion proofs
consistency proofs
```

Tests:

```text
tamper event payload, inclusion proof fails
tamper parent id, descendant commitment fails
change schema artifact, replay root changes
```

---

# 15. Lean 4 skeleton

**Historical / illustrative skeleton.** The completed proof of replay convergence
now lives in `lean/Vela/Log.lean` (Core Theorem 1; see Appendix A, the theorem
audit). The skeleton below is the original aspirational statement with its proof
obligations made explicit; it still carries a `sorry` and is kept only to show
the obligation structure, not as a current proof.

```lean
import Std.Data.HashMap
import Std.Data.HashSet
import Std.Data.List.Lemmas

namespace Vela

abbrev EventId := String

structure Event where
  id      : EventId
  parents : List EventId
  payload : String
deriving DecidableEq, Repr

structure AtlasState where
  bytes : String
deriving DecidableEq, Repr

abbrev Reducer := AtlasState → Event → AtlasState
abbrev EventSet := List Event

def downClosed (E : EventSet) : Prop :=
  ∀ e ∈ E, ∀ p ∈ e.parents, ∃ ep ∈ E, ep.id = p

def uniqueIds (E : EventSet) : Prop :=
  ∀ e₁ ∈ E, ∀ e₂ ∈ E, e₁.id = e₂.id → e₁ = e₂

/--
Canonical topological order with lexicographic event-id tie-break.

This dummy implementation exists only to make the skeleton parse.
A full formalization must replace it with a real canonical
topological sort and prove that it is invariant under different
list presentations of the same finite event set.
-/
opaque canonicalOrder : EventSet → EventSet := fun E => E

def replay (r : Reducer) (init : AtlasState) (E : EventSet) : AtlasState :=
  (canonicalOrder E).foldl r init

/--
The intended replay-convergence theorem.

Two list presentations of the same finite event set produce the same
Atlas state, assuming causal down-closure, unique ids, deterministic
replay, and canonical ordering.

The missing proof obligation is that `canonicalOrder` is extensional
over permutations of the same finite event set when ids are unique
and causal dependencies are closed.
-/
theorem replay_convergence_under_perm
    (r : Reducer) (init : AtlasState)
    (E₁ E₂ : EventSet)
    (h_perm : List.Perm E₁ E₂)
    (h₁ : downClosed E₁)
    (h₂ : downClosed E₂)
    (h_uniq : uniqueIds E₁) :
    replay r init E₁ = replay r init E₂ := by
  -- Required future lemmas:
  -- 1. canonicalOrder respects permutation of finite event sets.
  -- 2. canonicalOrder is a topological order of the event DAG.
  -- 3. lexicographic event-id tie-break gives a unique order for
  --    causal antichains.
  -- 4. replay is a pure fold over that canonical order.
  sorry

end Vela
```

This Lean skeleton states the intended theorem, not a completed
proof. The full formalization must prove that `canonicalOrder` is
invariant under list presentation of the same finite event set,
assuming unique ids and causal down-closure. A prior tautological
form `replay r init E = replay r init E` is rejected because it
proves only `x = x`, not convergence under permutation.

A fuller Lean development would need:

```text
finite sets instead of lists
content-addressed event identity
DAG acyclicity
canonical topological sort proof
schema-indexed deterministic reducer
event-set extensionality theorem
```

The important point is that replay convergence becomes almost
tautological once canonical order and deterministic replay are
specified correctly. The hard work is the canonical-order proof, not
the convergence statement.

---

# 16. Final statement

The formal core is this:

> Vela models science as attested, context-indexed state. An Atlas
> is a typed presheaf `A : C^op -> CarinaState`. Vela is an
> operation-based replicated datatype: a content-addressed
> transparent hash-DAG of signed, attested events whose
> deterministic replay constructs Atlas state. Discord is a monotone
> context assignment `D_A : C -> L` into a finite disagreement
> lattice; frontiers are the support of discord, ranked by Bayesian
> expected utility under the current Atlas posterior. Provenance is
> tracked in `N[X]`, allowing retractions to propagate algebraically.
> Contradictions are represented by contextual Belnap status,
> orthogonal to Bayesian confidence. The substrate records and
> propagates scientific state under explicit review policy; it does
> not adjudicate truth outside that policy.

That is the theorem-bearing formal core.

---

# Part II — The Frontier Calculus

*Part I proves the substrate is sound. Part II says what the state it carries
**means**. It is not a new theory of scientific truth; it composes standard
tools (provenance semirings, four-valued logic, a product bilattice, an
assumption-based truth-maintenance layer, a verification-cost admission rule)
into the read-side calculus of scientific state. The v1 kernel and the v2 delta
were validated 25/25 in `frontier_calculus_kernel.py`; the load-bearing laws are
machine-checked in `lean/Vela/FrontierCalculus.lean`. Realized in the substrate
at `vendor/vela/crates/vela-protocol/src/frontier_calculus.rs` (the Semiring
trait, the named projections, κ, the bilattice, admission, replay tiers,
assumption environments, the faithfulness monoid), surfaced by `vela claim
state`.*

Part II keeps the citation convention from the front matter: its theorems are
**Calculus Theorem N**. Where a result restates a Part I theorem it
cross-references rather than re-proves.

## 17. The spine: one free object, many readings

`N[X]`, the semiring of polynomials with natural-number coefficients over
indeterminates `X` (one variable per source event), is the **free commutative
semiring** on `X`. The kernel stores exactly one object per claim, the support
and refute provenance polynomials `π_T, π_F ∈ N[X]` of Part I §2.2 and §7, and
**derives every flag by a homomorphism out of it**. No flag is computed any
other way. This is the mathematical form of "derived, never stored": status,
confidence, cost, count, the bilattice point, are each an evaluation of the one
stored polynomial into a named semiring.

## 18. Design criteria for a scientific state plane

The calculus exists to satisfy twelve constraints, in tension with each other:
replayability; context safety; **contradiction preservation** (conflict is kept
as frontier signal, never averaged away); **retraction propagation** (no zombie
truths when support disappears); composability (verified results discharge
premises across frontiers via typed transfers); **trust separation** (formal
proof, human review, statement faithfulness, body-trace quality, and clinical
credibility are distinct coordinates, never one green check); body readiness;
model readiness; **failure memory** (failed attempts are first-class
search-pruning assets); opportunity ranking that never gates trust; forkability
and neutrality; and a minimal waist. The waist is not a paper, dataset, model
output, or lab run. It is the **signed scientific state transition**.

## 19. Related frameworks (what is composed, with citations)

The novelty is the stack and the boundary discipline, not one exotic theorem.
Provenance semirings (Green-Karvounarakis-Tannen, PODS 2007) give the support
algebra; Belnap-Dunn four-valued logic gives evidence polarity; presheaves and
sheaf-theoretic contextuality (Abramsky-Brandenburger) give local-to-global
discord; functorial data migration (Spivak) frames transfers; proof-carrying
code (Necula-Lee) generalizes to proof-carrying science; Bayesian experimental
design and do-calculus (Pearl) inform the opportunity layer and the causal
caveats; operation-based CRDTs give the convergence ambition without merging
truth; assumption-based truth maintenance (de Kleer 1986) gives the retraction
cascade; the product bilattice (Ginsberg 1988, Fitting 1991, Avron 1996) gives
the graded status. Full citations in §39.

## 20. Provenance algebra

Let `X` be the set of source, event, receipt, trace, attestation, theorem, and
transfer identifiers; `N[X]` the free commutative semiring (Part I §1). The
operations read:

```text
0      = no support
1      = empty derivation / identity
x ∈ X  = a source or event variable
p + q  = alternative support routes
p · q  = joint dependence
```

Example `π_T(F) = p1·d3 + r7·e2`: finding `F` is supported either by paper `p1`
and dataset `d3`, or by review `r7` and experiment `e2`. **Retraction** is the
homomorphism `ρ_Y` sending each variable in `Y` to `0` and fixing the rest (Part
I §6); Belnap status `σ ∈ {N,T,F,B}` is read off support/refute nonzeroness
(Part I §7). Part II grades both.

## 21. The named projections and the universality theorem

**Calculus Theorem (universality / factorization).** For any commutative
semiring `K` and valuation `v : X → K` there is a unique homomorphism
`Eval_v : N[X] → K` extending `v`, and (Green-Karvounarakis-Tannen) homomorphisms
commute with positive relational algebra: `h(Q(R)) = Q(h(R))`. Every flag
therefore factors uniquely through `N[X]`: provenance is computed once and read
many ways.

The named projections:

| projection | semiring | valuation | reading |
|---|---|---|---|
| existence | `({0,1}, ∨, ∧)` | trusted source = 1 | is there any supporting derivation |
| cost | tropical `(N∪{∞}, min, +)` | per-source verification cost | cheapest derivation; supplies `v(q,c)` in §25 |
| confidence | Viterbi `([0,1], max, ·)` | per-source confidence | best-path confidence; this is κ (§23) |
| count | `N` (bag) | each variable = 1 | how many derivations; multiplicity, never credibility |
| bottleneck | `([0,1], max, min)` | per-source confidence | a chain is as strong as its weakest premise |

*Proof.* `N[X]` is free, so any valuation extends to exactly one homomorphism;
checks c15-c17 exercise the laws and the correlated-provenance divergence
(counting vs confidence) with exact arithmetic. The **bottleneck** projection is
the one the blast-radius cascade uses (§32): it propagates a finding's support κ
along the required-premise edges.

## 22. The scope wall and the context wall

**Calculus Theorem (scope wall).** Projection commutes with derivation for
**positive** steps only. Negation, difference, and aggregation are not semiring
operations and homomorphism commutation provably fails for them (difference:
Amsterdamer-Deutch-Tannen, "On the Limitations of Provenance for Queries with
Difference", 2011; aggregation: their "Provenance for Aggregate Queries", 2011).
Semiring semantics for full first-order logic (Grädel-Tannen, dual indeterminates)
exist but are deliberately out of scope; the boundary is a scope choice, not a
claim that no semantics exists past it. The kernel enforces the boundary
mechanically: any
negation- or aggregation-shaped step tags the polynomial, and `Eval_v` refuses a
tagged polynomial; the only permitted reading of a tagged polynomial is the bare
Boolean existence degrade (check c16). This is why the calculus is silent on
graded refutation and meta-analysis rather than guessing: the argumentation and
synthesis layers (§35 laws 14, 16; §36) are the licensed extensions, deferred
until a producer needs them.

**Calculus Theorem (context wall), machine-checked.** The scope wall says which
*operations* commute with projection; the context wall is its scientific-safety
twin, saying which *movements between contexts* are licensed. No support moves
from a context `c` to a context `d` without an explicit licensed rule
(restriction, generalization, transfer, faithfulness, transport). In-context
derivation is context-preserving; only a licensed `move` advances the context.
Proved in `lean/Vela/FrontierCalculus.lean`: `context_confined` shows the context
of any supported claim is reachable from its origin along licensed moves;
`no_silent_context_jump` is the contrapositive; `confined_when_no_moves` is the
limiting instance. This is what structurally forbids `mouse model → human
claim`, `formal variant → named problem solved`, `cell assay → clinical
therapeutic`, and `benchmark result → real-world capability` from happening
silently.

**Calculus Theorem (retraction commutes with projection).** `Eval_v ∘ ρ_Y =
Eval_{v[Y→0]}`, because zero annihilates products and is the additive identity in
any semiring (check c15). This is the law the blast-radius cascade (§32) and
assumption invalidation (§27) rest on: retracting a source and recomputing κ is
the same as evaluating with that source zeroed.

## 23. The discount coordinate κ

Support accumulation σ is monotone in the knowledge order: more events never
reduce support. But multiplicity is not independence-backed credibility, a
thousand citations of one flawed source is one source. **κ** is `Eval_v` into the
Viterbi semiring `([0,1], max, ·)` with per-premise confidence: multiplication
contracts along a chain (depth decay), max selects the best alternative
derivation.

**The correlated-provenance correction (the v3 layer).** Within a monomial,
shared variables count once. Split provenance into two canonical layers:
`BagProv = N[X]` keeps multiplicity (counting, attribution); `EnvProv = Env(p)`
is the assumption-set lineage — each monomial becomes its variable *set* (an
assumption set), a polynomial becomes a *set of assumption sets*, and
multiplication is the pairwise **union** of assumption sets (idempotent: an
assumption appears once per environment). `env : N[X] → EnvProv` IS a
homomorphism (`env(p·q)` is the union of assumption sets; `env_mul_support`, T4).
κ is then the **terminal weighted readout** of that lineage:

```text
κ(p) = max over E ∈ env(p) of  ∏_{a ∈ E} w(a)
```

the best environment's product of assumption weights. **κ is NOT a semiring
homomorphism into ordinary scalar Viterbi** `([0,1], max, ·)`: that would force
`κ(x²) = κ(x)·κ(x)`, i.e. `w(x)² = w(x)`, which holds only at `w ∈ {0,1}`. On raw
`N[X]`, κ is *lax* (`κ(p·q) ≥ κ(p)·κ(q)`, strict exactly when evidence is
correlated); on the `EnvProv` layer the double-counting is impossible by
construction, because each assumption appears once per environment. So the honest
statement names its layer: **`env` is the homomorphism; `κ = weight ∘ env` is a
terminal evaluator of the environment lineage, not a homomorphism into Viterbi.**
Machine-checked in `lean/Vela/FrontierCalculus.lean`: the idempotent square-free
readout (`envWeight_idem`), the env homomorphism (`env_mul_support`, T4), and that
counting (bag) is provably distinct from κ (env), so shared evidence is never
promoted to independent support (T13 non-collapse). (Corrected per the GPT-pro
review, 2026-06-17: the earlier "κ = Eval_Viterbi ∘ env *homomorphism*" phrasing
was wrong for non-Boolean weights; `env` is the homomorphism, κ is the readout.)

**Where the weights come from (the calibration discipline).** κ's source weights
`w(a)` must come only from *auditable calibration channels*: historical verifier
pass/fail rates, prospectively scored reviewer forecasts (proper scoring rules),
replication frequencies, instrument/protocol error models, signed statistical
posteriors. They must NEVER come from LLM self-confidence, citation count, venue
prestige, institutional brand, or reviewer vibes; that would launder a guess into
authority, the exact failure the trust separation (§29) and incentive
non-interference (§35, law 19) exist to prevent. Until such channels are wired the
confidence map is empty, κ runs at its `{0,1}` corners, and the graded interior is
a conservative read-layer prepared for calibrated inputs, not a current source of
resolution.

**Calculus Theorem (σ/κ asymmetry).** σ is monotone in the knowledge order; κ is
not. A long chain of high-confidence steps still contracts; invalidating one
premise can collapse κ to zero (check c19: the telephone chain, the
thousand-citations fixture, the one-premise collapse).

**Calculus Theorem (idempotent DAG safety).** `Eval` into a semiring with
**idempotent** addition is well-defined on arbitrary DAGs with shared
sub-derivations. Viterbi (max) is idempotent and DAG-safe; a probabilistic-sum
semiring double-counts shared sub-paths and is mechanically flagged unsafe for
the confidence role (check c18, the diamond DAG). This is why the calculus uses
Viterbi/bottleneck and treats ProbSum as the unsafe foil it will not project
confidence through.

## 24. The bilattice status

A bilattice carries two lattice orders, truth and knowledge, with negation
inverting truth and preserving knowledge (Ginsberg 1988, Fitting 1991). Avron's
representation theorem (1996): every interlaced bilattice is isomorphic to a
*product* of two bounded lattices. We **choose** the unit square `[0,1] ⊙ [0,1]`
as a natural graded product instance: Avron forces the product *shape*, not the
choice of `[0,1]` as the factor lattice. Belnap's FOUR embeds as the four Boolean
corners: `T=(1,0)`, `F=(0,1)`, `N=(0,0)`, `B=(1,1)`. The conflict readout
`min(x, y)` below is likewise a declared projection, not forced by bilattice
theory.

The v2 status of a claim is one point `(x, y)`: `x = κ(π_T)`, `y = κ(π_F)`.
Information content is `x + y`; **conflict degree is `min(x, y)`**, the graded
reading that subsumes the discord kind "Conflict". Knowledge operations are
coordinatewise min/max; truth operations cross; negation swaps coordinates.

**Calculus Theorem (conservative extension), machine-checked.** Thresholding each
coordinate `(x>0, y>0)` recovers exactly the v1 Belnap status of Part I §7, for
*all* polynomials and *all* positive confidence assignments
(`graded_corner_conservative`, Theorem 20 in `lean/Vela/FrontierCalculus.lean`).
Nothing downstream breaks; the graded interior is a pure read over the v1 corner.
**Calculus Theorem (k-monotonicity).** An event fold only raises the coordinates;
only retraction lowers them, through §22's retraction law (`kappa_retract_le`,
machine-checked).

## 25. Verification cost and the admission boundary

Define `v(q, c)`: the cost of verifying claim `q` under verifier configuration
`c`, with `v = ∞` when no in-software verifier exists. For derived claims the
tropical-cost projection (§21) supplies `v` as the cheapest-derivation cost. The
admission law:

```text
admission_policy(claim_kind, v) -> required trust coordinates,  monotone increasing in v
permissionless admission  iff  v <= cheap threshold
v = ∞:  no admission path through the verifier gate at all
```

**Calculus Theorem (admission monotonicity).** If `v(q,c) <= v(q',c')` then the
trust coordinates required to admit `q` are a subset of those for `q'` (the
policy is a union of threshold-indexed coordinate sets; check c21).

**Calculus Theorem (scope boundary).** A claim kind with **no in-software
verifier** has no permissionless admission path: `v = ∞` exceeds every threshold,
so no policy admits. This makes the cheap-verifier scope boundary **derived, not
asserted**: clinical-shaped claims have `v = ∞`, so the discovery loop
structurally cannot fire there. This is the formal statement of the thesis-scope
boundary, and it is why the system goes deep in cheap-verifier domains rather
than wide.

## 26. Replay tiers

Two replay equivalence relations replace the scalar `artifact_replay` reading:
**R-bitwise** (output bytes identical: Lean, SAT, exact combinatorics, the
current wedge) and **R-semantic(τ)** (output within an attested tolerance τ,
forced by floating-point non-associativity and GPU nondeterminism). The
load-bearing rule: **a tolerance spec is an attestation, not a proof.** Someone
signs "within τ is the same result," and the signature carries the
responsibility; the kernel never invents τ and refuses a semantic receipt with no
signed tolerance.

**Calculus Theorem (tier monotonicity).** R-bitwise implies R-semantic(τ) for
every `τ >= 0`; a tier downgrades by re-verification but never upgrades without a
new replay event, so a semantic receipt can never produce a bitwise-grade trust
coordinate (check c22).

## 27. Assumption environments and generalized retraction

Provenance variables are assumptions; an **environment** is an assumption set, in
`N[X]` exactly the variable set of a support monomial (ATMS shape, de Kleer
1986). Retraction generalizes from "zero this source" to "invalidate this
assumption set": `invalidate(a)` removes every environment containing `a`, by the
same homomorphism machinery (§22), no new operator. Superseding an upstream claim
invalidates the assumption variables of everything derived through it, and the
cascade is the retraction theorem applied transitively.

**Calculus Theorem (subsumption of variable zeroing).** Environment invalidation
restricted to a singleton source variable equals v1 retraction (check c23: the
cascade reaches a second-order transfer and the downstream bilattice point moves
to zero). **Calculus Theorem (transfer closure is a least fixed point;
order-independent), machine-checked.** The transfer closure (the least set of
supported claims closed under `support(B) :- support(A), transfer(A,B)`) is the
*least fixed point* of that rule, hence unique, hence independent of event-fold
order (`closure_least`, `transfer_closure_order_independent` in
`lean/Vela/FrontierCalculus.lean`).

## 28. Statement-faithfulness strength

The statement attestation (`vsa_`) carries a six-valued strength relation for how
a formal statement relates to the informal claim it attests: `Equivalent |
FormalStronger | FormalWeaker | Incomparable | Ambiguous | Unfaithful`.
Composition along formalization chains is a total associative monoid with
`Equivalent` the identity and `Unfaithful` absorbing; mixed directions and any
incomparable leg compose to `Ambiguous` (information loss is explicit, never
silently resolved; composition never invents `Equivalent`). Associativity is
verified over all 216 triples (check c24).

## 29. The trust vector

Trust is not a Boolean. A claim carries a vector `τ(q,c)` of distinct
coordinates: `log_integrity, artifact_replay, verifier_gate, method_integrity,
statement_faithfulness, context_of_use, model_lineage, operator_residual,
uncertainty_calibration, body_trace_quality, human_review, transfer_status,
safety_scope, significance_endorsement`. This lets one substrate represent Lean
proofs, human-checked AI-origin proofs, computational replays, neural-operator
claims, wet-lab assays, and clinical signals without collapsing them into one
green check.

**Calculus Theorem (trust-vector non-collapse).** No Boolean `τ → verified`
projection preserves all domain-relevant distinctions. Construct two claims: one
Lean-kernel replayed but missing statement-faithfulness, one lab-assay traced but
not formally verified; any single label loses actionable information. This is the
graded form of Part I §11.4 (status and confidence cannot collapse to one
scalar): trust cannot collapse to one bit either.

## 30. Transfers, the constructive bridge

Part I §9.1 and Core Theorem 23 define a transfer as a verifier-homomorphism
`T = (toFun, sound)` between verifiable frontiers and prove verification
transports. The calculus adds the provenance consequence: if a verified `A`
discharges a named premise of `B`,

```text
π_T(B_premise) += π_T(A) · x_transfer · x_transfer_theorem
```

so the transferred support is a single monomial product of the source, the
transfer object, and the transfer theorem. Retracting any of the three deletes
the monomial (§20), so transferred support disappears by the same retraction
law, no special case. Real, re-checkable instances: Sidon `B_2 → B_h`; the
`[8,4,4]` code `→ E8` kissing configuration, which constructs the 240-point
witness matching the known optimum `K(8) = 240` (the upper bound is not part of
the transfer).

## 31. Body, model, and operator receipts

The same kernel must one day accept not only proof receipts but **body traces**
(execution against reality: executor type, protocol version, instrument config,
sample lineage, reagent lots, raw-output hashes, deviation log, failure modes,
cost/safety tier, replay command), **model receipts** (weights hash, training
data hashes, evaluation suite, calibration report, domain of validity, known
failure modes), and **operator receipts** (learned solution operators: input/output
function spaces, discretization, governing equations, residual error, uncertainty
method, out-of-distribution tests). A model prediction is **activity, not state**;
it becomes state only through validation, receipt, trace, and attestation. These
schemas are specified here and deferred in implementation until a producer of
each shape exists (§36).

## 32. Frontier discord and the opportunity calculus

Discord and frontiers are Part I §4. The calculus adds the **opportunity rank**,
which schedules work but never gates trust:

```text
Rank(a | S) = E[ FrontierDelta(S, a, y, θ) ] / Cost(a)
```

a practical score trades information gain, downstream dependencies unlocked,
failed-search cost avoided, transfer value, and translation value against
verification burden, safety risk, and resource cost. This is a scheduling rule,
not evidence (Part I §8, Calculus law 19 in §35).

**The decision-delta, made computable (and named precisely).** The graded
blast-radius (`FrontierGraph::blast_radius_graded`) computes one specific
quantity: retract a claim (its support κ → 0, the §22 retraction law),
min-propagate κ along required-premise edges (the **bottleneck** projection, §21),
and read the drop `Δκ` in each dependent's support. That is a **StructuralDelta**,
a deletion-counterfactual over a support projection (the database-causality /
deletion-propagation / responsibility lineage: Meliou et al.; Kimelfeld). It is
**not** a full **DecisionValue** (which needs an action, an outcome distribution,
a cost, and a utility — value-of-information, Howard 1966), and not an
**AttributionValue** (a Shapley / Banzhaf allocation over the provenance object;
Deutch et al.). κ measures *trust*; `Δκ` measures *structural consequence*; the
opportunity rank above measures *decision value*. Keeping the three distinct is
the correction from the GPT-pro review: conflating "what would break if this
moved" with "what should we do next" is the trap. A principled `Δκ` (and the
attribution and decision readings) wants the composed-provenance object of the
roadmap, since scalar κ propagation is a weakest-link *projection*, not a
provenance semantics.

## 33. The transport certificate (spec only)

For empirical-claim transfers (a causal-diagram domain), the certificate shape is
fixed now so the slot exists: a 4-tuple of a selection-diagram reference, the
sID-emitted transport formula, the do-calculus witness sequence, and source tags
per term (Bareinboim-Pearl 2013 give completeness of sID). **Scope guard:**
formal-math transfers keep the verifier-homomorphism object of §30; the two must
not be conflated. The kernel ships the schema and validator only, with an empty
consumer list (check c25); the full causal apparatus stays deferred (§36).

## 34. Calculus theorems, and the map to the formal core

The v1 calculus theorems coincide with Part I and are cited there, not re-proved:

| Calculus result | Canonical statement |
|---|---|
| replay convergence | Core Theorem 1 |
| retraction monotonicity | Core Theorem 2 |
| no-zombie status after retraction | Core Theorem 3 |
| conflict preservation (`B`, not forced resolution) | Part I §5.6.1, §7 |
| hash-DAG integrity | Core Theorem 5 |
| transfer support propagation / retraction | Core Theorem 23 + §30 |
| context no-generalization | Core §1 context law + §22 context wall |
| frontier as discord support, upward closure | Core Theorem 4 |

The genuinely calculus-side theorems are stated in §21–§32: universality,
the scope wall and context wall, retraction-commutes, the σ/κ asymmetry,
idempotent DAG safety, conservative extension, k-monotonicity, admission
monotonicity, the scope boundary, tier monotonicity, the subsumption of variable
zeroing, transfer-closure-as-least-fixed-point, faithfulness as a monoid, and
trust-vector non-collapse. **Failure-value positivity** (a failed attempt is
logged when `P(retry) · avoided_cost · applicability > storage_review_cost`) and
**opportunity-ranking separation** (ranking schedules but cannot alter σ, κ,
provenance, or the trust vector) are calculus-only and stated in §18 and §32.

## 35. Calculus doctrine laws (13–23)

Stated laws, not theorems; checkable in review. (Laws 1–14 are the formal-core
doctrine of Part I §12; these extend the list.)

13. **Projection soundness + provenance.** Every flag is the image of the stored
    polynomial under a declared homomorphism, and carries a proof packet naming
    its evaluator, valuation, source polynomial, and policy, so anyone can
    recompute it. The flag is auditable, never authoritative. Landed in `vela
    claim state` (the `projection_provenance` record).
14. **Attack locality.** A challenge attacks named monomials or assumptions,
    never the claim as an opaque whole, so disputes propagate through assumption
    retraction. (The Dung argumentation apparatus is the deferred extension.)
15. **No transport without certificate.** No transferred claim enters the record
    without a transfer object carrying its assumption set (and, for empirical
    transfers, the §33 certificate).
16. **No unsupported synthesis.** A synthesized estimate is a projection over its
    inputs' provenance polynomials, never a stored free-standing object
    (derived-never-stored applied to meta-analysis).
17. **Reproducibility-tier monotonicity.** Bitwise implies semantic; tiers never
    upgrade without a replay event (§26).
18. **Verification/admission separation.** What verifies a claim and what admits a
    writer are distinct; admission is a function of verification cost, never
    identity alone (§25).
19. **Incentive non-interference.** No incentive, stake, score, or significance
    signal is an input to σ, κ, the provenance polynomial, or the trust vector.
    Incentives price attention; they never touch state.
20. **Monotone safety gating.** Safety restrictions (access tiers) only ever
    narrow access; no event widens access to restricted bytes retroactively.
21. **Evaluation freshness.** A benchmark claim carries its contamination cutoff
    and statement-registration date; only statements registered after a model's
    cutoff are admissible freshness evidence (the anti-leaderboard foundation).
22. **Claim-identity receipts.** Identity between two natural-language claims is
    itself a signed, attested, retractable event, never a silent reducer input
    (no-AI-in-the-trust-path applied to entity resolution).
23. **Reproducibility, replicability, robustness are distinct coordinates**, never
    collapsed into one.

(Law 9 of the v1 list, "transfers amplify discovery," is recorded as **falsified**
and stays in the record as falsified. That is the point of having a record.)

## 36. The deferred ledger

Everything correct-but-consumerless, with its un-defer trigger. Nothing here is
built or scaffolded "while we're in there." Almost every trigger is **a producer
who needs it**, which is the honest statement that the next theory moves are
adoption-gated, not theory-gated.

**The one prioritized theory move (distinct from the consumer-gated deferrals
below): the composed-provenance object.** Today each finding's provenance is over
its OWN events; the calculus does not compose provenance across the dependency
graph, and cross-claim impact uses scalar κ/Bottleneck propagation (a weakest-link
*projection*, §32, not a provenance semantics). The fix is a **global composed
provenance object**: compile the whole transition DAG into a positive-derivation
lineage circuit over primitive assumptions (`support(B) += support(A₁) · … ·
x_rule · x_transfer`), with retraction as substitution on that object. Then
Boolean existence, count, κ (the weighted-environment readout), Bottleneck, cost,
Shapley/responsibility attribution, StructuralDelta, and the PCK replay predicate
all become projections of ONE object. This closes the cross-finding gap, gives κ
and the decision-delta a real lineage basis, and gives PCK a crisp statement to
fold over. It is the single highest-leverage theory move, is NOT consumer-gated,
but is still subordinate to standing up the live acceptance loop (a producer, a
reviewer, an accepted external write). Identified as load-bearing by the GPT-pro
review, 2026-06-17.

| deferred item | un-defer trigger |
|---|---|
| Incentive/mechanism layer (stake, slash, scoring) | a second external producer, or value gated on frontier delta |
| Dung argumentation framework (typed attacks, grounded/preferred extensions) | a producer emitting structured contested rebuttals |
| Clinical/observational cluster (CausalClaim, estimand discipline, GRADE) | a producer whose claims have an in-software verifier (likely never for clinical bytes; the scope boundary working as intended) |
| Full causal selection-diagram apparatus | the first empirical-claim transfer producer |
| Schema/reducer migration lenses | the first backward-incompatible reducer or schema change |
| Workflow-provenance interop (PROV, RO-Crate, CWL) | the first computational-replication producer; as export projection, not core object |
| Ontology binding (OBO, LinkML, SHACL) | a domain producer with an existing controlled vocabulary |
| Body cluster (quantity types, calibration custody, regulatory packets) | the first autonomous-lab or instrument producer |
| Evidence-synthesis reducer (random-effects over `N[X]`) | a domain producing multiple independent estimates of one quantity (build as projection, law 16) |
| Bitemporality (valid-time axis) | the first claim whose validity window diverges from record time |
| Contributor identity PIDs (ORCID, ROR, CRediT) | external contributors (the Argonaut trigger) |

## 37. The naming dictionary

| calculus name | symbol | protocol object / Rust home | id / status |
|---|---|---|---|
| claim-state cell | cell | reducer fold, `vela claim state` | live |
| status (v2 bilattice point) | `(x,y)`; v1 σ corners | Belnap in reducer; graded coords in the kernel | live (corners) / v2 (interior) |
| support / refute provenance | `π_T, π_F` | `N[X]`, wired to reducer flags | live |
| discount | κ | `frontier_calculus.rs` (Viterbi projection) | live |
| trust vector | τ | `cli_claim.rs` (derives 7 of 14 fields) | partial |
| verification cost | `v(q,c)` | admission policy parameter | live |
| decision-delta | `Δκ` / FrontierDelta | `frontier_graph.rs::blast_radius_graded` | live (structural instance) |
| finding / frontier / event | — | `vf_` / `vfr_` / `vev_` | live |
| transfer | — | cross-domain transfer | `vtr_`, live |
| statement attestation (faithfulness) | — | `statement_attestation.rs`; six-valued strength | live |

The bare word "attestation" is banned: it is always "statement attestation
(`vsa_`)" or "reviewer attestation (`vatt_`)".

## 38. Executable validation

The reference kernel `research/frontier-calculus/frontier_calculus_kernel.py`
runs 25 checks and exits nonzero unless all pass (wired into the conformance gate
by exit code via `scripts/full-conformance.sh`). The 14 v1 checks cover replay
convergence under shuffle, the semiring/retraction laws, no-zombie status,
hash-DAG tamper detection, transfer propagation/retraction, trust-vector
separation, and the Ramsey demo (`R(3,3)=6` by C5 witness + exhaustive
verification). The 11 v2 checks (c15–c25) cover the named projections as
homomorphisms, the negation/aggregation refusal, the counting-vs-confidence
divergence, Viterbi DAG safety, the σ/κ asymmetry, the bilattice corner
embedding and k-monotonicity, admission monotonicity, replay-tier monotonicity,
assumption-invalidation cascade, faithfulness composition, and the transport
certificate schema. The load-bearing laws are additionally machine-checked in
`lean/Vela/FrontierCalculus.lean` (Mathlib-free).

## 39. References

Provenance and database theory: Green-Karvounarakis-Tannen, "Provenance
semirings," PODS 2007 (free-semiring universality, commutation with positive
relational algebra); Green-Tannen, "The semiring framework for database
provenance," PODS 2017; Amsterdamer-Deutch-Tannen, "Provenance for aggregate
queries" (the negation/difference boundary). Status and bilattices: Belnap-Dunn
four-valued logic; Ginsberg, "Multivalued logics," 1988; Fitting, "Bilattices and
the semantics of logic programming," 1991; Avron, "The structure of interlaced
bilattices," MSCS 6, 1996 (the product representation theorem). Trust and
discounting: Jøsang, "Trust network analysis with subjective logic," ACSC 2006
(discount canonical on series-parallel graphs only). Truth maintenance: de Kleer,
"An assumption-based TMS," AI 28, 1986. Replicated data: Shapiro et al., CRDTs.
Contextuality: Abramsky-Brandenburger; Abramsky-Barbosa-Mansfield, "Contextual
fraction," PRL 2017. Data migration: Spivak, functorial data migration.
Proof-carrying: Necula-Lee, proof-carrying code. Causal transport: Bareinboim-
Pearl, "Deciding transportability," 2013 (sID completeness); Pearl, do-calculus.
Experimental design: Rainforth et al., modern Bayesian experimental design.
Models: Neural Operators (maps between function spaces); Universal Differential
Equations; IFP Natural Law Models. Formal-math frontier: AlphaProof, Formal
Conjectures, miniF2F-Lean, LeanMarathon. Standards (for the deferred export
projections): W3C PROV, RO-Crate, FAIR. Negation / aggregation boundary:
Amsterdamer-Deutch-Tannen, "On the Limitations of Provenance for Queries with
Difference," 2011, and "Provenance for Aggregate Queries," 2011; first-order
semiring semantics: Grädel-Tannen, 2017. Decision-delta lineages:
Meliou-Gatterbauer-Moore-Suciu (database causality and responsibility); Kimelfeld
(deletion propagation, 2012); Deutch-Frost-Kimelfeld-Monet (Shapley value of facts
in query answering); Koh-Liang (influence functions, ICML 2017); Howard,
"Information Value Theory," 1966. Kissing-number upper bound: Odlyzko-Sloane
(1979), Levenshtein (1979). PCK lineage: Necula (proof-carrying code);
Chiesa-Tromer (proof-carrying data); Valiant (incrementally verifiable
computation); Bünz-Chiesa-Mishra-Spooner (PCD from accumulation schemes); Nova /
HyperNova / ProtoStar (folding/accumulation).

---

# Appendix A — Theorem audit

*Folded from the former THEORY_AUDIT.md.*

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

---

# Appendix B — Guarantees: spec, proof, conformance

*Folded from the former PROTOCOL_GUARANTEES.md.*

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

## Honesty notes (from Appendix A, the theorem audit)

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
