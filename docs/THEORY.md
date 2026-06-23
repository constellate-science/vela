# Vela: The Formal Core and the Frontier Calculus

*The single canonical statement of the mathematics under Vela and Constellate.
**Part I** is the protocol formal core: the substrate is sound (replay,
hash-DAG integrity, signatures, deterministic merge). **Part II** is the
frontier calculus: the state the substrate carries is meaningful (provenance,
graded status, κ, the bilattice, the verification-cost admission boundary). The
machine-checked ground truth is `lean/Vela/*.lean`; the executable reference is
the 25/25-check `frontier_calculus_kernel.py`, the internal reference
implementation under `research/frontier-calculus/` (wired into the conformance
gate via `scripts/full-conformance.sh`). That kernel and the composed-lineage
`ScientificStateKernel.lean` it generalizes to are part of the internal
reference tree and are not vendored in this public distribution; the public
`lean/Vela/Frontier/FrontierCalculus.lean` (Mathlib-free) carries the checked
claim-local realization.*

## How to read this document

| You want | Read |
|---|---|
| The protocol-correctness guarantees (replay, hash-DAG, signatures, merge, quorum) | **Part I**, §1–§16 |
| The epistemic calculus (provenance algebra, Belnap/bilattice status, κ, admission, transfers) | **Part II**, §17–§39 |
| The narrative companion | `docs/THEORY_NARRATIVE.md` |
| The implementation-facing invariants that must survive product changes | `docs/PROTOCOL.md` |

Citation convention: Part I theorems are **Core Theorem N**, Part II's are
**Calculus Theorem N**. Where the two coincide (replay convergence, retraction
monotonicity, no-zombie status), Part I is the canonical statement and Part II
cross-references it rather than restating it. This document supersedes the
former `docs/MATH.md` and the working spec at
`research/frontier-calculus/frontier_calculus.md`; both are folded in here. The
executable kernel (`frontier_calculus_kernel.py`) and the paper draft live in
the internal `research/frontier-calculus/` tree, which is not vendored in this
public distribution.

---

# Part I: The Formal Core

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
survive product and protocol changes, see `docs/PROTOCOL.md`. The frontier
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

# 4. Obligations and frontiers

The **frontier** is the set of active, typed **obligations** derived
from state: the structured, unresolved work that would move the
Atlas. Not every unknown is a frontier. An obligation is an unknown
made *actionable*: bound to a target, a discharge condition, and the
verifier that would close it.

An obligation (the production object, `sidon_profile/frontier.rs`) is

```text
o = (target_cell, kind, dependencies, discharge_evaluator, verifier_profile, context)
```

with a status **derived** from state, not stored:

```text
latent      pre-conditions not yet met (a blocking dependency is open)
open        actionable now: pre-conditions met, not yet discharged
discharged  a certificate satisfying its discharge condition exists
```

The frontier of an Atlas is the support of its non-discharged
obligations:

```text
Frontier(A) = { o : status_A(o) in {latent, open} }
```

The **actionable edge** of the frontier is the boundary projection
(`boundary.rs`), which ranks the open obligations by how close they
are to discharge:

```text
one_premise_away   a single missing premise/certificate would close it
fragile / brittle  it rests on thin or single-source provenance
contested          a contradiction or verdict-conflict touches it
stale_open         long-open with no recent attempt
```

This ranked edge is what `vela attack` surfaces and what a producer
(human or agent) pulls work from.

## 4.1 Discord is one detector, not the definition

Earlier versions of this document defined the frontier as the support
of *discord*. Discord is now one **detector** that can populate
obligations, not the frontier itself. It survives only as a derived
signal in the edge layer (`crates/vela-edge/src/discord.rs`); the word
does not appear in the protocol crate, and the reducer mints no discord
object (§5.4).

A discord detector assigns kinds from a finite set

```text
K = { Conflict, ConflictingConfidence, MissingOverlap, TranslationFail,
      EvidenceGap, ReplicationFail, ProvenanceFragile, StatusDivergent,
      MethodMismatch }
```

as a monotone map `D_A : C -> P(K)` ordered by subset inclusion.
Its monotonicity is upward propagation:

```text
c' -> c  and  D_A(c') is nonempty  =>  D_A(c) is nonempty
```

A refined-context conflict makes the broader context unstable unless
resolved or scoped away. Theorem 4 (§10) proves this upward closure as
a property of the detector: it characterizes how a discord signal
propagates to populate obligations at coarser contexts, not what the
frontier *is*.

---

# 5. Vela event log

A frontier's history is a **single-writer, append-only, linear hash
chain** of signed events. State is not stored; it is computed by a
deterministic left-fold of the reducer over the chain (the
**loader = reducer**: there is exactly one code path that turns a log
into state, `reducer::replay_from_genesis`, and the loader calls it).
This is the shipped substrate. A multi-writer, merge-convergent DAG
(an operation-based CRDT over a content-addressed hash-DAG) is a
**target** for cross-hub federation; it is described as such in §5.6,
not as current behaviour.

## 5.1 Events

A `StateEvent` (`crates/vela-protocol/src/events.rs`) is

```text
e = (schema, id, kind, target, actor, timestamp, reason,
     before_hash, after_hash, payload, caveats, signature,
     schema_artifact_id)
```

where

```text
schema             = the event schema id (vela.event.v0.1)
id                 = H(canonical(e without id))
kind               = the typed reducer transition (e.g. finding.asserted)
target             = the object the transition acts on
actor              = the signing actor id
timestamp          = declared event timestamp
reason             = human-readable rationale
before_hash        = the chain hash of the prior event (genesis = empty)
after_hash         = the chain hash after applying this event
payload            = typed transition body
caveats            = declared scope limitations
signature          = the actor's Ed25519 signature over the canonical bytes
schema_artifact_id = content-addressed schema/reducer reference
```

`H` is assumed collision-resistant. `before_hash`/`after_hash` form
the linear chain: each event commits to the exact prior state, so a
tamper anywhere breaks every downstream hash (Theorem 5). There is no
`parents` set, no `attestations` field, and no `policy` field on the
event itself: attestations are separate `attestation.recorded`
events, and admission policy is evaluated by the gate and the
acceptance policy (§35, and Part II), not carried on the event.

## 5.2 Valid event logs

A log is **valid** if it is a chain from genesis: each event's
`before_hash` equals its predecessor's `after_hash`, every signature
verifies over the canonical bytes, and every `kind` is a declared
reducer transition. `reducer::verify_replay` checks that re-folding
the chain reproduces the materialized state byte-for-byte; a broken
chain still loads (cache-only, with empty side tables) so it can be
repaired, and `vela check` surfaces the failure.

## 5.3 Replay

Let `R(L)` be the state obtained by folding the deterministic reducer
over the linear log `L` from genesis:

```text
A = R(L) = foldl(apply_event, genesis_state, L)
```

`apply_event` is pure and total over declared kinds; a cross-impl
conformance suite pins the Rust reducer against the Python reference
(`clients/python/vela_reducer.py`) over shared fixtures, so `R` is
deterministic across implementations (this discharges the determinism
premise of Theorem 1 rather than assuming it).

## 5.4 Disagreement is a derived read, not a minted object

Replay does **not** emit a `discord` object. Evidence polarity is
recomputed on every read from the support and refutation provenance
polynomials (`status_provenance.rs`, `evidence_diff.rs`): a
claim-context pair with both supporting and refuting accepted
provenance reads as Belnap `B`. Nothing is persisted; the status is a
projection of the log (§7), which is why retraction can move it back
without a compensating event (Theorem 3, "no zombie status").

Genuine disagreement that the substrate *does* materialize is carried
by two first-class, content-addressed objects, neither auto-resolved:

```text
Contradiction (vcx_)   contradiction.rs — derived from a `contradicts`
                       edge; default status Candidate; resolution is a
                       key-custody human decision, never automatic.
VerdictConflict (vdc_) verdict_conflict.rs — two accepted reviews that
                       disagree on a proposal's disposition.
```

## 5.5 Discord as a derived signal

"Discord" survives only as a *derived detector signal* in the edge
layer (`crates/vela-edge/src/discord.rs`), used to populate the
boundary/obligation queue (§4). It is not a reducer-minted object and
the word does not appear in the protocol crate. The discord-kind
lattice and its upward-closure property are retained as a property of
that detector in §4 and Theorem 4, not as the definition of the
frontier.

## 5.6 Target: multi-frontier merge (not current substrate)

Cross-hub federation of *independent* frontiers, and any future
multi-writer convergence within a single frontier, is the place where
the op-CRDT / hash-DAG model applies: down-closed event sets, union
merge, canonical topological order with content-hash tie-break, and
deterministic classification of concurrent payload interactions
(polarity disagreement → `B` + a contradiction; commuting field
updates → apply both). This is a **roadmap object**, not shipped: the
current substrate is one linear chain per frontier with a single
writer, and federation today is hub-level distribution of whole
frontiers (signed manifests, `registry.rs`), not event-DAG merge.
When multi-writer merge lands it must preserve replay convergence
(Theorem 12 already proves commutativity for disjoint concurrent
events as the seed of that result).

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

**Formalization.** Lean module: `lean/Vela/Crypto/Signing.lean`. The
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

**Formalization.** Lean module: `lean/Vela/Protocol/ReplayIndex.lean`.
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

**Formalization.** Lean module: `lean/Vela/Constructions/EGZ.lean`. The
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

**Formalization.** Lean module: `lean/Vela/Crypto/CanonicalEventId.lean`.
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
`lean/Vela/Crypto/SignatureUniqueness.lean`. The main result is
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
`lean/Vela/Crypto/MultiSigThreshold.lean`. Three theorems:
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
`lean/Vela/Protocol/ConcurrentReplay.lean`. Two theorems:
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
`lean/Vela/Crypto/FrontierIdDeterminism.lean`. Two theorems:
`theorem13_frontier_id_injective` (main statement) and
`theorem13_same_id_implies_same_log` (the contrapositive form
used directly in the witness-check argument). Verifies with
`lake build Vela.FrontierIdDeterminism`.

**Substrate role.** This is the substrate-side guarantee that the
v0.129 `vela registry witness-check` primitive (A11 cross-hub
divergence detector) implicitly assumes: when two hubs agree on
the canonical bytes for a given `vfr_*`, they agree on the
frontier's underlying state. The Rust implementation lives at
`crates/vela-protocol/src/project.rs::frontier_id` (line 431),
with `frontier_id_from_genesis` (line 293) composing
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
`lean/Vela/Governance/ProposalIdempotency.lean`. Two theorems:
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
`lean/Vela/Governance/ConfidenceUpdate.lean`. Two theorems:
`theorem15_confidence_update_bounded` (main statement) and
`theorem15_two_sided_bound` (symmetric corollary for use in
policy-monitoring reasoning where one wants to bound the
upper or lower confidence independently). Verifies with
`lake build Vela.ConfidenceUpdate`.

**Substrate role (HONEST STATUS: the hypothesis is NOT yet
enforced).** Theorem 15 is a *conditional*: it bounds the move
*if* the substrate enforces `|revise c δ - c| ≤ cap`. The
current reducer does **not** enforce it. `apply_finding_confidence_revised`
(`crates/vela-protocol/src/reducer.rs:709`) writes
`state.findings[idx].confidence.score = new_score`
*unconditionally* (line 734), and the event constructor
`state.rs::revise_confidence` validates only that the new score
is a well-formed probability, not that the delta is within any
cap. There is no `cap` field in the reviewer policy today. So
the bounded-update rule is a **specification the substrate does
not currently satisfy**, not a shipped defense. Do not read
Theorem 15 as a live security guarantee.

What the substrate *does* provide is auditability, not a bound:
each `finding.confidence_revised` event records the prior and
new score on the canonical, immutable event, so an auditor can
reconstruct every move and the cumulative drift after the fact.
Bounding (rather than only recording) drift would require adding
a per-policy `cap` and a saturate-or-reject check at the apply
step; until then T15's hypothesis is unrealized and it is listed
among the conditional/unenforced theorems in Appendix A.

**Out of scope.** The N-event drift bound (linear in event
count) would follow from Theorem 15 by induction *once the
single-event hypothesis is enforced*. Multi-reviewer attestation
as a long-horizon defense against cumulative drift is a separate
threat surface.

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
`lean/Vela/Governance/GovernedQuorumSoundness.lean`. One theorem:
`theorem16_governed_quorum_sound`. Verifies with
`lake build Vela.GovernedQuorumSoundness`. Composes Theorem 11
(multi-sig threshold counting), Theorem 10 (signature
uniqueness), and Theorem 13 (frontier-id determinism, gives a
unique proposal preimage per frontier + epoch).

**Substrate role.** The distinct-signer / eligibility /
revocation / Ed25519 quorum rule is implemented in
`crates/vela-edge/src/governance.rs::verify_quorum` (line 482);
the protocol crate's owner-rotation path is single-signer today
(`crates/vela-protocol/src/registry.rs::verify_rotation`, line
196). The newer `crates/vela-protocol/src/acceptance_policy.rs`
`Quorum { threshold, eligible_roles }` is the policy-engine form
of the same threshold rule (see §35). Theorem 16 makes the rule
algebraic; note the full quorum check lives in `vela-edge`, not
the protocol crate, so T16 describes the edge implementation, not
a protocol-crate guarantee.

**Out of scope.** The full security argument against an
attacker who controls the *threshold* set of governance keys
(rather than just the current owner) is not formalized: no
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
in `lean/Vela/Transfer/Transfer.lean` (`transfer_sound`, `Transfer.id`,
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
| Append-only typed event log | Current | `PROTOCOL.md` |
| Content-addressed objects | Current | `PROTOCOL.md` |
| Replay-deterministic state | Current | `THEORY.md`, Theorem 1 |
| Canonical causal replay order | Current | `PROTOCOL.md` |
| Carina type kernel | Current | `CARINA.md` |
| Signed attestations | Current | `VERIFICATION.md` |
| Schema/reducer artifacts as content-addressed deps | Current | `PROTOCOL.md` |
| Federated hubs with deterministic merge | Partial (capability, not active deploy) | `HUB.md` §Federation |
| Missing ancestor fetch/fork policy | Target | `HUB.md` §Federation |
| Formal context category C | Partial | `THEORY.md` §27.1 |
| `CarinaState` morphisms | Target | `THEORY.md` §27 |
| Atlas as `C^op -> CarinaState` | Target | `THEORY.md` §27 |
| Discord assignment `D_A` | Target | `THEORY.md` §7 |
| Provenance semiring `N[X]` | Current (claim-local) / Target (composed lineage) | `THEORY.md` §2.2, §20.3; §40 |
| Belnap contextual status | Current (claim-local corners) | `THEORY.md` §7, §25.4; §40 |
| Bayesian frontier ranking | Target | `THEORY.md` §11.4 |
| Constellation bridge category | Current (transfer calculus) / Target (full bridge category) | `THEORY.md` §27.2; §40 |
| Mechanism-design review allocation | Target | `GOVERNANCE.md` |
| Theorem 1 (replay convergence) Lean-checked | Current (v0.90) | `lean/Vela/Protocol/Log.lean` |
| Theorem 2 (retraction monotonicity) Lean-checked | Current (v0.90) | `lean/Vela/Protocol/Provenance.lean` |
| Theorem 3 (status-provenance soundness) Lean-checked | Current (v0.90) | `lean/Vela/Protocol/Provenance.lean` |
| Theorem 4 (frontier upward closure) Lean-checked | Current (v0.90) | `lean/Vela/Protocol/Provenance.lean` |
| Theorem 5 (hash-DAG log integrity, structural) Lean-checked | Current (v0.90) | `lean/Vela/Protocol/Log.lean` |

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
now lives in `lean/Vela/Protocol/Log.lean` (Core Theorem 1; see Appendix A, the theorem
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

# Part II: The Scientific State Kernel

*Part I establishes the protocol substrate: deterministic replay, content
addressing, signatures, contradiction preservation, provenance-aware retraction,
and convergent federation. Part II defines the scientific state that substrate
carries. Its central object is the composed-provenance map `Γ_P : H → N[X]`
generated by an accepted, context-licensed presentation. Its operational surface
has three verbs: append, restrict, and observe.*

*This Part supersedes the earlier claim-local "Frontier Calculus" treatment,
which remains the current **live** realization: one support/refute polynomial per
claim, projected to κ, the product bilattice, and verification cost, shipped in
`vendor/vela/crates/vela-protocol/src/frontier_calculus.rs` and `frontier_graph.rs`
(the `Δκ` blast radius), surfaced by `vela claim state`, machine-checked in
`lean/Vela/Frontier/FrontierCalculus.lean` (Mathlib-free), and validated by the
25-check `frontier_calculus_kernel.py` (in the internal reference tree, not
vendored here). The kernel
defined here is its **composed-lineage generalization**: it lifts provenance from
one claim to the whole accepted dependency graph, so κ, the bilattice, cost,
attribution, structural delta, and the replay predicate all become readings of one
object. That generalization is machine-checked in the internal reference
implementation `lean/Vela/Frontier/ScientificStateKernel.lean` (ten named
declarations, axiom-clean beyond `propext`/`Classical.choice`/`Quot.sound`, no
`sorry`), which is not vendored in this public tree; most of
its protocol objects are still **spec-only** in Rust. §35 gives the kernel
realization table; §40 carries the live claim-local realization, the doctrine laws,
and the naming dictionary, so nothing the prior treatment guaranteed is dropped.*

*Convention: a result tagged `(Lean: name)` is a checked declaration in the kernel
file; a rule tagged `(Conformance Law)` is an implementation obligation enforced by
an executable gate, not a theorem. Where a result restates Part I it
cross-references rather than re-proves.*

The kernel is deliberately narrow:

```text
append   = extend the accepted presentation
restrict = evaluate historical lineage under an active view
observe  = produce a proof-carrying read
```

Scientific activity is not scientific state. A paper, theorem attempt, model
output, benchmark result, lab trace, reviewer note, or agent message becomes state
only when it is admitted as a typed transition in the accepted presentation.
Historical lineage is never rewritten. Current state is a declared active view over
that lineage. Every status, confidence, trust, cost, frontier, or correction value
is a replayable observation of the same kernel.

---

## 17. The mission problem

The mission is science translation. The formal problem is:

```text
How can scientific activity become durable, replayable, retractable,
context-safe, composable, and agent-operable scientific state?
```

A document store answers what was written. A knowledge graph answers what is linked.
A search index answers what is retrievable. None of these alone answers:

```text
what has been accepted;
which assumptions support it;
which contexts license the support;
which routes remain active after a challenge;
which observations can be replayed;
which correction would change the state;
which downstream claims depend on the result.
```

Vela answers those questions by making the accepted scientific state transition the
narrow waist. The transition names its claim cell, primitive assumptions, body
premises, context licenses, policy, attestations, and verifier or receipt objects. The
accepted transition enters a finite presentation. The presentation generates one
composed lineage object. All lawful state readings are derived from that object.

The central statement is:

```text
scientific state = initial context-licensed lineage kernel
active state     = view substitution over historical lineage
observation      = proof-carrying read of active lineage
state change     = append or restrict
```

The word *initial* is mathematical. It means that accepted positive scientific state
has one free representation from which every lawful positive interpretation is
obtained uniquely. The other mathematical frameworks in this document are not
parallel foundations. Bilattices, calibrated confidence, tropical cost, support
functions, game-theoretic attribution, Fourier influence, and Bayesian decision value
are applications or observations of the same lineage kernel.

---

## 18. The finite ranked kernel boundary

The checked v0.9 kernel is finite, positive, and ranked.

### 18.1 Finite

For a replayed event set `E`, the compiled presentation has finite sets:

```text
C_E = replay-visible contexts
Q_E = accepted claim identifiers
H_E = accepted claim-context-polarity cells
X_E = primitive lineage atoms
R_E = accepted positive lineage clauses
```

Finiteness gives finite derivation objects, finite circuit roots, finite active views,
and decidable conformance fixtures. It does not require the global scientific record
to remain finite. Each committed event closure and each replayed kernel snapshot is
finite.

### 18.2 Positive

The core lineage language contains only:

```text
0      no route
1      empty dependency
p + q  alternative routes
p * q  joint dependence
```

The kernel has no subtraction, negation-as-failure, aggregation, implicit statistical
synthesis, or hidden overwrite. Support and refutation are represented by separate
cells. A contradiction is therefore two positive lineages, not a cancellation.

Negation, aggregation, recursive rules, and causal transport require additional
semantics. They remain outside the finite kernel described here.

### 18.3 Ranked

Every cell has a natural-number rank:

```text
rank : H_E -> N
```

Every clause satisfies:

```text
b in body(r)  implies  rank(b) < rank(head(r))
```

The rank certificate ensures that lineage equations can be solved by induction. It
also ensures that derivation trees are finite and that canonical circuits can be
compiled without a recursive fixed-point engine.

The rank is a kernel boundary, not a claim about scientific importance. It is a
well-founded dependency order.

### 18.4 Scope consequence

The checked kernel covers the current formal-math wedge and other domains with finite,
positive, directly verifiable derivations. It is not yet a semantics for recursive
logic programs, meta-analysis, causal identification, or open-ended argumentation.
Those extensions must preserve the kernel's audit and correction laws before they can
enter the state path.

---

## 19. Accepted presentations

A finite ranked accepted presentation is a tuple:

```text
P = (C, Lic, Q, H, X, R, rank, origin, policy)
```

where:

```text
C       = finite category or preorder of scientific contexts
Lic     = accepted context-license structure over C
Q       = accepted claim identifiers
Pol     = {support, refute}
H       = finite subset of Q x Ob(C) x Pol
X       = primitive lineage atoms
R       = accepted positive lineage clauses
rank    = well-founded rank on H
origin  = origin and context packet for each atom
policy  = content-addressed admission and view policy roots
```

A cell is:

```text
h = (q, c, p)
```

where `q` is a claim, `c` is a context, and `p` is support or refute. Belnap status is
not stored in the presentation. It is derived from the two polarity cells.

### 19.1 Primitive atoms

An atom is the smallest named dependency that may need to be replayed, challenged,
retracted, superseded, quarantined, attributed, or licensed. Examples include:

```text
source id
accepted event id
reviewer attestation id
statement-attestation id
verifier receipt id
proof receipt id
body-trace receipt id
model receipt id
transfer id
transfer-soundness theorem id
transport certificate id
claim-identity receipt id
schema or reducer id
policy epoch id
calibration packet id
route id
snapshot id
safety-scope id
```

The design rule is:

```text
If a dependency may later require independent correction or attribution,
it must be represented by an atom when the route is accepted.
```

This rule is necessary because later deletion of an arbitrary conjunction is not, in
general, a semiring homomorphism. Named route atoms keep correction local and
compositional.

### 19.2 Lineage clauses

A positive lineage clause has the form:

```text
r = (head, body, atoms, moves, event_id, policy_id, mode)
```

with:

```text
head(r)  in H
body(r)  = finite list of lower-rank cells
atoms(r) = finite multiset of primitive atoms
moves(r) = explicit context-license receipts
mode(r)  in {persistent, snapshot}
```

Its reading is:

```text
head(r) receives a route through every atom in atoms(r)
and through every cell in body(r), under the listed licenses.
```

The atom monomial of a clause is:

```text
alpha(r) = product_{x in atoms(r)} x
```

### 19.3 Persistent and snapshot dependencies

A persistent body dependency refers to the final accepted lineage of the body cell.
If a new route is later appended to that body, the dependent cell inherits the route.

A snapshot dependency refers to a named snapshot atom. It records the exact support
available at acceptance time and does not inherit later routes unless a new transition
is accepted.

```text
persistent:  h <- alpha * b
snapshot:    h <- alpha * x_snapshot
```

The distinction is part of the accepted clause. It must never be inferred after the
fact.

### 19.4 Context licenses

Every body cell and atom origin must reach the head context through an accepted
license. Similarity, citation, analogy, institutional prestige, and model confidence
may propose a license. They are not licenses themselves.

The accepted presentation is therefore not merely a dependency graph. It is a typed,
context-licensed positive theory generated by replayed state transitions.

---

## 20. Free positive lineage

Let `X` be a finite set of primitive atoms. Let `Mon(X)` be the commutative monoid of
finite multisets over `X`. Define:

```text
N[X] = { p : Mon(X) -> N | p has finite support }
```

Addition is pointwise. Multiplication is convolution:

```text
(p + q)(m) = p(m) + q(m)

(p * q)(k) = sum_{m+n=k} p(m) q(n)
```

The unit is the delta function at the empty multiset. A generator `x in X` is the
delta function at the singleton multiset `{x}`.

A polynomial can be read as a finite bag of monomials:

```text
0      = no accepted route
1      = the empty route
x      = dependence on atom x
p + q  = alternative accepted routes
p * q  = joint dependence
n*m    = n accepted derivations with the same atom multiset m
```

Coefficients preserve route multiplicity for audit and attribution. They do not imply
independent confirmation. Independence is not inferred from repeated occurrence.

### 20.1 Free commutative-semiring property

For every commutative semiring `K` and valuation:

```text
v : X -> K
```

there is a unique semiring homomorphism:

```text
Eval_v : N[X] -> K
```

that extends `v` on generators. Explicitly, each monomial maps to the product of its
atom values and a polynomial maps to the finite sum of its monomial values.

This property is the reason `N[X]` is the carrier. Vela records lineage once, in the
free positive object, and obtains each lawful positive reading by interpretation.

> **Checked scope (honesty note).** The full free-commutative-semiring universal
> property stated above is a mathematical claim, *not yet machine-checked*. What Lean
> proves is its load-bearing consequence: the finite ranked lineage model exists and is
> **unique** as a fold into any operation bundle, axiom-clean
> (`VelaV09.ranked_model_exists_unique`, `VelaV09.initial_lineage_model` in the
> internal reference `lean/Vela/Frontier/ScientificStateKernel.lean`, not vendored
> here, both in that tree's CI axiom-audit registry). The freeness *laws* over `CommSemiring` are a future obligation, provable
> on Mathlib's `MvPolynomial`; until then read this subsection as motivation and the
> uniqueness-of-fold result as its proven core.

### 20.2 Separation in the free carrier

If two lineage polynomials differ, some positive semiring interpretation distinguishes
them. In particular, the identity interpretation into `N[X]` distinguishes them.
This is an audit property, not a claim that the ordinary product UI exposes every such
distinction. Section 31.3 gives the product-relevant limitation.

### 20.3 Composed provenance

The central object is not claim-local provenance. It is composed lineage:

```text
Gamma_P : H -> N[X]
```

A route to a downstream cell contains the primitive assumptions of every accepted
upstream route on which it depends. If `c` depends on `b`, and `b` depends on evidence
atom `x`, then `Gamma_P(c)` contains `x` through composition. This is the basis for
retraction propagation, challenge locality, downstream impact, and replayable trust.

---

## 21. The initial lineage model

For a presentation `P`, a carrier `K`, and atom valuation `v : X -> K`, a ranked model
is a map:

```text
M : H -> K
```

that satisfies the lineage equations:

```text
M(h) = sum_{r in R, head(r)=h}
         alpha_v(r) * product_{b in body(r)} M(b)
```

where:

```text
alpha_v(r) = product_{x in atoms(r)} v(x)
```

and an empty body product is `1_K`.

### 21.1 Ranked existence and uniqueness

For every finite ranked presentation, the lineage equations have a unique ranked
solution. The proof is induction on cell rank. Every body value needed at rank `n` is
already fixed at a lower rank. The right-hand side therefore determines the value at
rank `n`, and any two models agree by the same induction.

This statement is machine-checked for the finite kernel.

```text
(Lean: ranked_model_exists_unique)
```

### 21.2 Historical lineage

Take the target carrier to be `N[X]` and the atom valuation to be the generator map.
The unique ranked solution is:

```text
Gamma_P : H -> N[X]
```

`Gamma_P(h)` is the historical accepted lineage of cell `h`. It contains all accepted
positive routes generated by the presentation. It does not encode which atoms are
currently active under a particular view.

The checked definition is named:

```text
(Lean: Gamma)
```

### 21.3 Initial lineage interpretation

For any named target carrier and atom valuation admitted by the finite evaluator,
there is a unique ranked interpretation of the presentation. Equivalently, once the
atoms and positive operations are interpreted, the cell values are forced.

```text
(Lean: initial_lineage_model)
```

This is the kernel's representation theorem in finite form:

```text
accepted positive state is represented once;
lawful positive readings are interpretations of that representation.
```

The theorem does not make every useful readout a scalar semiring homomorphism. Some
readouts first pass through a lawful quotient, such as the environment map in Section
25, and then apply a terminal evaluator.

---

## 22. Three equivalent semantics

The same historical lineage has three useful descriptions.

### 22.1 Derivation-tree semantics

A derivation tree for cell `h` chooses a clause headed by `h` and, recursively, a
derivation tree for each body cell. The monomial of the tree is the product of all
clause atoms in the tree. The tree semantics is the sum of those monomials:

```text
Gamma_P^tree(h) = sum_{t in Tree_P(h)} monomial(t)
```

Rank ensures that every derivation tree is finite.

### 22.2 Equational semantics

The equational semantics is the unique ranked solution from Section 21:

```text
Gamma_P^eq = Gamma_P
```

This is the checked semantic core.

### 22.3 Circuit semantics

Expanded polynomials can be exponentially large. A practical implementation stores a
canonical lineage circuit or hash-consed DAG with nodes such as:

```text
Zero
One
Var(x)
Add(children)
Mul(children)
Cell(h)
```

The compiler expands cells in rank order, canonicalizes commutative children, removes
identities, and content-addresses each node. Let:

```text
Sem(Circ_P(h)) in N[X]
```

be the polynomial denoted by the circuit.

### 22.4 The adequacy triangle

The required equality is:

```text
Gamma_P^tree(h) = Gamma_P^eq(h) = Sem(Circ_P(h))
```

The tree and equation descriptions satisfy the same ranked equations because
accepted derivation trees partition by their root clause. The circuit description
satisfies the same equations when the compiler expands each lower-rank body exactly as
specified. Ranked uniqueness then identifies all three.

The checked theorem `ranked_model_exists_unique` discharges the shared uniqueness
obligation. The production compiler must additionally emit a
`CircuitSemanticsReceipt` that binds the presentation root, compiler version, circuit
root, cell, and denoted lineage hash. The named protocol object is currently
**spec-only** in the Rust substrate.

The adequacy triangle gives three distinct roles:

```text
derivation trees  explain routes;
equations         define the mathematics;
circuits           implement the mathematics at scale.
```

No implementation may replace circuit semantics with an unverified cache.

---

## 23. Presentation morphisms and historical extension

Scientific accumulation extends the accepted presentation. It does not rewrite old
lineage.

A `PresentationMorphism` maps contexts, claims, cells, atoms, licenses, and clauses
from one accepted presentation into another while preserving heads, bodies, atom
identities, ranks, origins, policy references, and context licenses.

```text
I : P -> P'
```

A conservative extension preserves every old clause and does not rewrite an old atom
identity. Under such an extension, every old derivation route remains present after
renaming. New clauses can add alternative routes and can propagate through persistent
body dependencies.

If no new clause has an old head and no new lower-rank route enters an old dependency
cone, old cell lineage is preserved exactly. If new clauses do have an old head, the
old lineage remains as a summand and the new lineage is added.

```text
Gamma_{P'}(I(h)) = I_*(Gamma_P(h)) + new accepted routes
```

This is the historical meaning of append.

### 23.1 Append

An append operation:

```text
append : P -> P'
```

is lawful only when the new event closure passes admission, signature, policy,
context-license, and rank checks. Append may introduce new atoms, cells, clauses, or
accepted routes. It may not mutate a prior atom's identity or silently replace a
prior clause.

At the event-log level, a retraction is itself appended as an event. At the kernel
level, its active effect is represented by a view substitution, not by deleting the
historical route from `Gamma_P`.

### 23.2 Persistent inheritance

If a clause contains a persistent body cell, later accepted support for that body
flows to the head through the same clause. If the dependency was intended to be frozen
at acceptance time, the presentation must use a snapshot atom instead.

This distinction prevents two opposite errors:

```text
failing to inherit later support through a live dependency;
rewriting a historical snapshot as if it had always depended on later evidence.
```

### 23.3 Protocol status

`PresentationMorphism` is currently **spec-only** as a named Rust protocol object.
The append-only event log and reducer are live, but the full context-, atom-, and
clause-preserving morphism is not yet represented as one substrate type.

---

## 24. Historical lineage and active views

Historical lineage and active state are different objects:

```text
historical lineage = Gamma_P
active lineage     = rho_nu(Gamma_P)
```

A view is a deterministic atom-state map:

```text
nu : X -> {active, inactive}
```

It induces the substitution:

```text
rho_nu(x) = x  if nu(x)=active
rho_nu(x) = 0  if nu(x)=inactive
```

extended over addition and multiplication. A monomial survives exactly when every
atom in it is active.

Views include:

```text
default public view
strict replay-only view
post-challenge view
policy-epoch view
safety-restricted view
lab-custody view
jurisdictional view
```

### 24.1 The view preorder

Define:

```text
nu <= mu  iff  every atom active in nu is active in mu
```

Thus `nu` is at least as strict as `mu`.

If a monomial survives a stricter view, it survives every looser view. This property is
machine-checked:

```text
(Lean: view_functoriality)
```

The named protocol object `ViewPreorder` is currently **spec-only** in the Rust
substrate. Retraction and policy mechanisms exist, but they are not yet exposed as one
content-addressed preorder of active views.

### 24.2 Historical monotonicity, active restriction

Append can only add historical routes to the positive presentation. Restrict can only
delete routes from an active read by setting atoms to zero. It cannot create a route
that is absent from historical lineage.

```text
append:    historical lineage grows by accepted alternatives
restrict:  active lineage narrows under a declared view
```

A later policy may create a different view with more active atoms, but it does not
rewrite the earlier view or the historical presentation. Each view has its own root.

### 24.3 Retraction as a special case

Part I's source retraction `rho_Y` is the view in which every atom in `Y` is inactive
and every other atom is active. The v0.9 view calculus therefore generalizes Part I's
retraction without changing its semantics.

### 24.4 No historical erasure

A successful challenge, revocation, quarantine, supersession, or safety restriction
changes active state by changing the view or atom-state ledger. The historical route
remains in `Gamma_P` for audit. A new accepted route is added by append. It does not
replace the challenged route.

---

## 25. The environment quotient and support functions

Bag lineage preserves multiplicity. Correction and correlation-safe readouts need to
know which distinct assumptions a route uses.

Let an environment be a finite subset of `X`. Let `Env[X]` be the finite antichains of
finite environments, ordered by subset. An antichain records only minimal support
environments.

Define:

```text
A + B = minimal elements of A union B
A * B = minimal elements of {a union b | a in A, b in B}
0     = empty antichain
1     = {empty environment}
```

The environment map:

```text
env : N[X] -> Env[X]
```

forgets coefficients and repeated occurrences of the same atom within a monomial,
then removes subsumed environments.

```text
env(0)     = 0
env(1)     = 1
env(x)     = {{x}}
env(p + q) = env(p) + env(q)
env(p * q) = env(p) * env(q)
```

The finite-core preservation laws are machine-checked:

```text
(Lean: env_add, env_mul)
```

The homomorphic step is `env`. The terminal readouts below need not themselves be
semiring homomorphisms from raw bag lineage.

### 25.1 Monotone support functions

Every environment antichain `A` defines a monotone Boolean support function:

```text
f_A(S) = 1  iff  some e in A satisfies e subset S
```

where `S` is the active atom set. Conversely, every monotone Boolean function on a
finite atom set is determined by its minimal satisfying environments. The environment
antichain and the support function therefore contain the same correction-relevant
information.

A `SupportFunctionPacket` contains the cell, view root, minimal environments,
canonical support-function encoding, and replay roots. It is currently **spec-only**
in the Rust substrate, although the Sidon conformance fixture exercises the same
semantics.

### 25.2 Kappa

Let:

```text
w : X -> [0,1]
```

be an auditable atom calibration. Define:

```text
kappa_w(p) = max_{e in env(p)} product_{x in e} w(x)
```

with value `0` when there is no environment.

Precisely:

```text
kappa = weight_w o env
```

`env` is the homomorphism. `weight_w` is a terminal weighted readout over minimal
environments. `kappa` is not a scalar semiring homomorphism from raw `N[X]` into the
ordinary Viterbi semiring.

For a non-Boolean weight `w(x)`:

```text
env(x^2)   = {{x}}
kappa(x^2) = w(x)
```

A scalar homomorphism would require:

```text
kappa(x^2) = kappa(x)^2 = w(x)^2
```

which would force `w(x)^2=w(x)`. That holds only at the Boolean corners. The
environment quotient is therefore necessary to avoid counting a shared assumption as
independent evidence.

### 25.3 Unique-assumption cost and bottleneck

For atom verification cost `c`:

```text
cost(p) = min_{e in env(p)} sum_{x in e} c(x)
```

For atom reliability `w`:

```text
bottleneck(p) = max_{e in env(p)} min_{x in e} w(x)
```

Both are terminal readouts over environments. They charge or score each distinct
assumption once per route.

### 25.4 Belnap status

For a claim-context pair `(q,c)`, let `h+` and `h-` be its support and refute cells.
Under view `nu`, status is:

```text
T  if rho_nu(Gamma_P(h+)) != 0 and rho_nu(Gamma_P(h-)) = 0
F  if rho_nu(Gamma_P(h+)) = 0  and rho_nu(Gamma_P(h-)) != 0
B  if both are nonzero
N  if both are zero
```

The graded bilattice point is:

```text
(kappa(h+), kappa(h-))
```

Thresholding the two coordinates at nonzero recovers the Part I Belnap corners.

---

## 26. Correction as hypergraph duality

For cell `h` under view `nu`, define its active minimal support environments:

```text
A_{h,nu} = env(rho_nu(Gamma_P(h)))
```

Treat `A_{h,nu}` as a hypergraph whose vertices are atoms and whose hyperedges are
minimal support environments.

### 26.1 Hitting-set kill

A challenge set `Y subset X` kills support exactly when it intersects every active
minimal environment:

```text
Y kills h under nu
iff
for every e in A_{h,nu}, Y intersection e is nonempty
```

This equivalence is machine-checked:

```text
(Lean: hitting_set_kill)
```

A minimal hitting set is a minimal sufficient challenge. It identifies the smallest
named assumption set whose deactivation removes every active route.

A `HittingSetPacket` records the presentation root, lineage or circuit root, active
view root, target cell, active minimal environments, proposed challenge set, and a
replay receipt for the kill predicate. It is **spec-only** in Rust. The current Sidon
conformance fixture is a live executable instance of the semantics.

### 26.2 Repair

A repair set `R` restores support when it completes at least one historical environment
under the repaired active predicate:

```text
R repairs h under nu
iff
there exists e in env(Gamma_P(h)) such that
for every x in e, x is active in nu or x is supplied by R
```

This equivalence is machine-checked:

```text
(Lean: repair)
```

A `RepairSetPacket` records the historical environments, active view, proposed repair,
and the completed route. It is **spec-only** in Rust. The executable Sidon fixture
covers the corresponding append, restrict, and observe path.

### 26.3 Challenge locality

A challenge attacks named atoms or named route atoms. It does not attack an opaque
claim object. If the challenge concerns a conjunction as a route, that conjunction
must have been represented by a route atom at acceptance time.

This is the correction rule:

```text
name the dependency;
change its active state;
replay the same lineage;
derive every downstream consequence.
```

### 26.4 Kill and repair are dual questions

The active hypergraph supports two operational questions:

```text
kill:   which atom sets hit every active environment?
repair: which atom sets complete at least one historical environment?
```

The first finds sufficient corrections. The second finds sufficient restoration or
validation work. Both are computed from the same kernel.

---

## 27. Context licenses, statement faithfulness, and transfer

The kernel does not permit support to move across contexts merely because two claims
look similar. Every movement is represented by an accepted license and named atoms.

### 27.1 Context confinement

Suppose a clause moves lineage from body context `c` to head context `d`. The clause
must include a license path:

```text
ell : c -> d in Lic
```

and every primitive atom in the route must have an origin that can reach `d` through
accepted licenses. This is the kernel form of the Part I context wall.

Examples of accepted license shapes include:

```text
restriction to a narrower context
reviewed generalization
formal verifier-homomorphism transfer
statement-faithfulness receipt
claim-identity receipt
unit or representation conversion
signed transport certificate
```

### 27.2 Formal transfer

Part I's transfer is a verification-preserving map between verifiable frontiers. In
the kernel, a transferred route is represented by an ordinary positive clause. If
cell `b` is transferred to cell `h`, the route contains:

```text
Gamma_P(b) * x_transfer * x_transfer_soundness
```

Retracting the source route, transfer object, or soundness receipt removes the
transferred route by the same view substitution. No special transfer retraction rule
is needed.

For the Sidon translation example:

```text
{0,1,4} -> {10,11,14}
```

the route contains the witness receipt, the translation construction atom, and the
translation-preserves-Sidon theorem receipt.

### 27.3 Statement faithfulness

A formal proof can be valid while formalizing the wrong informal claim. Statement
faithfulness is therefore a separate receipt. Its strength may be recorded as:

```text
Equivalent
FormalStronger
FormalWeaker
Incomparable
Ambiguous
Unfaithful
```

The receipt is an atom in the relevant lineage route and a coordinate in the trust
observation. It is not merged into proof validity.

### 27.4 Empirical transport

Empirical transport may eventually use selection diagrams, transport formulas, and
do-calculus witness sequences. Those objects remain outside the finite math-wedge
kernel until a producer requires them. The current kernel only requires that any such
transport enter as explicit, signed, challengeable atoms and licenses.

---

## 28. Trust, replay, and admission as kernel applications

Trust is not a second state theory. It is a family of observations over lineage,
receipts, views, and policy.

### 28.1 Trust vector

A claim may expose coordinates such as:

```text
log_integrity
artifact_replay
verifier_gate
method_integrity
statement_faithfulness
context_of_use
model_lineage
operator_residual
uncertainty_calibration
body_trace_quality
human_review
transfer_status
safety_scope
significance_endorsement
```

Each coordinate must name the atoms, evaluator, policy, and view used to derive it.
Coordinates remain separate because a formal proof receipt, a body trace, a human
review, and a clinical relevance judgment answer different questions.

### 28.2 Replay tiers

Bitwise replay and semantic replay are distinct observations:

```text
R-bitwise       exact output bytes
R-semantic(tau) output within a signed tolerance tau
```

A tolerance is an attested policy input. It is not inferred by the kernel. A semantic
receipt cannot be promoted to bitwise replay without a new replay event and packet.

### 28.3 Calibration discipline

Atom weights for `kappa` may come from auditable channels such as:

```text
historical verifier outcomes
prospectively scored reviewer forecasts
replication frequencies
instrument error models
signed statistical calibration
```

They do not come from model self-confidence, citation count, venue prestige,
institutional brand, or reviewer enthusiasm. Until a calibration channel exists, the
corresponding interior `kappa` coordinate is not authoritative.

### 28.4 Verification cost and admission

Verification cost is an environment readout. Admission is a policy predicate over
claim kind, verification cost, safety scope, and required trust coordinates.

```text
lineage answers: what routes exist?
cost answers: what is the cheapest distinct-assumption route to verify?
admission answers: which reviewed transition may enter the presentation?
```

Admission policy is not provenance. It governs append.

---

## 29. Receipts and application domains

The kernel accepts different scientific domains through typed atoms and receipts. It
does not collapse their verification standards.

### 29.1 Formal mathematics

A formal-math route may contain:

```text
statement-registration atom
formal statement hash
proof artifact hash
kernel replay receipt
statement-faithfulness receipt
reviewer attestation
```

This is the current deepest wedge because verification is cheap, deterministic, and
available in software.

### 29.2 Computational results

A computational route may contain:

```text
program hash
input hash
runtime and dependency lock
hardware or execution profile
output hash
bitwise or semantic replay receipt
reviewed tolerance, if semantic
```

### 29.3 Body traces

A body-trace route may contain:

```text
protocol version
instrument configuration
sample lineage
reagent lots
raw-output hashes
deviation log
operator identity or automation receipt
safety and custody scope
```

These are not yet the primary implementation wedge. Their place in the kernel is
already clear: each challengeable dependency is an atom, and each accepted conclusion
is a clause.

### 29.4 Model and operator receipts

A model receipt may contain weights, training-data lineage, evaluation suites,
calibration reports, domain-of-validity claims, and known failure modes. An operator
receipt may additionally name function spaces, discretization, governing equations,
residual tests, and out-of-distribution checks.

A model prediction is activity until it is accepted through a receipt-bearing clause.

### 29.5 Benchmark freshness

A benchmark claim must carry a contamination cutoff and statement-registration date.
Freshness is a policy observation over those atoms. It is not inferred from leaderboard
position.

### 29.6 Export and agent interfaces

Workflow provenance, RO-Crate, W3C PROV, domain ontologies, and MCP resources are
export or interface layers. They may expose kernel objects and observation packets.
They do not replace the kernel carrier.

---

## 30. Frontiers, influence, attribution, and decision value

Part I defines a frontier as the support of unresolved discord. The kernel supplies
the exact active lineage beneath each discord cell.

### 30.1 Structural delta

A structural delta asks:

```text
What active support changes if atom set Y is made inactive?
```

It is computed by applying a stricter view and comparing replayable observations. It
is a deletion counterfactual over represented state.

### 30.2 Attribution

Shapley, Banzhaf, responsibility, and related allocations may be computed over the
monotone support function from Section 25. They allocate contribution or pivotality
under a declared coalition model. They do not measure truth or credibility.

For uniformly sampled active sets, Banzhaf influence is the probability that toggling
an atom changes the support function. Fourier analysis of the Boolean support function
provides an equivalent influence decomposition under the chosen measure. These are
analyses of `SupportFunctionPacket`, not new state carriers.

### 30.3 Information value

Information value requires more than lineage. It requires:

```text
action set
outcome model
prior or posterior state
cost model
utility function
```

The expected value of an experiment may use entropy reduction, expected frontier
change, translation value, and downstream decisions. It remains a decision functional
over kernel observations and an explicit probabilistic model.

### 30.4 Three quantities that must remain separate

```text
StructuralDelta  = what represented support changes under an intervention
AttributionValue = how contribution is allocated over a support function
DecisionValue    = which action has greatest expected utility
```

The first is a kernel counterfactual. The second is a game-theoretic analysis. The
third is Bayesian decision theory. None may be substituted for another.

### 30.5 Frontier ranking

Part I's ranking function remains canonical:

```text
Rank(a | A) = E[U(A, a, y, theta)]
```

The v0.9 kernel provides replayable inputs to that expectation. Ranking schedules
work. It does not alter lineage, status, confidence, or trust.

---

## 31. Observations and proof-carrying reads

An observation is a deterministic, replayable read of historical or active lineage.
It does not mutate the presentation or the view.

### 31.1 Observation packets

An `ObservationPacket` must contain enough information to reproduce the emitted value:

```text
presentation_root
lineage_root or circuit_root
active_view_root
target cell or query
evaluator_id or policy_id
valuation_inputs or policy_inputs
canonical_output
output_hash
```

The packet may also reference a `CircuitSemanticsReceipt` and an
`ObservationReplayReceipt`.

An `ObservationReplayReceipt` binds the evaluator implementation, version, inputs,
roots, canonical output, and replay result. It is currently **spec-only** in Rust.

`ObservationPacket` is **partial** in the current substrate. `vela claim state`
already exposes derived readings, and the conformance fixtures bind roots and outputs,
but the full packet is not yet the universal return type for every authoritative
field.

### 31.2 Observation determinism

For a fixed presentation, view, cell, and observation kind, two lawful observation
packets have the same output.

```text
(Lean: observation_determinism)
```

At the protocol boundary, deterministic evaluator code, canonical inputs, and
content-addressed roots must make this equality byte-replayable.

### 31.3 Observation completeness and its limit

The full audit observation into `N[X]` separates positive lineage. This follows from
the free carrier: if two kernels expose different lineage polynomials, the identity
audit observation distinguishes them.

That statement is correct but near-definitional. The ordinary product family does not
separate kernels.

Consider one support cell `h`, with no refute lineage:

```text
Gamma_1(h) = a * b
Gamma_2(h) = a * c
```

Let all atoms be active and choose:

```text
w(a)=1/2
w(b)=1
w(c)=1

cost(a)=1
cost(b)=0
cost(c)=0
```

Then both kernels emit the same product readings:

```text
Belnap status                    T
kappa                            1/2
unique-assumption tropical cost 1
bottleneck                       1/2
```

The kernels are nevertheless different:

```text
challenge {b} kills Gamma_1 but not Gamma_2
challenge {c} kills Gamma_2 but not Gamma_1
```

Therefore the family:

```text
{Belnap status, kappa, unique cost, bottleneck}
```

is not observation-complete. A correction-capable product must retain access to at
least one of:

```text
identity audit lineage
minimal-environment packet
support-function packet
hitting-set packet
repair-set packet
```

The audit path is not optional simply because the default UI uses scalar summaries.

### 31.4 Conformance Law: no hidden state

No status, confidence, trust, frontier, cost, bottleneck, bilattice,
structural-delta, support, refute, or decision-delta field may be emitted as
authoritative scientific state unless it is reproduced by exactly one complete
observation packet.

Let `S` be a substrate export with:

```text
S.state
S.field_roles
S.observation_packets
```

Define:

```text
AuthoritativeRoles = {
  status, confidence, kappa, trust, frontier, cost, bottleneck,
  bilattice, structural_delta, support, refute, decision_delta
}
```

Let `ScalarPaths(S.state)` be all scalar JSON paths in the exported state. A path `p`
is authoritative when either:

```text
S.field_roles[p] is in AuthoritativeRoles
```

or its field name matches:

```text
/status|confidence|kappa|trust|frontier|cost|bottleneck|
 bilattice|structural_delta|support|refute|decision_delta/
```

Let `Packets(p)` be the packets whose `output_path` equals `p`. Define
`Complete(o)` to mean that `o` contains:

```text
presentation_root
lineage_root or circuit_root
active_view_root
evaluator_id or policy_id
valuation_inputs or policy_inputs
canonical_output
```

The executable predicate is:

```text
NoHiddenState(S) :=
  for every p in ScalarPaths(S.state),
    Authoritative(p) implies
      there exists exactly one o in Packets(p) such that
        Complete(o)
        and Canon(o.canonical_output) = Canon(value_at(S.state, p))
        and Replay(o) = o.canonical_output
        and, when output_hash is present,
            output_hash = H(Canon(o.canonical_output))
```

A substrate fails conformance if an authoritative field has no packet, multiple
competing packets, missing replay roots, a mismatched canonical value, or a failed
replay receipt.

The executable checker is the repository's no-hidden-state conformance gate.

```text
(Conformance Law)
```

The implementation rule is absolute:

```text
No status, confidence, trust, or frontier value may be emitted unless it
replays from {presentation root, lineage/circuit root, active-view root,
evaluator/policy id, valuation/policy inputs, canonical output}.
```

---

## 32. The lawful intervention algebra

The kernel has three verbs.

### 32.1 Append

Append extends the accepted presentation:

```text
P -> P'
```

It may add contexts, atoms, cells, clauses, licenses, and policy roots after admission.
It changes historical lineage through the unique ranked model of the new presentation.

### 32.2 Restrict

Restrict selects or creates a declared active view and applies its substitution:

```text
Gamma_P -> rho_nu(Gamma_P)
```

It changes active state without erasing historical lineage. Retraction, challenge,
quarantine, revocation, safety restriction, and policy-epoch selection are restrict
operations at the semantic boundary.

### 32.3 Observe

Observe applies a named evaluator or policy to historical or active lineage and emits
an observation packet. It does not mutate the presentation, atom-state ledger, or
view.

### 32.4 Conformance Law: intervention factorization

Every reducer arm or external write path that can affect authoritative scientific
state must be typed as exactly one of:

```text
append
restrict
observe
```

The abstract Lean operation datatype is exhaustive:

```text
(Lean: intervention_factorization)
```

That theorem concerns the closed abstract type. It does not prove that an arbitrary
Rust reducer has no hidden fourth path. The substrate-level statement is a conformance
obligation:

```text
for every state-affecting reducer arm a,
  kind(a) is append, restrict, or observe;
  observe leaves kernel state unchanged;
  append writes only accepted presentation extension;
  restrict writes only view or atom-state data;
  no arm writes authoritative derived fields directly.
```

```text
(Conformance Law)
```

### 32.5 Conformance Law: agent containment

Agent output may enter the system only as:

```text
proposal activity outside accepted state
reviewed append to the accepted presentation
policy-authorized restrict operation
proof-carrying observation
```

Agent text, summaries, embeddings, private scores, chain-of-thought, and model
self-confidence are not scientific state.

```text
(Conformance Law)
```

### 32.6 Conformance Law: incentive containment

Stake, reward, reputation, priority, and significance signals may affect scheduling,
review allocation, or decision utility. They must not be direct inputs to `Gamma_P`,
the active substitution, Belnap status, `kappa`, or trust coordinates unless they are
themselves accepted as explicit evidence about a scientific claim under the normal
review policy.

```text
(Conformance Law)
```

### 32.7 Consequence

There is no privileged fourth operation for administrators, agents, ranking systems,
or user interfaces. If an operation is not append, restrict, or observe, it is not a
scientific-state operation.

---

## 33. The Scientific State Kernel Theorem

Let `E` be a finite, valid, causally down-closed Vela event set. Assume:

```text
canonical deterministic replay;
content-addressed schemas, policies, and reducers;
a finite accepted positive presentation P_E;
a rank certificate for every lineage clause;
explicit atoms for every independently challengeable dependency;
explicit licenses for every cross-context movement;
canonical observation evaluators and outputs.
```

Then replay determines a Scientific State Kernel:

```text
K_E = (
  P_E,
  Gamma_E,
  Circ_E,
  View_E,
  rho_E,
  Obs_E,
  Roots_E
)
```

with the following properties.

### 33.1 Representation

`Gamma_E : H_E -> N[X_E]` is the unique finite ranked historical lineage model of the
accepted presentation.

```text
(Lean: ranked_model_exists_unique, Gamma)
```

### 33.2 Initial interpretation

Every admitted positive target interpretation of atoms and operations has a unique
ranked model induced by the presentation.

```text
(Lean: initial_lineage_model)
```

### 33.3 Adequacy

Derivation-tree, equational, and conformant circuit semantics denote the same
historical lineage. The equational uniqueness is checked. The circuit leg is accepted
only with a valid `CircuitSemanticsReceipt`.

### 33.4 Views

Every declared view induces an active substitution over historical lineage. Stricter
views cannot create surviving routes.

```text
(Lean: view_functoriality)
```

### 33.5 Correction

A challenge kills a cell exactly when it hits every active support environment. A
repair restores support exactly when it completes at least one historical environment.

```text
(Lean: hitting_set_kill, repair)
```

### 33.6 Observation

For fixed presentation, view, cell, and observation kind, lawful observation output is
deterministic.

```text
(Lean: observation_determinism)
```

The restricted scalar product family is not complete. Correction-capable systems must
retain audit, environment, or support-function packets.

### 33.7 Intervention

Every conformant scientific-state operation is append, restrict, or observe. The
closed abstract operation type is exhaustive, while the claim that the production
substrate has no hidden path remains a Conformance Law.

```text
(Lean: intervention_factorization)
(Conformance Law: intervention factorization)
```

### 33.8 Kernel identity

The kernel's practical identity is:

```text
scientific state = accepted presentation plus historical composed lineage
active state     = declared view substitution over that lineage
observation      = replayable packet over named roots and evaluators
correction       = hitting-set or repair reasoning over environments
state change     = append or restrict
```

### 33.9 Proof

Canonical replay fixes `P_E`. Ranked existence and uniqueness fix `Gamma_E`. The
initial interpretation theorem fixes every positive target model. The circuit and tree
representations satisfy the same ranked equations when their receipts validate, so
ranked uniqueness identifies them with `Gamma_E`. View substitution defines active
lineage, and view functoriality prevents stricter views from creating routes. The
environment map exposes minimal support hyperedges. The checked kill and repair
results characterize correction. Observation determinism fixes each lawful read. The
conformance laws close the implementation boundary by excluding direct writes to
derived state and hidden intervention paths. Therefore one kernel supports
representation, active views, observation, correction, and controlled state change.

---

## 34. Conservativity over Part I

The Scientific State Kernel is a conservative extension of the formal core in Part I.
It sharpens the internal representation of state without changing the Part I
commitments.

### 34.1 Replay convergence

Part I proves that the same valid event set and replay semantics yield the same Atlas
state. The kernel compiler is a deterministic stage of replay:

```text
E -> P_E -> Gamma_E -> observation packets
```

Therefore equal replay inputs yield equal presentation roots, lineage or circuit
roots, view roots, and lawful observations.

### 34.2 Provenance and retraction

Part I's claim-local provenance polynomials embed into `Gamma_E`. The v0.9 kernel
composes them through accepted dependencies. Part I's retraction substitution is the
special view that deactivates the retracted atoms. No Part I retraction theorem is
weakened.

### 34.3 Belnap status

Part I derives `N`, `T`, `F`, and `B` from nonempty support and refute provenance. The
kernel applies the same rule to active composed lineage. The graded `kappa` pair has
the same four nonzero corners. The kernel adds dependency detail; it does not change
the status meaning.

### 34.4 Atlas realization

For each context `c`, an Atlas bundle may be realized as the collection of lawful
observations over cells at `c`, together with their provenance roots, trust packets,
and discord outputs. The Lineage Kernel is the representation carrier. The Atlas is
the context-indexed realized state view.

### 34.5 Transfers

Part I's verifier-preserving transfer theorem remains the soundness condition for a
formal transfer. The kernel records each specific transfer as a licensed clause with
explicit transfer and soundness atoms.

### 34.6 Frontier ranking

Part I's Bayesian expected-utility ranking remains external to truth and provenance.
The kernel supplies replayable inputs such as active status, uncertainty, structural
delta, and verification cost. Ranking still schedules work and does not alter state.

### 34.7 Result

The kernel adds one canonical composed representation and a proof-carrying read path.
It does not contradict or replace Part I's replay, integrity, status, retraction,
transfer, or ranking results.

---

## 35. Protocol objects and realization status

The v0.9 theory names nine protocol objects. Their names should not imply that all nine
already exist as Rust types.

| Protocol object | Role | Rust / CLI status | Needed by a current feature |
|---|---|---|---|
| `ScientificStateKernel` | Bundles accepted presentation, historical lineage, circuits, views, observations, and roots | **Spec-only** as one named object. The event log, reducer, provenance, and claim-state pieces are live or partial. | Yes as the architectural contract; not necessarily as one public struct yet. |
| `PresentationMorphism` | Structure-preserving accepted extension between presentations | **Spec-only** | No immediate UI need. Required for explicit migration, federation, and conservative-extension proofs. |
| `ViewPreorder` | Content-addressed ordering of active views and restriction maps | **Spec-only** | Yes for challenge, policy-epoch, and safety-view semantics. |
| `ObservationPacket` | Proof-carrying authoritative read | **Partial**. `vela claim state` emits derived readings and conformance fixtures bind roots, but the packet is not yet universal. | Yes. This is the nearest-term product object. |
| `ObservationReplayReceipt` | Records deterministic evaluator replay from packet inputs | **Spec-only** | Yes for the no-hidden-state law and third-party verification. |
| `CircuitSemanticsReceipt` | Certifies that a canonical lineage circuit denotes the ranked lineage model | **Spec-only** | Required when composed-lineage circuits become the production representation. |
| `SupportFunctionPacket` | Exposes minimal environments or an equivalent monotone support function | **Spec-only** in Rust; semantics exercised by the conformance fixture | Yes for correction, influence, and dependency inspection. |
| `HittingSetPacket` | Carries a replayable sufficient challenge | **Spec-only** in Rust; live as fixture semantics | Yes for challenge tooling, not for basic claim display. |
| `RepairSetPacket` | Carries a replayable route completion or restoration | **Spec-only** in Rust; live as fixture semantics | Yes for repair tooling, not for basic claim display. |

Current live or partial substrate features remain the grounding layer:

```text
append-only event log and deterministic reducer
support and refute provenance
Belnap status
kappa and other frontier-calculus readouts
verification cost and admission logic
claim-state CLI output
transfer objects
statement attestations
structural blast-radius analysis
```

The highest-priority implementation gap is the composed cross-cell lineage root and
its universal observation packet. New names should enter the public protocol only when
a live producer or consumer requires them.

---

## 36. Conformance laws and executable gates

Theorems describe the finite lineage carrier. Conformance Laws describe what an
implementation is permitted to expose or mutate.

### 36.1 No hidden state

Every authoritative derived field must have exactly one complete observation packet
whose canonical output matches the field and whose replay succeeds.

```text
(Conformance Law; executable gate described in Section 31.4)
```

### 36.2 Intervention factorization

Every state-affecting reducer arm must be typed as append, restrict, or observe, with
no direct writes to authoritative derived fields.

```text
(Conformance Law)
```

### 36.3 Agent containment

Agent output is proposal activity unless and until it passes the ordinary append,
restrict, or observe path.

```text
(Conformance Law)
```

### 36.4 Incentive containment

Incentive and reputation signals may schedule attention. They may not enter lineage,
views, status, confidence, or trust except as explicitly reviewed evidence about a
claim.

```text
(Conformance Law)
```

### 36.5 Current gates

The checked and grounded v0.9 bundle supplies three complementary gates:

```text
Lean build of the finite ranked kernel
Sidon append/restrict/observe conformance fixture
executable no-hidden-state scan
```

The Lean development checks the mathematical core. The fixtures check representative
protocol behavior. The no-hidden-state scan checks that a substrate export does not
contain unaudited authoritative fields. None of the three substitutes for the others.

---

## 37. Worked Sidon instance

This example instantiates the kernel with finite formal-math claims. It also shows why
claim scope must remain explicit during repair.

### 37.1 Verified witnesses

Let:

```text
S_014 = {0,1,4}
```

Its unordered sums with repetition are:

```text
0, 1, 4, 2, 5, 8
```

They are distinct, so `S_014` is a Sidon set in `[0,4]`. Therefore:

```text
B_2([0,4]) >= 3
```

A translated witness is:

```text
S_101114 = {10,11,14}
```

Translation preserves all pair-sum equalities and inequalities.

A second witness is:

```text
S_025 = {0,2,5}
```

Its unordered sums with repetition are:

```text
0, 2, 5, 4, 7, 10
```

They are distinct, so `S_025` is a Sidon set in `[0,5]`. It repairs a lower-bound cell
for `[0,5]`. It does not, by itself, repair the stronger `[0,4]` cell. This distinction
is required by the context wall.

### 37.2 Cells

Use support cells:

```text
h_w014 : "{0,1,4} is Sidon in [0,4]"
h_lb4  : "B_2([0,4]) >= 3"
h_lb5  : "B_2([0,5]) >= 3"
h_t014 : "{10,11,14} is Sidon in [10,14]"
h_w025 : "{0,2,5} is Sidon in [0,5]"
```

Choose ranks:

```text
rank(h_w014)=0
rank(h_w025)=0
rank(h_lb4)=1
rank(h_t014)=1
rank(h_lb5)=2
```

### 37.3 Atoms

```text
a_w014              verifier receipt for S_014
a_w025              verifier receipt for S_025
a_lb_rule            accepted rule: a size-3 Sidon witness yields a lower bound of 3
a_interval_4_to_5     accepted inclusion [0,4] subset [0,5]
a_translate_rule      accepted translation construction by +10
a_translate_theorem   proof receipt: translation preserves the Sidon property
```

### 37.4 Base presentation

```text
r_w014:
  h_w014 <- a_w014

r_lb4:
  h_lb4 <- a_lb_rule * h_w014

r_lb5_from4:
  h_lb5 <- a_interval_4_to_5 * h_lb4

r_t014:
  h_t014 <- a_translate_rule * a_translate_theorem * h_w014
```

The historical lineage is:

```text
Gamma(h_w014) = a_w014

Gamma(h_lb4) = a_lb_rule * a_w014

Gamma(h_lb5) =
  a_interval_4_to_5 * a_lb_rule * a_w014

Gamma(h_t014) =
  a_translate_rule * a_translate_theorem * a_w014
```

### 37.5 Default observation

Under the default view, every listed atom is active. The support environment for
`h_lb4` is:

```text
{{a_lb_rule, a_w014}}
```

The Belnap status of the lower-bound claim is `T`, assuming no refute lineage. An
observation packet names the presentation root, lineage or circuit root, default view
root, evaluator id, and canonical `T` output.

### 37.6 Hitting-set challenge

Challenge:

```text
Y = {a_w014}
```

`Y` intersects every active environment of `h_lb4`, so it kills that support:

```text
rho_Y(Gamma(h_lb4)) = 0
```

It also kills the route to `h_lb5` through `[0,4]` and the translated witness route.
The historical polynomials remain unchanged.

This is the checked correction shape:

```text
(Lean: hitting_set_kill)
```

### 37.7 Repair by accepted append

Append a new witness and a direct lower-bound route for `[0,5]`:

```text
r_w025:
  h_w025 <- a_w025

r_lb5_from025:
  h_lb5 <- a_lb_rule * h_w025
```

The extended historical lineage is:

```text
Gamma'(h_lb5) =
    a_interval_4_to_5 * a_lb_rule * a_w014
  + a_lb_rule * a_w025
```

Under the view that keeps `a_w014` inactive but leaves `a_w025` active:

```text
rho(Gamma'(h_lb5)) = a_lb_rule * a_w025
```

The `[0,5]` lower-bound cell is restored. The `[0,4]` lower-bound cell remains
unsupported because `{0,2,5}` is not contained in `[0,4]`.

A same-cell repair for `h_lb4` would require a replacement witness contained in
`[0,4]`, such as `{0,2,3}`, together with its own verifier receipt and accepted clause.

### 37.8 Repair packet

The repair packet for `h_lb5` names:

```text
historical environment {a_lb_rule, a_w025}
challenged view root
append event and new presentation root
new lineage or circuit root
completed route
post-repair observation output T
```

The repair result follows the checked finite rule:

```text
(Lean: repair)
```

### 37.9 What the example demonstrates

The same instance exercises all three verbs:

```text
append   add the verified S_025 route
restrict deactivate a_w014 in the challenged view
observe  emit status and minimal-environment packets
```

It also demonstrates context discipline. A valid witness can repair only a claim whose
scope contains that witness.

---

## 38. Checked scope and deferred extensions

**Three trust tiers.** Vela's guarantees come at three distinct strengths. Conflating
them is the main way a "no silent gaps" project can overclaim, so they are named here
explicitly; a claim's tier is part of the claim.

| Tier | What it means | How it is enforced | Examples |
|---|---|---|---|
| **Lean-checked** | A machine-checked theorem, axiom-clean (`{propext, Classical.choice, Quot.sound}` or fewer) | `lake build` + `vela lean verify-all --axioms-report`; the decl is registered in `lean/Vela/AxiomAudit.lean`, so a rename or a `sorry` fails CI | Theorems 1-34; the kernel/calculus laws (`graded_corner_conservative`, `ranked_model_exists_unique`, `context_confined`, …) |
| **Conformance-checked** | An executable invariant verified at runtime over real accepted state, not proven in Lean | `./scripts/full-conformance.sh`; failure exits non-zero | loader=reducer replay (`verify_replay`), review-decision parity, the activity/state boundary (`activity_ids_in_lineage`), no-hidden-state |
| **Doctrine-only** | A design law stated and reviewed, not yet a theorem or an executable gate | Human review against this document | Laws 13-23 (§39); the prose framing of the Conformance Laws |

The finite-ranked core is checked in the internal reference implementation
(not vendored in this public distribution):

```text
lean/Vela/Frontier/ScientificStateKernel.lean
```

It builds on Lean 4.29.1 with Mathlib. The principal checked declarations are:

```text
ranked_model_exists_unique
Gamma
initial_lineage_model
view_functoriality
env_add
env_mul
hitting_set_kill
repair
observation_determinism
intervention_factorization
```

The relevant theorems are axiom-clean beyond Lean's standard logical implementation
principles reported by the environment, including `propext`, `Classical.choice`, and
`Quot.sound`. There is no `sorryAx` in the checked kernel.

The theorem `intervention_factorization` proves exhaustiveness of the closed abstract
operation type. The claim that the production reducer has no untyped path remains the
Conformance Law in Section 32.4.

The following remain deferred:

```text
positive recursive fixed points
negation and difference
aggregation and evidence synthesis
full causal transport
structured argumentation semantics
bitemporal valid-time semantics
probabilistic dependence models beyond environment-safe readouts
proof of the production circuit compiler against circuit semantics
```

These are not omissions from the finite kernel. They are separate semantic extensions.
Each must preserve historical audit, context licensing, active-view correction,
proof-carrying observation, and the append/restrict/observe boundary.

The immediate implementation sequence is:

```text
accepted event log
  -> accepted ranked presentation
  -> composed lineage circuit root
  -> active view root
  -> universal observation packet
  -> support-function, hitting-set, and repair packets as needed
```

---

## 39. Doctrine laws (13–23)

Stated laws, not theorems; checkable in review. Laws 1–14 are the formal-core
doctrine of Part I §12; these extend the list and are carried forward from the
claim-local treatment. Several are now also kernel **Conformance Laws** with
executable gates: law 17 is §28.2 (replay tiers), law 18 is §28.4 (admission), law
19 is §32.6 (incentive containment), and law 14 is §26.3 (challenge locality).

13. **Projection soundness + provenance.** Every flag is the image of the stored
    polynomial under a declared homomorphism, and carries a proof packet naming
    its evaluator, valuation, source polynomial, and policy, so anyone can
    recompute it. The flag is auditable, never authoritative. Landed in `vela
    claim state` (the `projection_provenance` record). The kernel form is the
    no-hidden-state Conformance Law (§31.4).
14. **Attack locality.** A challenge attacks named monomials or assumptions,
    never the claim as an opaque whole, so disputes propagate through assumption
    retraction (the kernel form is hitting-set correction, §26). The Dung
    argumentation apparatus is the deferred extension.
15. **No transport without certificate.** No transferred claim enters the record
    without a transfer object carrying its assumption set (and, for empirical
    transfers, the transport certificate of §27.4).
16. **No unsupported synthesis.** A synthesized estimate is a projection over its
    inputs' provenance polynomials, never a stored free-standing object
    (derived-never-stored applied to meta-analysis).
17. **Reproducibility-tier monotonicity.** Bitwise implies semantic; tiers never
    upgrade without a replay event (§28.2).
18. **Verification/admission separation.** What verifies a claim and what admits a
    writer are distinct; admission is a function of verification cost, never
    identity alone (§28.4).
19. **Incentive non-interference.** No incentive, stake, score, or significance
    signal is an input to status, κ, the provenance polynomial, or the trust
    vector. Incentives price attention; they never touch state (§32.6).
20. **Monotone safety gating.** Safety restrictions (access tiers) only ever
    narrow access; no event widens access to restricted bytes retroactively. In
    the kernel a safety restriction is a restrict view (§24), never an erasure.
21. **Evaluation freshness.** A benchmark claim carries its contamination cutoff
    and statement-registration date; only statements registered after a model's
    cutoff are admissible freshness evidence (the anti-leaderboard foundation,
    §29.5).
22. **Claim-identity receipts.** Identity between two natural-language claims is
    itself a signed, attested, retractable event, never a silent reducer input
    (no-AI-in-the-trust-path applied to entity resolution).
23. **Reproducibility, replicability, robustness are distinct coordinates**, never
    collapsed into one.

Law 9 of the v1 list, "transfers amplify discovery," is recorded as **falsified**
and stays in the record as falsified. That is the point of having a record.

## 40. The live claim-local realization and naming

The composed kernel above is mostly spec-only. This section records what ships
today, so the live surface stays documented and the prior treatment's guarantees
are not dropped.

**The live realization.** The claim-local frontier calculus runs in the substrate
now and is what `vela claim state` reads:

| calculus object | symbol | Rust home | status |
|---|---|---|---|
| support / refute provenance | `π_T, π_F` | `N[X]` in the reducer, wired to flags | live |
| Belnap status (v1 corners) | `σ ∈ {N,T,F,B}` | `status_provenance.rs` | live |
| graded status (bilattice point) | `(κ(π_T), κ(π_F))` | `frontier_calculus.rs` | live (corners) / graded interior conservative |
| discount | κ | `frontier_calculus.rs` (Viterbi / environment readout) | live |
| verification cost | `v(q,c)` | admission-policy parameter | live |
| structural delta | `Δκ` | `frontier_graph.rs::blast_radius_graded` (bottleneck min-propagation) | live (structural instance) |
| trust vector | τ | `cli_claim.rs` (derives 7 of 14 coordinates) | partial |
| statement faithfulness | six-valued strength | `statement_attestation.rs` | live |

The composed-lineage `Γ_P` of §17–38 is the generalization these readings will
fold over once the composed cross-cell lineage root and its universal observation
packet (§35) are built; that is the single highest-leverage theory move, and it is
not consumer-gated.

**Map to the formal core.** The kernel's results that coincide with Part I are
cited there, not re-proved:

| kernel result | Part I canonical statement |
|---|---|
| replay convergence | Core Theorem 1 |
| retraction monotonicity | Core Theorem 2 |
| no-zombie status after retraction | Core Theorem 3 |
| conflict preservation (`B`, not forced resolution) | Part I §5.6.1, §7 |
| hash-DAG integrity | Core Theorem 5 |
| transfer support propagation / retraction | Core Theorem 23 + §27.2 |
| context no-generalization | Core §1 context law + §27.1 context wall |
| frontier as discord support, upward closure | Core Theorem 4 |

**Naming dictionary.** The bare word "attestation" is banned: it is always
"statement attestation (`vsa_`)" or "reviewer attestation (`vatt_`)".

| name | symbol | protocol object / Rust home | id / status |
|---|---|---|---|
| claim-state cell | cell | reducer fold, `vela claim state` | live |
| status | `(x,y)`; σ corners | Belnap in reducer; graded coords in the kernel | live (corners) / kernel (interior) |
| support / refute provenance | `π_T, π_F` | `N[X]`, wired to reducer flags | live |
| discount | κ | `frontier_calculus.rs` (Viterbi projection) | live |
| trust vector | τ | `cli_claim.rs` (derives 7 of 14 fields) | partial |
| verification cost | `v(q,c)` | admission policy parameter | live |
| structural delta | `Δκ` / FrontierDelta | `frontier_graph.rs::blast_radius_graded` | live (structural instance) |
| finding / frontier / event | — | `vf_` / `vfr_` / `vev_` | live |
| transfer | — | cross-domain transfer | `vtr_`, live |
| statement attestation (faithfulness) | — | `statement_attestation.rs`; six-valued strength | live |

**Executable validation.** Beyond the kernel's three gates (§36.5), the live
claim-local calculus is validated by the 25-check reference kernel
`research/frontier-calculus/frontier_calculus_kernel.py` (in the internal
reference tree, not vendored here; wired into `scripts/full-conformance.sh` by
exit code) and machine-checked in the public
`lean/Vela/Frontier/FrontierCalculus.lean` (Mathlib-free). The 14 v1 checks cover
replay convergence under shuffle, the semiring/retraction laws, no-zombie status,
hash-DAG tamper detection, transfer propagation/retraction, trust-vector
separation, and the Ramsey demo; the 11 v2 checks (c15–c25) cover the named
projections as homomorphisms, the negation/aggregation refusal, the
counting-vs-confidence divergence, Viterbi DAG safety, the σ/κ asymmetry, the
bilattice corner embedding and k-monotonicity, admission monotonicity, replay-tier
monotonicity, assumption-invalidation cascade, faithfulness composition, and the
transport-certificate schema.

## 41. References

**Database provenance and free semirings.** Green, Karvounarakis, and Tannen,
"Provenance Semirings," PODS 2007. Green and Tannen, "The Semiring Framework for
Database Provenance," PODS 2017. Amsterdamer, Deutch, and Tannen on provenance for
aggregation and the limits of provenance for difference.

**Truth maintenance and environments.** de Kleer, "An Assumption-based TMS," Artificial
Intelligence 28, 1986.

**Four-valued logic and bilattices.** Belnap and Dunn on four-valued logic. Ginsberg,
"Multivalued Logics," 1988. Fitting, "Bilattices and the Semantics of Logic
Programming," 1991. Avron, "The Structure of Interlaced Bilattices," 1996.

**Context and data movement.** Spivak on functorial data migration. Abramsky and
Brandenburger on contextuality. Bareinboim and Pearl on causal transportability and
the `sID` algorithm.

**Correction, causality, and attribution.** Meliou, Gatterbauer, Moore, and Suciu on
database causality and responsibility. Kimelfeld on deletion propagation. Deutch,
Frost, Kimelfeld, and Monet on Shapley values in query answering. Standard Banzhaf and
Fourier influence results for Boolean functions.

**Decision and information value.** Howard, "Information Value Theory," 1966. Pearl on
causal inference. Modern Bayesian experimental-design literature.

**Proof-carrying systems and replay.** Necula and Lee on proof-carrying code. Shapiro et
al. on conflict-free replicated data types. W3C PROV, RO-Crate, and related workflow
standards as export layers.

**Vela checked artifacts.** `lean/Vela/Frontier/ScientificStateKernel.lean` (the
internal reference implementation, not vendored in this public distribution; the
public tree carries the claim-local `lean/Vela/Frontier/FrontierCalculus.lean`);
the Sidon append/restrict/observe conformance fixture; and the executable
no-hidden-state conformance gate.

Additional citations carried from the claim-local realization. Trust discounting:
Jøsang, "Trust network analysis with subjective logic," ACSC 2006 (discount
canonical on series-parallel graphs only). First-order semiring semantics:
Grädel-Tannen, 2017 (dual indeterminates, the boundary past the positive scope
wall). Attribution and influence: Koh-Liang, "Understanding black-box predictions
via influence functions," ICML 2017. Kissing-number upper bound (the `[8,4,4]` →
E8 transfer example): Odlyzko-Sloane (1979), Levenshtein (1979). Proof-carrying
data lineage (the PCK roadmap): Chiesa-Tromer (proof-carrying data); Valiant
(incrementally verifiable computation); Bünz-Chiesa-Mishra-Spooner (PCD from
accumulation schemes); Nova / HyperNova / ProtoStar (folding/accumulation).
Operator and model receipts: Neural Operators (maps between function spaces);
Universal Differential Equations; IFP Natural Law Models. Formal-math frontier:
AlphaProof, Formal Conjectures, miniF2F-Lean, LeanMarathon. Standards (deferred
export projections): W3C PROV, RO-Crate, FAIR.

The canonical statement of Part II is:

> Vela represents accepted scientific state by the initial, context-licensed,
> composed-lineage model `Gamma_P : H -> N[X]`. Historical state changes only by
> accepted presentation extension. Active state is a declared substitution over
> historical lineage. Every authoritative read is proof-carrying. Correction is
> computed over minimal support environments. The production substrate is conformant
> only when every state-affecting operation factors as append, restrict, or observe.

---

# Appendix A: Theorem audit

*Folded from the former THEORY_AUDIT.md.*

A correctness/depth audit of the Lean substrate theorems (2026-06-01), prompted by "make sure all
the theories are fully ideal and correct, not bad or shallow." Honest classification, no inflation.

## 1. Genuinely sound, non-trivial content

- **`Vela.Log`**: Theorem 1 (replay convergence) and Theorem 5 (hash-DAG integrity). Replay
  convergence over a canonical linear extension (lexicographic event-id tie-break) is the genuinely
  substantive substrate theorem; it is proven over concrete definitions.
- **`Vela.Transfer`**: Theorem 23 (cross-frontier transfer soundness) + category structure, AND a
  *concrete* worked instance `translateTransfer` whose `sound` field is the proven theorem
  `sidon_translate_sound` (translation preserves the Sidon property; membership-unfolding + `omega`).
  No axiom, no `opaque`, no `sorry`. Verified standalone (Mathlib-free, `lake env lean` exit 0).
- **`Vela.EGZ`**: Erdős-Ginzburg-Ziv (n=2), a real number-theory proof.

## 2. Correct but algebraically shallow (appropriate: they are invariants)

- **`Vela.Provenance`**: Theorems 2 (retraction monotonicity), 3 (status-provenance soundness),
  4 (frontier upward closure). Proven over concrete definitions (`rho_Y`, `deriveStatus`,
  `frontierSupport`), no cheating. They are near-trivial algebraically, which is correct *for
  invariants*: their job is to be obviously-true machine-checked guarantees that pin the model, not
  deep results. Honest framing: present them as invariants, not breakthroughs.

## 3. Legitimate boundary assumptions (standard idealizations, clearly labeled)

- `hash_injective : Function.Injective Hash` and `canonicalBytes_injective` (in
  `AgentAttestationInjectivity`, `ScientificDiffPackId`, `ToolDescriptorInjectivity`,
  `VerdictConflictResolution`, `EvaluationRecordInjectivity`). You cannot prove SHA-256 injective
  (false by pigeonhole); modeling the hash/serializer as injective is the standard cryptographic /
  canonicalization idealization. Acceptable as labeled assumptions, not hollowness.

## 4. HOLLOW: theorems that assume their own content as an axiom over an opaque reducer

These are the "bad/shallow" case and should be de-hollowed:

- **`ToolDescriptorComposition`** Theorem 28 and **`EvaluationDescriptorComposition`** Theorem 34.
  They conclude "the reducer preserves descriptor identity" by citing axioms
  (`accept_pack_preserves_descriptors`, `record_evaluation_preserves_descriptors`) that *are* that
  conclusion, over `opaque` (undefined) reducers `accept_pack` / `record_evaluation`. The substantive
  invariant is assumed, not proven. The composition step (chaining two preservation facts) is real,
  but the per-step preservation is axiomatic.
- Similar pattern: `descriptor_id_is_self`, `signed_bytes_determine_body` (`DiffPackFederationSoundness`).

**The fix (DONE):** `lean/Vela/Protocol/ReducerModel.lean` gives the reducer a *concrete model* (`St` carries an
append-only log, a descriptor table, and a finding store; `step` appends to the log and never touches
the descriptor table on `acceptPack`/`recordEvaluation`) and *proves* preservation from the definition
(`acceptPack_preserves_descriptors`, `eval_then_pack_preserves`, and `replay_preserves_descriptors` by
induction over the log). The invariant T28/T34 asserted as an axiom over an `opaque` reducer is now a
theorem over a concrete one: the assume-guarantee stubs are realized by a real model. Mathlib-free,
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

# Appendix B: Guarantees: spec, proof, conformance

*Folded from the former PROTOCOL_GUARANTEES.md.*

What makes a protocol *real* (git, TCP/IP) is not one document but a closed triangle: a normative
spec clause, a machine-checked guarantee, and an executable conformance test for every load-bearing
invariant, and two interoperating implementations that agree on the vectors. This file is that map
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
  concrete reducer: the axioms are realized by a real model.
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

# Appendix C: Frontier Fabric

*Folded from the former FRONTIER_FABRIC.md (which consolidated the FRONTIER_FABRIC_* /
adapter / transfer docs). Reference architecture; the production trust path is the Sidon
profile + Part II.*


The Frontier Fabric is the architecture for extending Vela beyond the exact-math
wedge: typed domain adapters, an obligation/frontier-map layer, a three-lane
transfer calculus, and a state-neutral role for learned systems. **Most of it is
a reference, not production.** The production trust path is the Sidon producer
profile plus the kernel in [THEORY.md](THEORY.md) Part II; the broader fabric is
admitted only when a named producer with an in-software verifier requires it.
This doc consolidates the former `FRONTIER_FABRIC_*`, `FRONTIER_MAP`,
`DOMAIN_ADAPTER_STANDARD`, `MODEL_AND_OPERATOR_ADAPTERS`, and `TRANSFER_CALCULUS`
docs into one place; the executable reference + conformance live at
`research/frontier-fabric-v2/` (gated by `scripts/check-frontier-fabric-v2.sh`).

## 1. Realization status

**One canonical scheme.** There is exactly one production canonical scheme:
`vela.canonical-json-subset.v1` (NFC, float-free, domain-prefixed sha256). The
shipped `sidon_profile` and the OEIS-referenced bounds use it, so the production
record, packets, observations, and frontier-map roots all derive from it. The
research artifact at `research/frontier-fabric-v2/` uses its own domain tag
(`vela.scientific-state-fabric.canonical.v1`) for its own fixtures and is **not**
in the production trust path. The architecture (record/map/extend, typed
evidence classes, no-silent-upgrade bridges) is adopted; its canonical tag is not.

**Realized in production Rust** (the `record -> map -> extend` loop is real in the
shipped binary for the exact Sidon profile):

| Layer | Where | Conformance |
|---|---|---|
| Record: canonical + signed packets | `sidon_profile::{canonical,packets}` | recompute 25 fixture ids + sigs |
| Record: kernel `Γ_P`, four roots, environments | `sidon_profile::kernel` | replay every snapshot |
| Record: evaluator + observation replay | `sidon_profile::evaluator` | best-bound output + digests |
| Record: producer constructors | `sidon_profile::producer` | regenerate genesis byte-for-byte |
| Map: obligations + frontier map | `sidon_profile::frontier` | latent/open/discharged over live cells; positive-gap monotonicity |
| Surface | `vela sidon observe / submit / frontier-map` | cross-verified by the Python reference |

**Reference / contract only** (no production Rust until a named producer needs it):
the eight `DomainAdapter` manifests, the certified / target-checked / exploratory
transfer lanes, the model and operator adapters, the trace/estimate profiles, and
the sharded query backend. Models stay outside accepted state in every case.

## 2. Mathematical core

State is a finite positive ranked presentation `P = (H, X, R, rank)` with clauses
`h <- a_1 … a_m · h_1 … h_n` where `rank(h_i) < rank(h)`, and accepted lineage
`Γ_P(h) = Σ_{r:head=h} α(r) · Π_{b in body(r)} Γ_P(b)` in `N[X]`. Existence,
uniqueness, initiality, view functoriality, environment semantics, correction,
and observation determinism for this core are Lean-checked in the v0.9 Scientific
State Kernel (THEORY.md Part II); the results below are the fabric-specific
extensions over that kernel.

A domain adapter `A` declares an obligation generator `Ω_A : (P, ν) -> finite set
of obligations`, each with a target cell and a deterministic discharge predicate
`D_o`. `Gap_A(P,ν) = { o ∈ Ω_A(P,ν) | D_o(ρ_ν Γ_P) = false }`.

- **T1 (relative gap determinacy).** For fixed `P, ν, A` and deterministic
  obligation/discharge evaluators, `Gap_A(P,ν)` is unique and replayable. (`Γ_P`
  unique; view substitution deterministic; `Ω_A`, `D_o` content-addressed.)
- **T2 (gap unidentifiability without a universe).** Accepted state alone does not
  determine its missing obligations: two worlds with the same `P` and lineage but
  different declared universes have different gap sets. *No completeness claim is
  meaningful without a declared obligation universe* (see Law 6).
- **T3 (conservative adapter extension).** For disjoint-namespace `P_A`, `P_B`,
  lineage in `P_A ⊔ P_B` equals lineage in `P_A` for every `A` cell (rank
  induction). Installing a new adapter cannot alter existing state; cross-domain
  influence begins only at an accepted bridge clause.
- **T4 (certified transfer soundness + composition).** A certified transfer
  `T = (f, sound: ∀o, V_A(o) -> V_B(f(o)))` carries verification across frontiers
  and composes associatively with identities. The route records source lineage,
  transfer object, certificate, context license, and acceptance, so restricting
  any atom removes the route.
- **T5 (extension locality).** Appending clauses with heads in `S` can change only
  cells in the forward dependency cone of `S` (rank induction); the incremental
  recomputation boundary.
- **T6 (fixed-universe gap monotonicity).** Under a fixed view, fixed obligation
  universe, and discharge predicates monotone in positive support, a discharged
  obligation stays discharged under positive extension. (This does not freeze the
  *visible* frontier; see T7.)
- **T7 (successor exposure).** If `o_2` depends on `o_1`'s target, `o_1` is open,
  `o_2` is latent, and an extension discharges `o_1` but not `o_2`, then `o_2`
  becomes open: the frontier *migrates* outward.
- **T8 (hitting-set kill) / T9 (route repair).** A restriction set `Y` kills
  support for `h` iff `Y` meets every active environment of `h`; support is
  restored when an append or accepted view-update makes some environment fully
  active. (T8 is the v0.9 machine-checked correction theorem.)

**Model non-interference (Conformance Law, not a semiring theorem).** A model
candidate is not in the accepted presentation; its weights/prompt/output cannot
alter `Γ_P` unless a target receipt and human acceptance append a clause. The
executable gate rejects model packets that claim a state effect.

Proof status: T6/T7/T5/T3 are rank-induction properties with executable
fixtures; T1/T2 require deterministic adapter definitions; T8/T9 and the kernel
results are Lean-checked; certified-transfer composition uses the existing Lean
transfer contract.

## 3. Conformance laws

Implementation obligations (not theorems about the carrier):

1. **No hidden state:** no authoritative status/confidence/trust/cost/frontier/
   gap/rank/transfer value without a binding observation packet (presentation +
   lineage + view roots, adapter/evaluator ids, inputs, canonical output, replay receipt).
2. **No model authority:** a model/agent packet has `state_effect=none`,
   `authority_claim=proposal_only`, and no accepted-event id.
3. **No silent transfer:** every context movement names lane, source/target,
   assumptions, preserved/lost coordinates, certificate/receipt requirements, human acceptance.
4. **No silent evidence upgrade:** a target evidence class appears only from a
   target-domain receipt.
5. **Gap provenance:** every gap names adapter id, obligation-generator id,
   coverage-model root, discharge evaluator, presentation/view roots.
6. **No completeness claim without a universe:** "open under adapter A and
   coverage model C", never "all unknowns in this field" absent a proof relative
   to a finite declared universe.
7. **Ranking non-interference:** opportunity/leverage/novelty/score may *order*
   work; they may not alter accepted support, evidence class, confidence, or trust.
8. **Target-check binding:** a target receipt binds candidate id, target claim/
   context, artifact digest, verifier id + executable digest, config/tolerance, output digest.
9. **Human acceptance:** every accepted clause and view restriction has an
   eligible human signature; models may draft review material, never supply the key.
10. **Failure memory:** a failed candidate affects state only through an accepted
    failure event naming the obligation, method, inputs, cost, and reason.
11. **Adapter immutability:** historical state cites content-addressed adapter
    versions; an update cannot reinterpret earlier packets silently.
12. **Query completeness labeling:** support/environment/hitting-set packets state
    whether the result is complete-exact, bounded-exact, approximate, or one-witness.

## 4. Frontier maps and dark matter

"Knowledge dark matter" is operational only as a typed open obligation. An
obligation carries: id, adapter/generator ids, target cell + context, gap kind,
discharge evaluator, required verifier profile, dependencies, rationale, base
presentation + view roots, so the system can answer *what is missing, why it
believes it is missing, what would discharge it, and from which accepted state*.

**Gap classes** (small, shared vocabulary; adapters may add subtypes, not redefine
state semantics):

| Class | Meaning |
|---|---|
| `coverage` | a declared parameter/context/case/benchmark cell lacks support |
| `dependency` | an accepted route is blocked by an unsupported premise |
| `discord` | support and refutation (or incompatible confidence) coexist |
| `replication` | a policy requires an additional independent route |
| `robustness` | active support rests on too few or too fragile environments |
| `failure_memory` | a search region has tried routes with no accepted discharge |

(The retired `translation` and `model_residual` classes remain in the taxonomy
but are not minted by the current math-wedge frontiers.)

A frontier map requires a **declared coverage model** (e.g. all `n` in a Sidon
interval; all proof obligations of a Lean declaration; all tests in a frozen
suite). Coverage models are versioned scientific commitments: the map must show
the chosen boundary. No system can infer a complete set of unknown-unknowns from
accepted state alone (T2); the frontier expands only by admitting adapters/
coverage schemas, mining contradictions, importing programs, or accepting
expert-declared dimensions, none of which prove completeness.

**Migration.** Obligations are `latent` (prerequisites inactive) → `open`
(prerequisites active, target unsupported) → `discharged` (target supported).
Under a fixed view and positive append a discharged monotone-support obligation
cannot reopen (T6); an append may instead expose a successor (T7); a restriction
can reverse the movement without erasing historical lineage.

## 5. DomainAdapter standard

A DomainAdapter connects a domain to the kernel and frontier map while preserving
local semantics. A *profile* is declarative policy; an *adapter* is its executable
realization. Required interface (human acceptance is **not** an adapter method):

```text
compile(activity, profile)              -> proposal packets
verify(candidate, verifier_profile)     -> receipt packets
obligations(state, view, coverage_model)-> obligation packets
transfer(source_state, target_context, lane) -> transfer or candidate packets
observe(state, view, evaluator)         -> observation packets
```

The content-addressed manifest names the adapter id + schema version, profile +
evidence class, context dimensions, compiler id, verifier profiles + receipt
kinds, obligation/candidate generators, allowed transfer lanes, observation
evaluators, and capabilities. **Every candidate generator declares
`state_effect=none`.** Conformant adapters preserve: identity (content-addressed
artifacts/receipts/contexts), receipt-to-claim binding, explicit context
movement, finite strict rank, positive core lineage, an evidence ceiling at the
profile, human-accepted extensions, root-bound replayable outputs, and gap
provenance.

Evidence classes: `exact`, `replay`, `trace`, `estimate`, `attestation` (a domain
may refine within a class; cross-class bridges create candidates until the target
class supplies a receipt). Lifecycle: `draft → conformance → admitted → versioned
→ deprecated`; an incompatible update gets a new id and old packets stay
replayable. The reference package ships eight example adapters (formal math, exact
combinatorics, software validation, numerical simulation, model evaluation,
experimental trace, observational estimate, human attestation) to demonstrate
extensibility, not to claim those production systems are integrated.

## 6. Model and operator adapters

Learned systems extend the *search* frontier; they never define accepted state.
Every model adapter emits a `CandidatePacket` (model class/id, weights/code/
training-data roots, base observation + frontier-map roots, source/target cells,
proposed artifact, assumptions + domain of validity, calibration/OOD receipts,
known failure modes, required target receipts, `state_effect=none`).

This covers neural operators (PDE surrogates: record function spaces, parameter
measure, discretizations, held-out error, stability diagnostics, OOD support),
natural-law models, symbolic regression / SINDy (gap generators: residual →
candidate term → law obligation → held-out test), graph models over the frontier
graph (candidate relations/bridges/duplicates), language models (extraction,
hypothesis, proof search, review, never a verifier or acceptance authority), and
generative design (each validation rung is a distinct cell + evidence class). In
all cases Vela records model lineage and target outcome; the model does not
certify its own output. The record also supports three training exports
(accepted-state, correction, search) without making predictions authoritative.

## 7. Transfer calculus

Scientific transfer is not one operation; the fabric uses three lanes:

- **Lane 1, certified.** Carries a verifier-preservation proof / exact checker:
  `verified_A(o) -> verified_B(T(o))` (e.g. translating a Sidon set by a vector,
  transporting a Lean theorem through a proved equivalence). After human
  acceptance the target route may inherit source verification; the transfer +
  certificate atoms stay in lineage so restriction propagates. Certified
  transfers compose in the verifier-preserving category (T4).
- **Lane 2, target-checked.** Source knowledge proposes a target artifact but
  source verification does not imply target verification (a neural operator in a
  new regime; a model-generated material checked by DFT/experiment). The target
  adapter names required receipts; the target cell gets its evidence class only
  after those pass and a human accepts.
- **Lane 3, exploratory.** Hypotheses, analogies, candidate bridges, search
  heuristics, all `state_effect=none`. The default lane for LM analogies and graph
  embeddings until a target check occurs.

Target-checked and exploratory transfers compose only as candidate paths; a chain
cannot skip an intermediate check by citing a strong source. `transfer_leverage =
expected downstream obligations discharged / target verification cost` is a
*decision* metric computed from a root-bound frontier map, never a trust
coordinate. A representation can look invariant while the task-relevant
conditional relation shifts, so the protocol never reads "transferable embedding"
as "preserved scientific truth" (Law 3, Law 4).

# Appendix D: Object model

*Folded from the former OBJECT_MODEL.md: the node / edge / finding / frontier / anchor
vocabulary and the authoritative-vs-derived split.*


*What the words mean. A node, an edge, a finding, a frontier, an anchor, a
transfer, the atlas. Written once because the question keeps coming back: what is
a finding versus a node versus all the other stuff.*

## The one line

A node is a dot someone else drew. A finding is a result Vela personally checked.

Everything below is that distinction, made precise.

## The six words

**node**: a pin on the map. A known object, ingested from a source: an OEIS
sequence, a Mathlib declaration, an Erdős problem. Cheap to make, so there are
many (about 809k). A node is a *claim of existence*, nothing more. When a node is
labeled "verified" it usually means the source it came from was already checked
(Mathlib's kernel proved that declaration), not that Vela did anything. Ingesting
a node copies a fact. It does not vouch for it.

**edge**: a wire between two pins. `A depends on B`, `A implies B`, `A reduces to
B`. This is the connective tissue: the Mathlib declaration-dependency graph, the
module import graph, the cross-source identity joins, the cross-problem
reductions. Edges are what make "mapping the frontier" real rather than a field of
unconnected dots. An edge between two Lean declarations is admissible only if the
proof actually invokes the premise (kernel-checkable, never asserted).

**finding** (`vf_`): a result Vela itself ran through a frozen verifier and a
human key-custody accept, with full provenance and a deterministic replay. This is
the trusted layer, and it is deliberately small (about 2,541) because each one
costs a verification anyone can re-run. A finding is not a node that got promoted.
It is a different kind of object: a node is "this exists in a corpus"; a finding
is "Vela re-checked this and will stand behind it."

**frontier** (`vfr_`): a governed domain. A question (Sidon sets, the Erdős
corpus, the formal-conjectures Lean repo) together with its findings, its open
obligations, and its append-only signed event log. The frontier is the unit of
governance: state changes only through accepted events on its log.

**anchor** (`val_`): a signed cross-namespace identity link. The join key. When
an OEIS sequence and an Erdős problem are the same mathematical object, an anchor
says so, and the atlas merges them into one cell. Two grades: `HardIdentity` (the
same object, merge them) and `SearchOnly` (a candidate, surface it, never
auto-merge). The hard grade is reserved for the unambiguous cases.

**transfer** (`vtr_`): a verifier-homomorphism. A result proved in one domain
discharging a premise of an open problem in another, checked by a kernel theorem,
not asserted. Six exist; lighting them up is the moat work.

## The derived layer

**atlas**: the projection over all of it. `atlas::project` runs union-find over
the anchors plus context and produces the cells, the cross-source joins, the
field rollups, the blast-radius cascades. The atlas is **derived**: it is
regenerated from the authoritative log, never edited by hand, never the source of
truth. If the atlas and the event log disagree, the log wins and the atlas is
rebuilt.

## Authoritative versus derived

The single most important split. Two of these you can never lose without losing
truth; the rest you can throw away and rebuild from them.

| layer | objects | status |
|---|---|---|
| **authoritative** | the event log, finding bundles (`vf_`), signed anchors (`val_`), signed transfers (`vtr_`) | the source of truth; signed; append-only; replayable byte-for-byte |
| **derived** | atlas cells, edges, blast-radius, Belnap status, the κ provenance weight | regenerable projections; a pure function of the authoritative layer |

A node is mostly the cheap end of this table: an ingested pin whose trust, if any,
is borrowed from its source. A finding is the expensive end: a result that carries
its own verification.

## Why the map looked small

The honest diagnosis (2026-06-22): about 809k nodes but, for a long time, only
about 1,624 edges and about 2,541 findings. The map was almost all pins and almost
no wires, and the one question a producer actually asks ("what is the most
attackable open target?") had no command. The fix was never "ingest more nodes."
Nodes are cheap and already plentiful. The work is edges (the connective graph),
queryability (`vela attack`, `vela explore`), and wiring what is already ingested
into the view. The trusted finding layer stays small on purpose: it is the part
Vela personally checked.

## One-primitive discipline

Findings, links, and anchors only. Do not invent a new object type per source (the
founder-abstraction-trap). A new science is a new frontier with the same three
states (known / attackable / dark) and the same join kinds, not a new schema. The
atlas stays a pure derived projection. No fabricated edges.

## See also

- [PROTOCOL.md](PROTOCOL.md): the normative wire spec: events, bundles, ids.
- [THEORY.md](THEORY.md): the formal core and the frontier calculus.
- [CANON.md](../../../docs/CANON.md): the front door and the canonical set.
