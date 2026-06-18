# Mathematical core of the frontier layer

## 1. State representation

Let `P = (H, X, R, rank)` be a finite positive ranked presentation. Each clause has the form

```text
h <- a_1 ... a_m · h_1 ... h_n
```

with `rank(h_i) < rank(h)`. The accepted lineage model is

```text
Γ_P(h) = Σ_{r : head(r)=h} α(r) · Π_{b in body(r)} Γ_P(b)
```

in the free commutative semiring `N[X]`.

The v0.9 Scientific State Kernel proves existence and uniqueness, initiality, view functoriality, environment semantics, correction, observation determinism, and the append/restrict/observe boundary for this finite ranked core.

## 2. Adapter-relative obligations

A domain adapter `A` declares an obligation generator

```text
Ω_A : (P, ν) -> finite set of obligations
```

Each obligation `o` contains a target cell and deterministic discharge predicate `D_o` over active lineage.

```text
Gap_A(P, ν) = { o in Ω_A(P, ν) | D_o(ρ_ν Γ_P) = false }
```

### Theorem 1: relative gap determinacy

For fixed `P`, `ν`, `A`, and deterministic obligation/discharge evaluators, `Gap_A(P,ν)` is unique and replayable.

**Proof.** `Γ_P` is unique. View substitution is deterministic. `Ω_A` and each `D_o` are content-addressed deterministic functions. Set comprehension therefore yields one gap set.

### Theorem 2: gap unidentifiability without an obligation universe

Accepted state alone does not determine its missing obligations.

**Proof.** Let `P` support cell `h_1`. In world `W_1`, let the declared universe be `{h_1}`. In world `W_2`, let it be `{h_1,h_2}`, where `h_2` is unsupported. Both worlds have the same accepted presentation and lineage, but their gap sets are respectively empty and `{h_2}`. No function of `P` alone can return the correct gap set in both worlds.

The conformance fixture constructs this counterexample exactly.

## 3. Conservative adapter extension

Let `P_A` and `P_B` be valid ranked presentations with disjoint cell, atom, and
accepted-event namespaces and no cross-profile clauses. Their independent union
is obtained by taking the union of their cells, clauses, events, metadata, and
admitted profiles.

### Theorem 3: conservative adapter extension

For every cell of `P_A`, lineage in `P_A ⊔ P_B` equals lineage in `P_A`, and
symmetrically for `P_B`.

**Proof.** Every lineage equation for an `A` cell contains only `A` clauses and
lower-ranked `A` body cells. Adding the disjoint `B` equations changes none of
those clauses or bodies. Rank induction gives equality for all `A` cells; the
same argument applies to `B`.

A new domain adapter therefore cannot alter existing scientific state merely by
being installed. Cross-domain influence begins only when an explicit bridge
clause is accepted. The reference implementation checks this property.

## 4. Transfer lanes

### Certified transfer

A verifiable frontier is `F=(Obj,V)` with verifier predicate `V`. A certified transfer is

```text
T = (f : Obj_A -> Obj_B,
     sound : ∀o, V_A(o) -> V_B(f(o)))
```

### Theorem 4: certified transfer soundness and composition

A verified source object transfers to a verified target object. Certified transfers compose associatively and have identities.

**Proof.** Soundness is the stored proof field. Composition uses function composition and chains the two soundness proofs.

The lineage route records the source lineage, transfer object, certificate, context license, and acceptance. Restricting any of those atoms removes the route.

### Target-checked transfer

A target-checked transfer has no soundness map from source verification to target verification. It becomes append-eligible only after the target adapter emits every required receipt and a human accepts the transition.

This is an implementation contract rather than a theorem about `N[X]`.

## 5. Frontier extension and migration

Let `Supp(P,ν)` be the active supported cells. For accepted clause `r`, define

```text
Δ_r(P,ν) = Supp(P + r, ν) \ Supp(P,ν)
```

### Theorem 5: extension locality

In a finite ranked presentation, appending clauses with heads in `S` can only change cells in the forward body-to-head dependency cone of `S`.

**Proof.** Order cells by rank. Cells outside the cone have no new clause and no body dependency on a changed cell. By induction on rank, their lineage equations and active support remain unchanged.

This theorem provides the incremental recomputation boundary used by the reference fixture.

### Theorem 6: fixed-universe gap monotonicity

Fix a view `ν`, an obligation universe `Ω`, and discharge predicates monotone in
positive support. If `P'` is a positive extension of `P`, then an obligation
discharged in `P` remains discharged in `P'`.

**Proof.** Positive append adds derivation routes and removes none. Active support
is therefore monotone under the fixed view. A monotone discharge predicate that
was true remains true.

This does not imply that the visible frontier can only shrink. Dependency-gated
obligations may move from `latent` to `open` when their prerequisites become
supported. That is frontier migration.

### Theorem 7: successor exposure

Let obligation `o_2` depend on the target cell of obligation `o_1`. If `o_1` is
open, `o_2` is latent, and an accepted extension discharges `o_1` without
discharging `o_2`, then `o_2` becomes open.

**Proof.** After the extension, every dependency of `o_2` is active while its
target remains unsupported. This is exactly the definition of `open`.

The executable fixture realizes `alpha=.2 : open -> discharged` and
`alpha=.3 : latent -> open`.

## 6. Correction and repair

For a cell `h`, let `Env(h)` be its minimal active support environments.

### Theorem 8: hitting-set kill

A restriction set `Y` kills support for `h` if and only if `Y` intersects every active environment in `Env(h)`.

This is the v0.9 machine-checked correction theorem.

### Theorem 9: route repair

After a restriction, support is restored if an append or accepted view update makes at least one historical or new environment fully active.

The reference fixture disables the first target replay receipt, removes a dependent coverage cell, then appends an independent receipt route and restores both cells.

## 7. Model non-interference

A model candidate does not belong to the accepted presentation. Changing its weights, prompt, ranking, or output cannot alter `Γ_P` unless a target receipt and human acceptance append a new clause.

This is a **Conformance Law**, not a theorem of the free semiring. The executable gate rejects model packets that claim a state effect.

## 8. Capstone: Frontier Representation and Extension Theorem

For a finite positive ranked accepted presentation `P`, active view `ν`, and finite family of conformant adapters `{A_i}`:

1. `Γ_P` uniquely represents accepted positive lineage.
2. Each adapter-relative frontier map is uniquely determined by `(P,ν,A_i)`.
3. Gaps are identifiable relative to declared obligation generators and not identifiable from `P` alone.
4. Independent adapter addition is conservative until an explicit bridge is accepted.
5. Certified transfers preserve verification and compose.
6. Learned and heuristic transfers remain state-neutral until target receipts and human acceptance.
7. Accepted extensions affect only their forward dependency cones.
8. Under a fixed view and obligation universe, positive append cannot reopen a discharged monotone-support obligation.
9. Dependency-gated obligations let the actionable frontier migrate outward as predecessors are discharged.
10. Restrictions and repairs operate through the same environment semantics as the kernel.
11. Every authoritative observation replays from state, view, evaluator, and input roots.

Items 1, 4, 7, 8, 9, and 10 are mathematical properties of the ranked lineage
and obligation system. Items 2 and 3 require deterministic adapter definitions.
Items 6 and 11 include protocol conformance obligations.

## 9. Proof status

| Result | Status |
|---|---|
| Initial finite ranked lineage model | Lean-checked in the v0.9 kernel |
| View functoriality | Lean-checked |
| Environment homomorphism | Lean-checked |
| Hitting-set kill and repair | Lean-checked |
| Observation determinism | Lean-checked |
| Gap determinacy / unidentifiability | Proved above; executable counterexample in this package |
| Conservative adapter extension | Proved by rank separation; executable disjoint-union check |
| Certified transfer composition | Existing Lean transfer contract plus executable fixture |
| Extension locality | Proved by rank induction; executable check in this package |
| Fixed-universe gap monotonicity / successor exposure | Proved above; executable frontier-migration fixture |
| Model non-interference | Conformance Law; executable negative fixture |
