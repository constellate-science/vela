import Mathlib

/-!
# Vela substrate theorems (Theorems 2, 3, 4)

This file formalizes three algebraic guarantees of the Vela
substrate as defined in `docs/THEORY.md`:

- Theorem 2: provenance retraction monotonicity.
- Theorem 3: status-provenance soundness, T-side.
- Theorem 4: detector monotonicity implies frontier support upward closure.

Theorems 1 (replay convergence) and 5 (hash-DAG log integrity) are
formalized in `Vela.Log`.
-/

namespace Vela

universe u

/-- A monomial is a finite multiset of source or event identifiers. -/
abbrev Monomial (X : Type u) := Multiset X

/-- Variables appearing in a monomial. -/
def monomialVars {X : Type u} [DecidableEq X] (m : Monomial X) : Finset X :=
  m.toFinset

/--
A finite-support representation of provenance polynomials over `ℕ[X]`.

`coeff m` is the natural-number coefficient of monomial `m`.
`supportMonomials` is the finite set of monomials with nonzero coefficient.
The invariant `support_spec` ties the finite support to the coefficient map.
-/
structure ProvenancePoly (X : Type u) [DecidableEq X] where
  coeff : Monomial X → ℕ
  supportMonomials : Finset (Monomial X)
  support_spec : ∀ m : Monomial X, m ∈ supportMonomials ↔ coeff m ≠ 0

namespace ProvenancePoly

/-- Variables appearing in any monomial with nonzero coefficient. -/
def support {X : Type u} [DecidableEq X] (p : ProvenancePoly X) : Finset X :=
  p.supportMonomials.biUnion (fun m => monomialVars m)

end ProvenancePoly

/-- A monomial survives retraction by `Y` iff it contains no variable in `Y`. -/
def monomialSurvives {X : Type u} [DecidableEq X]
    (Y : Set X) [DecidablePred (fun x : X => x ∈ Y)]
    (m : Monomial X) : Prop :=
  (monomialVars m).filter (fun x => x ∈ Y) = ∅

instance {X : Type u} [DecidableEq X]
    (Y : Set X) [DecidablePred (fun x : X => x ∈ Y)]
    (m : Monomial X) : Decidable (monomialSurvives Y m) := by
  unfold monomialSurvives
  infer_instance

/-- Retraction sends variables in `Y` to zero and deletes monomials containing them. -/
def rho_Y {X : Type u} [DecidableEq X]
    (Y : Set X) [DecidablePred (fun x : X => x ∈ Y)]
    (p : ProvenancePoly X) : ProvenancePoly X :=
  { coeff := fun m => if monomialSurvives Y m then p.coeff m else 0,
    supportMonomials := p.supportMonomials.filter (fun m => monomialSurvives Y m),
    support_spec := by
      intro m
      by_cases hm : monomialSurvives Y m
      · simp [hm, p.support_spec]
      · simp [hm] }

/-- Belnap four-valued status. -/
inductive BelnapStatus
| neither
| true_
| false_
| both
deriving DecidableEq, Repr

/-- Derive Belnap status from supporting and refuting provenance support. -/
def deriveStatus {X : Type u} [DecidableEq X]
    (piT piF : ProvenancePoly X) : BelnapStatus :=
  if piT.support.Nonempty ∧ ¬ piF.support.Nonempty then
    BelnapStatus.true_
  else if ¬ piT.support.Nonempty ∧ piF.support.Nonempty then
    BelnapStatus.false_
  else if piT.support.Nonempty ∧ piF.support.Nonempty then
    BelnapStatus.both
  else
    BelnapStatus.neither

/-- Aggregate discord set at context `c`. -/
def discordAssignment {C : Type u} {K : Type u}
    [Fintype K] [DecidableEq K]
    (D : K → C → Bool) (c : C) : Finset K :=
  Finset.univ.filter (fun k => D k c = true)

/-- Frontier support predicate for the aggregate discord assignment. -/
def frontierSupport {C : Type u} {K : Type u}
    [Fintype K] [DecidableEq K]
    (D : K → C → Bool) (c : C) : Prop :=
  (discordAssignment D c).Nonempty

-- Theorem 2
/-- Retraction can only remove variables from provenance support. -/
theorem retraction_monotone
    {X : Type u} [DecidableEq X]
    (Y : Set X) [DecidablePred (fun x : X => x ∈ Y)]
    (p : ProvenancePoly X) :
    (rho_Y Y p).support ⊆ p.support := by
  intro x hx
  simp [ProvenancePoly.support, rho_Y] at hx ⊢
  rcases hx with ⟨m, hm, hxmem⟩
  exact ⟨m, hm.1, hxmem⟩

-- Theorem 3
/-- If supporting provenance is deleted by retraction, status cannot remain `true_`. -/
theorem status_provenance_sound_t
    {X : Type u} [DecidableEq X]
    (piT piF : ProvenancePoly X)
    (h : deriveStatus piT piF = BelnapStatus.true_)
    (Y : Set X) [DecidablePred (fun x : X => x ∈ Y)]
    (h_empty : (rho_Y Y piT).support = ∅) :
    deriveStatus (rho_Y Y piT) (rho_Y Y piF) ≠ BelnapStatus.true_ := by
  intro hT
  -- After retraction `piT` has empty support, so `Nonempty` is false.
  -- The first two if-branches of `deriveStatus` then degenerate; the
  -- third checks `piF`-support and emits either `false_` or `neither`,
  -- never `true_`.
  by_cases hF : (rho_Y Y piF).support.Nonempty
  · simp [deriveStatus, h_empty, hF] at hT
  · simp [deriveStatus, h_empty, hF] at hT

-- Theorem 4
/-- If every discord detector is monotone, frontier support is upward closed. -/
theorem frontier_upward_closed
    {C : Type u} [Preorder C]
    {K : Type u} [Fintype K] [DecidableEq K]
    (D : K → C → Bool)
    (h_mono : ∀ k : K, ∀ c c' : C,
      c' ≤ c → D k c' = true → D k c = true) :
    ∀ c c' : C,
      c' ≤ c →
      (∃ k : K, D k c' = true) →
      (∃ k : K, D k c = true) := by
  intro c c' hle hfrontier
  rcases hfrontier with ⟨k, hk⟩
  exact ⟨k, h_mono k c c' hle hk⟩

end Vela
