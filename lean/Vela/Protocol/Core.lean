/-!
# Vela substrate core, Mathlib-free and self-contained

The richer proofs of substrate Theorems 2-4 live in `Vela.Provenance` (over Mathlib `Finset`/
`Multiset`). World-class infrastructure should also have its *core* invariants provable in seconds by
anyone, with no 5 GB dependency -- the git/Linux property: small, self-contained, instantly auditable.

This file re-proves the three algebraic substrate guarantees over plain `List`, importing NOTHING
(no Mathlib, no Std beyond the prelude). Together with `Vela.Transfer` and `Vela.ReducerModel` (also
Mathlib-free), the entire conceptual substrate core -- provenance retraction, no-zombie status,
frontier closure, cross-frontier transfer, and deterministic replay -- compiles standalone:

    lake env lean Vela/Core.lean      # or: lean Vela/Core.lean

with no external library. That is the dependency-free nucleus.
-/

namespace Vela.Core

/-- Provenance polynomial over `ℕ[X]`, concretely: an OR (the list) of ANDs (each monomial a list of
    variable ids). `x` is in the support iff some monomial contains it. -/
abbrev Poly := List (List Nat)

/-- A variable is in a polynomial's support iff some monomial mentions it. -/
def inSupport (p : Poly) (x : Nat) : Prop := ∃ m, m ∈ p ∧ x ∈ m

/-- Retraction by a set `Y` (as a decidable predicate): delete every monomial that mentions a
    retracted variable. (Setting a variable to 0 kills every monomial containing it.) -/
def retract (Y : Nat → Bool) (p : Poly) : Poly :=
  p.filter (fun m => m.all (fun x => ! Y x))

/-- **Substrate Theorem 2 (retraction monotonicity), Mathlib-free.** Retraction can only remove
    variables from the support, never add. -/
theorem retraction_monotone (Y : Nat → Bool) (p : Poly) (x : Nat)
    (h : inSupport (retract Y p) x) : inSupport p x := by
  obtain ⟨m, hm, hx⟩ := h
  rw [retract, List.mem_filter] at hm
  exact ⟨m, hm.1, hx⟩

/-- `supported p` is true iff the support is nonempty (some monomial has a variable). -/
def supported (p : Poly) : Bool := p.any (fun m => !m.isEmpty)

/-- Belnap four-valued status. -/
inductive Status | neither | true_ | false_ | both deriving DecidableEq, Repr

/-- Status from the polarity of supporting (`sT`) and refuting (`sF`) support. -/
def deriveStatus (sT sF : Bool) : Status :=
  match sT, sF with
  | true,  false => .true_
  | false, true  => .false_
  | true,  true  => .both
  | false, false => .neither

/-- **Substrate Theorem 3 (status-provenance soundness, T-side), Mathlib-free.** If retraction empties
    the supporting provenance, the status can no longer be `true_`: no zombie findings. -/
theorem status_provenance_sound_t (piT piF : Poly) (Y : Nat → Bool)
    (h : supported (retract Y piT) = false) :
    deriveStatus (supported (retract Y piT)) (supported (retract Y piF)) ≠ Status.true_ := by
  rw [h]
  cases supported (retract Y piF) <;> simp [deriveStatus]

/-- **Substrate Theorem 4 (frontier upward closure), Mathlib-free.** With a monotone discord detector
    family over any refinement relation `le`, frontier support is upward closed: if a more-specific
    context has detectable discord, so does the more-general one. (Pure logic; no `Preorder` needed.) -/
theorem frontier_upward_closed {C : Type} (le : C → C → Prop) (D : Nat → C → Bool)
    (mono : ∀ k c c', le c' c → D k c' = true → D k c = true)
    (c c' : C) (hle : le c' c) (h : ∃ k, D k c' = true) :
    ∃ k, D k c = true := by
  obtain ⟨k, hk⟩ := h
  exact ⟨k, mono k c c' hle hk⟩

/-- Sanity (computational): retracting variable `1` from `x1·x2 + x3` deletes the monomial `x1·x2`
    and keeps `x3`. -/
example : retract (fun x => x == 1) [[1, 2], [3]] = [[3]] := by decide

end Vela.Core
