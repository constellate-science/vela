import Vela.Core

/-!
# Frontier calculus v2: the graded status is a conservative extension

Mathlib-free, building only on `Vela.Core`. The v2 status is a point in the
graded bilattice `[0,1] ⊙ [0,1]`; its corner -- thresholding each coordinate at
`> 0` -- reproduces the v1 Belnap `deriveStatus` exactly, for every positive
per-source confidence assignment. This is the *machine-checked* form of the
conservative-extension theorem the Rust and Python kernels otherwise only test
on fixtures (`frontier_calculus.rs::graded_status_corner_is_conservative_over_v1`,
`frontier_calculus_kernel.py` check 20).

`kappa` is modelled over `ℕ` (a positive confidence is `≥ 1`): the conservativity
argument turns only on *positivity*, so `ℕ` suffices and keeps this file
dependency-free, provable in seconds by `lake env lean Vela/FrontierCalculus.lean`.
-/

namespace Vela.FrontierCalculus

open Vela.Core

/-- The weight of one monomial under a confidence valuation: the product of its
    variables' confidences (the empty monomial weighs `1`). The Viterbi `·`. -/
def monoWeight (conf : Nat → Nat) (m : List Nat) : Nat :=
  m.foldr (fun x acc => conf x * acc) 1

/-- `kappa`: the best-derivation weight = the max over monomials of `monoWeight`
    (the empty polynomial weighs `0`). The positivity skeleton of the Viterbi
    projection: `max` selects the best alternative, `·` contracts along a chain. -/
def kappa (conf : Nat → Nat) (p : Poly) : Nat :=
  p.foldr (fun m acc => Nat.max (monoWeight conf m) acc) 0

/-- A monomial's weight is positive when every confidence is positive. -/
theorem monoWeight_pos {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x) (m : List Nat) :
    0 < monoWeight conf m := by
  induction m with
  | nil => exact Nat.one_pos
  | cons x xs ih => exact Nat.mul_pos (hconf x) ih

/-- **`kappa` positivity tracks support.** With every confidence positive, the
    `kappa` coordinate is positive iff the polynomial has any derivation. -/
theorem kappa_pos_iff {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x) (p : Poly) :
    0 < kappa conf p ↔ p ≠ [] := by
  cases p with
  | nil => simp [kappa]
  | cons m rest =>
      have hm : 0 < monoWeight conf m := monoWeight_pos hconf m
      have : 0 < kappa conf (m :: rest) :=
        Nat.lt_of_lt_of_le hm (Nat.le_max_left _ _)
      simp [this]

/-- `decide (0 < kappa …)` is exactly the v2 support reading `!p.isEmpty`
    (the kernel's `derive_status = !is_zero`). -/
theorem kappa_decide_eq_nonempty {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x)
    (p : Poly) : decide (0 < kappa conf p) = !p.isEmpty := by
  cases p with
  | nil => simp [kappa]
  | cons m rest =>
      have : 0 < kappa conf (m :: rest) := (kappa_pos_iff hconf _).mpr (by simp)
      simp [this]

/-- The graded bilattice corner: threshold each `kappa` coordinate at `> 0`. -/
def corner (kT kF : Nat) : Status :=
  deriveStatus (decide (0 < kT)) (decide (0 < kF))

/-- **Conservative extension (machine-checked).** The corner of the v2 graded
    status reproduces the v1 Belnap `deriveStatus` for EVERY positive confidence
    assignment: thresholding each `kappa` coordinate at `> 0` recovers exactly the
    polarity of "the polynomial has a derivation". v1 readers are provably
    unaffected -- the graded layer adds resolution, never changes the corner. -/
theorem graded_corner_conservative {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x)
    (piT piF : Poly) :
    corner (kappa conf piT) (kappa conf piF)
      = deriveStatus (!piT.isEmpty) (!piF.isEmpty) := by
  unfold corner
  rw [kappa_decide_eq_nonempty hconf piT, kappa_decide_eq_nonempty hconf piF]

/-- **Retraction lowers the degree.** Retracting an assumption set can only lower
    the `kappa` coordinate (it deletes monomials; the max over a sub-family is no
    larger). This is the `sigma`/`kappa` asymmetry's safe direction: support never
    silently rises under retraction. -/
theorem kappa_retract_le (conf : Nat → Nat) (Y : Nat → Bool) (p : Poly) :
    kappa conf (retract Y p) ≤ kappa conf p := by
  induction p with
  | nil => simp [retract, kappa]
  | cons m rest ih =>
      by_cases h : m.all (fun x => ! Y x)
      · -- m survives retraction: head kept, tail by ih
        simp only [retract, List.filter_cons, h, kappa, List.foldr_cons]
        exact Nat.max_le.mpr ⟨Nat.le_max_left _ _, Nat.le_trans ih (Nat.le_max_right _ _)⟩
      · -- m is dropped: kappa (retract rest) ≤ kappa rest ≤ kappa (m :: rest)
        simp only [retract, List.filter_cons, h, kappa, List.foldr_cons]
        exact Nat.le_trans ih (Nat.le_max_right _ _)

/-- Sanity (computational): the support polynomial `x1·x2 + x3` has positive
    `kappa` under the all-ones confidence, and its corner is `true_`. -/
example : corner (kappa (fun _ => 1) [[1, 2], [3]]) (kappa (fun _ => 1) []) = Status.true_ := by
  decide

end Vela.FrontierCalculus
