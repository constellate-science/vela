import Vela.Transfer.TransferCWCtoDNA

/-!
# Cross-frontier transfer: bounded-intersection packing → Constant-Weight Code (→ DNA)

The pro model's #2 transfer is `Steiner(t,k,v) → CWC(v, 2(k−t+1), k)`: map each block to its incidence
vector; since distinct Steiner blocks meet in at most `t−1` points, the incidence vectors have pairwise
Hamming distance `≥ 2(k−t+1)`. This file formalizes the tractable, load-bearing core: the
**bounded-intersection → minimum-distance** step.

For constant-weight-`k` binary words, Hamming distance and support-intersection are tied by
`Ham x y + 2·|x ∩ y| = wt(x) + wt(y)` (proved here, subtraction-free as `ham_both_wt`). Hence a family of
weight-`k` words with pairwise support-intersection `≤ s` is a constant-weight code with minimum distance
`2(k−s)`. Taking `s = t−1` recovers the Steiner bound `2(k−t+1)`.

The transfer then *composes* with `cwcToDna` (the #1 transfer) via the `Transfer.comp` category
structure, giving a single proven bridge `packing → CWC → DNA`. The Steiner→packing step itself (distinct
blocks meet in `≤ t−1` points) is exhibited operationally end-to-end in
`scripts/transfer_cwc_to_dna_demo.py` through the frozen `verify_steiner`/`verify_constantweight`/
`verify_dnacode`. Mathlib-free; no `sorry`/`axiom`.
-/

namespace Vela.TransferPackingToCWC

open Vela Vela.TransferCWCtoDNA

/-- Count of coordinates where both binary words are `1` (the size of the support intersection). -/
def Both : List Nat → List Nat → Nat
  | [], _ => 0
  | _, [] => 0
  | a :: as, b :: bs => (if a = 1 ∧ b = 1 then 1 else 0) + Both as bs

/-- Per-coordinate identity for bits: `[a≠b] + 2·[a=1 ∧ b=1] = [a≠0] + [b≠0]`. -/
private theorem coord (a b : Nat) (ha : a ≤ 1) (hb : b ≤ 1) :
    (if a = b then 0 else 1) + 2 * (if a = 1 ∧ b = 1 then 1 else 0)
      = (if a = 0 then 0 else 1) + (if b = 0 then 0 else 1) := by
  rcases (show a = 0 ∨ a = 1 by omega) with rfl | rfl <;>
    rcases (show b = 0 ∨ b = 1 by omega) with rfl | rfl <;> decide

/-- For equal-length binary words: `Ham x y + 2·(support intersection) = wt(x) + wt(y)`. The
    subtraction-free form of `Ham = wt(x) + wt(y) − 2·|x ∩ y|`. -/
theorem ham_both_wt (x : List Nat) :
    ∀ (y : List Nat), x.length = y.length →
      (∀ a ∈ x, a ≤ 1) → (∀ b ∈ y, b ≤ 1) →
      Ham x y + 2 * Both x y = Wt x + Wt y := by
  induction x with
  | nil =>
    intro y hlen _ _
    cases y with
    | nil => simp [Ham, Both, Wt]
    | cons b bs => simp at hlen
  | cons a as ih =>
    intro y hlen hx hy
    cases y with
    | nil => simp at hlen
    | cons b bs =>
      have ha : a ≤ 1 := hx a List.mem_cons_self
      have hb : b ≤ 1 := hy b List.mem_cons_self
      have hlens : as.length = bs.length := by simpa using hlen
      have hxs : ∀ c ∈ as, c ≤ 1 := fun c hc => hx c (List.mem_cons_of_mem a hc)
      have hys : ∀ c ∈ bs, c ≤ 1 := fun c hc => hy c (List.mem_cons_of_mem b hc)
      have hrec := ih bs hlens hxs hys
      have hc := coord a b ha hb
      simp only [Ham, Both, Wt]
      omega

/-- The bounded-intersection packing frontier `(v, k, s)`: binary words of length `v`, weight `k`,
    with pairwise support-intersection `≤ s`. Steiner systems give such families with `s = t − 1`. -/
def IsPacking (v k s : Nat) (C : List (List Nat)) : Prop :=
  (∀ x ∈ C, x.length = v) ∧
  (∀ x ∈ C, ∀ a ∈ x, a ≤ 1) ∧
  (∀ x ∈ C, Wt x = k) ∧
  (∀ x ∈ C, ∀ y ∈ C, x ≠ y → Both x y ≤ s)

def packingFrontier (v k s : Nat) : Frontier := { Obj := List (List Nat), verified := IsPacking v k s }

/-- **Soundness of packing → CWC.** A weight-`k` family with pairwise intersection `≤ s` is a
    constant-weight code with minimum distance `2(k − s)`. -/
theorem packing_to_cwc_sound (v k s : Nat) (C : List (List Nat)) (h : IsPacking v k s C) :
    IsCWC v (2 * (k - s)) k C := by
  obtain ⟨hlen, hbin, hwt, hboth⟩ := h
  refine ⟨hlen, hbin, hwt, ?_⟩
  intro x hx y hy hxy
  have key := ham_both_wt x y (by rw [hlen x hx, hlen y hy]) (hbin x hx) (hbin y hy)
  rw [hwt x hx, hwt y hy] at key
  have hbxy := hboth x hx y hy hxy
  omega

/-- The cross-frontier transfer `Packing(v,k,s) → CWC(v, 2(k−s), k)`, identity on words, genuine proof. -/
def packingToCWC (v k s : Nat) : Transfer (packingFrontier v k s) (cwcFrontier v (2 * (k - s)) k) where
  toFun := fun C => C
  sound := fun C h => packing_to_cwc_sound v k s C h

/-- **Composition** `Packing → CWC → DNA` via the `Transfer.comp` category structure (with the #1
    transfer `cwcToDna`). A bounded-intersection design becomes a DNA code in one proven step. Side
    condition `2(k−s) ≤ v` (the code's distance cannot exceed its length). -/
def packingToDNA (v k s : Nat) (hdv : 2 * (k - s) ≤ v) :
    Transfer (packingFrontier v k s) (dnaFrontier v (2 * (k - s)) k) :=
  (packingToCWC v k s).comp (cwcToDna v (2 * (k - s)) k hdv)

/-- The composed bridge fires with content: a verified packing is, after both transfers, a verified DNA
    code — a discovery on the DNA frontier obtained from a design, invisible to single-frontier search. -/
example (v k s : Nat) (hdv : 2 * (k - s) ≤ v) {C : List (List Nat)} (h : IsPacking v k s C) :
    (dnaFrontier v (2 * (k - s)) k).verified ((packingToDNA v k s hdv).toFun C) :=
  transfer_sound (packingToDNA v k s hdv) h

end Vela.TransferPackingToCWC
