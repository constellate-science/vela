import Mathlib

/-!
# Cross-frontier transfer (Lean-proven): Hadamard matrix → constant-weight code

The operational bridge `scripts/transfer_hadamard_to_cwc_demo.py`, now machine-checked. Let `H` be an
`n × n` Hadamard matrix (`±1` entries, normalized first row all `+1`, rows pairwise orthogonal). Map each
non-first row to a binary word `b i k = (H i k = 1)`. Then every such row is a **constant-weight word of
weight `n/2`** and any two distinct rows are at **Hamming distance `n/2`** — i.e. the rows form a
`CWC(n, n/2, n/2)`. Both facts come from the single algebraic relation `H i k = 2·b i k − 1` together
with row orthogonality.
-/

namespace Vela.TransferHadamardToCWC

open Finset

variable {n : ℕ} [NeZero n] (H : Fin n → Fin n → ℤ)

/-- Binary image of an entry: `+1 ↦ 1`, `−1 ↦ 0`. -/
def b (i k : Fin n) : ℤ := if H i k = 1 then 1 else 0

omit [NeZero n] in
/-- The defining algebraic relation `H i k = 2·(b i k) − 1` when entries are `±1`. -/
theorem entry_eq (hpm : ∀ i k, H i k = 1 ∨ H i k = -1) (i k : Fin n) :
    H i k = 2 * b H i k - 1 := by
  unfold b
  rcases hpm i k with h | h
  · rw [h]; norm_num
  · rw [h]; norm_num

/-- **Weight.** Every non-first row has Hamming weight exactly `n/2`: `2·weight = n`. -/
theorem weight_eq (hpm : ∀ i k, H i k = 1 ∨ H i k = -1)
    (hrow0 : ∀ k, H 0 k = 1)
    (horth : ∀ i j, i ≠ j → ∑ k, H i k * H j k = 0)
    (i : Fin n) (hi : i ≠ 0) :
    2 * (∑ k, b H i k) = n := by
  have hsum0 : ∑ k, H i k = 0 := by
    have h := horth i 0 hi
    simpa [hrow0] using h
  have hexp : ∑ k, H i k = 2 * (∑ k, b H i k) - n := by
    rw [show (n : ℤ) = ∑ _k : Fin n, (1 : ℤ) by simp]
    rw [Finset.mul_sum, ← Finset.sum_sub_distrib]
    apply Finset.sum_congr rfl
    intro k _; exact entry_eq H hpm i k
  rw [hexp] at hsum0; linarith

omit [NeZero n] in
/-- **Distance.** Two distinct rows differ on exactly `n/2` coordinates: `2·(disagreements) = n`.
    With equal weights (`weight_eq`) this is the constant-weight minimum-distance content. -/
theorem distance_eq (hpm : ∀ i k, H i k = 1 ∨ H i k = -1)
    (horth : ∀ i j, i ≠ j → ∑ k, H i k * H j k = 0)
    (i j : Fin n) (hij : i ≠ j) :
    2 * ((univ.filter (fun k => H i k ≠ H j k)).card : ℤ) = n := by
  classical
  -- per-term: for ±1 entries, H i k * H j k = 1 − 2·[differ]
  have hterm : ∀ k, H i k * H j k = 1 - 2 * (if H i k ≠ H j k then (1 : ℤ) else 0) := by
    intro k
    rcases hpm i k with hi1 | hi1 <;> rcases hpm j k with hj1 | hj1 <;>
      rw [hi1, hj1] <;> norm_num
  have h0 := horth i j hij
  simp only [hterm] at h0
  rw [Finset.sum_sub_distrib, Finset.sum_const, ← Finset.mul_sum,
      Finset.sum_boole] at h0
  simp only [Finset.card_univ, Fintype.card_fin, nsmul_eq_mul, mul_one] at h0
  linarith

end Vela.TransferHadamardToCWC
