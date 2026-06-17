import Mathlib

/-!
# Cross-frontier transfer (Lean-proven): orthogonal array → constant-weight code (one-hot)

The operational bridge `scripts/transfer_oa_to_cwc_demo.py`, now machine-checked. One-hot encode each row
of a `k`-column, `s`-symbol array: the binary word `oh row (c,σ) = (row c = σ)` over the index set
`Fin k × Fin s`. Then:

* **weight** is exactly `k` (one `1` per column block) — the constant-weight property; and
* the **Hamming distance** between two rows is `2·(number of columns where they differ)`.

So a pair of rows agreeing in at most `t−1` columns (the strength-`t` orthogonal-array property) maps to a
constant-weight code of weight `k` and minimum distance `≥ 2(k−t+1)`. This file proves the two
encoding-soundness facts; the agreement bound is the OA input, checked by the frozen `verify_oa`.
-/

namespace Vela.TransferOAtoCWC

open Finset

variable {k s : ℕ}

/-- One-hot encoding of a row: position `(c,σ)` is `1` iff column `c` carries symbol `σ`. -/
def oh (row : Fin k → Fin s) (p : Fin k × Fin s) : ℤ := if row p.1 = p.2 then 1 else 0

/-- **Constant weight.** The one-hot image of any row has Hamming weight exactly `k`. -/
theorem onehot_weight (row : Fin k → Fin s) :
    ∑ p : Fin k × Fin s, oh row p = k := by
  unfold oh
  rw [Fintype.sum_prod_type]
  have : ∀ c : Fin k, ∑ σ : Fin s, (if row c = σ then (1 : ℤ) else 0) = 1 := by
    intro c; simp
  simp [this]

/-- One-hot entries are `0` or `1`. -/
theorem oh_mem (row : Fin k → Fin s) (p : Fin k × Fin s) : oh row p = 0 ∨ oh row p = 1 := by
  unfold oh; split <;> simp

/-- The inner product of two one-hot rows counts the columns on which they agree. -/
theorem onehot_inner (r r' : Fin k → Fin s) :
    ∑ p : Fin k × Fin s, oh r p * oh r' p
      = ((univ.filter (fun c : Fin k => r c = r' c)).card : ℤ) := by
  unfold oh
  rw [Fintype.sum_prod_type]
  rw [Finset.card_filter]
  push_cast
  apply Finset.sum_congr rfl
  intro c _
  -- inner over σ: 1 iff r c = σ and r' c = σ, i.e. iff r c = r' c (with σ = r c)
  by_cases h : r c = r' c
  · simp [h]
  · have : ∀ σ : Fin s, (if r c = σ then (1:ℤ) else 0) * (if r' c = σ then 1 else 0) = 0 := by
      intro σ; by_cases h1 : r c = σ <;> by_cases h2 : r' c = σ <;> simp [h1, h2]
      · exact absurd (h1 ▸ h2.symm ▸ rfl) h
    simp [this, h]

/-- **Distance.** The one-hot Hamming distance between two rows equals `2·(columns where they differ)`.
    Proof via `dist = ∑ (oh r − oh r')² = weight r + weight r' − 2·⟨r,r'⟩ = 2k − 2·agreements`. -/
theorem onehot_distance (r r' : Fin k → Fin s) :
    ((univ.filter (fun p : Fin k × Fin s => oh r p ≠ oh r' p)).card : ℤ)
      = 2 * ((univ.filter (fun c : Fin k => r c ≠ r' c)).card : ℤ) := by
  classical
  -- per position, [oh r ≠ oh r'] = oh r + oh r' − 2·(oh r · oh r')  (true for 0/1 entries)
  have hkey : ((univ.filter (fun p : Fin k × Fin s => oh r p ≠ oh r' p)).card : ℤ)
      = ∑ p : Fin k × Fin s, (oh r p + oh r' p - 2 * (oh r p * oh r' p)) := by
    simp only [Finset.card_filter]; push_cast
    apply Finset.sum_congr rfl
    intro p _
    rcases oh_mem r p with h1 | h1 <;> rcases oh_mem r' p with h2 | h2 <;>
      simp [h1, h2]
  rw [hkey, Finset.sum_sub_distrib, Finset.sum_add_distrib, ← Finset.mul_sum,
      onehot_weight r, onehot_weight r', onehot_inner r r']
  -- k + k − 2·agreements = 2·(differ),  since agreements + differ = k
  have hpart : ((univ.filter (fun c : Fin k => r c = r' c)).card : ℤ)
      + ((univ.filter (fun c : Fin k => r c ≠ r' c)).card : ℤ) = k := by
    have h := Finset.card_filter_add_card_filter_not
      (s := (univ : Finset (Fin k))) (p := fun c => r c = r' c)
    have hcard : (univ : Finset (Fin k)).card = k := by simp
    rw [hcard] at h
    exact_mod_cast h
  linarith [hpart]

end Vela.TransferOAtoCWC
