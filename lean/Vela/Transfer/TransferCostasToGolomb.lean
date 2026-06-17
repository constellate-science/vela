import Mathlib

/-!
# Cross-frontier transfer (Lean-proven): Costas array → Golomb ruler

The operational bridge `scripts/transfer_costas_to_golomb_demo.py`, now machine-checked. A Costas array
is a permutation `p` whose displacement vectors `(i−j, p i − p j)` are distinct. Encode it as integer
marks `m i = i·(2n+1) + p i`. Then all pairwise differences `m i − m j` are distinct — a Golomb ruler —
because the modulus `2n+1` exceeds the range of `p`-differences, so a coincidence of mark-differences
forces a coincidence of displacement vectors, which Costas forbids.
-/

namespace Vela.TransferCostasToGolomb

/-- The mark encoding of a width-`n` permutation `p` (values in `[0,n)`). -/
def mark (n : ℕ) (p : Fin n → ℤ) (i : Fin n) : ℤ := (i : ℤ) * (2 * n + 1) + p i

/-- **Costas → Golomb.** If `p`'s displacement vectors are distinct (the Costas property) and its values
    lie in `[0,n)`, then the marks have distinct pairwise differences (a Golomb ruler): equal
    mark-differences force equal index-gaps and equal value-gaps, hence equal displacement vectors. -/
theorem costas_to_golomb (n : ℕ) (p : Fin n → ℤ)
    (hrange : ∀ i, 0 ≤ p i ∧ p i < n)
    (hcostas : ∀ i j k l : Fin n, i ≠ j → k ≠ l →
        (i : ℤ) - j = (k : ℤ) - l → p i - p j = p k - p l → i = k ∧ j = l)
    (i j k l : Fin n) (hij : i ≠ j) (hkl : k ≠ l)
    (hmark : mark n p i - mark n p j = mark n p k - mark n p l) :
    i = k ∧ j = l := by
  have hMpos : (0 : ℤ) < 2 * n + 1 := by positivity
  -- value-gaps lie strictly inside (−n, n)
  have hpb : ∀ a b : Fin n, -(n : ℤ) < p a - p b ∧ p a - p b < n := by
    intro a b
    obtain ⟨ha0, ha1⟩ := hrange a; obtain ⟨hb0, hb1⟩ := hrange b
    constructor <;> linarith
  have hcg := hpb i j
  have hcl := hpb k l
  -- core identity: (index-gap difference) * (2n+1) = (value-gap difference)
  have key : ((i : ℤ) - j - ((k : ℤ) - l)) * (2 * n + 1) = (p k - p l) - (p i - p j) := by
    simp only [mark] at hmark; ring_nf at hmark ⊢; linarith
  -- RHS is strictly smaller in magnitude than the modulus
  have hRb : |(p k - p l) - (p i - p j)| < 2 * n + 1 := by
    rw [abs_lt]; constructor <;> linarith [hcg.1, hcg.2, hcl.1, hcl.2]
  -- hence the index-gap difference is 0
  have hc0 : (i : ℤ) - j - ((k : ℤ) - l) = 0 := by
    by_contra hc
    have h0 : 0 < |(i : ℤ) - j - ((k : ℤ) - l)| := abs_pos.mpr hc
    have h1 : (1 : ℤ) ≤ |(i : ℤ) - j - ((k : ℤ) - l)| := by omega
    have hge : (2 * n + 1 : ℤ) ≤ |((i : ℤ) - j - ((k : ℤ) - l)) * (2 * n + 1)| := by
      rw [abs_mul, abs_of_pos hMpos]; nlinarith [h1, hMpos]
    rw [key] at hge
    linarith [hRb]
  -- index-gaps equal; then value-gaps equal; then Costas gives pair equality
  have hidx : (i : ℤ) - j = (k : ℤ) - l := by linarith [hc0]
  have hval : p i - p j = p k - p l := by
    have hz : ((i : ℤ) - j - ((k : ℤ) - l)) * (2 * n + 1) = 0 := by rw [hc0]; ring
    rw [hz] at key; linarith [key]
  exact hcostas i j k l hij hkl hidx hval

end Vela.TransferCostasToGolomb
