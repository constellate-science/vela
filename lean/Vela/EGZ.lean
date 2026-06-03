import Mathlib

/-!
# Erdős-Ginzburg-Ziv (1961), n = 2 case (Theorem 8)

The Erdős-Ginzburg-Ziv theorem (1961) states: among any `2 * n - 1`
integers, some `n` of them have a sum divisible by `n`. The `n = 2`
case asserts that among any 3 integers, two of them have an even
sum. The proof is pigeonhole on parity: 3 integers distributed over
2 parity classes force at least 2 into the same class, and two
integers with the same parity have an even sum.

This file formalizes the `n = 2` case as Theorem 8 in the Vela
substrate's machine-checked theorem bundle. The general theorem
(arbitrary `n`) requires the Chevalley-Warning machinery from
combinatorics; the substrate value of formalizing the `n = 2` case
is that it gives an end-to-end checked statement about a non-trivial
combinatorial fact in the same bundle as the substrate's own
correctness theorems, demonstrating that Vela can carry external
mathematical claims alongside its own kernel guarantees.

## What is and is not formalized

The theorem proved here is the substrate-relevant existence claim:
given a 3-element list of integers, there exists a 2-element sublist
whose sum is divisible by 2. The proof walks the parity cases of the
three elements explicitly via pigeonhole on `Int.emod x 2 ∈ {0, 1}`.

The substrate-honesty doctrine: this is a real Lean proof, not a
`sorry`. Verify with `lake build Vela.EGZ`.
-/

namespace Vela.EGZ

/-- For any integer, `x % 2` is either `0` or `1`. -/
lemma int_emod_two (x : ℤ) : x % 2 = 0 ∨ x % 2 = 1 := by
  have h0 : 0 ≤ x % 2 := Int.emod_nonneg x (by decide)
  have h1 : x % 2 < 2 := Int.emod_lt_of_pos x (by decide)
  -- x % 2 is a nonneg integer below 2, so it is 0 or 1.
  interval_cases (x % 2)
  · exact Or.inl rfl
  · exact Or.inr rfl

/-- Two integers with the same residue mod 2 have an even sum. -/
lemma sum_even_of_same_parity (a b : ℤ) (h : a % 2 = b % 2) :
    (a + b) % 2 = 0 := by
  have : (a + b) % 2 = (a % 2 + b % 2) % 2 := by
    rw [Int.add_emod]
  rw [this, h]
  -- Now (b % 2 + b % 2) % 2 = 0.
  rcases int_emod_two b with hb | hb
  · simp [hb]
  · simp [hb]

/-- **Theorem 8 (Erdős-Ginzburg-Ziv, n = 2 case).** Among any three
integers, some two have an even sum. The proof is pigeonhole on
parity: with two parity classes and three integers, at least two
share a class, and two integers sharing a parity class have an even
sum (by `sum_even_of_same_parity`). -/
theorem theorem8_egz_two (a b c : ℤ) :
    (a + b) % 2 = 0 ∨ (a + c) % 2 = 0 ∨ (b + c) % 2 = 0 := by
  rcases int_emod_two a with ha | ha
  all_goals rcases int_emod_two b with hb | hb
  all_goals rcases int_emod_two c with hc | hc
  -- Eight residue patterns; in each, at least two of a, b, c share
  -- a parity, so one of the three pair-sums is even.
  · exact Or.inl (sum_even_of_same_parity a b (ha.trans hb.symm))
  · exact Or.inl (sum_even_of_same_parity a b (ha.trans hb.symm))
  · exact Or.inr (Or.inl (sum_even_of_same_parity a c (ha.trans hc.symm)))
  · exact Or.inr (Or.inr (sum_even_of_same_parity b c (hb.trans hc.symm)))
  · exact Or.inr (Or.inr (sum_even_of_same_parity b c (hb.trans hc.symm)))
  · exact Or.inr (Or.inl (sum_even_of_same_parity a c (ha.trans hc.symm)))
  · exact Or.inl (sum_even_of_same_parity a b (ha.trans hb.symm))
  · exact Or.inl (sum_even_of_same_parity a b (ha.trans hb.symm))

end Vela.EGZ
