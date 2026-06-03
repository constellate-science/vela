/-!
# Folding soundness: the Nova accumulation step is sound (machine-checked, Mathlib-free)

`scripts/pck_fold.py` runs the Nova folding scheme and checks the identity
`folded_residual = residual_1 + r²·residual_2` numerically. This file PROVES it, over `Int` (an
integral domain), with no Mathlib and no `sorry`/`axiom` — so the soundness of what the demo runs is a
checked theorem, not an observation.

A relaxed-R1CS row is *satisfied* when `a*b = u*c + e` (the subtraction-free form of
`a*b - u*c - e = 0`). Folding two rows under challenge `r` produces folded values with the Nova cross
term `T = a1*b2 + a2*b1 - u1*c2 - u2*c1` (here carried subtraction-free as a hypothesis), folded error
`e1 + r*T + r²*e2`, and folded `a,b,c,u` by `x1 + r*x2`. Two theorems:

* **`fold_complete`** — folding two satisfied rows yields a satisfied folded row (accumulation preserves
  satisfaction).
* **`fold_sound`** — over an integral domain with `r ≠ 0`, if the folded row is satisfied and the first
  row is satisfied, then the second row *must* have been satisfied. Contrapositive: you cannot fold an
  UNsatisfied (forged) row into a satisfied accumulator and have the result pass. This is exactly the
  anti-gaming guarantee the running demo exhibits, now proven.

The single load-bearing fact is the cross-term cancellation: the `r¹` terms vanish, leaving
`residual_1 + r²·residual_2`, so a nonzero `residual_2` survives as `r²·residual_2 ≠ 0`.
-/

namespace Vela.FoldingSoundness

/-- The product expansion underlying folding: `(a1+r·a2)(b1+r·b2)` splits into its `r⁰, r¹, r²` parts.
    Pure ring identity, closed by associative-commutative normalization (no Mathlib `ring`). -/
theorem fold_expand (a1 a2 b1 b2 r : Int) :
    (a1 + r*a2) * (b1 + r*b2) = a1*b1 + r*(a1*b2 + a2*b1) + r*r*(a2*b2) := by
  simp only [Int.mul_add, Int.add_mul, Int.mul_assoc, Int.mul_comm, Int.mul_left_comm,
             Int.add_assoc, Int.add_comm, Int.add_left_comm]

/-- **Folding completeness.** Folding two satisfied relaxed-R1CS rows yields a satisfied folded row.
    `hT` carries the Nova cross-term definition in subtraction-free form. -/
theorem fold_complete
    (a1 a2 b1 b2 c1 c2 e1 e2 u1 u2 T r : Int)
    (h1 : a1*b1 = u1*c1 + e1)
    (h2 : a2*b2 = u2*c2 + e2)
    (hT : a1*b2 + a2*b1 = T + u1*c2 + u2*c1) :
    (a1 + r*a2) * (b1 + r*b2) = (u1 + r*u2)*(c1 + r*c2) + (e1 + r*T + r*r*e2) := by
  rw [fold_expand, h1, hT, h2]
  -- goal: (u1*c1+e1) + r*(T+u1*c2+u2*c1) + r*r*(u2*c2+e2) = (u1+r*u2)*(c1+r*c2) + (e1+r*T+r*r*e2)
  simp only [Int.mul_add, Int.add_mul, Int.mul_assoc, Int.mul_comm, Int.mul_left_comm,
             Int.add_assoc, Int.add_comm, Int.add_left_comm]

/-- `r ≠ 0 → r*r ≠ 0` over `Int` (integral domain). -/
private theorem sq_ne_zero {r : Int} (hr : r ≠ 0) : r*r ≠ 0 := by
  intro h; rcases Int.mul_eq_zero.mp h with h' | h' <;> exact hr h'

/-- **Folding soundness (anti-gaming).** Over `Int`, with `r ≠ 0`: if the folded row is satisfied and
    the first row is satisfied, the second row must have been satisfied. So a forged (unsatisfied) row
    cannot be folded into a satisfied accumulator without breaking the folded check — exactly the
    property `scripts/pck_fold.py` exhibits (the forged delta flips the relaxed check). -/
theorem fold_sound
    (a1 a2 b1 b2 c1 c2 e1 e2 u1 u2 T r : Int)
    (h1 : a1*b1 = u1*c1 + e1)
    (hT : a1*b2 + a2*b1 = T + u1*c2 + u2*c1)
    (hr : r ≠ 0)
    (hfold : (a1 + r*a2) * (b1 + r*b2) = (u1 + r*u2)*(c1 + r*c2) + (e1 + r*T + r*r*e2)) :
    a2*b2 = u2*c2 + e2 := by
  -- rewrite both sides into  A + r*r*(·)  form, A the shared prefix
  have lhs_eq : (a1 + r*a2) * (b1 + r*b2)
      = (u1*c1 + e1) + r*(T + u1*c2 + u2*c1) + r*r*(a2*b2) := by
    rw [fold_expand, h1, hT]
  have rhs_eq : (u1 + r*u2)*(c1 + r*c2) + (e1 + r*T + r*r*e2)
      = (u1*c1 + e1) + r*(T + u1*c2 + u2*c1) + r*r*(u2*c2 + e2) := by
    simp only [Int.mul_add, Int.add_mul, Int.mul_assoc, Int.mul_comm, Int.mul_left_comm,
               Int.add_assoc, Int.add_comm, Int.add_left_comm]
  rw [lhs_eq, rhs_eq] at hfold
  -- hfold : A + r*r*(a2*b2) = A + r*r*(u2*c2 + e2)
  have key : r*r*(a2*b2) = r*r*(u2*c2 + e2) := Int.add_left_cancel hfold
  have hz : r*r*((a2*b2) - (u2*c2 + e2)) = 0 := by rw [Int.mul_sub]; omega
  rcases Int.mul_eq_zero.mp hz with h' | h'
  · exact absurd h' (sq_ne_zero hr)
  · omega

/-- Sanity (concrete numbers): two satisfied rows (2·3=6, 4·5=20; u=1, e=0), cross term T=−4, r=7,
    fold to a satisfied row — both sides equal 1140. -/
example : ((2:Int) + 7*4) * (3 + 7*5) = (1 + 7*1)*(6 + 7*20) + (0 + 7*((2*5 + 4*3) - 1*20 - 1*6) + 7*7*0) := by
  decide

end Vela.FoldingSoundness
