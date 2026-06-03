import Mathlib

/-!
# The hypergraph-product CSS precondition holds over ANY characteristic-2 commutative ring

`Vela.TransferHypergraphProduct.hgp_css_precondition` proves `Hx · Hzᵀ = 0` over `GF(2)`. This file shows
the fact is purely ring-theoretic: it holds over **any** commutative ring `R` of characteristic two. The
proof is unchanged in shape — the Kronecker mixed-product identity plus `x + x = 0` (which is exactly
characteristic two). This is the stepping stone toward the lifted/balanced product, whose entries live in
the group algebra `F₂[Zₗ]` — itself a commutative ring of characteristic two. (The lifted product adds an
antipode/involution on top; that extra structure is the remaining formalization, documented as the W3
obstruction in `docs/PLAN_2026-06d_QUANTUM_RESEARCH.md`.)
-/

namespace Vela.TransferHypergraphProductRing

open Matrix
open scoped Kronecker

variable {R : Type*} [CommRing R] [CharP R 2]
variable {m n : ℕ} (H : Matrix (Fin m) (Fin n) R)

/-- X-check matrix of the hypergraph product over `R`: `[ H ⊗ Iₙ | Iₘ ⊗ Hᵀ ]`. -/
def Hx : Matrix (Fin m × Fin n) ((Fin n × Fin n) ⊕ (Fin m × Fin m)) R :=
  fromCols (H ⊗ₖ (1 : Matrix (Fin n) (Fin n) R)) ((1 : Matrix (Fin m) (Fin m) R) ⊗ₖ Hᵀ)

/-- Z-check matrix of the hypergraph product over `R`: `[ Iₙ ⊗ H | Hᵀ ⊗ Iₘ ]`. -/
def Hz : Matrix (Fin n × Fin m) ((Fin n × Fin n) ⊕ (Fin m × Fin m)) R :=
  fromCols ((1 : Matrix (Fin n) (Fin n) R) ⊗ₖ H) (Hᵀ ⊗ₖ (1 : Matrix (Fin m) (Fin m) R))

/-- **The hypergraph-product CSS precondition over any char-2 commutative ring.** `Hx · Hzᵀ = 0`. -/
theorem hgp_css_precondition_ring : (Hx H) * (Hz H)ᵀ = 0 := by
  have h2 : ∀ x : R, x + x = 0 := fun x => by
    have h20 : (2 : R) = 0 := by exact_mod_cast CharP.cast_eq_zero R 2
    rw [← two_mul, h20, zero_mul]
  unfold Hx Hz
  rw [transpose_fromCols, fromCols_mul_fromRows]
  simp only [← kroneckerMap_transpose, transpose_one, transpose_transpose]
  rw [← mul_kronecker_mul, ← mul_kronecker_mul]
  simp only [Matrix.mul_one, Matrix.one_mul]
  ext i j
  simp only [Matrix.add_apply, Matrix.zero_apply]
  exact h2 _

end Vela.TransferHypergraphProductRing
