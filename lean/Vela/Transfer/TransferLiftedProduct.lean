import Mathlib

/-!
# The lifted-product CSS precondition over a char-2 commutative ring with involution

The lifted/balanced product (Panteleev–Kalachev) lives over the group algebra `F₂[Zₗ]`. Binary-transposing
an expanded circulant introduces the antipode `x ↦ x⁻¹`, a ring **involution** `σ`. So the lifted
precondition is the hypergraph-product identity with a *conjugate transpose* `B† = (Bᵀ).map σ`. This file
proves it for any commutative ring `R` of characteristic two equipped with a ring involution `σ`:

  `Hx = [ B ⊗ I | I ⊗ B† ]`,  `Hz = [ I ⊗ B | B† ⊗ I ]`,  with the dagger `Hz† = (Hz.map σ)ᵀ`,

then `Hx · Hz† = B⊗B† + B⊗B† = 0` (characteristic two) — the same cancellation as the antipode-free case
(`Vela.TransferHypergraphProductRing`), now with the involution that the lifted product requires.
Instantiating `R = F₂[Zₗ]`, `σ =` antipode recovers the lifted/balanced product precondition.
-/

namespace Vela.TransferLiftedProduct

open Matrix
open scoped Kronecker

variable {R : Type*} [CommRing R] [CharP R 2]
variable (σ : R →+* R) (hσ : Function.Involutive σ)
variable {m n : ℕ} (B : Matrix (Fin m) (Fin n) R)

/-- Conjugate transpose: transpose then apply the involution entrywise. -/
def dagger (M : Matrix (Fin m) (Fin n) R) : Matrix (Fin n) (Fin m) R := (Mᵀ).map σ

/-- X-check of the lifted product: `[ B ⊗ Iₙ | Iₘ ⊗ B† ]`. -/
def Hx : Matrix (Fin m × Fin n) ((Fin n × Fin n) ⊕ (Fin m × Fin m)) R :=
  fromCols (B ⊗ₖ (1 : Matrix (Fin n) (Fin n) R)) ((1 : Matrix (Fin m) (Fin m) R) ⊗ₖ dagger σ B)

/-- Z-check of the lifted product: `[ Iₙ ⊗ B | B† ⊗ Iₘ ]`. -/
def Hz : Matrix (Fin n × Fin m) ((Fin n × Fin n) ⊕ (Fin m × Fin m)) R :=
  fromCols ((1 : Matrix (Fin n) (Fin n) R) ⊗ₖ B) (dagger σ B ⊗ₖ (1 : Matrix (Fin m) (Fin m) R))

/-- **The lifted-product CSS precondition.** `Hx · (Hz.map σ)ᵀ = 0` — the binary precondition after the
    antipode-introducing transpose, proven over any char-2 commutative ring with involution. -/
theorem lifted_css_precondition (hσ : Function.Involutive σ) :
    (Hx σ B) * ((Hz σ B).map σ)ᵀ = 0 := by
  have h2 : ∀ x : R, x + x = 0 := fun x => by
    have h20 : (2 : R) = 0 := by exact_mod_cast CharP.cast_eq_zero R 2
    rw [← two_mul, h20, zero_mul]
  -- σ-map commutes with the Kronecker product (entrywise, via the ring-hom multiplicativity of σ)
  have hmapk : ∀ {p q r s : ℕ} (A : Matrix (Fin p) (Fin q) R) (C : Matrix (Fin r) (Fin s) R),
      (A ⊗ₖ C).map σ = (A.map σ) ⊗ₖ (C.map σ) := by
    intro p q r s A C
    ext ⟨i1, i2⟩ ⟨j1, j2⟩
    simp [Matrix.kroneckerMap_apply, Matrix.map_apply, map_mul]
  have hone : ∀ {p : ℕ}, (1 : Matrix (Fin p) (Fin p) R).map σ = 1 :=
    fun {p} => Matrix.map_one σ (map_zero σ) (map_one σ)
  unfold Hx Hz dagger
  rw [Matrix.fromCols_map, hmapk, hmapk, hone, Matrix.transpose_fromCols,
      Matrix.fromCols_mul_fromRows]
  -- the two transposed Kronecker blocks, with σ-maps and σ∘σ = id collapsed
  simp only [← Matrix.kroneckerMap_transpose, Matrix.transpose_one, Matrix.transpose_map,
             Matrix.transpose_transpose, Matrix.map_map, Function.Involutive.comp_self hσ,
             Matrix.map_id]
  rw [← Matrix.mul_kronecker_mul, ← Matrix.mul_kronecker_mul]
  simp only [hone, Matrix.transpose_one, Matrix.mul_one, Matrix.one_mul]
  ext i j
  simp only [Matrix.add_apply, Matrix.zero_apply]
  exact h2 _

end Vela.TransferLiftedProduct
