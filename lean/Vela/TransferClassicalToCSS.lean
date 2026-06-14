import Mathlib

/-!
# Cross-frontier transfer (Lean-proven): classical linear codes → CSS quantum code

The bridge that points the moat at the flagship (docs/PLAN_2026-06b.md). A CSS code is built from two
classical binary parity-check matrices `Hx`, `Hz` satisfying the orthogonality `Hx · Hzᵀ = 0` over `GF(2)`
(equivalently the dual-containment `C₂ ⊆ C₁`). The X-type stabilizers are the rows of `Hx`, the Z-type the
rows of `Hz`. This file proves the **load-bearing soundness fact**: that single classical condition makes
the entire quantum stabilizer set pairwise commute — i.e. a *valid* stabilizer code. This is exactly the
commutation check the frozen `scripts/verify_qec.py` re-runs, so a verified classical orthogonal pair maps
to a verified quantum `[[n, k]]` code. (The distance bound `d ≥ min(d(C₁), d(C₂^⊥))` is the OA/Hadamard-
style minimum-weight content, certified separately by `verify_qec` exactly or by witness.)
-/

namespace Vela.TransferClassicalToCSS

open Finset

variable {n : ℕ}

/-- A Pauli operator on `n` qubits in symplectic `GF(2)` form: an `X`-part and a `Z`-part. -/
structure Pauli (n : ℕ) where
  x : Fin n → ZMod 2
  z : Fin n → ZMod 2

/-- Symplectic inner product. Two Paulis commute iff it is `0`. -/
def symplectic (p q : Pauli n) : ZMod 2 := ∑ a, (p.x a * q.z a + p.z a * q.x a)

/-- X-type stabilizer from a row of `Hx` (zero Z-part). -/
def Xstab {rx : ℕ} (Hx : Fin rx → Fin n → ZMod 2) (i : Fin rx) : Pauli n :=
  ⟨Hx i, fun _ => 0⟩

/-- Z-type stabilizer from a row of `Hz` (zero X-part). -/
def Zstab {rz : ℕ} (Hz : Fin rz → Fin n → ZMod 2) (j : Fin rz) : Pauli n :=
  ⟨fun _ => 0, Hz j⟩

/-- The full CSS stabilizer family, indexed by `Fin rx ⊕ Fin rz`. -/
def stab {rx rz : ℕ} (Hx : Fin rx → Fin n → ZMod 2) (Hz : Fin rz → Fin n → ZMod 2) :
    (Fin rx ⊕ Fin rz) → Pauli n
  | Sum.inl i => Xstab Hx i
  | Sum.inr j => Zstab Hz j

/-- **Classical orthogonality ⇒ valid stabilizer code.** If `Hx · Hzᵀ = 0` over `GF(2)`, then every pair
    of CSS stabilizers commutes — the verifier-homomorphism from classical codes to a valid quantum code. -/
theorem css_commute {rx rz : ℕ}
    (Hx : Fin rx → Fin n → ZMod 2) (Hz : Fin rz → Fin n → ZMod 2)
    (hortho : ∀ i j, ∑ a, Hx i a * Hz j a = 0) :
    ∀ s t : Fin rx ⊕ Fin rz, symplectic (stab Hx Hz s) (stab Hx Hz t) = 0 := by
  intro s t
  cases s with
  | inl i =>
    cases t with
    | inl j => simp [stab, Xstab, symplectic]
    | inr j =>
      simp only [stab, Xstab, Zstab, symplectic, mul_zero, add_zero]
      exact hortho i j
  | inr i =>
    cases t with
    | inl j =>
      simp only [stab, Xstab, Zstab, symplectic, mul_zero, zero_add]
      rw [show (∑ a, Hz i a * Hx j a) = ∑ a, Hx j a * Hz i a from
        Finset.sum_congr rfl (fun a _ => mul_comm _ _)]
      exact hortho j i
    | inr j => simp [stab, Zstab, symplectic]

/-- Self-commutation is automatic in this representation (over `GF(2)`, `2 = 0`), recorded for clarity. -/
theorem symplectic_self (p : Pauli n) : symplectic p p = 0 := by
  unfold symplectic
  apply Finset.sum_eq_zero
  intro a _
  have h : p.x a * p.z a + p.z a * p.x a = 2 * (p.x a * p.z a) := by ring
  rw [h, show (2 : ZMod 2) = 0 by decide, zero_mul]

end Vela.TransferClassicalToCSS
