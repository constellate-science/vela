import Mathlib

/-!
# Cross-frontier transfer (Lean-proven): MDS / Reed–Solomon codes → threshold secret sharing

A new domain pair for the moat: **coding theory → cryptography**. Shamir's `(k, n)` threshold scheme is
Reed–Solomon evaluation: the dealer picks a polynomial `p` of degree `< k` with secret `p(0)`, and hands
share `i` the value `p(xᵢ)` at a distinct point. The load-bearing soundness fact — the reason `k` shares
*reconstruct* and the scheme is well-defined — is that a degree-`< k` polynomial is determined by its
values at any `k` distinct points. We prove exactly that, and the corollary that the recovered secret is
unique. (The complementary privacy bound — that `k−1` shares reveal nothing — is the information-theoretic
half, not formalized here.)
-/

namespace Vela.TransferMDSToSecretSharing

open Polynomial

variable {F : Type*} [Field F] [DecidableEq F]

/-- **Reconstruction soundness.** Two polynomials of degree `< k` that agree at `k` distinct points are
    equal — so any `k` shares determine a unique sharing polynomial (Reed–Solomon ⇒ Shamir). -/
theorem shares_determine_polynomial {k : ℕ} (p q : F[X])
    (hp : p.degree < (k : ℕ)) (hq : q.degree < (k : ℕ))
    (pts : Finset F) (hcard : k ≤ pts.card)
    (hagree : ∀ x ∈ pts, p.eval x = q.eval x) :
    p = q := by
  by_contra hne
  have hd : p - q ≠ 0 := sub_ne_zero.mpr hne
  have hdeg : (p - q).degree < (k : ℕ) := lt_of_le_of_lt (degree_sub_le p q) (max_lt hp hq)
  have hndeg : (p - q).natDegree < k := (natDegree_lt_iff_degree_lt hd).mpr hdeg
  have hsub : pts ⊆ (p - q).roots.toFinset := by
    intro x hx
    rw [Multiset.mem_toFinset, mem_roots hd]
    show (p - q).eval x = 0
    rw [eval_sub, hagree x hx, sub_self]
  have h1 : pts.card ≤ (p - q).roots.toFinset.card := Finset.card_le_card hsub
  have h2 : (p - q).roots.toFinset.card ≤ Multiset.card (p - q).roots := (p - q).roots.toFinset_card_le
  have h3 : Multiset.card (p - q).roots ≤ (p - q).natDegree := card_roots' (p - q)
  omega

/-- **Unique secret.** Under the same hypotheses, the recovered secret `p(0)` is unique. -/
theorem secret_recovered {k : ℕ} (p q : F[X])
    (hp : p.degree < (k : ℕ)) (hq : q.degree < (k : ℕ))
    (pts : Finset F) (hcard : k ≤ pts.card)
    (hagree : ∀ x ∈ pts, p.eval x = q.eval x) :
    p.eval 0 = q.eval 0 := by
  rw [shares_determine_polynomial p q hp hq pts hcard hagree]

end Vela.TransferMDSToSecretSharing
