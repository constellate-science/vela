import Mathlib

/-!
# Cross-domain transfer: combinatorial packing → group-testing pooling design (math → diagnostics)

A genuine bridge from pure combinatorics into biology/medicine. A non-adaptive **group-testing** scheme
pools items into tests; a binary pooling matrix is **d-disjunct** when no item's column is contained in
the union of any `d` others — which is exactly the condition that lets `d` defectives be identified from
the pooled results (used in pooled diagnostics, library screening, COVID pool testing).

The classical superimposed-code fact, here machine-checked: if every item's column is a set of `w` tests
(constant weight `w`) and any two columns share at most `λ` tests (pairwise intersection `≤ λ`), then the
matrix is **d-disjunct for every `d` with `d·λ < w`**. Constant-weight codes / packings (which Vela
already produces — Steiner incidence vectors, OA one-hot, our CWC constructions) therefore *transfer*
into verified pooling designs. The same verifier-homomorphism discipline, crossing from math into a
diagnostic application.

`Vela.GroupTesting.packing_is_disjunct` is the theorem; the operational instance (a Steiner/CWC
construction → a frozen-verified disjunct matrix) is `scripts/verify_grouptesting.py`.
-/

namespace Vela.GroupTesting

open Finset

/-- **Packing → d-disjunct.** If each column `S i` has `w` tests, any two columns share `≤ λ` tests, and
    `d·λ < w`, then no column is contained in the union of any `d` other columns — i.e. the pooling
    matrix is `d`-disjunct, the condition for identifying `d` defectives by non-adaptive group testing. -/
theorem packing_is_disjunct {ι T : Type*} [DecidableEq ι] [DecidableEq T]
    (S : ι → Finset T) (w lam d : ℕ)
    (hw : ∀ i, (S i).card = w)
    (hint : ∀ i j, i ≠ j → (S i ∩ S j).card ≤ lam)
    (hd : d * lam < w)
    (i : ι) (D : Finset ι) (hiD : i ∉ D) (hDcard : D.card = d) :
    ¬ S i ⊆ D.biUnion S := by
  intro hsub
  -- S i ⊆ ⋃_{j∈D} S j, so S i = S i ∩ ⋃ = ⋃_{j∈D} (S i ∩ S j); bound its card by d·λ < w = |S i|.
  have hcover : S i = D.biUnion (fun j => S i ∩ S j) := by
    apply Finset.ext; intro x
    simp only [Finset.mem_biUnion, Finset.mem_inter]
    constructor
    · intro hx
      obtain ⟨j, hj, hxj⟩ := Finset.mem_biUnion.mp (hsub hx)
      exact ⟨j, hj, hx, hxj⟩
    · rintro ⟨j, _, hx, _⟩; exact hx
  have hcard : (S i).card ≤ ∑ j ∈ D, (S i ∩ S j).card := by
    calc (S i).card = (D.biUnion (fun j => S i ∩ S j)).card := by rw [← hcover]
      _ ≤ ∑ j ∈ D, (S i ∩ S j).card := Finset.card_biUnion_le
  have hsum : ∑ j ∈ D, (S i ∩ S j).card ≤ ∑ _j ∈ D, lam := by
    apply Finset.sum_le_sum
    intro j hj
    exact hint i j (fun e => hiD (e ▸ hj))
  have hconst : ∑ _j ∈ D, lam = d * lam := by
    rw [Finset.sum_const, hDcard, smul_eq_mul]
  rw [hw i] at hcard
  -- w ≤ Σ(S i ∩ S j).card ≤ Σ λ = d·λ < w, contradiction
  linarith [hcard, hsum, hconst, hd]

end Vela.GroupTesting
