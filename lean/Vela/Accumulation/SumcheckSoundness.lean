import Mathlib

/-!
# Sum-check round soundness: a cheating prover is caught (machine-checked)

`scripts/pck_spartan.py` runs the sum-check protocol and rejects a forged folded instance. This file
proves the soundness core that makes that rejection sound: **single-variable Schwartz-Zippel**.

In each sum-check round the honest prover would send a specific degree-`≤ d` univariate polynomial `p`;
a cheating prover sends some `g ≠ p` (forced to differ because the claimed sum is wrong). The verifier
picks a uniformly random challenge `r` and continues with the cheater only if `g(r) = p(r)`. Since
`g - p` is a nonzero polynomial of degree `≤ d`, it has at most `d` roots, so there are at most `d`
"fooling" challenges out of `|F|`. The cheat survives a round with probability `≤ d / |F|`, which over a
large field is negligible — and it must survive every round.

`sumcheck_round_sound` states exactly this: the set of fooling challenges has cardinality `≤ d`.

This is the field/polynomial fact that the substrate's Mathlib-free nucleus cannot express; it depends
on `Mathlib` (`Polynomial.card_roots'`, etc.), so it is part of the full bundle, not the
seconds-to-verify nucleus.
-/

namespace Vela.SumcheckSoundness

open Polynomial

/-- **Sum-check round soundness (single-variable Schwartz–Zippel).** Over a finite field `F`, if a
    cheating round polynomial `g` differs from the honest one `p` (both of degree `≤ d`), then the set
    of challenges `r` at which the verifier fails to notice (`g(r) = p(r)`) has cardinality at most `d`.
    Hence a cheat survives a round with probability `≤ d / |F|`. -/
theorem sumcheck_round_sound {F : Type*} [Field F] [Fintype F] [DecidableEq F] {d : ℕ}
    (g p : F[X]) (hg : g.natDegree ≤ d) (hp : p.natDegree ≤ d) (hne : g ≠ p) :
    (Finset.univ.filter (fun r : F => g.eval r = p.eval r)).card ≤ d := by
  have hsub : g - p ≠ 0 := sub_ne_zero.mpr hne
  -- the fooling challenges are exactly the roots of g - p
  have hset : (Finset.univ.filter (fun r : F => g.eval r = p.eval r)) = (g - p).roots.toFinset := by
    ext r
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Multiset.mem_toFinset,
               mem_roots, hsub, ne_eq, not_false_eq_true, true_and, IsRoot.def, eval_sub,
               sub_eq_zero]
  rw [hset]
  calc (g - p).roots.toFinset.card
      ≤ Multiset.card (g - p).roots := (g - p).roots.toFinset_card_le
    _ ≤ (g - p).natDegree := card_roots' _
    _ ≤ max g.natDegree p.natDegree := natDegree_sub_le g p
    _ ≤ d := max_le hg hp

/-- Corollary: at least `|F| - d` challenges expose the cheat — so over a large field a single round
    catches a dishonest prover except with probability `d / |F|`. -/
theorem sumcheck_round_catches {F : Type*} [Field F] [Fintype F] [DecidableEq F] {d : ℕ}
    (g p : F[X]) (hg : g.natDegree ≤ d) (hp : p.natDegree ≤ d) (hne : g ≠ p) :
    Fintype.card F - d ≤ (Finset.univ.filter (fun r : F => g.eval r ≠ p.eval r)).card := by
  have hfool := sumcheck_round_sound g p hg hp hne
  have hsplit : (Finset.univ.filter (fun r : F => g.eval r = p.eval r)).card
      + (Finset.univ.filter (fun r : F => ¬ g.eval r = p.eval r)).card = Fintype.card F := by
    rw [Finset.card_filter_add_card_filter_not, Finset.card_univ]
  simp only [ne_eq]
  omega

end Vela.SumcheckSoundness
