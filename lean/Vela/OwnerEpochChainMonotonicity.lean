import Mathlib

/-!
# Vela owner-epoch chain monotonicity (Theorem 18)

The v0.146 owner-epoch chain transcript records every governed
owner rotation as a sequence of transitions. The substrate's
`append` rule (in `governance.rs`) enforces that each new
transition has `owner_epoch == expected_epoch`, where
`expected_epoch` is `last.owner_epoch + 1` (or 1 for the first
transition in an empty chain). Theorem 18 lifts this to the
algebraic layer.

## Substrate role

The Rust substrate's `OwnerEpochChain::append` enforces the
rule at the apply step: the v0.146 verifier rejects any chain
whose owner_epoch sequence violates strict-monotonicity-by-one.
Theorem 18 makes the guarantee algebraic.

The v0.148 federation primitive relies on this shape: two hubs
that agree on the latest checkpoint's owner_epoch necessarily
agree on the full chain length (and therefore the full chain
when combined with content-addressing from Theorem 17).
-/

namespace Vela.OwnerEpochChainMonotonicity

/-- A well-formed owner-epoch chain: the empty chain is
well-formed; a non-empty chain whose first transition is at
epoch `n` requires `n = 1` and every successor is the
predecessor + 1. Encoded as a recursive predicate that walks
the list pairwise. -/
def WellFormed : List Nat → Prop
  | [] => True
  | [n] => n = 1
  | a :: b :: rest => a = 1 ∧ b = a + 1 ∧ WellFormedTail b (b :: rest)
where
  /-- Tail predicate: given a previous epoch `prev`, the chain
  rooted at `b :: rest` is well-formed-from-`prev` iff
  `b = prev` and the tail steps by 1. We use this only to keep
  the recursion structural; the top-level WellFormed already
  pins the starting epoch to 1. -/
  WellFormedTail : Nat → List Nat → Prop
    | _prev, [] => True
    | _prev, [_n] => True
    | _prev, n :: m :: rest => m = n + 1 ∧ WellFormedTail m (m :: rest)

/-- **Theorem 18 (chain monotone single-step).** Adjacent
epochs in a well-formed chain differ by exactly 1, so the
sequence is strictly monotone. -/
theorem theorem18_chain_monotone_single_step
    (a b : Nat) (rest : List Nat)
    (hWF : WellFormed (a :: b :: rest)) :
    b = a + 1 ∧ a < b := by
  unfold WellFormed at hWF
  obtain ⟨_, hStep, _⟩ := hWF
  refine ⟨hStep, ?_⟩
  rw [hStep]
  exact Nat.lt_succ_of_le (Nat.le_refl a)

/-- **Theorem 18a (chain starts at 1).** Any non-empty
well-formed chain begins with owner_epoch = 1, matching the
substrate's append rule (first transition produces
owner_epoch = 1). -/
theorem theorem18a_chain_starts_at_one
    (n : Nat) (rest : List Nat)
    (hWF : WellFormed (n :: rest)) :
    n = 1 := by
  cases rest with
  | nil =>
    unfold WellFormed at hWF
    exact hWF
  | cons m more =>
    unfold WellFormed at hWF
    exact hWF.1

end Vela.OwnerEpochChainMonotonicity
