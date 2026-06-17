import Mathlib

/-!
# Vela confidence-update bounds (Theorem 15)

This file formalizes the substrate's claim that a single
reviewer-policy confidence revision cannot move a finding's
confidence by more than the policy-declared per-event delta cap.
Pins the bounded-update guarantee that defends against
confidence drift under reviewer compromise.

## What is and is not formalized

This is a structural theorem under one abstract predicate plus
one bound.

We model the reviewer-policy revision as a function
`revise : ℝ → ℝ → ℝ` taking the current confidence `c` and a
proposed delta `δ` and producing the new confidence. The
substrate's policy says: the magnitude of the actual change is
bounded by `cap`, the per-event delta cap the reviewer policy
declares. Encoded as the hypothesis:

  `∀ c δ. |revise c δ - c| ≤ cap`

Under this, a single reviewer event cannot move confidence by
more than `cap`. The proof is one line via the hypothesis.

## Substrate role

The Rust substrate's `state::revise_confidence` enforces this
at the apply step: a `finding.confidence_revise` event whose
proposed delta magnitude exceeds the reviewer-policy cap is
either rejected or saturated at the cap. Theorem 15 names that
bound algebraically.

The substrate-honest consequence: an attacker who compromises
a single reviewer key can move a finding's confidence by at
most `cap` per event. Defending against confidence drift across
many events requires multi-reviewer attestation, which is a
separate threat surface.
-/

namespace Vela.ConfidenceUpdate

variable {S : Type*} {F : Type*}

/-- The reviewer-policy revision shape: input confidence c and
proposed delta δ, output new confidence. The substrate's
implementation lives at `state::revise_confidence`. -/
def Revise := ℝ → ℝ → ℝ

/-- The substrate's "single revision is bounded by the policy
cap" hypothesis. Concretely: the substrate's reviewer policy
declares a per-event cap and the apply step enforces it. -/
def BoundedBy (revise : Revise) (cap : ℝ) : Prop :=
  ∀ c δ, |revise c δ - c| ≤ cap

/-- **Theorem 15 (confidence-update bounds).** Under the
substrate's bounded-update policy, a single
`finding.confidence_revise` event cannot move a finding's
confidence by more than the declared cap.

The proof is one line via the bound hypothesis. -/
theorem theorem15_confidence_update_bounded
    (revise : Revise) (cap : ℝ)
    (hBounded : BoundedBy revise cap)
    (c δ : ℝ) :
    |revise c δ - c| ≤ cap := by
  exact hBounded c δ

/-- **Symmetry corollary.** The bound holds both ways: a
single revision cannot push confidence above `c + cap` or
below `c - cap`. -/
theorem theorem15_two_sided_bound
    (revise : Revise) (cap : ℝ)
    (hBounded : BoundedBy revise cap)
    (c δ : ℝ) :
    revise c δ ≤ c + cap ∧ c - cap ≤ revise c δ := by
  have h := hBounded c δ
  constructor
  · linarith [abs_le.mp h]
  · linarith [abs_le.mp h]

end Vela.ConfidenceUpdate
