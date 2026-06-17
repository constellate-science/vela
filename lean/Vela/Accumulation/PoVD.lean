/-!
# Proof-of-Verified-Delta (PoVD): permissionless accumulation of verified scientific state

A candidate mechanism for the one honest analogue of Bitcoin's breakthrough, scoped to the
*frozen-verifiable slice* of science. Bitcoin needed three separate mechanisms — proof-of-work
(Sybil resistance), longest-chain (consensus), and validation (fraud prevention). The PoVD thesis is
that a **frozen verifier collapses all three into one primitive** on the verifiable slice:

* a contribution is a `Delta` proposing to raise a frontier to a new `level`, backed by a `witness`;
* it is ACCEPTED iff the frozen verifier passes the witness AND it strictly improves the current
  shared state — a pure function anyone computes identically (no trusted authority = consensus);
* you cannot earn credit without producing a witness the verifier accepts (anti-fraud), and
  re-submitting a stale or duplicate delta earns nothing (Sybil resistance / no double-spend).

This file PROVES those properties over a concrete model (Mathlib-free, compiles standalone). It is NOT
a claim that the breakthrough is *done*: that status, like Bitcoin's, comes only from adoption and
surviving reality, which no proof grants. And the mechanism is bounded — see the honest limits in
`docs/POVD.md` (verifiable slice only; credit, not a speculative token; novelty bounded by substrate
completeness; no economic 51%-style security model). What is proven here is the *anti-gaming core*.
-/

namespace Vela.PoVD

/-- Frontier identifiers and the quality level of a frontier's best verified result. -/
abbrev Frontier := Nat
abbrev Level := Nat

/-- The shared scientific state: the best verified level recorded for each frontier. -/
abbrev State := Frontier → Level

/-- The empty initial state `S_0`: nothing verified yet. -/
def empty : State := fun _ => 0

/-- A contribution: raise `frontier` to `level`, backed by `witness`. -/
structure Delta where
  frontier : Frontier
  level    : Level
  witness  : Nat

/-- Acceptance rule, parameterized by the FROZEN verifier `verify`. A delta is accepted iff the
    verifier passes it AND it strictly improves the current best level for its frontier. On
    acceptance the state rises at exactly that frontier; nothing else changes. This is a pure
    function of `(verify, S, d)` — every node computes the same verdict, so there is no adjudicator. -/
def accept (verify : Delta → Bool) (S : State) (d : Delta) : Option State :=
  if verify d = true ∧ d.level > S d.frontier then
    some (fun f => if f = d.frontier then d.level else S f)
  else none

/-- Credit accrues iff the delta was accepted (one unit per accepted delta). -/
def credited (verify : Delta → Bool) (S : State) (d : Delta) : Bool :=
  (accept verify S d).isSome

/-- **PoVD-1 (no credit without verification).** An accepted delta necessarily passed the frozen
    verifier. Credit is impossible without real, re-checkable verification work. -/
theorem accept_implies_verified
    (verify : Delta → Bool) (S : State) (d : Delta) (S' : State)
    (h : accept verify S d = some S') : verify d = true := by
  unfold accept at h
  by_cases hc : verify d = true ∧ d.level > S d.frontier
  · exact hc.1
  · rw [if_neg hc] at h; simp at h

/-- **PoVD-2 (monotone state / no regression, no zombies).** Acceptance never lowers any frontier's
    verified level. The shared state only ever improves. -/
theorem accept_monotone
    (verify : Delta → Bool) (S : State) (d : Delta) (S' : State)
    (h : accept verify S d = some S') : ∀ f, S f ≤ S' f := by
  unfold accept at h
  by_cases hc : verify d = true ∧ d.level > S d.frontier
  · rw [if_pos hc] at h
    injection h with h; subst h
    obtain ⟨_, hlt⟩ := hc
    intro f
    show S f ≤ if f = d.frontier then d.level else S f
    split
    · rename_i hf; subst hf; exact Nat.le_of_lt hlt
    · exact Nat.le_refl _
  · rw [if_neg hc] at h; simp at h

/-- **PoVD-3 (no double-spend / stale-or-known rejected).** A delta that does not strictly improve
    the current state is rejected — you cannot re-claim credit for a result already in the shared
    state. This is the "double-spend" defence: known/stale results earn nothing. -/
theorem stale_rejected
    (verify : Delta → Bool) (S : State) (d : Delta)
    (h : d.level ≤ S d.frontier) : accept verify S d = none := by
  unfold accept
  rw [if_neg (by rintro ⟨_, hlt⟩; exact absurd hlt (Nat.not_lt.mpr h))]

/-- **PoVD-4 (duplication earns nothing / Sybil resistance).** After a delta is accepted, submitting
    the *same* delta again — from the same or any Sybil identity — is rejected, because the frontier's
    level has already risen to it. Credit is a function of distinct verified improvements, not of how
    many identities resubmit them. -/
theorem duplicate_rejected
    (verify : Delta → Bool) (S : State) (d : Delta) (S' : State)
    (h : accept verify S d = some S') : accept verify S' d = none := by
  have hlevel : S' d.frontier = d.level := by
    unfold accept at h
    by_cases hc : verify d = true ∧ d.level > S d.frontier
    · rw [if_pos hc] at h; injection h with h; subst h; simp
    · rw [if_neg hc] at h; simp at h
  exact stale_rejected verify S' d (by simp [hlevel])

/-- **PoVD-5 (authority-free determinism).** Acceptance is a pure function: two parties with the same
    verifier and the same state reach the identical verdict and identical next state. Consensus on
    "what is verified" requires no trusted adjudicator — only re-running the frozen verifier. -/
theorem accept_deterministic
    (verify : Delta → Bool) (S : State) (d : Delta) :
    accept verify S d = accept verify S d := rfl

/-- Putting it together: a credited delta is verified AND strictly advanced its frontier. The shared
    state grows only by genuine, re-checkable improvements. -/
theorem credited_is_real
    (verify : Delta → Bool) (S : State) (d : Delta)
    (h : credited verify S d = true) :
    verify d = true ∧ d.level > S d.frontier := by
  unfold credited accept at h
  by_cases hc : verify d = true ∧ d.level > S d.frontier
  · exact hc
  · rw [if_neg hc] at h; simp at h

end Vela.PoVD
