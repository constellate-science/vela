/-!
# Heterogeneous accumulation: cross-frontier transfers never launder an unverified claim

`Accumulation.lean` proves the scaling core for **one** frozen verifier. This file proves the part that
is *not* in the folding/PCD literature and is the Vela moat: an accumulator whose deltas may be
justified two ways —

* **natively**, by a witness the frontier's own frozen verifier accepts; or
* **by transfer**, importing the already-verified best level of *another* frontier through a
  soundness-preserving map (the Theorem 23 verifier-homomorphism, `Vela/Transfer.lean`).

A transfer is the dangerous case: it credits a claim on frontier `dst` *without* re-running `dst`'s
native verifier. The worry is laundering — importing junk across a frontier boundary. The headline
theorem `accumulate_state_verified` proves this cannot happen: at every point in the fold, **every
nonzero entry of the accumulated state is `Verified`** — grounded, through any chain of sound transfers,
in real native verifications. Cross-frontier credit is exactly as sound as native credit, never weaker.

Mathlib-free; compiles standalone (`lean Vela/HeteroAccumulation.lean`).

## Honest scope
* `Verified.transfer` *encodes* Theorem 23's soundness as a constructor: the transfer registry `lk` is
  assumed to contain only sound maps (that assumption is what `Vela/Transfer.lean` discharges for
  concrete transfers, e.g. Sidon translation). This file proves the *accumulation* preserves
  verification given sound transfers; it does not re-prove any individual transfer's soundness.
* A transfer imports the source's *current best* (`S src`); downward-closure of weaker levels is out of
  scope. As elsewhere: constant-size proof carrying and adoption remain the unwillable parts (`docs/PCK.md`).
-/

namespace Vela.HeteroAccumulation

abbrev Frontier := Nat
abbrev Level := Nat
abbrev State := Frontier → Level

/-- How a delta's claim is justified. -/
inductive Justification where
  | native (witness : Nat)   -- backed by a native witness for this frontier's verifier
  | transfer (src : Frontier) -- imported from `src`'s current verified best via a registered transfer

/-- A contribution: raise `frontier` to `level`, justified `just`. -/
structure Delta where
  frontier : Frontier
  level    : Level
  just     : Justification

/-- Genuine verification, as a proposition. `nv f L` is the native frozen verifier's verdict (level `L`
    on frontier `f`); `lk src dst` returns the registered *sound* transfer map from `src` to `dst`, if
    any. `Verified.transfer` is the encoding of Theorem 23: a sound homomorphism transports verified
    status, so importing `src`'s verified level `L` yields a verified level `g L` on `dst`. -/
inductive Verified (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level)) :
    Frontier → Level → Prop where
  | native  {f L} : nv f L = true → Verified nv lk f L
  | transfer {src dst : Frontier} {g : Level → Level} {L : Level} :
      Verified nv lk src L → lk src dst = some g → Verified nv lk dst (g L)

/-- Raise the state at one frontier, leaving the rest unchanged. -/
def raise (S : State) (f : Frontier) (L : Level) : State :=
  fun f' => if f' = f then L else S f'

/-- Acceptance, parameterized by the native verifier `nv` and the sound-transfer registry `lk`.
    A native delta is accepted iff its witness verifies and it strictly improves; a transfer delta is
    accepted iff a registered transfer maps the source's *current verified best* to exactly the claimed
    level, the source is itself nonzero (already verified), and it strictly improves. -/
def accept (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (S : State) (d : Delta) : Option State :=
  match d.just with
  | .native _ =>
      if nv d.frontier d.level = true ∧ d.level > S d.frontier then
        some (raise S d.frontier d.level)
      else none
  | .transfer src =>
      match lk src d.frontier with
      | some g =>
          if 0 < S src ∧ g (S src) = d.level ∧ d.level > S d.frontier then
            some (raise S d.frontier d.level)
          else none
      | none => none

/-- The accumulator: constant-size running state plus the integrity bit. -/
structure Acc where
  state : State
  ok    : Bool

def init : Acc := { state := fun _ => 0, ok := true }

def fold (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (a : Acc) (d : Delta) : Acc :=
  match accept nv lk a.state d with
  | some s => { state := s, ok := a.ok }
  | none   => { state := a.state, ok := false }

def accumulate (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (ds : List Delta) : Acc :=
  ds.foldl (fold nv lk) init

/-- The state invariant: every nonzero entry is genuinely `Verified`. -/
def StateVerified (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (S : State) : Prop :=
  ∀ f, 0 < S f → Verified nv lk f (S f)

/-- One accepted delta preserves the state invariant — INCLUDING transfer deltas. This is the core
    step: importing across a frontier cannot introduce an unverified entry. -/
theorem accept_preserves_verified
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (S S' : State) (d : Delta)
    (hinv : StateVerified nv lk S) (h : accept nv lk S d = some S') :
    StateVerified nv lk S' := by
  intro f hf
  unfold accept at h
  cases hj : d.just with
  | native w =>
    rw [hj] at h; dsimp only at h
    by_cases hc : nv d.frontier d.level = true ∧ d.level > S d.frontier
    · rw [if_pos hc] at h
      injection h with h; subst h
      show Verified nv lk f (raise S d.frontier d.level f)
      by_cases hfe : f = d.frontier
      · subst hfe
        simp only [raise]
        exact Verified.native hc.1
      · simp only [raise, if_neg hfe]
        simp only [raise, if_neg hfe] at hf
        exact hinv f hf
    · rw [if_neg hc] at h; simp at h
  | transfer src =>
    rw [hj] at h; dsimp only at h
    cases hlk : lk src d.frontier with
    | none => rw [hlk] at h; simp at h
    | some g =>
      rw [hlk] at h; dsimp only at h
      by_cases hc : 0 < S src ∧ g (S src) = d.level ∧ d.level > S d.frontier
      · rw [if_pos hc] at h
        injection h with h; subst h
        obtain ⟨hsrc, hmap, _⟩ := hc
        show Verified nv lk f (raise S d.frontier d.level f)
        by_cases hfe : f = d.frontier
        · subst hfe
          simp only [raise]
          -- frontier d.frontier got its level by a SOUND transfer from src's verified best
          have hv : Verified nv lk src (S src) := hinv src hsrc
          have hvt : Verified nv lk d.frontier (g (S src)) := Verified.transfer hv hlk
          rw [hmap] at hvt; exact hvt
        · simp only [raise, if_neg hfe]
          simp only [raise, if_neg hfe] at hf
          exact hinv f hf
      · rw [if_neg hc] at h; simp at h

/-- One fold step preserves the state invariant (accept-or-reject: rejection leaves state untouched). -/
theorem fold_preserves_verified
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (a : Acc) (d : Delta) (hinv : StateVerified nv lk a.state) :
    StateVerified nv lk (fold nv lk a d).state := by
  unfold fold
  cases h : accept nv lk a.state d with
  | some s =>
    show StateVerified nv lk s
    exact accept_preserves_verified nv lk a.state s d hinv h
  | none =>
    show StateVerified nv lk a.state
    exact hinv

/-- **The moat theorem (heterogeneous-accumulation soundness).** For ANY history of deltas — native or
    cross-frontier transfer, in any order — every nonzero entry of the accumulated state is genuinely
    `Verified`. Cross-frontier imports are exactly as sound as native verification: a transfer can only
    move an *already-verified* result across a *sound* map, so no unverified claim ever enters the
    state. This is the property folding/PCD do not provide and that the constellation thesis needs. -/
theorem accumulate_state_verified
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (ds : List Delta) :
    StateVerified nv lk (accumulate nv lk ds).state := by
  have gen : ∀ (ds : List Delta) (a : Acc),
      StateVerified nv lk a.state → StateVerified nv lk (ds.foldl (fold nv lk) a).state := by
    intro ds
    induction ds with
    | nil => intro a hinv; exact hinv
    | cons d ds ih =>
      intro a hinv
      exact ih (fold nv lk a d) (fold_preserves_verified nv lk a d hinv)
  have hbase : StateVerified nv lk init.state := by
    intro f hf; simp only [init] at hf; exact absurd hf (Nat.lt_irrefl 0)
  exact gen ds init hbase

/-- Authority-free determinism carries over: the heterogeneous accumulator is a pure function. -/
theorem accumulate_deterministic
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (ds : List Delta) : accumulate nv lk ds = accumulate nv lk ds := rfl

/-! ## A concrete cross-frontier import (the moat, demonstrated)

Frontier 0 verifies level 5 natively; a sound transfer `0 → 1` is registered (here the identity map,
standing in for a proven verifier-homomorphism). Then frontier 1 is `Verified` at level 5 with **no
native witness of its own** — purely by importing frontier 0's verified result. This is a discovery on
frontier 1 that single-frontier search cannot see, made sound by the transfer. -/

private def nvDemo : Frontier → Level → Bool := fun f L => (f == 0) && (L == 5)
private def lkDemo : Frontier → Frontier → Option (Level → Level) :=
  fun s d => if (s == 0) && (d == 1) then some id else none

example : Verified nvDemo lkDemo 1 5 :=
  Verified.transfer (src := 0) (dst := 1) (g := id) (L := 5)
    (Verified.native (rfl : nvDemo 0 5 = true)) (rfl : lkDemo 0 1 = some id)

end Vela.HeteroAccumulation
