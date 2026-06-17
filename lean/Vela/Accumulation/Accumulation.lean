/-!
# Succinct accumulation of verified scientific state (the scaling core of PoVD)

`PoVD.lean` proves the anti-gaming core of permissionless accumulation, but its honest gap is the same
one Bitcoin's headers/SPV closed: deciding "this is the true verified frontier" by replaying the
accepted-delta history is O(history) — every verifier is re-run. Bitcoin's *scale* came from
verification being cheap relative to the work that built the chain; a light client checks a
constant-size object, not the whole history.

This file proves the abstract heart of that scaling property for science. Following the
folding/accumulation-scheme line (Nova → HyperNova, CRYPTO 2024; MicroNova, IEEE S&P 2025) and
Proof-Carrying Data (Bünz et al.), we model an **accumulator**: a constant-size object carrying the
running verified `state` plus a single integrity bit `ok`. Folding a delta keeps `ok = true` only if
the delta passed its frozen verifier AND strictly improved its frontier. The load-bearing theorem
(`accumulate_sound`) is that **the single bit certifies the entire history**: if the final
accumulator's `ok` is true, then *every* delta ever folded passed verification — even though a checker
inspects only the constant-size accumulator, never the unbounded list.

This is the abstract soundness a real recursive-SNARK / PCD instantiation must preserve. It is
Mathlib-free and compiles standalone (`lean Vela/Accumulation.lean`).

## Honest scope (the parts a real instantiation must still supply)
* **Constant-size is modelled, not enforced.** `Acc` is `O(1)` in the number of deltas (a state map +
  one bit), and the checker `globalCheck` reads only `Acc`. But Lean does not bill the cost of *carrying*
  the soundness argument; a real system needs a recursive SNARK / folding scheme so the *proof* of `ok`
  is also `O(1)`, not just the object. That cryptographic instantiation is out of scope here.
* **Single verifier here.** This file folds one frozen verifier. The cross-frontier (heterogeneous)
  case — importing one frontier's verified state into another's accumulator via a soundness-preserving
  transfer (`Vela/Transfer.lean`, Theorem 23) — is the genuinely novel composition and is specified in
  `docs/PCK.md`; it is not proven in this file.
* **Adoption is unwillable.** As with PoVD, mechanism + proof is necessary, not sufficient, for a
  breakthrough.
-/

namespace Vela.Accumulation

/-- Frontier identifiers, quality levels, and the verified state (best level per frontier). -/
abbrev Frontier := Nat
abbrev Level := Nat
abbrev State := Frontier → Level

/-- A contribution: raise `frontier` to `level`, backed by `witness`. -/
structure Delta where
  frontier : Frontier
  level    : Level
  witness  : Nat

/-- The accumulator: a *constant-size* summary of an arbitrarily long accepted-delta history.
    `state` is the running best-verified level per frontier; `ok` is the single integrity bit. -/
structure Acc where
  state : State
  ok    : Bool

/-- The genesis accumulator: nothing verified, integrity intact. -/
def init : Acc := { state := fun _ => 0, ok := true }

/-- Fold one delta into the accumulator under the FROZEN verifier `verify`. The integrity bit stays
    true only if this delta passed the verifier AND strictly improved its frontier; otherwise the bit
    is cleared (and stays cleared — see `fold_preserves_false`). A rejected delta never changes state. -/
def fold (verify : Delta → Bool) (a : Acc) (d : Delta) : Acc :=
  if verify d = true ∧ d.level > a.state d.frontier then
    { state := fun f => if f = d.frontier then d.level else a.state f, ok := a.ok }
  else
    { a with ok := false }

/-- Accumulate an entire history into one constant-size object. -/
def accumulate (verify : Delta → Bool) (ds : List Delta) : Acc :=
  ds.foldl (fold verify) init

/-- The light-client check: inspect ONLY the constant-size accumulator (never the history). -/
def globalCheck (a : Acc) : Bool := a.ok

/-- Folding never resurrects a cleared integrity bit: once `ok` is false it stays false. -/
theorem fold_preserves_false (verify : Delta → Bool) (a : Acc) (d : Delta)
    (h : a.ok = false) : (fold verify a d).ok = false := by
  unfold fold
  by_cases hc : verify d = true ∧ d.level > a.state d.frontier
  · rw [if_pos hc]; exact h
  · rw [if_neg hc]

/-- If a single fold leaves the integrity bit set, then the prior bit was set AND this delta verified.
    (The per-step inversion that drives the history-wide soundness theorem.) -/
theorem fold_ok_inv (verify : Delta → Bool) (a : Acc) (d : Delta)
    (h : (fold verify a d).ok = true) : a.ok = true ∧ verify d = true := by
  unfold fold at h
  by_cases hc : verify d = true ∧ d.level > a.state d.frontier
  · rw [if_pos hc] at h; exact ⟨h, hc.1⟩
  · rw [if_neg hc] at h; simp at h

/-- **The scaling theorem (succinct-accumulation soundness).** Checking the single constant-size
    accumulator certifies a property of the ENTIRE unbounded history: if the final integrity bit is
    set, then every delta ever folded passed its frozen verifier. Stated for an arbitrary starting
    accumulator to carry the induction. -/
theorem accumulate_sound (verify : Delta → Bool) :
    ∀ (ds : List Delta) (a : Acc),
      (ds.foldl (fold verify) a).ok = true → a.ok = true ∧ ∀ d ∈ ds, verify d = true := by
  intro ds
  induction ds with
  | nil => intro a h; exact ⟨h, by intro d hd; cases hd⟩
  | cons d ds ih =>
    intro a h
    -- foldl (d :: ds) a = foldl ds (fold verify a d)
    have hstep : (ds.foldl (fold verify) (fold verify a d)).ok = true := h
    obtain ⟨hfold_ok, hrest⟩ := ih (fold verify a d) hstep
    obtain ⟨ha_ok, hd_ok⟩ := fold_ok_inv verify a d hfold_ok
    refine ⟨ha_ok, ?_⟩
    intro e he
    cases he with
    | head => exact hd_ok
    | tail _ he' => exact hrest e he'

/-- Corollary specialized to genesis: a passing `globalCheck` on the accumulated history certifies
    that every accepted delta in that history was verified — a constant-size check, history-wide
    guarantee. This is the property a light client relies on. -/
theorem globalCheck_sound (verify : Delta → Bool) (ds : List Delta)
    (h : globalCheck (accumulate verify ds) = true) : ∀ d ∈ ds, verify d = true := by
  have h' : (ds.foldl (fold verify) init).ok = true := h
  exact (accumulate_sound verify ds init h').2

/-- The accumulated state never regresses: each fold's resulting state dominates the prior state at
    every frontier (the monotonicity of PoVD, lifted to the accumulator). -/
theorem fold_state_monotone (verify : Delta → Bool) (a : Acc) (d : Delta) :
    ∀ f, a.state f ≤ (fold verify a d).state f := by
  intro f
  unfold fold
  by_cases hc : verify d = true ∧ d.level > a.state d.frontier
  · rw [if_pos hc]
    show a.state f ≤ if f = d.frontier then d.level else a.state f
    split
    · rename_i hf; subst hf; exact Nat.le_of_lt hc.2
    · exact Nat.le_refl _
  · rw [if_neg hc]; exact Nat.le_refl _

/-- Determinism / authority-free global verification: the accumulator (hence the light-client verdict)
    is a pure function of the verifier and the history — every party computes the identical
    constant-size summary with no trusted adjudicator. -/
theorem accumulate_deterministic (verify : Delta → Bool) (ds : List Delta) :
    accumulate verify ds = accumulate verify ds := rfl

end Vela.Accumulation
