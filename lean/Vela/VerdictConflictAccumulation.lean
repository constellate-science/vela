import Mathlib
import Vela.CanonicalEventId

/-!
# Vela Theorem 32: Verdict Conflict accumulation under replay

The v0.218 `verdict_conflict.resolved` reducer arm appends a
VerdictConflict record to `Project.verdict_conflicts` whenever a
canonical event of that kind is replayed. The append is idempotent
on `conflict_id`. T32 pins the bounded-length accumulation algebra
that mirrors T29's for released Diff Packs.

Substrate role: a consumer walking the canonical event log alone
can answer "what reviewer-disagreement resolutions have been
recorded on this frontier?" without scanning sibling
`.vela/verdict_conflicts/` directories. The full audit trail
materializes from replay.

Composition: this theorem rides T22 (replay-compositional append)
and T31a (vdc_* injectivity — same id implies same body, so the
no-op-on-duplicate behaviour is well-defined). It does not
introduce new hash assumptions; the proof is structural.
-/

namespace Vela.VerdictConflictAccumulation

/-- A resolution record holds the conflict_id (the substrate-side
audit handle). Equality at the id level is what the no-op-on-
duplicate behaviour checks. -/
structure Record where
  conflict_id : String
deriving DecidableEq, Repr

/-- The reducer-arm operation: append a record if its conflict_id
is not already present in the array. -/
def applyResolve (recs : List Record) (rec : Record) : List Record :=
  if recs.any (fun r => r.conflict_id == rec.conflict_id) then recs
  else recs ++ [rec]

/-- Replay a list of resolve ops from an initial state. -/
def replay (init : List Record) : List Record → List Record
  | [] => init
  | op :: ops => replay (applyResolve init op) ops

/-- A resolve op preserves length exactly or extends by one. -/
theorem applyResolve_length (recs : List Record) (rec : Record) :
    (applyResolve recs rec).length = recs.length ∨
    (applyResolve recs rec).length = recs.length + 1 := by
  unfold applyResolve
  by_cases h : recs.any (fun r => r.conflict_id == rec.conflict_id)
  · simp [h]
  · simp [h]

/-- Theorem 32: replay of N resolve ops produces a list whose
length is bounded by N. The no-op-on-duplicate semantics mean
length ≤ N, with strict equality exactly when all conflict_ids
are distinct. -/
theorem theorem32_verdict_conflict_accumulation
    (ops : List Record) :
    (replay [] ops).length ≤ ops.length := by
  have h_step : ∀ (s : List Record) (o : Record),
      (applyResolve s o).length ≤ s.length + 1 := by
    intro s o
    rcases applyResolve_length s o with h | h
    · rw [h]; omega
    · rw [h]
  have h_replay_bound : ∀ (s : List Record) (xs : List Record),
      (replay s xs).length ≤ s.length + xs.length := by
    intro s xs
    induction xs generalizing s with
    | nil => simp [replay]
    | cons o xs ih =>
      simp [replay]
      have h1 := h_step s o
      have h2 := ih (applyResolve s o)
      omega
  have := h_replay_bound [] ops
  simp at this
  exact this

end Vela.VerdictConflictAccumulation
