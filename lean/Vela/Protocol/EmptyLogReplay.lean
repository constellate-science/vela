import Mathlib
import Vela.Protocol.Log

/-!
# Vela Theorem 20: empty-log replay identity

Replaying the empty canonical event log produces the initial state.
This is the base case of replay convergence (Theorem 1): the reducer
sees no events, so `init` passes through unchanged.

Substrate role: pins the substrate's claim that a fresh frontier with
zero events replays deterministically to its initial state. Any
inductive replay argument starts here.
-/

namespace Vela.EmptyLogReplay

open Vela.Log

/-- The empty event log: no event ids, an arbitrary (unused) core map. -/
def emptyLog : EventLog :=
  { ids := ∅, coreOf := fun _ => { parents := [], payload := "", schema := "" } }

/-- Theorem 20: replay of the empty canonical log produces the initial
state. The reducer is never invoked because the canonical sequence is
empty. -/
theorem theorem20_empty_log_replay_identity
    (r : Reducer) (init : AtlasState) :
    replayCanonical r init emptyLog = init := by
  unfold replayCanonical canonicalSequence emptyLog replay
  simp

end Vela.EmptyLogReplay
