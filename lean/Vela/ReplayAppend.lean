import Mathlib
import Vela.Log

/-!
# Vela Theorem 22: replay-compositional append

Replaying a concatenated event list equals replaying the prefix,
then continuing the replay from that intermediate state through
the suffix:

  replay r init (a ++ b) = replay r (replay r init a) b

This is a structural rewrite of `List.foldl_append` lifted onto the
substrate's `replay` definition.

Substrate role: pins the legitimacy of incremental replay. A hub
that has processed events `a` and now receives events `b` can
resume from its current state rather than replaying everything
from genesis — and the result is byte-identical. Underlies the
v0.105 replay-index maintenance optimization (T7) at the
type-level, and the v0.148 federation's incremental sync.
-/

namespace Vela.ReplayAppend

open Vela.Log

/-- Theorem 22: replay distributes over list append. -/
theorem theorem22_replay_append
    (r : Reducer) (init : AtlasState) (a b : List Event) :
    replay r init (a ++ b) = replay r (replay r init a) b := by
  unfold replay
  exact List.foldl_append

end Vela.ReplayAppend
