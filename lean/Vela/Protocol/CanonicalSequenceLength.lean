import Mathlib
import Vela.Protocol.Log

/-!
# Vela Theorem 21: canonical-sequence cardinality preservation

The canonical event sequence has the same length as the underlying
finite id set's cardinality. Pins the substrate's claim that every
event in the log is replayed exactly once — no duplicates, no drops.

Substrate role: defends against replay engines that accidentally
elide or duplicate events. Two consumers walking the same finite
id set produce canonical sequences of the same length.
-/

namespace Vela.CanonicalSequenceLength

open Vela.Log

/-- Theorem 21: the canonical event sequence length equals the
id-set's cardinality. -/
theorem theorem21_canonical_sequence_length
    (log : EventLog) :
    (canonicalSequence log).length = log.ids.card := by
  unfold canonicalSequence
  rw [List.length_map, Finset.length_sort]

end Vela.CanonicalSequenceLength
