import Mathlib
import Vela.CanonicalEventId

/-!
# Vela Theorem 34: Evaluation × Descriptor × Diff Pack composition

T25 (`vtd_*` injectivity) anchors that a Tool Descriptor id uniquely
identifies its (name, version, provider, …) tuple. T27 (`ver_*`
injectivity) anchors that an Evaluation Record id uniquely identifies
its (target_kind, target_id, evaluation_kind, …) tuple. T28
(vtd_*×vsd_* composition) says: when a Diff Pack contains members
that reference a Tool Descriptor, the descriptor's identity is
preserved across `accept_pack`.

T34 closes the three-way composition: if an Evaluation Record `e`
targets a Tool Descriptor `d`, and a Diff Pack `p` on the same
frontier contains members that also reference `d`, then `d`'s
identity is preserved across the full chain (replay `e` then
accept `p`, or accept `p` then replay `e`). The descriptor cannot
be silently mutated by either path.

Substrate role: a reviewer evaluating a `vtd_*` via a `ver_*`,
then accepting a `vsd_*` whose members cite the same `vtd_*`,
sees a consistent descriptor identity through both operations.
Downstream consumers replaying the log can resolve `vtd_*`
references the same way regardless of event order.

Composition (rides):
- T25 (vtd_* injectivity): the descriptor id pins the tuple.
- T27 (ver_* injectivity): the evaluation id pins its preimage.
- T28 (Diff Pack × Tool Descriptor): accept_pack preserves
  descriptor storage.

The proof is two algebraic applications of the substrate
invariants: `record_eval` is descriptor-pure (does not touch
descriptor storage) and `accept_pack` is descriptor-pure (T28).
-/

namespace Vela.EvaluationDescriptorComposition

/-- Abstract substrate state: a nominal carrier kept inhabited (one constructor) so the `opaque`
reducer arms below are well-formed without adding any axiom. -/
inductive State : Type where
  | mk
deriving Inhabited

/-- A Tool Descriptor id. -/
abbrev DescriptorId := String

/-- A Diff Pack carrying member proposal ids. -/
structure Pack where
  pack_id : String
  members : List String
deriving DecidableEq, Repr

/-- An Evaluation Record carrying its target id (a vtd_*) and a
score. The substrate side stores it in `.vela/evaluations/` and
indexes it by `target_id`. -/
structure Evaluation where
  record_id : String
  target_id : DescriptorId
  score : String
deriving DecidableEq, Repr

/-- Does pack `p` reference descriptor `d`? Same opaque relation as
T28's `references_descriptor`. -/
opaque pack_references_descriptor : Pack → DescriptorId → Prop

/-- Reducer arm for accepting a Diff Pack. Mirror of T28. -/
opaque accept_pack : State → Pack → State

/-- Reducer arm for recording an Evaluation. The substrate side
writes the record to `.vela/evaluations/<ver_id>.json` and inserts
into the evaluation index; descriptor storage is untouched. -/
opaque record_evaluation : State → Evaluation → State

/-- Descriptor-id resolver. Same opaque relation as T28's
`descriptor_id_in_state`. -/
opaque descriptor_id_in_state : State → DescriptorId → Option DescriptorId

/-- Axiom (substrate invariant, rides T28): accept_pack preserves
descriptors. -/
axiom accept_pack_preserves_descriptors :
  ∀ (s : State) (p : Pack) (d : DescriptorId),
    descriptor_id_in_state s d = some d →
    descriptor_id_in_state (accept_pack s p) d = some d

/-- Axiom (substrate invariant, new): record_evaluation preserves
descriptors. The v0.200 evaluation-record reducer arm appends to
`.vela/evaluations/`; the descriptor-storage table is read-only
from the evaluation path. -/
axiom record_evaluation_preserves_descriptors :
  ∀ (s : State) (e : Evaluation) (d : DescriptorId),
    descriptor_id_in_state s d = some d →
    descriptor_id_in_state (record_evaluation s e) d = some d

/-- Theorem 34: composing record_evaluation then accept_pack
preserves descriptor identity, when both reference the same
descriptor. -/
theorem theorem34_eval_descriptor_composition_eval_first
    (s : State) (e : Evaluation) (p : Pack) (d : DescriptorId)
    (h_eval_targets : e.target_id = d)
    (h_pack_refs : pack_references_descriptor p d)
    (h_pre : descriptor_id_in_state s d = some d) :
    descriptor_id_in_state (accept_pack (record_evaluation s e) p) d
      = some d := by
  have h1 : descriptor_id_in_state (record_evaluation s e) d = some d :=
    record_evaluation_preserves_descriptors s e d h_pre
  exact accept_pack_preserves_descriptors (record_evaluation s e) p d h1

/-- Theorem 34 (symmetric): composing accept_pack then
record_evaluation also preserves descriptor identity. The two event
orderings produce equivalent descriptor-resolution behaviour;
substrate-side this is the formal anchor for "replay is
order-equivalent over these two arms." -/
theorem theorem34_eval_descriptor_composition_pack_first
    (s : State) (e : Evaluation) (p : Pack) (d : DescriptorId)
    (h_eval_targets : e.target_id = d)
    (h_pack_refs : pack_references_descriptor p d)
    (h_pre : descriptor_id_in_state s d = some d) :
    descriptor_id_in_state (record_evaluation (accept_pack s p) e) d
      = some d := by
  have h1 : descriptor_id_in_state (accept_pack s p) d = some d :=
    accept_pack_preserves_descriptors s p d h_pre
  exact record_evaluation_preserves_descriptors (accept_pack s p) e d h1

end Vela.EvaluationDescriptorComposition
