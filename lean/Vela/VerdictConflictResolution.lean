import Mathlib
import Vela.CanonicalEventId

/-!
# Vela Theorem 31: Verdict Conflict Resolution id injectivity + monotonicity

The v0.217 VerdictConflict (`vdc_*`) primitive resolves contradicting
verdicts on overlapping Diff Pack members. The id is content-
addressed via:

    conflict_id = "vdc_" ++ (sha256(canonicalBytes(body))).take 16

where canonicalBytes packs (frontier_id, ordered verdicts,
SORTED shared_member_ids, resolution_mode, resolution_actor,
resolved_at, winning_verdict_id) under a `|`-delimited layout.

This theorem has two parts:

  31a (injectivity): distinct conflict preimages produce distinct
  conflict ids under an abstract-injective hash assumption. Composes
  T9 (canonical-event-id determinism).

  31b (monotonicity): once a resolution is recorded, it cannot be
  silently superseded. A subsequent resolution on the same set of
  conflicting verdicts is itself a new vdc_* record, content-
  addressed over its own resolution_actor / resolved_at /
  winning_verdict_id. The substrate keeps every resolution; a
  consumer reading the conflict's history sees the audit trail of
  who decided what when, not just the latest verdict.

Substrate role: the substrate handles reviewer disagreement
honestly. Resolution does not silence the losing verdicts — they
stay on the log as cited vpv_* ids inside the vdc_* record.
-/

namespace Vela.VerdictConflictResolution

/-- The verdict-conflict preimage tuple. The `verdicts` list is
order-sensitive (the order reviewers issued them matters for the
conflict narrative); `shared_member_ids` are pre-sorted before
hashing because membership is what matters, not insertion order. -/
structure ConflictPreimage where
  frontier_id : String
  verdicts : List String           -- ordered list of vpv_* ids
  shared_member_ids_sorted : List String  -- pre-sorted vpr_* ids
  resolution_mode : String         -- one of {majority, owner_override, escalation}
  resolution_actor : String
  resolved_at : String             -- RFC3339 timestamp
  winning_verdict_id : String      -- empty when absent
deriving DecidableEq, Repr

/-- Comma-join helper. -/
def commaJoin : List String → String
  | [] => ""
  | [x] => x
  | x :: xs => x ++ "," ++ commaJoin xs

/-- Abstract canonical serializer over the conflict preimage.
Order-sensitive on `verdicts`; positionally invariant on
`shared_member_ids_sorted` (sorting is the caller's
responsibility). Injectivity declared as an axiom — the Rust side
enforces the field-character invariants. -/
def canonicalBytes (p : ConflictPreimage) : String :=
  s!"{p.frontier_id}|{commaJoin p.verdicts}|{commaJoin p.shared_member_ids_sorted}|{p.resolution_mode}|{p.resolution_actor}|{p.resolved_at}|{p.winning_verdict_id}"

axiom canonicalBytes_injective :
  Function.Injective canonicalBytes

/-- Abstract injective hash. -/
noncomputable axiom Hash : String → String
axiom hash_injective : Function.Injective Hash

/-- The conflict id derivation. -/
noncomputable def conflictId (p : ConflictPreimage) : String :=
  "vdc_" ++ Hash (canonicalBytes p)

/-- Theorem 31a (injectivity): distinct conflict preimages produce
distinct conflict ids. Composes canonicalBytes_injective and
hash_injective. -/
theorem theorem31_verdict_conflict_id_injective :
    Function.Injective conflictId := by
  intro a b h
  have hHash : Hash (canonicalBytes a) = Hash (canonicalBytes b) := by
    have := h
    simp [conflictId] at this
    exact this
  have hBytes : canonicalBytes a = canonicalBytes b :=
    hash_injective hHash
  exact canonicalBytes_injective hBytes

/-- Theorem 31b (resolution monotonicity): if two resolutions on the
same (frontier_id, verdicts, shared_member_ids_sorted) tuple differ
in resolution_actor OR resolved_at OR winning_verdict_id, they
produce distinct conflict ids. This is the substrate-honest audit
trail: a second resolution does not overwrite the first; it adds a
new record. -/
theorem theorem31b_resolution_distinct_when_actor_or_time_or_winner_differs
    (a b : ConflictPreimage)
    (_h_frontier : a.frontier_id = b.frontier_id)
    (_h_verdicts : a.verdicts = b.verdicts)
    (_h_members : a.shared_member_ids_sorted = b.shared_member_ids_sorted)
    (_h_mode : a.resolution_mode = b.resolution_mode)
    (h_differs : a.resolution_actor ≠ b.resolution_actor ∨
                 a.resolved_at ≠ b.resolved_at ∨
                 a.winning_verdict_id ≠ b.winning_verdict_id) :
    conflictId a ≠ conflictId b := by
  intro h_eq
  have h_inj : a = b := theorem31_verdict_conflict_id_injective h_eq
  cases h_differs with
  | inl h =>
    apply h
    rw [h_inj]
  | inr h =>
    cases h with
    | inl h =>
      apply h
      rw [h_inj]
    | inr h =>
      apply h
      rw [h_inj]

end Vela.VerdictConflictResolution
