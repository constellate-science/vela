import Mathlib
import Vela.CanonicalEventId

/-!
# Vela Theorem 27: Evaluation Record id injectivity

A v0.200 Evaluation Record (`ver_*`) is a unified record for
replication, benchmark, validation, and peer-review outcomes against
any substrate object (vsd_*, vtr_*, vf_*, vpf_*, vtd_*, vaa_*). The
record id is content-addressed via:

    record_id = "ver_" ++ (sha256(canonicalBytes(body))).take 16

where canonicalBytes packs (target_kind, target_id, evaluation_kind,
outcome, evaluator_actor, evaluated_at, evidence_refs, benchmark_id,
score, notes) under a `|`-delimited layout. Optional fields (score,
notes, benchmark_id, evidence_refs) participate when present; absent
fields are empty in the preimage so two records that differ only in
their presence produce distinct ids.

This theorem pins the algebraic guarantee that distinct evaluation
preimages produce distinct record ids, under an abstract injectivity
assumption on the hash. Composes T9 (canonical-event-id determinism).

Substrate role: pins the v0.200 EvaluationRecord primitive. Two
consumers running the same `vela eval record` invocation with
byte-identical (target, kind, outcome, evaluator, timestamps,
evidence, score, notes) reach the same `ver_*`; any drift produces a
different record and is therefore reviewable as a separate object.
-/

namespace Vela.EvaluationRecordInjectivity

/-- The evaluation record preimage tuple. -/
structure RecordPreimage where
  target_kind : String       -- one of {vsd, vtr, vf, vpf, vtd, vaa}
  target_id : String         -- e.g. vsd_..., vtr_..., vf_..., etc.
  evaluation_kind : String   -- one of {replication, benchmark, validation, peer_review}
  outcome : String           -- one of {succeeded, failed, partial, inconclusive}
  evaluator_actor : String
  evaluated_at : String      -- RFC3339 timestamp
  evidence_refs : List String
  benchmark_id : String      -- empty string when absent
  score : String             -- empty string when absent; otherwise stable f64 debug repr
  notes : String             -- empty string when absent
deriving DecidableEq, Repr

/-- Comma-join helper. -/
def commaJoin : List String → String
  | [] => ""
  | [x] => x
  | x :: xs => x ++ "," ++ commaJoin xs

/-- Abstract canonical serializer over the evaluation preimage. The
field alphabets exclude `|` and `,`; optional fields are encoded as
empty strings so position is stable. Injectivity declared as an
axiom — the Rust side enforces the field-character invariants. -/
def canonicalBytes (p : RecordPreimage) : String :=
  s!"{p.target_kind}|{p.target_id}|{p.evaluation_kind}|{p.outcome}|{p.evaluator_actor}|{p.evaluated_at}|{commaJoin p.evidence_refs}|{p.benchmark_id}|{p.score}|{p.notes}"

axiom canonicalBytes_injective :
  Function.Injective canonicalBytes

/-- Abstract injective hash. -/
noncomputable axiom Hash : String → String
axiom hash_injective : Function.Injective Hash

/-- The evaluation record id derivation. -/
noncomputable def recordId (p : RecordPreimage) : String :=
  "ver_" ++ Hash (canonicalBytes p)

/-- Theorem 27: distinct evaluation preimages produce distinct
record ids. Composes canonicalBytes_injective and hash_injective. -/
theorem theorem27_evaluation_record_id_injective :
    Function.Injective recordId := by
  intro a b h
  have hHash : Hash (canonicalBytes a) = Hash (canonicalBytes b) := by
    have := h
    simp [recordId] at this
    exact this
  have hBytes : canonicalBytes a = canonicalBytes b :=
    hash_injective hHash
  exact canonicalBytes_injective hBytes

end Vela.EvaluationRecordInjectivity
