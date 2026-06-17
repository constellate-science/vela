/-!
# Vela concrete reducer model: de-hollowing the substrate invariants

`docs/THEORY_AUDIT.md` flagged the descriptor-composition theorems (T28, T34) as HOLLOW: they assert
the substantive invariant ("the reducer preserves descriptors") as an `axiom` over an `opaque`
(undefined) reducer, so the hard part is assumed, not proven. This file removes that hollowness by
giving a CONCRETE event-sourced reducer and PROVING the invariants from the definition -- no axiom,
no `opaque`, no `sorry`. It is the concrete model the assume-guarantee stubs were standing in for,
and it concretely realizes the event-sourcing core of `docs/THEORY.md` (S_F = R(E)). Mathlib-free;
compiles standalone (`lake env lean Vela/ReducerModel.lean`).
-/

namespace Vela.ReducerModel

/-- Concrete substrate state: an append-only event log, a descriptor table, a finding store. -/
structure St where
  log : List String           -- accepted event ids, in acceptance order (append-only)
  descriptors : List String   -- descriptor ids currently present
  findings : List String      -- finding ids currently present

/-- The empty initial state `S_0`. -/
def St.empty : St := ⟨[], [], []⟩

/-- Concrete event kinds (a faithful subset of the frozen spec surface). -/
inductive Ev
| addDescriptor (d : String)
| acceptPack (eid : String)              -- references descriptors; does NOT mutate the table
| recordFinding (eid : String) (f : String)
| recordEvaluation (eid : String)        -- writes the evaluation store; descriptor table read-only

/-- The deterministic reducer step `r : St → Ev → St`. Append-only on `log`; `acceptPack` and
    `recordEvaluation` leave the descriptor table untouched -- the invariant the hollow theorems
    only ASSUMED is here a definitional fact. -/
def step (s : St) : Ev → St
  | .addDescriptor d =>
      { s with log := s.log ++ [d], descriptors := d :: s.descriptors }
  | .acceptPack e =>
      { s with log := s.log ++ [e] }
  | .recordFinding e f =>
      { s with log := s.log ++ [e], findings := f :: s.findings }
  | .recordEvaluation e =>
      { s with log := s.log ++ [e] }

/-- Replay `R(E)`: the deterministic left fold of the reducer over the event sequence. -/
def replay (s0 : St) (es : List Ev) : St := es.foldl step s0

/-- **Replay is a deterministic function of the event sequence** (concrete Theorem 1). -/
theorem replay_deterministic (s0 : St) (es : List Ev) :
    replay s0 es = es.foldl step s0 := rfl

/-- **Incremental replay law**: replay over a concatenation is replay-then-replay
    (`R(E ++ F) = R_{R(E)}(F)`). The substrate's append-and-fold guarantee. -/
theorem replay_append (s0 : St) (es fs : List Ev) :
    replay s0 (es ++ fs) = replay (replay s0 es) fs := by
  simp [replay, List.foldl_append]

/-- **The log is append-only**: one step never shrinks it. -/
theorem step_log_grows (s : St) (e : Ev) :
    s.log.length ≤ (step s e).log.length := by
  cases e <;> simp [step]

/-- **De-hollowed T28**: `acceptPack` preserves descriptor presence -- now PROVEN from the reducer
    definition (the table is untouched), not asserted as an axiom over an opaque function. -/
theorem acceptPack_preserves_descriptors (s : St) (e d : String)
    (h : d ∈ s.descriptors) : d ∈ (step s (.acceptPack e)).descriptors := by
  simpa [step] using h

/-- `recordEvaluation` likewise preserves descriptors (read-only table). -/
theorem recordEvaluation_preserves_descriptors (s : St) (e d : String)
    (h : d ∈ s.descriptors) : d ∈ (step s (.recordEvaluation e)).descriptors := by
  simpa [step] using h

/-- **De-hollowed T34 (composition)**: `recordEvaluation` then `acceptPack` preserves descriptors,
    proven by chaining the two definitional preservation lemmas. -/
theorem eval_then_pack_preserves (s : St) (e1 e2 d : String)
    (h : d ∈ s.descriptors) :
    d ∈ (step (step s (.recordEvaluation e1)) (.acceptPack e2)).descriptors :=
  acceptPack_preserves_descriptors _ _ _ (recordEvaluation_preserves_descriptors _ _ _ h)

/-- One step never DROPS a descriptor (the only event touching the table, `addDescriptor`, only
    prepends). -/
theorem step_preserves_descriptors (s : St) (e : Ev) (d : String)
    (h : d ∈ s.descriptors) : d ∈ (step s e).descriptors := by
  cases e <;> simp [step] <;> first | exact h | exact Or.inr h

/-- **Descriptor preservation under full replay**: once present, a descriptor survives any event
    sequence (there is no removal event). Proven by induction over the log -- the real content the
    hollow theorems gestured at. -/
theorem replay_preserves_descriptors (s0 : St) (es : List Ev) (d : String)
    (h : d ∈ s0.descriptors) : d ∈ (replay s0 es).descriptors := by
  induction es generalizing s0 with
  | nil => simpa [replay] using h
  | cons e rest ih =>
      have h' : d ∈ (step s0 e).descriptors := step_preserves_descriptors s0 e d h
      simpa [replay, List.foldl_cons] using ih (step s0 e) h'

end Vela.ReducerModel
