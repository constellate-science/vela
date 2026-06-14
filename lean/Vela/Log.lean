import Mathlib

/-!
# Vela log theorems (Theorems 1 and 5)

This file formalizes two substrate guarantees of the Vela event log:

- Theorem 1: replay convergence for deterministic replay over the canonical
  event sequence determined by a finite event-id set and a core map.
- Theorem 5: structural hash-DAG log integrity under an abstract injective
  hash assumption.

The full cryptographic version of Theorem 5 depends on computational
assumptions about collision resistance and second-preimage resistance. Lean
does not prove those assumptions here. Instead, this file proves the structural
core: if event ids are produced by an injective abstract hash of canonical
event content, then changing canonical event content changes the event id; and
if descendant event content commits to parent ids, changing a parent-id list
changes the descendant's canonical content and therefore its id.

The canonical ordering model here is finite and deterministic. An event log is
represented by a finite set of event ids together with a core map. The canonical
event sequence is obtained by sorting event ids and reconstructing events from
the core map. If two hubs have the same finite id set and same core map, their
canonical sequences are equal and deterministic replay produces byte-identical
Atlas state.
-/

namespace Vela.Log

/-- Event identifiers are natural numbers here to give a built-in total order.
In the Rust substrate these are content hashes ordered lexicographically. -/
abbrev EventId := Nat

/-- Hashes are represented by event identifiers in this structural model. -/
abbrev Hash := EventId

structure EventCore where
  parents : List EventId
  payload : String
  schema  : String
deriving DecidableEq, Repr

structure Event where
  id   : EventId
  core : EventCore
deriving DecidableEq, Repr

def contentAddressed (H : EventCore → EventId) (e : Event) : Prop :=
  e.id = H e.core

structure AtlasState where
  bytes : String
deriving DecidableEq, Repr

abbrev Reducer := AtlasState → Event → AtlasState

def replay (r : Reducer) (init : AtlasState) (events : List Event) : AtlasState :=
  events.foldl r init

/-- A finite event log is a finite id set and a total core map. Only ids in
`ids` are replayed. -/
structure EventLog where
  ids    : Finset EventId
  coreOf : EventId → EventCore

/-- Reconstruct an event from a log and an id. -/
def eventOf (log : EventLog) (id : EventId) : Event :=
  { id := id, core := log.coreOf id }

/-- Canonical event sequence, obtained by sorting event ids by `≤`. -/
def canonicalSequence (log : EventLog) : List Event :=
  (log.ids.sort (· ≤ ·)).map (fun id => eventOf log id)

/-- Replay over the canonical sequence of a finite event log. -/
def replayCanonical (r : Reducer) (init : AtlasState) (log : EventLog) : AtlasState :=
  replay r init (canonicalSequence log)

/-- Causal down-closure for a finite event log. -/
def downClosed (log : EventLog) : Prop :=
  ∀ child : EventId, child ∈ log.ids →
    ∀ parent : EventId, parent ∈ (log.coreOf child).parents → parent ∈ log.ids

/-- A sufficient condition for sorted-by-id replay to be topological: all parent
ids are smaller than their child id. -/
def parentIdsStrictlySmaller (log : EventLog) : Prop :=
  ∀ child : EventId, child ∈ log.ids →
    ∀ parent : EventId, parent ∈ (log.coreOf child).parents → parent < child

/-- Valid finite causal log for this formalization. -/
def ValidCausalLog (log : EventLog) : Prop :=
  downClosed log ∧ parentIdsStrictlySmaller log

/-- Two logs have the same finite event content if they have the same ids and
same core map. -/
def SameFiniteLog (log₁ log₂ : EventLog) : Prop :=
  log₁.ids = log₂.ids ∧ log₁.coreOf = log₂.coreOf

-- Theorem 1a
/-- Same finite log gives the same canonical sequence. -/
theorem canonical_sequence_convergence
    (log₁ log₂ : EventLog)
    (h : SameFiniteLog log₁ log₂) :
    canonicalSequence log₁ = canonicalSequence log₂ := by
  rcases h with ⟨hids, hcore⟩
  simp [canonicalSequence, eventOf, hids, hcore]

-- Theorem 1b
/-- Replay convergence for the same finite log. -/
theorem replay_convergence_same_finite_log
    (r : Reducer) (init : AtlasState)
    (log₁ log₂ : EventLog)
    (h : SameFiniteLog log₁ log₂) :
    replayCanonical r init log₁ = replayCanonical r init log₂ := by
  unfold replayCanonical
  rw [canonical_sequence_convergence log₁ log₂ h]

-- Theorem 1c
/-- Replay convergence for valid causal logs with the same finite content.
Validity states the operational precondition for causal replay. -/
theorem replay_convergence_valid_causal_logs
    (r : Reducer) (init : AtlasState)
    (log₁ log₂ : EventLog)
    (_hvalid₁ : ValidCausalLog log₁)
    (_hvalid₂ : ValidCausalLog log₂)
    (h : SameFiniteLog log₁ log₂) :
    replayCanonical r init log₁ = replayCanonical r init log₂ := by
  exact replay_convergence_same_finite_log r init log₁ log₂ h

-- Theorem 5a
/-- Under an injective abstract hash, different canonical event cores cannot
have the same event id. -/
theorem changed_core_changes_id
    (H : EventCore → EventId)
    (hH : Function.Injective H)
    (core₁ core₂ : EventCore)
    (hcore : core₁ ≠ core₂) :
    H core₁ ≠ H core₂ := by
  intro hids
  exact hcore (hH hids)

-- Theorem 5b
/-- If two content-addressed events have the same id, then they have the same
canonical core. -/
theorem same_id_implies_same_core
    (H : EventCore → EventId)
    (hH : Function.Injective H)
    (e₁ e₂ : Event)
    (hca₁ : contentAddressed H e₁)
    (hca₂ : contentAddressed H e₂)
    (hid : e₁.id = e₂.id) :
    e₁.core = e₂.core := by
  apply hH
  calc
    H e₁.core = e₁.id := by exact Eq.symm hca₁
    _ = e₂.id := hid
    _ = H e₂.core := hca₂

/-- Parent commitment predicate. -/
def commitsToParent (parent : EventId) (core : EventCore) : Prop :=
  parent ∈ core.parents

-- Theorem 5c
/-- If canonical event content commits to parent ids, changing the parent-id
list changes the event core. -/
theorem changed_parent_list_changes_core
    (parents₁ parents₂ : List EventId)
    (payload schema : String)
    (hparents : parents₁ ≠ parents₂) :
    ({ parents := parents₁, payload := payload, schema := schema } : EventCore) ≠
    ({ parents := parents₂, payload := payload, schema := schema } : EventCore) := by
  intro hcore
  exact hparents (congrArg EventCore.parents hcore)

-- Theorem 5d
/-- Under injective content addressing, changing a committed parent-id list
changes the descendant event id. -/
theorem changed_parent_list_changes_descendant_id
    (H : EventCore → EventId)
    (hH : Function.Injective H)
    (parents₁ parents₂ : List EventId)
    (payload schema : String)
    (hparents : parents₁ ≠ parents₂) :
    H ({ parents := parents₁, payload := payload, schema := schema } : EventCore) ≠
    H ({ parents := parents₂, payload := payload, schema := schema } : EventCore) := by
  apply changed_core_changes_id H hH
  exact changed_parent_list_changes_core parents₁ parents₂ payload schema hparents

-- Theorem 5e
/-- If a content-addressed descendant keeps the same id after its parent list
changes, then the parent lists were not actually different. -/
theorem same_descendant_id_forces_same_parent_list
    (H : EventCore → EventId)
    (hH : Function.Injective H)
    (parents₁ parents₂ : List EventId)
    (payload schema : String)
    (hid :
      H ({ parents := parents₁, payload := payload, schema := schema } : EventCore) =
      H ({ parents := parents₂, payload := payload, schema := schema } : EventCore)) :
    parents₁ = parents₂ := by
  have hcore :
      ({ parents := parents₁, payload := payload, schema := schema } : EventCore) =
      ({ parents := parents₂, payload := payload, schema := schema } : EventCore) := by
    exact hH hid
  exact congrArg EventCore.parents hcore

end Vela.Log
