import Mathlib

/-!
# Vela canonical event-id determinism (Theorem 9)

This file formalizes the substrate's canonical-event-id pipeline as
the composition of two layers:

1. A canonical-bytes serializer `canonicalBytes : EventCore → ByteString`
   that maps each event core to a unique byte sequence. The Rust
   substrate implements this via canonical JSON serialization with
   sorted keys, fixed numeric formatting, and an explicit field
   order; the property the substrate needs is that two cores produce
   the same bytes if and only if they are equal.

2. An abstract hash `H : ByteString → EventId` that compresses canonical
   bytes into a fixed-width id. Under cryptographic assumptions this is
   collision-resistant; the substrate guarantee proved here is one
   layer weaker: under an *abstract-injectivity* assumption on `H`, the
   composed pipeline `H ∘ canonicalBytes` is itself injective.

Theorem 9 is the substrate-honest claim that the full canonical-event-id
function is collision-free under the same abstract-hash assumption that
Theorem 5 already uses. Where Theorem 5 worked at the level of an
abstract `EventCore → EventId` map, Theorem 9 names the
`canonical_bytes` serialization layer explicitly so the substrate's
two-stage id pipeline (serialize → hash) is checked end-to-end.

## What is and is not formalized

This is a structural theorem. It does not prove cryptographic
collision resistance of the substrate's actual hash function (sha256);
that is an algorithmic property Lean does not address here. It does
prove that the substrate's design choice (serialize first, hash
second) does not introduce its own collisions, which is the load-
bearing question for the canonical-event-id pipeline.

`canonicalBytes` and `ByteString` are abstract: the Lean proof commits
only to their injectivity property, not to any particular byte
representation. The Rust substrate's
`canonical_bytes(event) := canonical_json_with_sorted_keys(event)` is
the concrete instance the structural theorem covers.
-/

namespace Vela.CanonicalEventId

variable {EventCore : Type*} {ByteString : Type*} {EventId : Type*}

/-- The canonical-bytes layer of the substrate's id pipeline. Maps
each event core to a unique byte sequence. -/
def CanonicalBytesInjective (canonicalBytes : EventCore → ByteString) : Prop :=
  Function.Injective canonicalBytes

/-- The composed canonical-event-id function: serialize, then hash. -/
def canonicalEventId
    (canonicalBytes : EventCore → ByteString)
    (H : ByteString → EventId) :
    EventCore → EventId :=
  H ∘ canonicalBytes

/-- **Theorem 9 (canonical event-id determinism).** If the canonical-
bytes serializer is injective on event cores and the abstract hash is
injective on byte sequences, then the composed canonical-event-id
function is injective on event cores. Equivalently: distinct event
cores produce distinct canonical event ids.

This pins the substrate's two-stage id pipeline (serialize → hash)
end-to-end. Theorem 5 already proved this for an abstract
`EventCore → EventId` map; Theorem 9 names the intermediate
`canonical_bytes` layer explicitly so a reader can see the
serialization step is doing real work, not just sitting between two
abstractions.
-/
theorem theorem9_canonical_event_id_injective
    (canonicalBytes : EventCore → ByteString)
    (hCanonicalBytes : Function.Injective canonicalBytes)
    (H : ByteString → EventId)
    (hH : Function.Injective H) :
    Function.Injective (canonicalEventId canonicalBytes H) := by
  unfold canonicalEventId
  exact hH.comp hCanonicalBytes

/-- A direct restatement in event-id terms: same canonical event id
implies same event core. The substrate uses this contrapositive
shape in the replay-index correctness argument (Theorem 7). -/
theorem theorem9_same_id_implies_same_core
    (canonicalBytes : EventCore → ByteString)
    (hCanonicalBytes : Function.Injective canonicalBytes)
    (H : ByteString → EventId)
    (hH : Function.Injective H)
    (a b : EventCore)
    (hEq : canonicalEventId canonicalBytes H a
         = canonicalEventId canonicalBytes H b) :
    a = b := by
  exact theorem9_canonical_event_id_injective canonicalBytes hCanonicalBytes H hH hEq

end Vela.CanonicalEventId
