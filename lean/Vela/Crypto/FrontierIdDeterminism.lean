import Mathlib

/-!
# Vela frontier-id determinism (Theorem 13)

This file formalizes the substrate's claim that two frontiers with
byte-identical canonical event-log inputs produce byte-identical
`vfr_*` ids. Composes the canonical-bytes layer of Theorem 9 with
the abstract injective hash of Theorem 5 — but one layer up: at the
*event-log* level rather than the per-event level.

Theorem 9 (`Vela.CanonicalEventId`) proved per-event id determinism:
distinct event cores produce distinct event ids under
`H ∘ canonicalBytes`. Theorem 13 closes the analogous statement for
frontier ids: distinct canonical event-log bytes produce distinct
`vfr_*` ids under `H ∘ canonicalEventLog`. The substrate's
content-addressing record now has injectivity proven end-to-end at
both layers: event-id and frontier-id.

## What is and is not formalized

This is a structural theorem under two abstract assumptions:

1. `canonicalEventLog : EventLog → ByteString` is injective. The
   Rust substrate satisfies this via canonical-event ordering plus
   per-event canonicalization (Theorem 9 already proved per-event
   injectivity; a deterministic ordering over distinct events
   preserves it at the log level).

2. `H : ByteString → FrontierId` is injective. The Rust substrate
   uses sha256; the abstract-injectivity assumption stays consistent
   with Theorem 5's structural model.

Under these, the composed function `H ∘ canonicalEventLog` is
injective on event logs: distinct logs produce distinct frontier
ids.

## Substrate role

The substrate's `vfr_*` ids are content-addressed: a frontier id is
`sha256(canonical_bytes(event_log))`. Theorem 13 pins this at the
algebraic level. A consumer who fetches the same `vfr_*` id from two
hubs and reproduces the canonical bytes can be sure (under the
abstract-injectivity assumption) that the underlying event logs are
identical.

This is the substrate-side guarantee that the v0.129 `vela registry
witness-check` primitive (A11 cross-hub divergence detector)
implicitly assumes: when two hubs agree on the canonical bytes for
a given `vfr_*`, they agree on the frontier's underlying state.
-/

namespace Vela.FrontierIdDeterminism

variable {EventLog : Type*} {ByteString : Type*} {FrontierId : Type*}

/-- The substrate's frontier-id pipeline: canonicalize the event log,
then hash. -/
def frontierId
    (canonicalEventLog : EventLog → ByteString)
    (H : ByteString → FrontierId) :
    EventLog → FrontierId :=
  H ∘ canonicalEventLog

/-- **Theorem 13 (frontier-id determinism).** If the canonical
event-log serializer is injective on event logs and the abstract
hash is injective on byte strings, then the composed frontier-id
function is injective on event logs. Equivalently: distinct event
logs produce distinct `vfr_*` ids.

The proof is one line via `Function.Injective.comp`, mirroring the
structure of Theorem 9 at the event-log layer rather than the
per-event layer. -/
theorem theorem13_frontier_id_injective
    (canonicalEventLog : EventLog → ByteString)
    (hCanonical : Function.Injective canonicalEventLog)
    (H : ByteString → FrontierId)
    (hH : Function.Injective H) :
    Function.Injective (frontierId canonicalEventLog H) := by
  unfold frontierId
  exact hH.comp hCanonical

/-- Contrapositive form. Same `vfr_*` id implies same canonical
event log. The substrate uses this shape in the witness-check
argument: two hubs returning byte-identical canonical bytes for a
shared `vfr_*` necessarily agree on the underlying event log. -/
theorem theorem13_same_id_implies_same_log
    (canonicalEventLog : EventLog → ByteString)
    (hCanonical : Function.Injective canonicalEventLog)
    (H : ByteString → FrontierId)
    (hH : Function.Injective H)
    (a b : EventLog)
    (hEq : frontierId canonicalEventLog H a
         = frontierId canonicalEventLog H b) :
    a = b := by
  exact theorem13_frontier_id_injective canonicalEventLog hCanonical H hH hEq

end Vela.FrontierIdDeterminism
