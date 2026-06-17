import Mathlib

/-!
# Vela search-index determinism (Theorem 17)

This file pins the algebraic guarantee underlying v0.149
vela-search: two consumers running `build_index` over the same
ordered list of frontiers produce byte-identical indices (and
therefore byte-identical `vsi_*` ids).

The Rust crate's `build_index` is a pure function over its
inputs: it walks the supplied frontier paths in order, derives
each entry deterministically from the on-disk frontier state,
sorts the entry list by (kind, frontier_id, target_id), and
content-addresses the result via sha256 over canonical bytes.

Theorem 17 lifts this guarantee to the algebraic layer:
composing a deterministic build function with an injective
canonical-bytes serializer and an injective abstract hash
produces an injective composed pipeline. Same inputs always
produce the same id; distinct inputs produce distinct ids
(modulo the abstract hash injectivity).

## What is and is not formalized

This is a structural theorem under two abstract assumptions:

1. `canonicalBytes : Index → ByteString` is injective.
2. `H : ByteString → IndexId` is injective.

Under these, the composed `H ∘ canonicalBytes ∘ buildIndex` is
injective on input lists. Two distinct frontier-list inputs
produce distinct `vsi_*` ids; equal inputs produce equal ids.

Composes with Theorem 13 (frontier-id determinism) at the
layer below: each frontier's `vfr_*` is already content-
addressed via the same canonical-bytes+hash pipeline; the
index composes on top.

## Substrate role

The Rust crate's `Index::derive_id` mirrors this composition:
`vsi_` + first 16 hex of `sha256(canonical_bytes(index_body))`
where the index body excludes `index_id` + `generated_at` from
the preimage. The test gate `test-search-index.sh` exercises
the determinism end-to-end at the substrate layer.
-/

namespace Vela.SearchIndexDeterminism

variable {Input : Type*} {Index : Type*} {ByteString : Type*} {IndexId : Type*}

/-- The substrate's search-index pipeline: build, canonicalize,
hash. -/
def indexId
    (buildIndex : Input → Index)
    (canonicalBytes : Index → ByteString)
    (H : ByteString → IndexId) :
    Input → IndexId :=
  H ∘ canonicalBytes ∘ buildIndex

/-- **Theorem 17 (search-index determinism).** If `buildIndex`
is injective on inputs (distinct frontier-list inputs produce
distinct indices), `canonicalBytes` is injective on indices,
and the abstract hash `H` is injective on byte strings, then
the composed `vsi_*` derivation is injective on inputs.
Equivalently: two consumers running build_index over the same
input list produce the same `vsi_*`; distinct inputs produce
distinct ids.

The proof is two compositions of `Function.Injective.comp`. -/
theorem theorem17_search_index_deterministic
    (buildIndex : Input → Index)
    (hBuild : Function.Injective buildIndex)
    (canonicalBytes : Index → ByteString)
    (hCanonical : Function.Injective canonicalBytes)
    (H : ByteString → IndexId)
    (hH : Function.Injective H) :
    Function.Injective (indexId buildIndex canonicalBytes H) := by
  unfold indexId
  exact (hH.comp hCanonical).comp hBuild

/-- Contrapositive: equal `vsi_*` ids imply equal inputs.
The substrate's federation primitive at v0.148 relies on this
shape: two hubs that report the same index id necessarily
agree on the underlying frontier set. -/
theorem theorem17_same_id_implies_same_input
    (buildIndex : Input → Index)
    (hBuild : Function.Injective buildIndex)
    (canonicalBytes : Index → ByteString)
    (hCanonical : Function.Injective canonicalBytes)
    (H : ByteString → IndexId)
    (hH : Function.Injective H)
    (a b : Input)
    (hEq : indexId buildIndex canonicalBytes H a
         = indexId buildIndex canonicalBytes H b) :
    a = b := by
  exact theorem17_search_index_deterministic
    buildIndex hBuild canonicalBytes hCanonical H hH hEq

end Vela.SearchIndexDeterminism
