import Mathlib

/-!
# Vela registry-checkpoint root injectivity (Theorem 19)

The v0.147 `RegistryCheckpoint` carries a `registry_root` field:
`sha256` over canonical bytes of an alphabetically-sorted
summary of the registry's entries. Theorem 19 pins the
algebraic guarantee underlying v0.148 federation: two
checkpoints with the same `registry_root` over byte-identical
summary inputs necessarily came from the same registry state
(modulo abstract hash injectivity).

## What is and is not formalized

This is the same compositional shape as Theorem 13 (frontier-
id determinism) + Theorem 17 (search-index determinism), one
level up to the registry-state layer:

  registry → canonical_bytes(summary) → sha256 → registry_root

Under injective canonical-bytes + injective abstract H, the
composed registry_root function is injective on registry
summaries. Two checkpoints reporting the same root therefore
agree on the underlying summary, which (since the summary is
content-addressed over the entry list) means they agree on
the underlying entry set.

## Substrate role

The Rust substrate's `checkpoint::compute_registry_root` is
the operational counterpart. The v0.148
`hub-federation status` command compares roots across hubs;
under T19, unanimous roots = unanimous registry state, which
is the substrate-honest guarantee the federation consensus
rests on.
-/

namespace Vela.CheckpointRootInjectivity

variable {RegistrySummary : Type*} {ByteString : Type*} {RootHash : Type*}

/-- The substrate's registry-root pipeline: canonicalize the
ordered summary, then hash. -/
def registryRoot
    (canonicalBytes : RegistrySummary → ByteString)
    (H : ByteString → RootHash) :
    RegistrySummary → RootHash :=
  H ∘ canonicalBytes

/-- **Theorem 19 (checkpoint root injectivity).** If
`canonicalBytes` is injective on registry summaries and the
abstract hash `H` is injective on byte strings, then the
composed registry_root function is injective on summaries:
distinct summaries produce distinct roots, and equal roots
imply equal summaries. -/
theorem theorem19_registry_root_injective
    (canonicalBytes : RegistrySummary → ByteString)
    (hCanonical : Function.Injective canonicalBytes)
    (H : ByteString → RootHash)
    (hH : Function.Injective H) :
    Function.Injective (registryRoot canonicalBytes H) := by
  unfold registryRoot
  exact hH.comp hCanonical

/-- **Theorem 19a (contrapositive form).** Two registries
agreeing on the root necessarily agree on the canonical
summary. The substrate's v0.148 federation primitive uses
this shape directly: unanimous-consensus roots across hubs =
unanimous-consensus underlying entry sets. -/
theorem theorem19a_same_root_implies_same_summary
    (canonicalBytes : RegistrySummary → ByteString)
    (hCanonical : Function.Injective canonicalBytes)
    (H : ByteString → RootHash)
    (hH : Function.Injective H)
    (a b : RegistrySummary)
    (hEq : registryRoot canonicalBytes H a
         = registryRoot canonicalBytes H b) :
    a = b := by
  exact theorem19_registry_root_injective
    canonicalBytes hCanonical H hH hEq

end Vela.CheckpointRootInjectivity
