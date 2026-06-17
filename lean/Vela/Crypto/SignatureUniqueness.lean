import Mathlib

/-!
# Vela signature uniqueness (Theorem 10)

This file formalizes the substrate's claim that the signing pipeline
does not produce ambiguous signatures: two distinct `(event_core,
signing_key)` pairs cannot produce the same signature under canonical
bytes.

Theorem 6 (in `Vela.Signing`) proved that toggling cache-only fields
on a `Finding` does not change the canonical bytes it signs. Theorem 9
(in `Vela.CanonicalEventId`) proved that the canonical-bytes
serialization composed with an abstract injective hash gives an
injective event-id function. Theorem 10 closes the analogous statement
one layer up: given an abstract sign function that is injective on
`(canonical_bytes, signing_key)` pairs, the substrate's full signing
pipeline (canonicalize then sign) is injective on `(event_core,
signing_key)` pairs.

## What is and is not formalized

This is a structural theorem. The substrate's actual signing function
is `ed25519_dalek::SigningKey::sign(canonical_bytes)`, which is
cryptographically EUF-CMA-secure under standard assumptions but is not
proved injective inside Lean. Theorem 10 says: *given* that abstract
injectivity, the canonical-bytes layer does not introduce its own
collisions. The substrate-honest reading: the serialization step plus
the keying step are both load-bearing in the signing record, and they
compose cleanly.

The lemma `theorem10_signature_uniqueness_under_canonical` is the main
statement; `theorem10_distinct_core_or_key_implies_distinct_sig` is the
contrapositive form the substrate uses when arguing that
`{event_core, signing_key} -> signature` cannot collide for distinct
inputs.
-/

namespace Vela.SignatureUniqueness

variable {EventCore : Type*} {ByteString : Type*}
  {SigningKey : Type*} {Signature : Type*}

/-- The substrate's signing pipeline as a function on
`(event_core, signing_key)` pairs. Equals `sign ∘ (canonicalBytes ⊗ id)`
where `sign` takes a `(ByteString, SigningKey)` pair to a `Signature`
and `canonicalBytes ⊗ id` lifts canonical-bytes onto the first
component. -/
def signPipeline
    (canonicalBytes : EventCore → ByteString)
    (sign : ByteString × SigningKey → Signature) :
    EventCore × SigningKey → Signature :=
  fun (c, k) => sign (canonicalBytes c, k)

/-- **Theorem 10 (signature uniqueness under canonical bytes).**

If `canonicalBytes` is injective on event cores and `sign` is
injective on `(canonical_bytes, signing_key)` pairs, then the
substrate's full signing pipeline is injective on
`(event_core, signing_key)` pairs.

In substrate terms: distinct `(event_core, signing_key)` inputs
produce distinct signatures. -/
theorem theorem10_signature_uniqueness_under_canonical
    (canonicalBytes : EventCore → ByteString)
    (hCanonicalBytes : Function.Injective canonicalBytes)
    (sign : ByteString × SigningKey → Signature)
    (hSign : Function.Injective sign) :
    Function.Injective (signPipeline canonicalBytes sign) := by
  intro a b hEq
  -- Unfold the pipeline to expose the (canonicalBytes c, k) pairs.
  obtain ⟨c₁, k₁⟩ := a
  obtain ⟨c₂, k₂⟩ := b
  -- `hEq : sign (canonicalBytes c₁, k₁) = sign (canonicalBytes c₂, k₂)`.
  -- Apply sign's injectivity to recover equality of the pre-images.
  have h_pairs : (canonicalBytes c₁, k₁) = (canonicalBytes c₂, k₂) := hSign hEq
  -- Split the pair equality.
  have h_bytes : canonicalBytes c₁ = canonicalBytes c₂ := (Prod.mk.injEq _ _ _ _).mp h_pairs |>.1
  have h_key   : k₁ = k₂                                := (Prod.mk.injEq _ _ _ _).mp h_pairs |>.2
  -- canonicalBytes is injective, so c₁ = c₂.
  have h_core : c₁ = c₂ := hCanonicalBytes h_bytes
  -- Reassemble the pair equality.
  exact Prod.ext h_core h_key

/-- Contrapositive form. If two inputs differ in either the event core
or the signing key, the resulting signatures differ. This is the shape
the substrate uses when arguing the canonical-bytes layer does not
let an attacker forge a signature that validates for two distinct
event-core values under one key, or for one event-core value under
two distinct keys. -/
theorem theorem10_distinct_core_or_key_implies_distinct_sig
    (canonicalBytes : EventCore → ByteString)
    (hCanonicalBytes : Function.Injective canonicalBytes)
    (sign : ByteString × SigningKey → Signature)
    (hSign : Function.Injective sign)
    (c₁ c₂ : EventCore) (k₁ k₂ : SigningKey)
    (hDistinct : c₁ ≠ c₂ ∨ k₁ ≠ k₂) :
    signPipeline canonicalBytes sign (c₁, k₁) ≠ signPipeline canonicalBytes sign (c₂, k₂) := by
  intro hEq
  -- If the signatures matched, the pipeline injectivity would force
  -- the inputs to be equal, contradicting hDistinct.
  have h_pair : (c₁, k₁) = (c₂, k₂) :=
    theorem10_signature_uniqueness_under_canonical
      canonicalBytes hCanonicalBytes sign hSign hEq
  have h_core : c₁ = c₂ := (Prod.mk.injEq _ _ _ _).mp h_pair |>.1
  have h_key  : k₁ = k₂ := (Prod.mk.injEq _ _ _ _).mp h_pair |>.2
  rcases hDistinct with h | h
  · exact h h_core
  · exact h h_key

end Vela.SignatureUniqueness
