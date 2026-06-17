import Mathlib

/-!
# Vela signing theorem (Theorem 6)

This file formalizes the v0.104 multi-sig kernel correctness fix as a
machine-checked structural guarantee:

- Theorem 6: signature stability under `jointly_accepted` flips.

## The substrate fix

Pre-v0.104, `sign::canonical_json` serialized the entire `FindingBundle`
including `flags.jointly_accepted` into the signing preimage. The
v0.37 multi-sig flow flipped that flag from `false` to `true` once
`k` distinct registered actors had each signed the finding, via
`refresh_jointly_accepted`. The flip mutated the canonical bytes,
which invalidated every signature that just made the threshold.

The fix excludes `jointly_accepted` from the canonical signing
preimage. `signature_threshold` stays in (cryptographically locked
so an attacker cannot lower the threshold without invalidating
signatures). Theorem 6 proves the structural claim that backs the
fix: under the new `canonicalJson` rule, signature verification is
stable across `jointly_accepted` flips.

## What is and is not formalized

This is a structural theorem under an abstract signing scheme. It
proves that if `canonicalJson` is invariant under `jointly_accepted`
flips, then a verifier that recomputes `canonicalJson` against
current bytes will accept signatures taken before the flip. It does
not prove the cryptographic strength of Ed25519 or the implementation
correctness of the Rust `canonical_json` function. The Rust function
is exercised by `crates/vela-protocol/src/sign.rs` tests and the
shell-level `scripts/test-multisig-threshold.sh` gate; this Lean
theorem is the algebraic guarantee they are testing.
-/

namespace Vela.Signing

/-- A finding is modeled by the substrate fields that participate in
the signing preimage debate. `core` carries everything else (id,
assertion, evidence, etc.); `signatureThreshold` and `jointlyAccepted`
are the two `flags` fields the v0.104 fix discusses. -/
structure Finding where
  core               : String
  signatureThreshold : Option Nat
  jointlyAccepted    : Bool
deriving DecidableEq, Repr

/-- Encode the threshold field as a plain string for the
structural model. `none` becomes `"_"`; `some n` becomes the
decimal `n`. -/
def thresholdEncode : Option Nat → String
  | none     => "_"
  | some n   => toString n

/-- Encode the cache flag as a plain string. -/
def jointlyEncode : Bool → String
  | false => "0"
  | true  => "1"

/-- The pre-v0.104 canonical signing preimage. Includes
`jointlyAccepted` directly, which is what made the substrate
broken: flipping that flag produced different bytes, invalidating
prior signatures. -/
def canonicalJsonPreFix (f : Finding) : String :=
  f.core ++ "|" ++ thresholdEncode f.signatureThreshold ++ "|"
    ++ jointlyEncode f.jointlyAccepted

/-- The v0.104 canonical signing preimage. `jointlyAccepted` is
stripped before serialization. `signatureThreshold` stays in so an
attacker cannot lower the threshold without invalidating
signatures. -/
def canonicalJson (f : Finding) : String :=
  f.core ++ "|" ++ thresholdEncode f.signatureThreshold

/-- An abstract signature scheme over byte strings. The model is
generic: any deterministic verifier that consults the bytes through
`canonicalJson` is sufficient. -/
structure SignatureScheme where
  /-- A signature is a string for the structural model. -/
  Signature : Type
  /-- `verify pubkey bytes sig` returns `true` iff the signature
  cryptographically validates against the bytes under the named
  public key. The model leaves the cryptographic guarantee abstract;
  what matters here is that `verify` consults the bytes only. -/
  verify   : String → String → Signature → Bool

/-- Flip the `jointlyAccepted` flag on a finding. -/
def flipJointlyAccepted (f : Finding) : Finding :=
  { f with jointlyAccepted := ¬ f.jointlyAccepted }

/-- **Lemma**: `canonicalJson` is invariant under flips of
`jointlyAccepted`. The post-v0.104 signing preimage does not depend
on the cache flag, so any change to that flag is invisible at the
signing layer. -/
theorem canonicalJson_flip_invariant (f : Finding) :
    canonicalJson (flipJointlyAccepted f) = canonicalJson f := by
  rfl

/-- **Theorem 6 (signature stability under cache-flag flips)**:
for any signature scheme, any public key, any signature, and any
finding `f`, the verifier accepts the signature against the
post-flip canonical bytes iff it accepts the same signature against
the pre-flip canonical bytes. The `jointlyAccepted` flip is invisible
to verification. -/
theorem theorem6_signature_stable_under_flip
    (scheme : SignatureScheme) (pk : String) (sig : scheme.Signature)
    (f : Finding) :
    scheme.verify pk (canonicalJson (flipJointlyAccepted f)) sig =
      scheme.verify pk (canonicalJson f) sig := by
  rw [canonicalJson_flip_invariant]

/-- A negative companion: under the pre-v0.104 broken rule,
`canonicalJsonPreFix` IS sensitive to flips, which is exactly the
substrate-correctness gap the v0.104 fix closed. We prove this
witnesses a real difference rather than a vacuous one: there exists
a finding for which the pre-fix bytes change under the flip. -/
theorem canonicalJson_pre_fix_was_flip_sensitive :
    ∃ f : Finding,
      canonicalJsonPreFix (flipJointlyAccepted f) ≠ canonicalJsonPreFix f := by
  refine ⟨{ core := "x", signatureThreshold := some 2,
            jointlyAccepted := false }, ?_⟩
  decide

/-- **Theorem 6 honesty companion**: the pre-fix preimage was
demonstrably flip-sensitive on a concrete finding, while the
post-fix preimage is provably flip-invariant on every finding.
The structural difference is what makes the v0.104 fix real
correctness work rather than a stylistic refactor. -/
theorem theorem6_pre_vs_post_fix_distinction :
    (∃ f : Finding,
        canonicalJsonPreFix (flipJointlyAccepted f) ≠ canonicalJsonPreFix f) ∧
    (∀ f : Finding,
        canonicalJson (flipJointlyAccepted f) = canonicalJson f) := by
  refine ⟨canonicalJson_pre_fix_was_flip_sensitive, ?_⟩
  intro f
  exact canonicalJson_flip_invariant f

/-- Threshold lock: `canonicalJson` IS sensitive to changes in
`signatureThreshold`. This is the dual property to flip-invariance:
flipping the cache flag is invisible (Theorem 6) but lowering or
raising the threshold changes the canonical bytes and therefore
invalidates signatures, which is the right behavior. An attacker
who tries to weaken the threshold cannot do so silently. -/
theorem canonicalJson_threshold_locked :
    ∃ f : Finding, ∃ t : Nat,
      canonicalJson { f with signatureThreshold := some t } ≠
        canonicalJson { f with signatureThreshold := some (t + 1) } := by
  refine ⟨{ core := "x", signatureThreshold := none,
            jointlyAccepted := false }, 2, ?_⟩
  decide

end Vela.Signing
