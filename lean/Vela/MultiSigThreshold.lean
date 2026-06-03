import Mathlib

/-!
# Vela multi-sig threshold soundness (Theorem 11)

This file formalizes the v0.37 multi-sig threshold semantics at the
algebraic layer: a k-of-n multi-sig predicate is satisfied iff at
least `k` distinct registered actors each produced a valid signature
on the canonical bytes.

Theorem 6 (`Vela.Signing`) proved that toggling cache-only fields
on a `Finding` does not invalidate signatures already taken.
Theorem 10 (`Vela.SignatureUniqueness`) proved the signing pipeline
is injective on `(event_core, signing_key)` pairs. Theorem 11 closes
the multi-sig predicate at the algebraic layer: counting distinct
valid signers and comparing to `k` is sound under monotonicity,
distinctness, and registration-bound.

## What is and is not formalized

This is a structural theorem under an abstract `validate` predicate.
It proves three load-bearing properties of the substrate's
distinct-signer counting rule:

1. **Distinctness**: the distinct-valid-signer count equals the
   cardinality of the set of valid signing keys.
2. **Monotonicity**: appending a signature never decreases the count.
3. **Registration-bound**: the count is at most the number of
   distinct keys appearing in the signature list.

The Rust kernel implements this via
`sign::verify_multisig_threshold`; this Lean theorem is the
algebraic guarantee that the kernel's counting rule matches the
substrate's threshold semantics.

The cryptographic strength of Ed25519 and the implementation
correctness of `canonical_json` are out of scope. Theorem 6 handles
the canonical-bytes-stability layer; the substrate's
`scripts/test-multisig-threshold.sh` regression gate covers the
Rust implementation.
-/

namespace Vela.MultiSigThreshold

variable {SignerKey : Type*} [DecidableEq SignerKey]
  {Signature : Type*} {ByteString : Type*}

/-- The set of distinct keys with a valid signature on `canonical`.
Filters the signature list by `validate`, extracts the keys, and
takes the underlying Finset (which deduplicates by `DecidableEq`). -/
def distinctValidSigners
    (validate : SignerKey × Signature → ByteString → Bool)
    (sigs : List (SignerKey × Signature))
    (canonical : ByteString) : Finset SignerKey :=
  ((sigs.filter (fun p => validate p canonical)).map Prod.fst).toFinset

/-- The distinct-valid-signer count. -/
def distinctValidSignerCount
    (validate : SignerKey × Signature → ByteString → Bool)
    (sigs : List (SignerKey × Signature))
    (canonical : ByteString) : ℕ :=
  (distinctValidSigners validate sigs canonical).card

/-- **Theorem 11.a (distinctness).** A key is in the
distinct-valid-signers set iff there exists a signature for that key
in the list whose `validate` returns `true`. This is the substrate's
distinct-signer counting rule's defining property. -/
theorem theorem11a_distinctness
    (validate : SignerKey × Signature → ByteString → Bool)
    (sigs : List (SignerKey × Signature))
    (canonical : ByteString) (sk : SignerKey) :
    sk ∈ distinctValidSigners validate sigs canonical
      ↔
    ∃ sig, (sk, sig) ∈ sigs ∧ validate (sk, sig) canonical = true := by
  unfold distinctValidSigners
  simp only [List.mem_toFinset, List.mem_map, List.mem_filter]
  constructor
  · rintro ⟨⟨k, sig⟩, ⟨hMem, hValid⟩, hFst⟩
    refine ⟨sig, ?_, ?_⟩
    · simp only at hFst
      cases hFst
      exact hMem
    · simp only at hFst
      cases hFst
      exact hValid
  · rintro ⟨sig, hMem, hValid⟩
    refine ⟨(sk, sig), ⟨hMem, hValid⟩, rfl⟩

/-- **Theorem 11.b (monotonicity under append).** Appending a
signature to the signature list never decreases the
distinct-valid-signer count. -/
theorem theorem11b_monotone_under_append
    (validate : SignerKey × Signature → ByteString → Bool)
    (sigs : List (SignerKey × Signature))
    (newSig : SignerKey × Signature)
    (canonical : ByteString) :
    distinctValidSignerCount validate sigs canonical
      ≤ distinctValidSignerCount validate (sigs ++ [newSig]) canonical := by
  unfold distinctValidSignerCount
  apply Finset.card_le_card
  intro sk hMem
  rw [theorem11a_distinctness] at hMem
  rw [theorem11a_distinctness]
  obtain ⟨sig, hMemPair, hValid⟩ := hMem
  refine ⟨sig, ?_, hValid⟩
  exact List.mem_append.mpr (Or.inl hMemPair)

/-- **Theorem 11.c (registration bound).** The distinct-valid-signer
count is at most the number of distinct keys appearing in the
signature list.

In particular, when the substrate's kernel `validate` returns `false`
on every key not in the registered-signers set, the count is bounded
above by the number of distinct registered signers represented in the
signature list. An attacker who inserts unregistered signers cannot
inflate the count past the number of distinct registered signers,
because their signatures fail `validate`. -/
theorem theorem11c_registration_bound
    (validate : SignerKey × Signature → ByteString → Bool)
    (sigs : List (SignerKey × Signature))
    (canonical : ByteString) :
    distinctValidSignerCount validate sigs canonical
      ≤ (sigs.map Prod.fst).toFinset.card := by
  unfold distinctValidSignerCount distinctValidSigners
  apply Finset.card_le_card
  intro sk hMem
  simp only [List.mem_toFinset, List.mem_map, List.mem_filter] at hMem
  obtain ⟨⟨k, sig⟩, ⟨hMemPair, _hValid⟩, hFst⟩ := hMem
  simp only at hFst
  cases hFst
  simp only [List.mem_toFinset, List.mem_map]
  exact ⟨(sk, sig), hMemPair, rfl⟩

end Vela.MultiSigThreshold
