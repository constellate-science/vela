# Vela Sidon Producer Profile v1

## 1. Scope

This profile applies the finite, positive, ranked Scientific State Kernel to one live frontier: lower bounds for OEIS A309370, Sidon sets in the binary cube.

It does not define a new general scientific protocol. It constrains existing Vela operations for one certificate kind whose verifier is exact and inexpensive.

## 2. State model

A profile presentation contains two ranked cell kinds:

```text
rank 0: verified-witness(artifact_digest)
rank 1: lower-bound(n, k, support)
```

An accepted result emits two positive clauses:

```text
verified-witness(w)
  <- artifact(w)
     · verifier_A(receipt_A)
     · verifier_B(receipt_B)
     · probes(probe_receipts)
     · gate(g)
     · acceptance_event(e)

lower-bound(n,k)
  <- verified-witness(w)
     · statement(claim_digest)
     · rule(sidon-lower-bound-v1)
```

The compiler derives:

```text
Γ_P : H -> N[X]
```

Alternative accepted witnesses add polynomial terms. Joint dependencies multiply. The production implementation may store a canonical circuit, but its interpretation must equal the expanded fixture semantics.

## 3. Three lawful verbs

### 3.1 Append

A human-signed `AcceptancePacket` appends an accepted event and its two clauses. Append may add historical lineage. It may not remove earlier events, clauses, or monomials.

### 3.2 Restrict

A `ChallengePacket` is a proposal and has no state effect. A human-signed `ViewDecisionPacket` applies a named atom substitution under a view policy.

Restriction changes:

```text
active_view_root
active support environments
observed frontier values
```

Restriction does not change:

```text
presentation_root
circuit_root
historical lineage_root
```

### 3.3 Observe

An `ObservationPacket` is an authoritative read only when it carries:

```text
presentation_root
circuit_root
lineage_root
active_view_root
evaluator_id
evaluator_inputs
canonical_output
replay_receipt
```

The replay receipt commits to the input-root digest, evaluator digest, and output digest.

## 4. Root-pinned work

Every `TaskPacket` carries a `base_state` commitment:

```text
observation_id
presentation_root
circuit_root
lineage_root
active_view_root
evaluator_id
evaluator_inputs_digest
canonical_output_digest
```

A `ResultPacket` must repeat this object byte-for-byte. The gate may not rewrite it.

## 5. Staleness

Acceptance compares the result's base observation with the current decision observation.

Allowed outcomes are:

```text
fresh
stale_revalidated_as_improvement
stale_revalidated_as_confirmation
```

There is no silent rebase. A stale result that is neither a current improvement nor an explicitly allowed confirmation is rejected.

The conformance fixture issues two tasks at the same root. Producer A lands first. Producer B's size-7 result is then accepted only as `stale_revalidated_as_confirmation` against the new root.

## 6. Verification gate

The result artifact is bound to a claim digest and artifact digest. The reference gate requires:

1. pair-sum uniqueness by hash-set membership;
2. pair-sum uniqueness by base-3 encoding, sorting, and adjacent comparison;
3. distinct method families;
4. distinct executable source digests;
5. exact claim and artifact digest match;
6. rejection of duplicate-point, claimed-size, and semantic pair-sum-collision negative controls.

This is **algorithmic diversity**, not proof of statistical or organizational independence. Production policy may impose stronger separation.

## 7. Support functions and correction

`env(Γ_P(h))` gives the minimal assumption environments for a cell.

A `SupportFunctionPacket` carries both historical and active minimal environments. A challenge set kills a target exactly when it hits every active minimal environment at the challenged root.

A challenge remains non-authoritative until a reviewer accepts a `ViewDecisionPacket`.

A repair occurs through one of two lawful operations:

- append a newly accepted alternative environment; or
- issue a separate human view decision that re-enables previously disabled atoms under policy.

The fixture uses the first. The `RepairPacket` explains restoration but does not itself mutate lineage.

## 8. Packet identity and signature

The packet body excludes `packet_id` and `signature`. Values are encoded with the profile's canonical JSON subset:

```text
null, Boolean, integer, NFC string, array, string-keyed object
```

Floats are forbidden.

The packet ID is a full SHA-256 content identifier. The Ed25519 signature covers a domain-separated preimage containing the packet ID and canonical body. Unknown schema versions and unknown packet fields fail closed.

## 9. Operational packets versus scientific state

Tasks and leases coordinate work but do not alter scientific state. Results, gate receipts, and challenges are proposals or evidence. Historical state changes only through accepted append events. Active state changes only through accepted view decisions. Reads become authoritative only through ObservationPackets.

## 10. Conformance

A conformant implementation must reproduce the fixture's roots and trace:

```text
6 -> 7 -> 7 -> 6 -> 7
```

It must also reject the negative no-hidden-state fixture and preserve historical lineage across restriction.

## 11. Rust realization (status)

The profile is realized in Rust at `crates/vela-protocol/src/sidon_profile/`
(modules `canonical` · `packets` · `kernel` · `evaluator` · `producer`) and
surfaced through `vela sidon`. Every layer is conformance-pinned to the Python
reference and to the landed fixtures:

- **canonical + packets** — recompute all 25 fixture packet IDs and re-verify
  every Ed25519 signature (`tests/sidon_profile_conformance.rs`).
- **kernel + evaluator** — replay each snapshot's four roots, canonical output,
  and digests; reproduce the `6,7,7,6,7` trace; the restrict-kill and
  append-repair through the bag-lineage environments
  (`tests/sidon_profile_kernel_conformance.rs`).
- **producer** — `make_support_function` / `make_observation` / `make_task` /
  `make_result` regenerate the genesis observation, task, and result *byte for
  byte*, signatures included (`tests/sidon_profile_producer_conformance.rs`).

`vela sidon submit WITNESS --base-observation OBS --key K --actor A` emits the
signed `ResultPacket` a producer proposes; `vela sidon observe --presentation P
--key K --actor A` emits the authoritative `ObservationPacket` (which replays
from the presentation it names). Both sign with the caller's own key. Packets
emitted by the Rust CLI are accepted by the independent Python
`verify_signed_packet`.

Not yet realized in Rust: the reviewer-side constructors
(gate/acceptance/challenge/view/repair) — where the **production gate runs the
frozen `vela-verify` Sidon verifier**, not the fixture's hashed Python
executables; the live-frontier reducer (accepted findings → presentation); and
the hub observation endpoint that mints `bounds.json` carrying the observation
id.
