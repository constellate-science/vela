# Proof verification

Arc 4 ships Carina Proof verification records at v0.151 +
their site integration at v0.152. The substrate stores
attested verification records; the verifier itself (Lean
kernel, Coq, Isabelle, etc.) runs outside the substrate.

## Substrate-honest split (scoping decision 1)

Consumers trust the verifier's judgment for the named
`(tool, tool_version, lake_manifest_hash)` tuple. Replacing the
verifier with an attacker pipeline is detectable via the
`verifier_pubkey` signature on the `vpv_*` record. The
substrate is not in the business of running Lean; it is in the
business of pinning that someone with a known pubkey ran Lean
and produced the named output.

## CLI

```bash
# Build + sign a vpv_* record (typically run by CI):
vela proof-attest-verification \
  --proof-id vpf_egz_n2 \
  --tool lean4 --tool-version 4.29.1 \
  --script-locator sha256:$(shasum -a 256 lean/Vela/EGZ.lean | awk '{print $1}') \
  --lake-manifest-hash sha256:$(shasum -a 256 lean/lake-manifest.json | awk '{print $1}') \
  --verifier-output-hash sha256:$(lake build Vela.EGZ | shasum -a 256 | awk '{print $1}') \
  --status verified \
  --verifier-actor github-action:vela/.github/workflows/verify-carina-proofs.yml \
  --key /secrets/verifier.key \
  --out attestations/vpv_egz_n2.json

# Verify a vpv_* record (any consumer):
vela proof-verify-attestation attestations/vpv_egz_n2.json
```

## Canonical CI pipeline

`.github/workflows/verify-carina-proofs.yml` ships the canonical
GitHub Action. Disabled by default (`if: false`); enable by
provisioning `VERIFIER_SIGNING_KEY` and `VERIFIER_ACTOR_ID`
secrets in the repo settings. The action runs on:

- `workflow_dispatch` (manual).
- Weekly cron (default: `0 6 * * 1`, Monday 06:00 UTC).
- `push` to `lean/Vela/**` or `crates/vela-protocol/src/proof_verification.rs`.

Steps:

1. Install elan + the Lean toolchain pinned in `lean/lean-toolchain`.
2. Build the vela CLI.
3. Compute script + manifest + output hashes for each `vpf_*`.
4. Sign + emit `vpv_*` records via `proof-attest-verification`.
5. Re-verify the records self-check.
6. Commit + push (or upload as artifact).

## Site integration

`/theorems/[id]` surfaces the verification when the theorem has
a pinned `vpf_*` (today: Theorem 8 / EGZ n=2 ↔ `vpf_egz_n2`).
The page renders status badge, verification id, proof id, tool
+ version, script locator, lake manifest hash, verifier output
hash, verifier actor + pubkey, verified-at timestamp, and a
"verify yourself locally" hint.

## What this guarantees + what it does not

Guarantees:

- A `vpv_*` record cannot be forged without the verifier's
  signing key.
- Two consumers who fetch the same record + run
  `proof-verify-attestation` agree on the verification outcome.
- The record is content-addressed; tampering changes the id.

Does not guarantee:

- That the verifier honestly ran the proof. The substrate
  trusts the verifier's signature; if the verifier is
  compromised, it can sign records claiming verified status
  for proofs that did not verify. Mitigation: institutional
  verifier stewards, multiple independent verifiers per proof,
  cross-checking the `verifier_output_hash` against an
  independent run.
- That the proof is mathematically correct. The Lean kernel's
  acceptance is what gives the proof its trust; the substrate
  only validates that someone with a known key ran it.

Future cycles add multiple-verifier requirements (so a single
compromised verifier cannot rubber-stamp) and a verifier-key
rotation primitive parallel to v0.145 governed owner-rotate.
