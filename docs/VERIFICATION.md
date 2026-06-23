# The verification gate

The substrate makes the *log* trustworthy: every change is signed over
content-addressed bytes and replays to the same state on any machine. That is
necessary and not sufficient. A signed event can still carry an overstated
claim, a proof of the wrong statement, or a single self-confirming run dressed
up as "verified". The gate is the layer that decides what counts as verified,
and it is deliberately separate from both the human review verdict and Bayesian
confidence.

The design follows one rule the codebase already uses for Belnap status
(`status_provenance`): **derive, never store.** Verification status is a pure
function of the evidence attached to a claim. There is no setter. A claim cannot
be stamped verified; it can only derive as verified from attachments that
satisfy four conditions.

## Verifier attachments (`vva_`)

A `VerifierAttachment` (`crate::verifier_attachment`) is a standalone,
content-addressed object — the `Replication` (`vrep_`) precedent, not a mutable
field on the finding. Each attachment is one verifier's judgment, bound to the
exact claim it checked by `claim_digest` (`sha256(trimmed claim)[..16]`, the same
rule as the Python reference). It records:

- `verifier_method` — one of the closed set (`computational_search`,
  `lp_dual_recompute`, `sat_unsat_cert`, `lean_kernel`,
  `exact_arithmetic_recompute`, `literature_corroboration`, `manual_referee`).
  `proof_verification` and `lean_verification` are instances of `lean_kernel`.
- `solver_id` — the independent tool that produced the check (`cp-sat`,
  `pulp-cbc`, `lean4@4.29.1`).
- `independent_of` — ids of other attachments this one declares independence
  from.
- `match_to_claim` — the verifier's assertion that it checked the target claim
  verbatim, not a weaker statement.
- `adversarial_probes` — probes run against the claim, each surviving or
  refuting.
- `outcome` — `passed` or `failed`.

## The four conditions

`derive_gate_status(current_claim_digest, attachments)` returns
`needs_verification`, `verified`, or `refuted`, with the reasons it is not
verified.

- **G1 independence** — at least two *matched* attachments by different
  `(verifier_method, solver_id)`, with at least one declaring `independent_of`
  another in the set (one-directional; a mutual 2-cycle is unconstructable since
  the `vva_` id content-addresses `independent_of`). One run, or two runs of the
  same method, never suffices.
- **G2 claim-match** — every passing attachment is bound to the current claim
  digest with `match_to_claim.matches`. A passing attachment bound to a
  different claim is `passed_but_unmatched` and counts for nothing.
- **G3 adversarial** — at least one probe present across the matched set and
  none refuted. A single refuting probe drives the whole gate to `refuted`.
- **G4 well-formed** — matched attachments are structurally valid, content-
  addressed (`vva_…`), and verify their own id.

A claim with zero attachments derives to `needs_verification`, even if a
reviewer accepted it. That is the bug class the gate exists to prevent: in the
Erdős dogfooding, 47 of 76 "verified" records carried an empty verification
field and were trusted anyway.

## Deliverable grade

`crate::deliverable_grade` is the orthogonal anti-inflation axis: *what was
delivered*, independent of how strong the evidence is. The taxonomy runs from
`unconditional_solve` and `conditional_solve` (the only two that license
solve-language) through `improved_published_bound`, `verified_reduction`,
`obstruction_map`, `partial_proof`, `extends_prior_work`, `new_oeis_term`,
`lean_fragment`, down to `honest_null` and `retracted`.

`grade_gate(claim, grade)` requires a grade and blocks solve-language ("solve",
"resolves #", "first to solve", …) in the claim text unless the grade is a
solve. A bound improvement may not call itself a resolution.

## CLI

```sh
vela gate vocab
vela gate grade --claim "This resolves #647 with an improved bound." \
  --grade improved_published_bound          # exit 1: solve-language mismatch
vela gate check --claim "<exact claim>" --attachments attachments.json
```

`vela gate check` reads a JSON array of `VerifierAttachment`, verifies each is
well-formed, derives the status against the claim digest, and exits non-zero
unless the status is `verified`. It is distinct from `vela verify`, which checks
that a proof packet is byte-for-byte what was signed — the log guarantee, not
the claim guarantee.

---

## Proof-attestation records (`vpv_`)

*Folded from the former PROOF_VERIFICATION.md.*

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
  --script-locator sha256:$(shasum -a 256 lean/Vela/Constructions/EGZ.lean | awk '{print $1}') \
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
