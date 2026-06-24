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

## Contents

- The verification gate (this section): verifier attachments, the four
  conditions, deliverable grade, CLI
- §Proof-attestation records (`vpv_`)
- §How a new frozen verifier enters vela-verify (verifier-kind RFC)
- §The exact-lane gate (machine_verified): de-human-gating the rote admit
- §Transparency log (P2): Merkle tamper-evidence over each frontier's log

## Verifier attachments (`vva_`)

A `VerifierAttachment` (`crate::verifier_attachment`) is a standalone,
content-addressed object (the `Replication` (`vrep_`) precedent), not a mutable
field on the finding. Each attachment is one verifier's judgment, bound to the
exact claim it checked by `claim_digest` (`sha256(trimmed claim)[..16]`, the same
rule as the Python reference). It records:

- `verifier_method`: one of the closed set (`computational_search`,
  `lp_dual_recompute`, `sat_unsat_cert`, `lean_kernel`,
  `exact_arithmetic_recompute`, `literature_corroboration`, `manual_referee`).
  `proof_verification` and `lean_verification` are instances of `lean_kernel`.
- `solver_id`: the independent tool that produced the check (`cp-sat`,
  `pulp-cbc`, `lean4@4.29.1`).
- `independent_of`: ids of other attachments this one declares independence
  from.
- `match_to_claim`: the verifier's assertion that it checked the target claim
  verbatim, not a weaker statement.
- `adversarial_probes`: probes run against the claim, each surviving or
  refuting.
- `outcome`: `passed` or `failed`.

## The four conditions

`derive_gate_status(current_claim_digest, attachments)` returns
`needs_verification`, `verified`, or `refuted`, with the reasons it is not
verified.

- **G1 independence**: at least two *matched* attachments by different
  `(verifier_method, solver_id)`, with at least one declaring `independent_of`
  another in the set (one-directional; a mutual 2-cycle is unconstructable since
  the `vva_` id content-addresses `independent_of`). One run, or two runs of the
  same method, never suffices.
- **G2 claim-match**: every passing attachment is bound to the current claim
  digest with `match_to_claim.matches`. A passing attachment bound to a
  different claim is `passed_but_unmatched` and counts for nothing.
- **G3 adversarial**: at least one probe present across the matched set and
  none refuted. A single refuting probe drives the whole gate to `refuted`.
- **G4 well-formed**: matched attachments are structurally valid, content-
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
that a proof packet is byte-for-byte what was signed: the log guarantee, not
the claim guarantee.

---

## Proof-attestation records (`vpv_`)

*Folded from the former PROOF_VERIFICATION.md.*

Arc 4 ships Carina Proof verification records at v0.151 +
their site integration at v0.152. The substrate stores
attested verification records; the verifier itself (Lean
kernel, Coq, Isabelle, etc.) runs outside the substrate.

### Substrate-honest split (scoping decision 1)

Consumers trust the verifier's judgment for the named
`(tool, tool_version, lake_manifest_hash)` tuple. Replacing the
verifier with an attacker pipeline is detectable via the
`verifier_pubkey` signature on the `vpv_*` record. The
substrate is not in the business of running Lean; it is in the
business of pinning that someone with a known pubkey ran Lean
and produced the named output.

### Records

A `vpv_*` proof-attestation record is built and signed (typically by CI) by
hashing the proof script, the lake manifest, and the verifier output for a
proof id (e.g. `vpf_egz_n2`), pinning `(tool, tool_version,
lake_manifest_hash)`, the verifier actor, and a `verified` status, signed with
the verifier key. Any consumer re-checks the record by re-hashing the same
inputs and verifying the signature against the recorded `verifier_pubkey`.

### Canonical CI pipeline

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

### Site integration

`/theorems/[id]` surfaces the verification when the theorem has
a pinned `vpf_*` (today: Theorem 8 / EGZ n=2 ↔ `vpf_egz_n2`).
The page renders status badge, verification id, proof id, tool
+ version, script locator, lake manifest hash, verifier output
hash, verifier actor + pubkey, verified-at timestamp, and a
"verify yourself locally" hint.

### What this guarantees + what it does not

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

---

The gate above is only as good as the verifiers feeding it. This section is the
mechanical bar a new frozen verifier kind must clear to enter vela-verify.

## How a new frozen verifier enters vela-verify

*Folded from the former VERIFIER_RFC.md.*

The Wikidata anti-lesson: proposal processes that stall for years kill
contributor trust. This template has mechanical acceptance criteria and
a stated decision SLA so a second producer never waits on vibes.

### The bar

A verifier kind is accepted when ALL of the following hold; each is
checkable, none is editorial:

1. **Determinism evidence.** Same witness bytes, same verdict, on two
   machines (CI + one maintainer machine). No network, no clock, no
   randomness, no environment reads.
2. **Pinned dependencies.** Pure Rust in vela-verify (preferred), or a
   pinned-toolchain external checker (the Lean model) with the toolchain
   hash recorded in the attachment's `toolchain_hash`.
3. **Golden vectors.** At least 3 valid witnesses that must PASS,
   committed under the proposing frontier's `witnesses/`.
4. **Mutation cases.** At least 3 invalid witnesses that must be
   REJECTED, committed to `vela-verify/corpus/invalid/`. A verifier that
   cannot reject mutants is a rubber stamp and is refused.
5. **Time budget.** Every golden vector verifies in under 10 seconds on
   the reference machine; the full corpus addition keeps
   `vela reproduce` under its current budget.
6. **A pulling problem.** A named open obligation on a live frontier
   that this kind would close or move (no-tool-without-a-pulling-problem
   is doctrine). Cite the obligation finding id.
7. **Dominance order (when applicable).** If records of this kind can
   improve on each other, define `dominates()` so `improves_on` is
   machine-checked.

### Process

Open a PR against constellate-science/vela adding: the `Witness` variant, the
verify fn, golden vectors, mutation cases, and the doc-comment stating
the mathematical claim the verifier checks. CI runs everything above
mechanically.

**Decision SLA: accept or reject with a written reason within 14 days.**
A rejection names the failed criterion; resubmission resets the clock.
Silence past the SLA is a process bug: escalate by opening an issue
titled "RFC SLA breach".

### What is never accepted

Verifiers whose verdict depends on a model, a network service, wall-clock
time, or human judgment mid-run. Judgment enters the protocol as signed
attestations, never inside a verifier.

---

The gate above still presumes a human presses accept on every reproduce-clean
witness. This section is the design that removes the human from the rote,
kernel-clean admit while keeping the human for significance and release.

## The exact-lane gate (machine_verified): de-human-gating the rote admit

*Folded from the former EXACT_LANE_GATE.md.*

> Status: **command shipped + functional; no unattended firing.** The full
> trust path (floor + proposal guards + attachment corroboration + the
> idempotent emit + the tier projection + surfaces) is built and gate-green.
> `vela gate auto-admit <frontier> --finding <vf>` previews read-only;
> `--apply` records the unsigned, idempotent `policy.auto_admitted` ONLY on a
> YES verdict, in the narrow enabled scope (§Enabled scope). It never auto-fires
> (an unattended producer/foundry driving it is Phase 2). Of the §Acceptance
> checklist: **done** = 1 (reproduce-binding, the command re-runs the frozen
> verifier), 2 (faithfulness), 3 (attachment provenance, REVISED: a second
> adversarial review found the human-vouch forgeable via open actor
> self-enrollment, so the vouch is removed from the admission path; the
> un-forgeable floor is the trust and attachments are non-gating corroboration;
> the non-floor lane refuses until an owner-rooted reviewer roster exists), 6
> (producer != verifier), 7 (lifecycle), 9 (idempotent emit), 10 (payload
> validation), 11 (tier honesty), 12 (surface separation, terminal + the
> `finding_context` data layer serve reads); **deferred with rationale** = 4
> (toolchain_hash distinctness, needs the attachment-creation path to populate
> real build hashes first; enforcing it now blocks the lane with no data to
> satisfy it), 5 (a frozen re-runnable FormalismFidelity probe, superseded for
> the exact lane by the floor's `claim_witness_faithful`, which IS the frozen
> faithfulness re-check); **remaining** = the web (`apps/web`) render half of
> #12. This is the design + safety record.

### The problem

Two things block adoption, and neither is capability: everything is
human-gated, and a kernel-clean result still waits on a human key-stamp that
adds no verification. The kernel passing IS the certainty. Making a person
press accept on every reproduce-clean witness is administrative overhead.

The fix is to remove the human from the **rote, kernel-clean** admit while
keeping the human for **significance and release**. The trust model becomes
two distinct tiers:

- **`machine_verified`**: deterministic, unsigned, reproducible. Materialized
  by a frozen audited predicate over frozen verifier evidence. No human, no
  key, no model.
- **`accepted`**: human, signed, key-custody. Significance and consequential
  release. Strictly above `machine_verified`; the machine never reaches it.

"No AI in the trust path" stays literally true: the trust is the frozen
verifier plus an audited deterministic Rust predicate frozen in `vela-verify`,
never a model and never an unaudited stamp.

### The trap the adversarial review caught (read this first)

A naive design auto-admits when the verifier-attachment gate
(`derive_gate_status`) reaches `Verified` and no probe is refuted. **That is
forgeable by the agent producing the claim.** A `VerifierAttachment` is
unsigned, self-asserted data. The same agent that produces a finding can
hand-author two attachments over a *single* run with cosmetic-distinct
`solver_id` / `implementation_id`, a one-directional `independent_of`, a
`Survived` FormalismFidelity probe, and `MethodIntegrity::Sound`. The
attachment-shape guards then pass. Distinct strings are not distinct verifiers:
independence and implementation diversity here are *declared, auditable*
properties, not cryptographic ones. (Two things that previously made this attack
*easier* are now closed: a forged mutual `independent_of` 2-cycle is
unconstructable because the `vva_` id content-addresses `independent_of`, and
gate G4 re-derives `derive_id() == id` so a hand-set forged id never enters the
matched set. The residual self-assertion is why the human accept of the
attachments stays the backstop.)

Worse, `verify_witness` only confirms a witness is *internally* valid (a
genuine Sidon set of size `points.len()`); it never reads the assertion. So an
*inflated* assertion ("a(20) >= 2500") over a valid-but-weaker witness (a real
Sidon set of 1989 points) passes `verify_witness`.

**Conclusion: admission must be re-derived by the gate from inputs the agent
cannot forge, never read from self-asserted fields.**

### The un-forgeable floor (what the gate actually trusts)

Two frozen inputs the producing agent cannot fake:

1. **Fresh `vela reproduce`** over the finding's witness, run by the gate at
   admit time with the frozen `vela-verify` binary. The agent cannot make a
   false witness reproduce.
2. **Frozen claim<->witness faithfulness** (`vela_verify::claim_witness_faithful`,
   shipped): parses the assertion into a structured `ParsedClaim` (kind,
   ambient `n`, lower/exact bound) and asserts the witness's parameters
   *establish* it. Fail-closed: an assertion it cannot parse unambiguously is
   never faithful. This closes the inflated-assertion attack (the 1989-point
   witness is not faithful to an "a(20) >= 2500" claim) and bounds the lane to
   exact size/order claims over the frozen `Witness` variants.

These two are the trust. Everything below is secondary.

### Secondary corroboration (defense in depth, not the trust)

`vela_protocol::verifier_attachment::exact_lane_attachment_admit` (shipped,
red-team-tested 10/10) is strictly stronger than `derive_gate_status == Verified`:

1. gate `Verified` (inherits G1-G5, including G4 id-integrity: every matched
   attachment re-derives `derive_id() == id`, so a forged-id attachment is
   excluded before the lane reasons over it),
2. every matched attachment `MethodIntegrity::Sound` (reject the legacy
   `Unattested` default the gate tolerates),
3. a `FormalismFidelity` probe PRESENT and `Survived` (gate G3 accepts any
   survived probe),
4. declared independence: ≥1 matched attachment names another in
   `independent_of` (one-directional; mutual is a hash circularity over the
   content-addressed id, so the diversity teeth are guard 5 + gate G1, not a
   bidirectional handshake, so do NOT re-tighten to mutual),
5. no implementation monoculture.

This is corroboration metadata. Because it is self-assertable, it is layered
ON TOP of the §The un-forgeable floor, never instead of it. (It also surfaced a
latent bug: `derive_gate_status`'s monoculture comment "never demotes in v1"
contradicts its code; guard 5 insulates the lane from that.)

### The event: `policy.auto_admitted`

Unsigned, deterministic audit record (shipped: const + `KNOWN_EVENT_KINDS` +
`EventKind` enum + validate arm + no-op reducer arms in all three conformance
reducers). `before_hash = after_hash = NULL_HASH` => a no-op on every finding
digest, so `reproduce` / `materialize` stay byte-identical and cross-impl
parity holds. It binds `(proposal_id, claim_digest, attachment_ids,
policy_version, verifier_env_hash)` so any auditor re-derives the admission. It
is mechanically un-signable (no signing step on the path); the human `accepted`
tier is the only signed one. The tier is a **projection** over the log
(`review.accepted` => accepted; else `policy.auto_admitted` + live recomputed
`Verified` => machine_verified), never a stored field, so a forged audit event
cannot by itself raise the tier: the projection recomputes from live evidence.

### Charter reconciliation

- Agents may not accept/finalize a truth-bearing proposal: the path never emits
  `review.accepted`, never calls `accept_proposal_in_frontier_*`, never marks a
  finding human-accepted. `accepted` stays a strictly higher, key-custody tier.
- An AI never signs: the event has `signature: None`; there is no signing step.
- No model in the trust path: the trust is `vela reproduce` +
  `claim_witness_faithful` + the frozen predicate, all audited Rust over frozen
  verifier output. Two reviewers running it get the same answer.

### Acceptance checklist (the lane stays OFF until ALL hold)

From the three-lens adversarial review. Each is a hard requirement, several are
new tests:

1. **Reproduce-binding (critical):** the admit command runs `vela reproduce`
   over the witness itself at admit time and requires PASS; it never trusts a
   recorded result field.
2. **Faithfulness (critical), HARDENED after a third adversarial review.** The
   command calls `claim_witness_faithful` and requires `faithful`. The check now
   binds the WHOLE claim to the witness, not just one parsed token: it reads the
   OEIS order `a(N)` (not only an ambient literal) and binds it to the witness
   `n` (mandatory for every size/order kind; for GF(2) every element must fit in
   `2^N`); it rejects equality/optimality claims and dual-bound assertions; and
   it binds EVERY record-defining parameter (`(kind, n, bound)` for sidon, cap,
   gf2_sidon, union_free, plus the order `h` for B_h and the `(d, w)` for
   constant-weight), routing golomb and every non-size/order kind to review. The
   gate also surfaces `canonical_claim` (the witness-derived verified claim) so
   prose cannot puff a true bound. See §Enabled scope and the
   `claim_witness_faithful` adversarial regression tests
   (`faithful_binds_a_of_n_order_to_witness`,
   `faithful_rejects_dual_bound_headline`, `faithful_gf2_binds_dimension`,
   `faithful_binds_bh_order_and_constant_weight_params`,
   `faithful_routes_equality_optimality_to_review`, `canonical_claim_is_witness_derived`).
3. **Attachment provenance (critical), REVISED after a second adversarial
   review.** The first design verified each matched attachment was "human-
   vouched" by a non-agent reviewer (an accepted `verifier.attach` proposal, or
   a registered-reviewer-signed `verifier_attachment.added` event). A five-lens
   adversarial review found this **forgeable**: actor registration (`vela actor
   add`) is open self-enrollment, so an agent mints a keypair, registers
   `reviewer:<name>` (any id lacking the `agent:` prefix) under its own pubkey,
   and **honestly** signs the vouch with its own key. No private human key is
   needed; every predicate passes. The vouch authenticated a *key*, not a
   *human*. **The fix removes the vouch from the admission path.** The exact
   lane's trust is the FLOOR (guards 1+2: a fresh frozen `vela reproduce` plus
   `claim_witness_faithful`), which an agent cannot forge: a fabricated witness
   does not reproduce, and an inflated claim is not faithful to its witness. The
   floor IS a complete proof of an exact lower-bound/size claim, so matched
   attachments are non-load-bearing corroboration and **do not gate** admission
   (mirroring `exact_lane_auto_admit`'s guard #8, which already waives the
   ≥2-attachment requirement under floor-sufficiency). When the floor does NOT
   hold (the non-exact / Lean lane, where attachments would be the evidence) the
   lane **refuses**, because a sound vouch there must bind the reviewer key to an
   **owner/maintainer-signed roster rooted in the frontier owner key**, which
   does not yet exist. That roster is the prerequisite for ever enabling the
   non-floor lane (it stays off until then). See `attachment_vouch_gate`
   (cli_engine.rs) + its two soundness unit tests.
4. **Independence (high):** require distinct non-empty `toolchain_hash` across
   matched attachments, not just distinct `implementation_id` strings.
5. **Non-vacuous FormalismFidelity (high):** require the probe be backed by a
   frozen re-runnable check, or drop its load-bearing claim.
6. **Positive provenance (high):** replace the "no synthetic_source signal"
   guard with a positive requirement (a SourceRecord typed to a frozen verifier
   run / a present reproduce-clean witness), and require the finding's producing
   actor differ from every verifier_actor on the matched attachments.
7. **Lifecycle (medium):** refuse if the finding is retracted/superseded;
   `derive_trust_tier` treats retract/supersede as overriding machine_verified.
8. **Contradiction (medium):** derive contradictions fresh
   (`FrontierGraph::derive_candidates`), not only persisted adjudicated ones.
9. **Idempotent emit (byte-parity):** re-running `--apply` yields one event and
   a byte-identical log (dedup on `(kind, proposal_id)` or drop the timestamp
   from this kind's content preimage). The `vev_` id includes the timestamp, so
   the parity guarantee is replay-stable, not mint-deterministic; state it that
   way.
10. **Payload validation (medium):** `validate_event_payload` for
    `policy.auto_admitted` requires `claim_digest`, non-empty `attachment_ids`,
    `policy_version`, `verifier_env_hash`, and on replay checks
    `claim_digest == claim_digest(assertion)` and a matching `verifier_env_hash`.
11. **Tier honesty (high):** `derive_trust_tier`'s `Accepted` arm recognizes the
    real human-accept signal the ceremony emits; a human-accepted finding never
    mis-projects as merely machine_verified.
12. **Surface separation (high):** every consumer of the tier (cli finding show,
    serve task-packet/finding_context, atlas, hub, web) renders machine_verified
    visually and semantically distinct from accepted, shows the
    `policy:exact-lane` actor, and labels corroboration as self-asserted unless
    independently keyed. A conformance test asserts no surface collapses the two.

### Enabled scope (when on)

The narrowest safe start: reproduce-clean LOWER-BOUND witnesses where the
verifier IS frozen `vela-verify` and `claim_witness_faithful` binds EVERY
record-defining parameter to the witness. After five adversarial review rounds,
the floor admits a kind only when every parameter that changes its record
hardness is parsed from the assertion and bound to the witness:

- **Sidon ({0,1}^n), Cap (F_3^n), GF(2)-Sidon (GF(2)^n), union-free ({1..n})**:
  fully determined by `(kind, n, bound)`. The floor reads the OEIS order `a(N)`
  (and/or the ambient literal), binds it to the witness `n` (for GF(2), every
  element `< 2^N`), and requires `witness size >= bound`.
- **B_h ({0,1}^n, order h)**: additionally parses `h` (from `B_<h>` / `<h>-fold`)
  and binds `h == witness.h`. Unstated `h` routes to review.
- **constant-weight A(n,d,w)**: additionally parses `(d, w)` from the `A(n,d,w)`
  signature and binds both to the witness. Unstated `(d,w)` routes to review.

Routed to review (NOT floor-admissible): **golomb** (a min-length problem with no
`>=` witness binding) and every non-size/order kind; **equality / optimality
claims** (`= N` / `exactly N`, since a construction witness proves only a lower
bound, never that no larger object exists); and any **dual-bound** assertion (a
`= 2500` headline beside an `at least 5` clause).

The fourth round (5 lenses over the then-four admissible kinds) and the fifth (4
lenses over the B_h/constant-weight binding + the canonical claim) found no
false-bound break: the verifiers constrain each witness to the claimed ambient
space, struct parameters cannot diverge from the verified ones, no admissible
kind carries an unbound hardness parameter, and `len()` is the deduplicated size
the verifier validated.

**Residual closed: the canonical claim.** Author prose could once puff a TRUE
bound ("a(20) >= 5, a new record!"). The gate now derives the verified claim
PURELY from the witness (`vela_verify::canonical_claim`), e.g. "Sidon set:
a(20) >= 1989 (a Sidon set of 1989 points in {0,1}^20)", and surfaces it as the
authoritative `machine_verified` claim, with the author prose demoted to an
unverified description. No FALSE bound, dimension, or hardness parameter can
reach `machine_verified`, and the displayed claim is the witness-verified one,
not the prose. (Surfaces beyond the CLI gate, web/atlas/hub, should display
`canonical_claim` when the lane is enabled and live records exist.)

### Shipped vs pending

- Shipped: `policy.auto_admitted` event kind (all three reducers, no-op);
  `exact_lane_attachment_admit` + 10 red-team tests; `claim_witness_faithful` +
  `parse_claim` + 9 adversarial tests. All gate-green, byte-parity preserved.
- Pending (the lane stays off until done): the §Acceptance checklist, the
  `exact_lane_auto_admit` proposal wrapper, the admit command that runs
  reproduce + faithfulness + the predicate, the idempotent emit, the
  `derive_trust_tier` projection, and the surface separation.

---

The gate decides what counts as verified; this section makes the log it runs
over tamper-evident, so a client can verify membership and append-only growth
without trusting the hub.

## Transparency log (P2)

*Folded from the former TRANSPARENCY_LOG.md.*

RFC 6962-style Merkle transparency log over each frontier's append-only event
log. The unit of trust is the **event content-address preimage**: a log leaf is
exactly the bytes whose SHA-256 is an event's `vev_` id
(`vela_protocol::events::event_content_preimage_bytes`). The leaf excludes the
event's `id`, `signature`, and `schema_artifact_id`, so it is immune to
legitimate re-signing and reproducible byte-for-byte by any independent
implementation that can produce `vela.canonical-json/v1`.

This is the load-bearing minimal core: a signed tree head, inclusion proofs, and
consistency proofs: everything a client needs to verify membership and
append-only growth without trusting the hub. Witness co-signing (defeating
split-view) is the documented next phase (§Witness co-signing).

### Endpoints

All read-only, cacheable, served by `vela-hub` over the existing
`frontier_events` projection. `merkle_root`, `inclusion_proof`,
`consistency_proof`, and their verifiers live in
`crates/vela-protocol/src/merkle.rs` (RFC 6962 §2.1; exhaustive property tests).

#### `GET /entries/{vfr}/log/sth`: signed tree head

```json
{
  "sth": {
    "schema": "vela.sth.v1",
    "log_id": "vela-log:<vfr>:<hub-pubkey-hex>",
    "vfr_id": "vfr_…",
    "tree_size": 33,
    "root_hash": "sha256:…",
    "timestamp": "2026-06-03T…Z"
  },
  "signature": {
    "alg": "Ed25519", "alg_variant": "pure",
    "pubkey": "<hex>", "value": "<hex>",
    "canonical_format": "vela.canonical-json/v1",
    "verifier_steps": ["…"]
  },
  "mode": "signed"
}
```

The signature is Ed25519 (pure) over `to_canonical_bytes(sth)`. When the hub has
no signing key, `mode` is `"unsigned"` and `signature` is null. The hub publishes
its public key at `/.well-known/vela` for first-use pinning.

#### `GET /entries/{vfr}/log/proof/{event_id}`: inclusion proof

Returns `{leaf_index, tree_size, root_hash, audit_path: [hex…]}`. The verifier
rebuilds the leaf preimage from event content, then reconstructs the root from
the leaf + audit path alone (`verify_inclusion`) and checks it equals the signed
STH root.

#### `GET /entries/{vfr}/log/consistency?first={m}&second={n}`: consistency proof

`second` defaults to the current length. Returns `{first_size, second_size,
first_root, second_root, consistency_proof: [hex…]}`. Lets a verifier holding an
older signed STH (size `m`) confirm the log only **grew**, never forked or
rewrote history, before trusting a newer STH (size `n`). `verify_consistency`
reconstructs both roots from the proof alone.

### Independent verifier

`clients/python/vela_verify_log.py` (also published at
`app.constellate.science/vela_verify_log.py`). Pure Python; reproduces
`vela.canonical-json/v1` and the RFC 6962 hashing. With **no trust** in the hub
it checks, in order:

1. the STH Ed25519 signature over `canonical(sth)`;
2. every event's content reproduces its `vev_` id (canonical-JSON parity);
3. the recomputed Merkle root equals the signed STH root;
4. an inclusion proof reconstructs that root from a leaf + audit path;
5. (with `--consistency-from M`) the log is an append-only extension of size `M`.

```
python3 vela_verify_log.py --hub https://hub.constellate.science \
    --vfr vfr_06cfcbe7c449d86a --pubkey <pinned-hex> [--consistency-from 1000]
```

`pip install pynacl` for the signature step (skipped with a loud warning
otherwise; the Merkle checks still run). Pinning `--pubkey` out of band is what
makes this a real tamper check rather than a corruption check.

Verified against the Rust hub on a 33-event frontier: signature valid, all
`vev_` ids reproduce, roots match, inclusion + consistency verify, and a wrong
pinned key correctly **fails**.

### Trust model

- **Pin the hub key out of band.** The STH advertises a pubkey; a malicious hub
  could advertise its own. Pinning (`/.well-known/vela` on first use, stored by
  the verifier) is what binds the log to an identity.
- **Save STHs to detect rewrites.** A single STH proves the current root is
  signed; it does not prove the hub never rewrote history. Saving an STH and
  later running a consistency proof against it does. Witnesses
  (§Witness co-signing) remove the need for each client to do this.
- **Split-view is still possible until witnesses exist.** A hub can show
  consistent-but-divergent logs to different clients. Only independent witnesses
  co-signing STHs close this.

### Witness co-signing: designed, not yet built (recruitment-gated)

A witness is an independent party that periodically fetches a hub's STH,
verifies it (and consistency vs. the last STH it saw), and **co-signs** it. A
verifier that pins a set of witness keys and requires ≥k co-signatures cannot be
shown a split view, because the witnesses would have to collude.

Design (deliberately not deployed until a real second signer exists, since shipping a
write-accepting endpoint nothing exercises is dead, risky surface):

- **Table** `sth_witness_cosignatures(vfr_id, tree_size, root_hash,
  sth_timestamp, witness_id, witness_pubkey, cosignature, received_at)`, PK
  `(vfr_id, tree_size, root_hash, witness_pubkey)`. Dual Postgres/SQLite, same
  pattern as the existing projection tables.
- **`POST /entries/{vfr}/log/sth/cosign`** `{sth, witness_id, witness_pubkey,
  cosignature}`. The hub (a) re-canonicalizes `sth` and verifies the
  cosignature is Ed25519 over those bytes by `witness_pubkey`; (b) confirms the
  STH is one it actually issued by recomputing the size-`tree_size` root and
  checking it equals `sth.root_hash`; then stores it. The cosignature binds the
  STH **timestamp** because the timestamp is inside the canonical `sth` the
  witness signs, so a cosignature is pinned to a specific issuance.
- **`GET /entries/{vfr}/log/witnesses?tree_size=&root_hash=`** returns the
  stored cosignatures with enough fields (`log_id, tree_size, root_hash,
  timestamp`) for a verifier to rebuild each `sth` and check each cosignature
  against an out-of-band-pinned witness set.
- Self-authenticating writes (Ed25519-verified, must match a real issued STH);
  trusting *which* witnesses is the verifier's out-of-band job.

Only **recruiting the first independent witness host** is external. The protocol
and storage are specified above and slot into the existing dual-arm db + axum
handler patterns.

### Not in scope here

- STH anchoring to a public chain/log for independent timestamping (P4).
- Chunk-dedup of bulk objects (P3: measure first; the CAS stub breaks the typed
  materializer).
- Proof-Carrying-Knowledge / constant-size DAG verification (research, P4+).
