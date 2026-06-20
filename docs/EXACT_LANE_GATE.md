# The exact-lane gate (machine_verified): de-human-gating the rote admit

> Status: **command shipped + functional; no unattended firing.** The full
> trust path (floor + proposal guards + attachment corroboration + the
> idempotent emit + the tier projection + surfaces) is built and gate-green.
> `vela gate auto-admit <frontier> --finding <vf>` previews read-only;
> `--apply` records the unsigned, idempotent `policy.auto_admitted` ONLY on a
> YES verdict, in the narrow enabled scope (§8). It never auto-fires — an
> unattended producer/foundry driving it is Phase 2. Of the §7 checklist:
> **done** = 1 (reproduce-binding, the command re-runs the frozen verifier),
> 2 (faithfulness), 3 (attachment provenance — REVISED: a second adversarial
> review found the human-vouch forgeable via open actor self-enrollment, so the
> vouch is removed from the admission path; the un-forgeable floor is the trust
> and attachments are non-gating corroboration; the non-floor lane refuses until
> an owner-rooted reviewer roster exists), 6 (producer != verifier), 7
> (lifecycle), 9 (idempotent emit), 10 (payload validation), 11 (tier honesty),
> 12 (surface separation, terminal + the `finding_context` data layer serve
> reads); **deferred with rationale** = 4
> (toolchain_hash distinctness — needs the attachment-creation path to populate
> real build hashes first; enforcing it now blocks the lane with no data to
> satisfy it), 5 (a frozen re-runnable FormalismFidelity probe — superseded for
> the exact lane by the floor's `claim_witness_faithful`, which IS the frozen
> faithfulness re-check); **remaining** = the web (`apps/web`) render half of
> #12. This is the design + safety record.

## 1. The problem

Two things block adoption, and neither is capability: everything is
human-gated, and a kernel-clean result still waits on a human key-stamp that
adds no verification. The kernel passing IS the certainty. Making a person
press accept on every reproduce-clean witness is administrative overhead.

The fix is to remove the human from the **rote, kernel-clean** admit while
keeping the human for **significance and release**. The trust model becomes
two distinct tiers:

- **`machine_verified`** — deterministic, unsigned, reproducible. Materialized
  by a frozen audited predicate over frozen verifier evidence. No human, no
  key, no model.
- **`accepted`** — human, signed, key-custody. Significance and consequential
  release. Strictly above `machine_verified`; the machine never reaches it.

"No AI in the trust path" stays literally true: the trust is the frozen
verifier plus an audited deterministic Rust predicate frozen in `vela-verify`,
never a model and never an unaudited stamp.

## 2. The trap the adversarial review caught (read this first)

A naive design auto-admits when the verifier-attachment gate
(`derive_gate_status`) reaches `Verified` and no probe is refuted. **That is
forgeable by the agent producing the claim.** A `VerifierAttachment` is
unsigned, self-asserted data. The same agent that produces a finding can
hand-author two attachments over a *single* run with cosmetic-distinct
`solver_id` / `implementation_id`, self-assert mutual `independent_of`, a
`Survived` FormalismFidelity probe, and `MethodIntegrity::Sound`. All five
attachment-shape guards then pass. Distinct strings are not distinct verifiers.

Worse, `verify_witness` only confirms a witness is *internally* valid (a
genuine Sidon set of size `points.len()`); it never reads the assertion. So an
*inflated* assertion ("a(20) >= 2500") over a valid-but-weaker witness (a real
Sidon set of 1989 points) passes `verify_witness`.

**Conclusion: admission must be re-derived by the gate from inputs the agent
cannot forge, never read from self-asserted fields.**

## 3. The un-forgeable floor (what the gate actually trusts)

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

## 4. Secondary corroboration (defense in depth, not the trust)

`vela_protocol::verifier_attachment::exact_lane_attachment_admit` (shipped,
red-team-tested 9/9) is strictly stronger than `derive_gate_status == Verified`:

1. gate `Verified` (inherits G1-G5),
2. every matched attachment `MethodIntegrity::Sound` (reject the legacy
   `Unattested` default the gate tolerates),
3. a `FormalismFidelity` probe PRESENT and `Survived` (gate G3 accepts any
   survived probe),
4. mutual independence (gate G1 accepts one-directional),
5. no implementation monoculture.

This is corroboration metadata. Because it is self-assertable, it is layered
ON TOP of the §3 floor, never instead of it. (It also surfaced a latent bug:
`derive_gate_status`'s monoculture comment "never demotes in v1" contradicts
its code; guard 5 insulates the lane from that.)

## 5. The event: `policy.auto_admitted`

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
cannot by itself raise the tier — the projection recomputes from live evidence.

## 6. Charter reconciliation

- Agents may not accept/finalize a truth-bearing proposal: the path never emits
  `review.accepted`, never calls `accept_proposal_in_frontier_*`, never marks a
  finding human-accepted. `accepted` stays a strictly higher, key-custody tier.
- An AI never signs: the event has `signature: None`; there is no signing step.
- No model in the trust path: the trust is `vela reproduce` +
  `claim_witness_faithful` + the frozen predicate, all audited Rust over frozen
  verifier output. Two reviewers running it get the same answer.

## 7. Acceptance checklist (the lane stays OFF until ALL hold)

From the three-lens adversarial review. Each is a hard requirement, several are
new tests:

1. **Reproduce-binding (critical):** the admit command runs `vela reproduce`
   over the witness itself at admit time and requires PASS; it never trusts a
   recorded result field.
2. **Faithfulness (critical) — HARDENED after a third adversarial review.** The
   command calls `claim_witness_faithful` and requires `faithful`. The check now
   binds the WHOLE claim to the witness, not just one parsed token: it reads the
   OEIS order `a(N)` (not only an ambient literal) and binds it to the witness
   `n` (mandatory for every size/order kind; for GF(2) every element must fit in
   `2^N`); it rejects equality/optimality claims and dual-bound assertions; and
   it binds EVERY record-defining parameter — `(kind, n, bound)` for sidon, cap,
   gf2_sidon, union_free, plus the order `h` for B_h and the `(d, w)` for
   constant-weight — routing golomb and every non-size/order kind to review. The
   gate also surfaces `canonical_claim` (the witness-derived verified claim) so
   prose cannot puff a true bound. See §8 and the `claim_witness_faithful`
   adversarial regression tests (`faithful_binds_a_of_n_order_to_witness`,
   `faithful_rejects_dual_bound_headline`, `faithful_gf2_binds_dimension`,
   `faithful_binds_bh_order_and_constant_weight_params`,
   `faithful_routes_equality_optimality_to_review`, `canonical_claim_is_witness_derived`).
3. **Attachment provenance (critical) — REVISED after a second adversarial
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
   `claim_witness_faithful`), which an agent cannot forge — a fabricated witness
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

## 8. Enabled scope (when on)

The narrowest safe start: reproduce-clean LOWER-BOUND witnesses where the
verifier IS frozen `vela-verify` and `claim_witness_faithful` binds EVERY
record-defining parameter to the witness. After five adversarial review rounds,
the floor admits a kind only when every parameter that changes its record
hardness is parsed from the assertion and bound to the witness:

- **Sidon ({0,1}^n), Cap (F_3^n), GF(2)-Sidon (GF(2)^n), union-free ({1..n})** —
  fully determined by `(kind, n, bound)`. The floor reads the OEIS order `a(N)`
  (and/or the ambient literal), binds it to the witness `n` (for GF(2), every
  element `< 2^N`), and requires `witness size >= bound`.
- **B_h ({0,1}^n, order h)** — additionally parses `h` (from `B_<h>` / `<h>-fold`)
  and binds `h == witness.h`. Unstated `h` routes to review.
- **constant-weight A(n,d,w)** — additionally parses `(d, w)` from the `A(n,d,w)`
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

**Residual closed — the canonical claim.** Author prose could once puff a TRUE
bound ("a(20) >= 5, a new record!"). The gate now derives the verified claim
PURELY from the witness (`vela_verify::canonical_claim`) — e.g. "Sidon set:
a(20) >= 1989 (a Sidon set of 1989 points in {0,1}^20)" — and surfaces it as the
authoritative `machine_verified` claim, with the author prose demoted to an
unverified description. No FALSE bound, dimension, or hardness parameter can
reach `machine_verified`, and the displayed claim is the witness-verified one,
not the prose. (Surfaces beyond the CLI gate — web/atlas/hub — should display
`canonical_claim` when the lane is enabled and live records exist.)

## 9. Shipped vs pending

- Shipped: `policy.auto_admitted` event kind (all three reducers, no-op);
  `exact_lane_attachment_admit` + 9 red-team tests; `claim_witness_faithful` +
  `parse_claim` + 9 adversarial tests. All gate-green, byte-parity preserved.
- Pending (the lane stays off until done): the §7 checklist, the
  `exact_lane_auto_admit` proposal wrapper, the admit command that runs
  reproduce + faithfulness + the predicate, the idempotent emit, the
  `derive_trust_tier` projection, and the surface separation.
