# The exact-lane gate (machine_verified): de-human-gating the rote admit

> Status: **lane DISABLED.** Stages 1, 2, and the faithfulness floor are built
> and gate-green; the lane does not auto-admit anything until the acceptance
> checklist (§7) is met. This is the design + safety record, not a claim that
> machine admission is live.

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
2. **Faithfulness (critical):** the command calls `claim_witness_faithful` and
   requires `faithful` (shipped function; wiring pending).
3. **Attachment provenance (critical):** verify each matched attachment landed
   via a human-accepted `verifier.attach` proposal whose reviewer is a non-agent
   key, OR document this as a hard invariant with a conformance test that an
   agent cannot self-apply `verifier.attach`. (Today it is excluded from all
   agent self-apply sets; the gate must enforce or test it, not assume it.)
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

The narrowest safe start: reproduce-clean exact witnesses where the verifier IS
frozen `vela-verify` and `claim_witness_faithful` parses the assertion (Sidon /
Golomb / Cap / Bh / GF(2)-Sidon / constant-weight / union-free lower-bound and
matched-equality size/order claims). It widens only as the faithfulness parser
and the §7 checks mature. Everything else routes to human review, unchanged.

## 9. Shipped vs pending

- Shipped: `policy.auto_admitted` event kind (all three reducers, no-op);
  `exact_lane_attachment_admit` + 9 red-team tests; `claim_witness_faithful` +
  `parse_claim` + 9 adversarial tests. All gate-green, byte-parity preserved.
- Pending (the lane stays off until done): the §7 checklist, the
  `exact_lane_auto_admit` proposal wrapper, the admit command that runs
  reproduce + faithfulness + the predicate, the idempotent emit, the
  `derive_trust_tier` projection, and the surface separation.
