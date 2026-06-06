# Reviewer playbook — anti-amyloid decision substrate

The decision substrate is staged for one focused `reviewer:will-blair`
pass. This is the exact, ordered command set. Step 1 has been
completed in the current frontier. Steps 2-4 state the real mechanism
and the remaining reviewer work honestly. No step is pretended ready.

Nothing here is run by the agent. Every signature attests human
judgement under a key the substrate must never hold.

## Step 1 — corpus attestation (complete in current frontier)

22 source-inbox records mapped exactly to the 22-source decision
corpus (`review/decision-corpus-queue.v1.md`). Verifying attests "this
is the right corpus and every entry resolves", not a science
judgement. In the current frontier all 27 source-inbox records are
`verified` and 0 are `discovered`. If rebuilding from a pre-attestation
frontier, the preferred guarded path is:

```bash
ANTI_AMYLOID_CORPUS_REVIEW=1 ./scripts/reviewer-corpus-attest.sh
```

The script is human-only: it refuses without the env guard, an
interactive terminal, and an exact typed confirmation. The underlying
commands are listed below for auditability and manual fallback. Run, in
any order:

```bash
cat >/tmp/anti-amyloid-corpus-attest.tsv <<'EOF'
vsrcin_1bd56785b0211b4c	corpus attestation: pmid:32722745 - plasma p-tau217 diagnostic accuracy
vsrcin_9bc31e6afd30a507	corpus attestation: pmid:33656288 - amyloid hypothesis versus clinical benefit (contested causal)
vsrcin_a96c19737d87723b	corpus attestation: pmid:33865446 - lecanemab phase 2b BAN2401 Study 201
vsrcin_70973ece35e6dadf	corpus attestation: pmid:34905145 - amyloid-PET Centiloid quantification
vsrcin_f2d656dc146141ce	corpus attestation: pmid:35099507 - ARIA / APOE4 monoclonal-antibody safety
vsrcin_29c6a55e0cedd009	corpus attestation: pmid:35401412 - ARIA / APOE4 monoclonal-antibody safety
vsrcin_9779d31310e0e1bd	corpus attestation: pmid:35542990 - aducanumab EMERGE/ENGAGE phase 3
vsrcin_e905d0cc7b99d471	corpus attestation: pmid:35542991 - aducanumab EMERGE/ENGAGE companion
vsrcin_a4ed10ec083e1977	corpus attestation: pmid:36094645 - donanemab TRAILBLAZER-ALZ phase 2
vsrcin_ee9acc9cee65b9a8	corpus attestation: pmid:36449413 - lecanemab CLARITY-AD pivotal
vsrcin_d2f12e8382d84fb1	corpus attestation: pmid:37357276 - ARIA / APOE4 monoclonal-antibody safety
vsrcin_69ba1d1f4c14092c	corpus attestation: pmid:37459141 - donanemab TRAILBLAZER-ALZ 2 pivotal
vsrcin_f98ba0af1d74e131	corpus attestation: pmid:37966285 - gantenerumab GRADUATE I/II phase 3
vsrcin_e9f560562dc44bd2	corpus attestation: pmid:37995736 - ARIA / APOE4 monoclonal-antibody safety
vsrcin_d3f932dca834c0f7	corpus attestation: pmid:38252443 - plasma p-tau217 diagnostic accuracy
vsrcin_d2c7553478c175bd	corpus attestation: pmid:38730496 - lecanemab CLARITY-AD updated safety
vsrcin_ad4a22e5f729c114	corpus attestation: pmid:38961808 - amyloid-PET Centiloid quantification
vsrcin_a20e44079fddacd7	corpus attestation: pmid:39887500 - gantenerumab GRADUATE follow-up
vsrcin_ea85b5a9d8b1b746	corpus attestation: pmid:39998021 - donanemab vs aducanumab amyloid clearance, TRAILBLAZER-ALZ 4
vsrcin_f7ce98ef8a7a9115	corpus attestation: pmid:40011173 - ARIA / APOE4 monoclonal-antibody safety
vsrcin_c534f193134fde9f	corpus attestation: pmid:40156286 - plasma p-tau217 diagnostic accuracy
vsrcin_349dc71ba1eef4df	corpus attestation: pmid:40720133 - amyloid-PET Centiloid quantification
EOF

while IFS=$'\t' read -r id reason; do
  vela source-inbox verify projects/anti-amyloid-translation "$id" \
    --reviewer reviewer:will-blair \
    --reason "$reason"
done </tmp/anti-amyloid-corpus-attest.tsv
```

After this, all 22 corpus records are `verified` and the corpus is
reviewer-backed. Confirm the current state with:

```bash
vela source-inbox list projects/anti-amyloid-translation --json \
  | jq '{
      total: (.records | length),
      discovered: ([.records[] | select(.state == "discovered")] | length),
      verified: ([.records[] | select(.state == "verified")] | length),
      rejected: ([.records[] | select(.state == "rejected")] | length)
    }'
```

Expected after the corpus pass: `discovered == 0`, `verified == 27`,
and `rejected == 0`.

## Step 2 — extraction batch-sign (mechanism + required agent step)

`review/decision-extraction-queue.v1.md` holds E1-E12: 11 sources of
verbatim quantitative extraction (all pivotal trials + the aducanumab
EMERGE/ENGAGE primary and controversy), each a real `pmid:`/`doi:`/
`nct:` locator with transcribed spans, batch-signable class per
`review/extraction-policy.v1.md`.

Run, in an interactive terminal, as you:

```bash
WILL_BLAIR_REVIEW=1 ./scripts/reviewer-extraction-signoff.sh
```

Per E-item this runs `vela finding add` (author
`agent:extraction-bot-2026-05-16`, classified agent — not a verdict),
captures the proposal id, then `vela accept <vpr_> --reviewer
reviewer:will-blair`: your signed canonical event applying the
agent-drafted extraction. Assertions are faithful concise
restatements; `--evidence-span`s are the verbatim quotes already in
`review/decision-extraction-queue.v1.md` — nothing from memory.

This is **stage 1 of a curation wave, not a one-shot to
release-clean**. In the current post-wave frontier, E1-E12 already
appear as agent-drafted findings accepted by `reviewer:will-blair`, and
the baseline-sensitive release gates have already been recalibrated.
Do not rerun the script unless you are intentionally rebuilding from a
pre-wave frontier.

- The script lands E1-E12 as reviewer-accepted findings, re-locks,
  and re-seals the proof. End state: `vela check` `state_integrity:
  ok`, `errors: 0`, replay ok, findings 144 → ~156, `snapshot_hash`
  moved off `b9559279`. This **is** your action and mutates the
  flagship.
- It is **not** release-clean. `vela check --strict` is `ok=false`
  because the new findings are unsigned (no Ed25519 envelope). The
  remaining wave is your follow-on and is partly key-gated:
  1. `vela attest <frontier> --key <your Ed25519 key>` — sign the new
     findings (only you hold the key; the agent cannot do this).
  2. Complete A1-A5, R1-R3, and P1-P2 reviewer verdicts.
  3. Send and return R1-R4 outside-review packets with action maps.
  4. Run the completion validators until both human and outside-review
     completion are green.

So the genuinely turnkey part of this playbook is Step 1 (corpus
attestation) and the stage-1 script; the finding wave's completion is
a real reviewed+signed curation pass, not a script.

## Trust model (honest disclosure)

`vela propose`/`vela accept --reviewer` take **no key**. There is no
cryptographic barrier on a `reviewer:will-blair` verdict at the
propose/accept layer — "reviewer authority" is the id string. The
integrity model rests on: (1) **you** being the operator at this
layer; (2) the separate `vela attest`/`sign apply` key layer; and
(3) the fail-closed external-review harness for cold-reviewer
provenance. That is exactly why the agent never runs these and why
`scripts/reviewer-extraction-signoff.sh` hard-refuses unless
`WILL_BLAIR_REVIEW=1` with an interactive TTY and a typed
confirmation: an executable file emitting a will-blair verdict is a
forgery vector if anything but you runs it. The agent's session-long
refusal to sign is load-bearing, not theatrical.

## Step 3 — adjudication A1-A5 (full reviewer judgement)

`review/decision-adjudication-queue.v1.md`: five full-adjudication
nodes — efficacy magnitude/MCID, the amyloid-clearance↔clinical-
benefit causal node (the gantenerumab "amyloid down, no benefit"
contrast in E8 is the pivot), ARIA/unblinding, APOE4, benefit-risk.
Same instantiation gap as Step 2: each node must exist as a
`vf_`/`vpr_` object, then per-node:

```bash
vela propose projects/anti-amyloid-translation <vf_id> \
  --status accepted|contested|rejected --reviewer reviewer:will-blair \
  --reason "<your verdict>"   # individually; reject liberally
```

Record the explicit reviewer disposition in the decision ledger as
well. Rejection, contest, and deferral are valid holds when the
evidence does not support a canonical finding.

```bash
./scripts/build-anti-amyloid-decision-review-ledger.sh /tmp/vela-decision-review-ledger-template
./scripts/init-anti-amyloid-decision-review-ledger.sh
./scripts/build-anti-amyloid-decision-review-worksheet.sh /tmp/vela-decision-review-worksheet
# fill projects/anti-amyloid-translation/review/decision-review-ledger.v1.json as reviewer:will-blair
./scripts/validate-anti-amyloid-decision-review-ledger.sh \
  projects/anti-amyloid-translation/review/decision-review-ledger.v1.json \
  --out /tmp/vela-decision-review-ledger --expect-complete
```

## Step 4 — replication / prediction R1-R3, P1-P2

`review/decision-replication-queue.v1.md`: `replicates` edges +
predictions, full-adjudication, accept only genuine ones. Same
instantiation-then-`vela accept` mechanism as Step 3. The same
decision ledger records R1-R3 and P1-P2 dispositions.

## What flips on completion

After Steps 2-4 land signed canonical events, `vela decision-brief
projects/anti-amyloid-translation` moves off "NOT decision-ready",
`_meta.snapshot_hash` advances from `b9559279`, and the frontier is
dense and signed.

## The true P1 (parallel)

The real outside-scientist cold-reviewer run
(`docs/COLD_REVIEWER_KIT.md`, fail-closed harness). It validates the
science; no review pass or engineering substitutes for it.

Use the read-only outside-review worksheet before dispatching or
recording returns:

```bash
./scripts/build-anti-amyloid-outside-review-worksheet.sh /tmp/vela-outside-review-worksheet
```
