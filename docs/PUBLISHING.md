# Publishing Vela frontiers

This document defines the public release path for frontier state. It
covers three distribution surfaces:

- GitHub release artifacts: immutable files, proof packets, manifests,
  and checksums.
- Hub mirror: signed transport for a live `vfr_*` entry.
- Optional dataset-style mirror: a Hugging Face dataset repository or
  equivalent archive carrying the same release pack.

The local frontier remains the authority. A mirror helps other people
find and verify state. It does not make the science true.

## Current frontier package

The reference package is:

```text
projects/anti-amyloid-translation/
```

Read these files first:

- `projects/anti-amyloid-translation/FRONTIER_CARD.md`
- `projects/anti-amyloid-translation/FRONTIER_PACKAGE.md`
- `projects/anti-amyloid-translation/review/outside-review-2026-q2.md`
- `docs/OPEN_SCIENTIFIC_STATE.md`
- `docs/REVIEWER_PLAYBOOK.md`
- `docs/COLD_REVIEWER_KIT.md`

Current boundary: the anti-amyloid decision substrate is prepared but
not yet decision-ready. The corpus attestation and extraction signoff
are complete in the current frontier. Adjudication, replication and
prediction review, and outside-scientist review remain required.

## GitHub release artifact pack

Build the release assets from the repository root:

```bash
cargo build --release --bin vela
./scripts/package-release-assets.sh /tmp/vela-release-assets
./tests/test-release-bundle-manifest.sh /tmp/vela-release-assets
./scripts/validate-workbench-review-work-snapshots.sh \
  /tmp/vela-release-assets \
  --out /tmp/vela-workbench-review-work-snapshot-validation
```

The pack must include:

- `RELEASE_MANIFEST.json`
- `CITATION.cff`
- `LICENSE-APACHE`
- `LICENSE-MIT`
- `SHA256SUMS`
- `anti-amyloid-translation.json`
- `anti-amyloid-translation-proof-packet.tar.gz`
- `packet-validate-anti-amyloid-translation.txt`
- `anti-amyloid-decision-brief.v1.json`
- `anti-amyloid-decision-brief-projection.json`
- `anti-amyloid-trial-outcomes.v1.json`
- `anti-amyloid-source-verification.v1.json`
- `anti-amyloid-source-ingest-plan.v1.json`
- `OPEN_SCIENTIFIC_STATE.md`
- `neuro-translation-atlas-manifest.yaml`
- `neuro-translation-atlas-snapshot.json`
- `neuro-translation-atlas-index.html`
- `anti-amyloid-frontier-card.md`
- `anti-amyloid-frontier-package.md`
- `anti-amyloid-outside-review-2026-q2.md`
- `anti-amyloid-outside-review-launch-2026-q2.md`
- `cold-reviewer-packet-validation.json`
- `cold-reviewer-packet-validation.md`
- `outside-review-return-template.md`
- `outside-review-action-map-template.md`
- `anti-amyloid-outside-review-completion-validation.json`
- `anti-amyloid-outside-review-completion-validation.md`
- `anti-amyloid-human-reviewer-handoff.json`
- `anti-amyloid-human-reviewer-handoff.md`
- `anti-amyloid-human-reviewer-execution-checklist.json`
- `anti-amyloid-human-reviewer-execution-checklist.md`
- `anti-amyloid-decision-review-ledger.template.json`
- `anti-amyloid-decision-review-ledger.template.md`
- `anti-amyloid-human-reviewer-handoff-validation.json`
- `anti-amyloid-human-reviewer-handoff-validation.md`
- `anti-amyloid-human-reviewer-completion-validation.json`
- `anti-amyloid-human-reviewer-completion-validation.md`
- `gbm-egfrviii-strict-signal-human-handoff.json`
- `gbm-egfrviii-strict-signal-human-handoff.md`
- `gbm-egfrviii-strict-signal-execution-checklist.json`
- `gbm-egfrviii-strict-signal-execution-checklist.md`
- `gbm-egfrviii-strict-signal-human-handoff-validation.json`
- `gbm-egfrviii-strict-signal-human-handoff-validation.md`
- `gbm-egfrviii-strict-signal-completion-validation.json`
- `gbm-egfrviii-strict-signal-completion-validation.md`
- `pediatric-hgg-cleanup-packet.json`
- `PEDIATRIC_HGG_CLEANUP_PACKET.md`
- `pediatric-hgg-cleanup-lanes.json`
- `PEDIATRIC_HGG_CLEANUP_LANES.md`
- `pediatric-hgg-cleanup-packet-validation.json`
- `pediatric-hgg-cleanup-packet-validation.md`
- `pediatric-hgg-cleanup-packet.tar.gz`
- `pediatric-hgg-human-handoff.json`
- `pediatric-hgg-human-handoff.md`
- `pediatric-hgg-execution-checklist.json`
- `pediatric-hgg-execution-checklist.md`
- `pediatric-hgg-human-handoff-validation.json`
- `pediatric-hgg-human-handoff-validation.md`
- `pediatric-hgg-cleanup-completion-validation.json`
- `pediatric-hgg-cleanup-completion-validation.md`
- `decision-grade-completion-audit.json`
- `decision-grade-completion-audit.md`
- `SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json`
- `SCIENTIFIC_STATE_ARTIFACT_CONTRACT.md`
- `DECISION_GRADE_NEXT_ACTIONS.json`
- `DECISION_GRADE_NEXT_ACTIONS.md`
- `anti-amyloid-review-work.json`
- `anti-amyloid-review-work.md`
- `gbm-egfrviii-review-work.json`
- `gbm-egfrviii-review-work.md`
- `pediatric-hgg-review-work.json`
- `pediatric-hgg-review-work.md`
- `workbench-review-work-snapshot-validation.json`
- `workbench-review-work-snapshot-validation.md`
- `cold-reviewer-packet.tar.gz`
- `source-freshness-anti-amyloid-translation.json`
- `trust-audit-anti-amyloid-translation.json`

Use a GitHub release when you want a citable frozen package. Upload
the files in `/tmp/vela-release-assets` as release assets for the
matching tag in `RELEASE_MANIFEST.json`.

Do not publish a decision-grade release note until the reviewer gates
listed in `FRONTIER_PACKAGE.md` are complete.

## Public release set

For a full public artifact set, build the composed release directory:

```bash
./scripts/package-public-release-set.sh /tmp/vela-public-release-set
./tests/test-public-release-set.sh /tmp/vela-public-release-set
./scripts/validate-public-release-set.sh /tmp/vela-public-release-set \
  --out /tmp/vela-public-release-set-download-validation
```

If `/tmp/vela-release-assets` already exists and has been verified,
reuse it instead of rebuilding the asset pack:

```bash
./scripts/package-public-release-set.sh \
  /tmp/vela-public-release-set \
  /tmp/vela-release-assets
```

The generated directory contains:

```text
README.md
START_HERE.md
CLEAN_RELEASE_START_HERE.md
CITATION.cff
LICENSE-APACHE
LICENSE-MIT
SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json
SCIENTIFIC_STATE_ARTIFACT_CONTRACT.md
PUBLIC_RELEASE_SET_MANIFEST.json
PUBLIC_RELEASE_SET_VALIDATION.json
PUBLIC_RELEASE_SET_VALIDATION.md
public-release-set-validation.json      # emitted by scripts/validate-public-release-set.sh
public-release-set-validation.md        # emitted by scripts/validate-public-release-set.sh
CITATION.cff                         # inside vela-v<tag>-release-assets/
OUTSIDE_REVIEW_DISPATCH.json
OUTSIDE_REVIEW_DISPATCH.md
OUTSIDE_REVIEW_DISPATCH_VALIDATION.json
OUTSIDE_REVIEW_DISPATCH_VALIDATION.md
GBM_STRICT_SIGNAL_START_HERE.md
PEDIATRIC_HGG_START_HERE.md
gbm-strict-signal-review-packet-validation.json
gbm-strict-signal-review-packet-validation.md
outside-review-send-kits/
outside-review-return-stubs/
outside-review-action-map-stubs/
SHA256SUMS
vela-v<tag>-release-assets/
github-release/vela-v<tag>-release-assets.tar.gz
huggingface-dataset-mirror/
reviewer-packets/gbm-egfrviii-strict-signal/
```

`PUBLIC_RELEASE_SET_MANIFEST.json` uses schema
`vela.public_release_set.v0.1`.
The public set carries a root-level copy of `OPEN_SCIENTIFIC_STATE.md`.
`README.md` includes `Start here: `START_HERE.md`` so a downloaded
public release set has one coordinator entrypoint before the lane-specific
handoffs.
`README.md` includes `Clean release start here: `CLEAN_RELEASE_START_HERE.md``
so maintainers have a direct path for clean-checkout and fresh clone
release certification.
`README.md` includes
`Open scientific-state map: `OPEN_SCIENTIFIC_STATE.md`` so consumers can
start from the release map before opening nested assets.
The root `CITATION.cff` is byte-for-byte copied from
`vela-v<tag>-release-assets/CITATION.cff`, and `README.md` includes
`Root citation metadata: `CITATION.cff`` so a downloaded public set is
citable without digging into nested release assets.
The root `LICENSE-APACHE` and `LICENSE-MIT` files are byte-for-byte
copied from `vela-v<tag>-release-assets/`, and `README.md` includes
`Root licenses: `LICENSE-APACHE`, `LICENSE-MIT`` so the software
license terms are visible at the top of the downloaded public set.
The public set also carries a root-level copy of `SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json`
and `.md`; `README.md` includes
`Root artifact contract: `SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json`` so
consumers can inspect the release-file authority contract before opening
nested assets.
`scripts/validate-public-release-set.sh` emits
`public-release-set-validation.json` with schema
`vela.public_release_set_download_validation.v0.1` and a matching
Markdown report. This validator is the read-only check for a downloaded
public release set: it verifies top-level checksums, embedded validation,
root status files, the root coordinator start-here file, clean-release
start-here file, selected-domain
start-here manifest hash bindings, the packaged validator script hash, and root runbook hash
bindings. The public download validator reports the scientific-state artifact contract status,
checks that the root open scientific-state map matches release asset bytes,
checks that the root artifact contract matches release asset bytes, and
checks manifest-bound hash fields for `SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json` and `.md`. The public set includes the validator at
`scripts/validate-public-release-set.sh` so the downloaded directory can
check itself without requiring the internal test suite.
`OUTSIDE_REVIEW_DISPATCH.json` uses schema
`vela.outside_review_dispatch.v0.1`.

This is the practical publication surface: GitHub gets the tarball and
release assets, the dataset repository gets `huggingface-dataset-mirror`,
and the strict-signal packet goes to reviewers with its blocker index
and remediation lanes. The strict-signal packet also includes
`strict-signal-invitations/`, one lane-specific draft invitation for
wave-1 entity review, pending proposal review, diagnostic prework, and
backlog entity review. These drafts do not count as review and do not
clear reviewer-gated blockers.
It also includes `strict-signal-return-stubs/` and
`strict-signal-action-map-stubs/` for the same lanes.
Return stubs do not count as returned review.
Action-map stubs do not mutate frontier state.
The manifest states the same authority boundary as the lower-level
packs: distribution surfaces do not replace the local frontier state and
signed event log.

`START_HERE.md` is the root coordinator entrypoint for a downloaded public
release set. It tells a human operator to verify checksums, run the packaged
download validator, inspect `PORTFOLIO_STATUS.md`, `REVIEW_STATUS.md`, and
`NEXT_ACTIONS.md`, then choose the solo-maintainer preview, human-review,
outside-review, GBM, or pediatric lane, or open `CLEAN_RELEASE_START_HERE.md` for release
certification. It does not count as review, outside review, decision
readiness, release certification, or frontier mutation.

`SOLO_MAINTAINER_START_HERE.md` is the root coordinator entrypoint for
the current solo-maintainer preview scope. It points to checksum
verification, public-set validation, status files, and the local review
workspace command. It makes the package usable for inspection and public
preview without claiming independent outside review. It does not count
as review, outside review, decision readiness, or frontier mutation.
`README.md` includes `Solo maintainer start here: `SOLO_MAINTAINER_START_HERE.md``
so a downloaded package exposes this scope without treating it as
external validation.

`CLEAN_RELEASE_START_HERE.md` is the root coordinator entrypoint for the
final clean-checkout release gate. It points to package checksum
verification, `scripts/validate-public-release-set.sh`,
`tests/test-release-check-clean-tree-gate.sh`, and
`scripts/release-check.sh`. It names the fresh clone and clean checkout
requirements, but it does not certify the current dirty checkout and does
not count as release certification.

`GBM_STRICT_SIGNAL_START_HERE.md` is the root coordinator entrypoint for
the second-frontier strict-signal remediation pass. It points to the
strict-signal review packet, GBM handoff, execution checklist, and
validators. It does not count as review or clear GBM blockers.

`PEDIATRIC_HGG_START_HERE.md` is the root coordinator entrypoint for
the third-domain pediatric HGG cleanup rehearsal. It points to the
cleanup packet, lanes, human handoff, execution checklist, and validators.
It does not count as review or clear pediatric cleanup blockers.

`README.md` is the cold-start guide for a public release-set consumer.
It names the release assets, GitHub tarball, dataset-style mirror,
reviewer packet, citation metadata, checksum commands, and dispatch
validator command. It does not count as returned outside review or
reviewer-signed state.
`PUBLIC_RELEASE_SET_VALIDATION.json` and `.md` record read-only
validation for the composed release set: nested checksums, dispatch
validation, required lanes, the machine-readable not-decision-ready
projection boundary, and the no-mutation boundary. They do not count
as outside review or state work.

`OUTSIDE_REVIEW_DISPATCH.md` is the send-readiness cover for the
anti-amyloid outside-review loop. It binds the GitHub tarball, dataset
mirror manifest, decision-readiness projection, cold-reviewer packet,
required R1-R4 lanes, and return validator command. It does not count
as returned outside review.
`OUTSIDE_REVIEW_DISPATCH_VALIDATION.json` and `.md` record the read-only
dispatch validation result shipped inside the public set. They prove
hash binding, machine-readable not-decision-ready status, and
send-readiness checks only.
They do not count as outside review or state work.
`outside-review-invitations/` contains one lane-specific R1-R4
invitation draft per required reviewer lane. Each draft carries the
concrete packet hash, lane focus, and not-decision-ready boundary, but
still has recipient/date placeholders.
The invitation drafts do not count as returned outside review.
`outside-review-send-kits/` contains one lane-local R1-R4 send kit per
required reviewer lane. Each kit uses schema
`vela.outside_review_send_kit.v0.1` and includes `MANIFEST.json`,
`SEND_KIT.md`, `invitation.md`, `return-stub.md`, and
`action-map-stub.md`. The kit bundles the packet hash, invitation,
return stub, and action-map stub for handoff. It does not count as
returned outside review.
`outside-review-return-stubs/` contains one lane-specific R1-R4 return
stub per required reviewer lane. Each stub carries the concrete packet
hash and lane context, but it still has reviewer, date, and answer
placeholders. The stubs do not count as returned outside review.
`outside-review-action-map-stubs/` contains matching lane-specific
action-map stubs. Each one carries the same packet hash context and
the expected return-artifact filename pattern, but it remains a
placeholder until a returned artifact validates.
These stubs do not count as outside review or state work.
Validate the dispatch itself before sending:

```bash
./scripts/validate-outside-review-dispatch.sh \
  /tmp/vela-public-release-set \
  --out /tmp/outside-review-dispatch-validation
```

Returned outside-review files should use `outside-review-return-template.md`
and pass the read-only validator before they are counted in the review
trail. The validator requires lane, domain familiarity, packet-hash
context, and an assistance disclosure. A completed `cold_external`
review must disclose `assistance_disclosure: unassisted`; assisted,
scripted, synthetic, or failed runs cannot clear the outside-review gate.

```bash
./scripts/validate-outside-review-return.sh \
  outside-review-r1-<reviewer-handle>-2026-q2.md \
  projects/anti-amyloid-translation
```

Then map returned critiques with `outside-review-action-map-template.md`
and validate the action map:

```bash
./scripts/validate-outside-review-action-map.sh \
  outside-review-r1-<reviewer-handle>-action-map.md \
  projects/anti-amyloid-translation \
  --return-validation outside-review-return-validation.json
```

The action map is not itself a verdict. It proves that returned
feedback has an explicit proposed disposition: proposal, caveat, review,
hold, or no-action rationale.

The completion validator is read-only. It checks the full R1-R4
outside-review loop after returned artifacts and action maps exist:

```bash
./scripts/validate-outside-review-completion.sh \
  --out /tmp/outside-review-completion-validation
```

It emits `outside-review-completion-validation.json` and `.md`. The
packaged aliases are `anti-amyloid-outside-review-completion-validation.json`
and `.md`. The validator does not count as outside review and does not
mutate frontier state.
In short: it does not count as outside review and does not mutate frontier state.

The packaged cold-reviewer packet has its own read-only freshness
validator:

```bash
./scripts/validate-cold-reviewer-packet.sh \
  /path/to/cold-reviewer-packet.tar.gz \
  projects/anti-amyloid-translation \
  --out /tmp/cold-reviewer-packet-validation
```

It emits `cold-reviewer-packet-validation.json` and `.md`. The report
checks the packet's internal checksums, share package, proof packet,
decision brief, source-inbox snapshot, and stable reviewer-facing files
against a fresh packet build. It does not count as outside review and
does not mutate frontier state.

`decision-grade-completion-audit.json` is the active-goal completion
audit. It should report `goal_complete: false` until human corpus
attestation, extraction signoff, adjudication, outside review, second
frontier remediation, rehearsal cleanup, and clean release
certification are all complete.

`SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json` is the release-file authority
contract. It names whether an artifact is frontier state, proof, review
handoff, validation, queue snapshot, mirror metadata, or citation
metadata. It does not count as human review, returned outside review,
decision readiness, or frontier mutation.

`DECISION_GRADE_NEXT_ACTIONS.json` is an ordered, read-only list of remaining human, outside-review, frontier cleanup, and release-certification actions derived from the completion audit. It is also an operator runbook with blockers, artifacts to open, clearance evidence, and verification commands. It does not complete the actions it lists and does not mutate frontier state.
Build it directly with `./scripts/build-decision-grade-next-actions.sh /tmp/vela-next-actions` when the next-action index is needed without composing the full release asset directory.

`DECISION_GRADE_REVIEW_WORKSPACE.json` is the manifest for a local,
read-only operator workspace that materializes the current next-action
index plus the anti-amyloid decision worksheet, anti-amyloid outside
review worksheet, GBM strict-signal worksheet, and pediatric HGG cleanup
worksheet into stable subdirectories. Build it with
`./scripts/build-decision-grade-review-workspace.sh /tmp/vela-review-workspace`.
The workspace does not run reviewer commands, send outside-review packets,
count as review, count as outside review, or mutate frontier state.

`solo-maintainer-completion-audit.json` is the local completion audit for
the current solo-maintainer public-preview profile. Build it with
`./scripts/build-solo-maintainer-completion-audit.sh /tmp/vela-solo-maintainer-audit`.
It validates a generated public release set and the packaged download
validator, while preserving the stricter outside-review profile as
incomplete. It does not claim independent outside review and does not
mutate frontier state.

The audit includes a `clean_release_certification` requirement. It is
incomplete whenever tracked release-surface edits or broader
uncommitted worktree changes are present. This keeps packaged release
assets separate from release certification from a clean checkout.
`tests/test-release-check-clean-tree-gate.sh` protects the final
`release-check.sh` guard so pre-existing dirty state is reported as a blocker
and release-check mutation is reported separately.

`anti-amyloid-human-reviewer-handoff.json` is the internal human
handoff for the next reviewer pass. It is read-only and does not count
as review. It exists so the human-gated commands are carried with the
same release context as the proof packet.

`anti-amyloid-human-reviewer-execution-checklist.json` is the ordered
human-only gate checklist derived from the same handoff. It is
read-only, does not count as review, and tells agents not to run the
human reviewer commands.

`anti-amyloid-decision-review-ledger.template.json` is the fillable
A/R/P disposition ledger for A1-A5, R1-R3, and P1-P2. Agents may
generate and validate the template, but must not fill reviewer
verdicts.

`anti-amyloid-human-reviewer-handoff-validation.json` validates the
packaged handoff and checklist against a fresh handoff build, confirms
source-inbox state did not change, and preserves the human-only boundary.
It is read-only and does not count as review.
Run it with:

```bash
./scripts/validate-human-reviewer-handoff.sh \
  /path/to/human-handoff-dir \
  projects/anti-amyloid-translation \
  --out /tmp/human-reviewer-handoff-validation
```

`tests/test-human-reviewer-authority-boundary.sh` protects that boundary.
It fingerprints the anti-amyloid reviewer-state files before and after
handoff generation, verifies that reviewer-only commands remain marked
human-only, and checks that release automation does not contain direct
`reviewer:will-blair` authority commands.

After the human pass, run
`./scripts/validate-human-reviewer-completion.sh --out /tmp/vela-human-reviewer-completion`.
It is read-only. It checks the handoff, source-inbox state, strict
check, proof verification, and decision-grade completion audit, then
reports which human gates still block completion. Use
`--expect-complete` only after the reviewer pass is believed complete.
The release assets carry the current validation JSON and Markdown so
public mirrors preserve the present human-gate state.

`gbm-egfrviii-strict-signal-human-handoff.json` is the second-frontier
strict-signal reviewer handoff. It is read-only and does not count as
review. It orders source review, wave-1 entity review, pending proposal
review, diagnostic prework, backlog entity review, outside-review
dispatch, and post-review refresh without clearing findings, entities,
proposals, or strict signals.

`gbm-egfrviii-strict-signal-execution-checklist.json` is the ordered
GBM remediation checklist derived from the same handoff. After a human
pass, run
`./scripts/validate-gbm-strict-signal-completion.sh --out /tmp/vela-gbm-strict-completion`.
The validator is read-only. It reports which strict-signal gates still block
the selected second frontier and does not count as review. Its JSON also
includes a `vela.frontier_blocker_queue.v0.1` queue for source review,
entity review, proposal review, outside review, and post-review refresh.
For a single local operator directory containing the handoff, checklist,
and current completion validation, run
`./scripts/build-gbm-strict-signal-review-worksheet.sh /tmp/vela-gbm-strict-signal-worksheet`.
The worksheet is read-only. It does not count as review, outside review,
or frontier mutation.

`gbm-egfrviii-strict-signal-human-handoff-validation.json` validates the
packaged GBM handoff and checklist against a fresh handoff build, confirms
source-inbox state did not change, and preserves the reviewer boundary.
It is read-only and does not count as review. Run it with:

```bash
./scripts/validate-gbm-strict-signal-human-handoff.sh \
  /path/to/gbm-handoff-dir \
  projects/gbm-egfrviii-translation \
  --out /tmp/gbm-strict-handoff-validation
```

The local Workbench page `/review/work` renders those queue totals without
counting as review or mutating frontier state. `/review/work.json`
emits the same `vela.workbench.review_work.v0.1` payload for agents and
release checks.
For local operator inspection without starting a browser server, run
`vela review-work <frontier> --json`. It uses the same read-only
review-work builder as the Workbench route.
The generated strict-signal review packet includes
`strict-signal-invitations/` with lane-specific invitation drafts for
the same four remediation lanes. The drafts preserve reviewer/date
placeholders and carry `counts_as_review: false`.
The drafts do not clear reviewer-gated blockers.
Before sending that packet, validate the packaged packet against current
frontier state with
`./scripts/validate-strict-signal-review-packet.sh`.
The public release set carries
`gbm-strict-signal-review-packet-validation.json` and `.md` as a
read-only freshness report. It does not count as review and it does not
clear strict-signal blockers.
The packet also includes `strict-signal-return-stubs/` and
`strict-signal-action-map-stubs/`. Return stubs preserve answer
placeholders and do not count as returned review. Action-map stubs
preserve mapping placeholders, carry `mutates_frontier: false`, and do
not clear reviewer-gated blockers.
Returned strict-signal lane artifacts validate with
`./scripts/validate-strict-signal-return.sh`. Strict-signal action maps
validate with `./scripts/validate-strict-signal-action-map.sh`.
Both validators are read-only; they do not mutate frontier state.

`pediatric-hgg-cleanup-packet.json` is the third-domain cleanup packet.
`pediatric-hgg-cleanup-lanes.json` orders the same work into source
review, Diff Pack attestation, strict-signal review, task closure, and
post-cleanup refresh lanes. Both are read-only and do not clear source
review, Diff Packs, attestations, findings, or proposals.
`pediatric-hgg-cleanup-packet-validation.json` validates the packaged
cleanup packet against current frontier state. It is read-only, does not
count as review, and does not clear cleanup blockers.
`pediatric-hgg-cleanup-packet.tar.gz` carries the full cleanup packet,
including `pediatric-hgg-return-stubs/` and
`pediatric-hgg-action-map-stubs/`. Return stubs do not count as
returned review. Action-map stubs do not mutate frontier state.
Returned pediatric cleanup lane artifacts validate with
`./scripts/validate-pediatric-hgg-cleanup-return.sh`. Pediatric cleanup
action maps validate with
`./scripts/validate-pediatric-hgg-cleanup-action-map.sh`. Both
validators are read-only; they do not clear source review, Diff Packs,
attestations, findings, proposals, tasks, or strict signals.

`pediatric-hgg-human-handoff.json` is the third-domain cleanup handoff.
`pediatric-hgg-execution-checklist.json` orders the same cleanup gates
for reviewer action and agent prework. After a human pass, run
`./scripts/validate-pediatric-hgg-cleanup-completion.sh --out /tmp/vela-pediatric-hgg-completion`.
The validator is read-only. It reports which pediatric cleanup gates
still block the rehearsal frontier and does not count as review. Its JSON
also includes a `vela.frontier_blocker_queue.v0.1` queue for source
review, Diff Pack attestation, strict-signal review, task closure, and
post-cleanup refresh.
For a single local operator directory containing the handoff, checklist,
and current completion validation, run
`./scripts/build-pediatric-hgg-cleanup-review-worksheet.sh /tmp/vela-pediatric-hgg-cleanup-worksheet`.
The worksheet is read-only. It does not count as review, outside review,
or frontier mutation.

`pediatric-hgg-human-handoff-validation.json` validates the packaged
pediatric HGG handoff and checklist against a fresh handoff build,
confirms source-inbox state did not change, and preserves the reviewer
boundary. It is read-only and does not count as review. Run it with:

```bash
./scripts/validate-pediatric-hgg-human-handoff.sh \
  /path/to/pediatric-hgg-handoff-dir \
  projects/pediatric-hgg \
  --out /tmp/pediatric-hgg-handoff-validation
```

The local Workbench page `/review/work` renders those queue totals without
counting as review or mutating frontier state. `/review/work.json`
emits the same `vela.workbench.review_work.v0.1` payload for agents and
release checks.
For local operator inspection without starting a browser server, run
`vela review-work <frontier> --json`. It uses the same read-only
review-work builder as the Workbench route.
The cleanup lane map does not clear source review, Diff Packs, or
attestations.

`anti-amyloid-review-work.json`, `gbm-egfrviii-review-work.json`, and
`pediatric-hgg-review-work.json` are packaged snapshots of
`vela review-work <frontier> --json`. Their `.md` companions render the
same queues, examples, operator artifacts, and boundaries for human
reviewers without requiring them to inspect JSON. They use schema
`vela.workbench.review_work.v0.1`, are read-only, and carry
`counts_as_review: false` and `mutates_frontier: false`.
`frontier-portfolio-readiness.json` also embeds the same read-only
review-work lane totals for the selected frontier set, with
`review_work_source: "vela review-work --json"`.
The release pack also carries
`workbench-review-work-snapshot-validation.json` and `.md`, so package
consumers can inspect whether the snapshots matched fresh `vela review-work`
output at packaging time.
Validate them with
`./scripts/validate-workbench-review-work-snapshots.sh`; it compares the
packaged queue snapshots against fresh `vela review-work --json` output from temporary
frontier copies. The validator is read-only, does not count as review,
and does not mutate frontier state.

## Checksum verification

Every release pack has a top-level `SHA256SUMS` file. Verify before
using the pack:

```bash
cd /tmp/vela-release-assets
shasum -a 256 -c SHA256SUMS
jq -e '.release_artifact_format == "vela.v0.release-assets"' RELEASE_MANIFEST.json
```

Then validate the proof packet:

```bash
tar -xzf anti-amyloid-translation-proof-packet.tar.gz
vela packet validate anti-amyloid-translation-proof-packet
```

This proves that the packet is internally replayable and hash-bound.
It does not prove clinical actionability.

## Hub mirror

The public hub mirrors signed frontier state:

```text
https://vela-hub.fly.dev
```

For a fresh frontier file, publish with:

```bash
vela sign generate-keypair --out keys
vela actor add ./frontier.json reviewer:you \
  --pubkey "$(cat keys/public.key)"

vela registry publish ./frontier.json \
  --owner reviewer:you \
  --key keys/private.key \
  --to https://vela-hub.fly.dev \
  --json
```

For split local frontiers such as `projects/anti-amyloid-translation`,
materialize and lock before publishing a snapshot:

```bash
vela frontier materialize projects/anti-amyloid-translation
vela lock projects/anti-amyloid-translation
vela check projects/anti-amyloid-translation --strict --json
vela proof projects/anti-amyloid-translation --out /tmp/anti-amyloid-proof
```

The hub can withhold or go stale. It should not be treated as the
scientific authority. Consumers should verify with `vela registry pull`,
`vela check`, and `vela proof`.

## Optional dataset-style mirror

The Hugging Face mirror is optional. Treat it as a dataset-style
distribution of the same GitHub release assets, not a different source
of truth.

Build a local mirror directory from an already-built release pack:

```bash
./scripts/package-dataset-mirror.sh /tmp/vela-release-assets /tmp/vela-dataset-mirror
cd /tmp/vela-dataset-mirror
shasum -a 256 -c SHA256SUMS
jq -e '.schema == "vela.dataset_mirror.v0.1"' DATASET_MIRROR_MANIFEST.json
jq -e '.schema == "vela.dataset_mirror_validation.v0.1" and .ok == true and .decision_readiness_status == "not_decision_ready" and .decision_readiness_ready == false' DATASET_MIRROR_VALIDATION.json
jq -e '.license_apache == "LICENSE-APACHE" and .license_mit == "LICENSE-MIT"' DATASET_MIRROR_MANIFEST.json
jq -e '.dataset_infos == "dataset_infos.json" and .dataset_infos_schema == "vela.huggingface_dataset_infos.v0.1"' DATASET_MIRROR_MANIFEST.json
jq -e '.frontier_manifest_card_count == 4 and .frontier_manifest_cards_valid == true' DATASET_MIRROR_MANIFEST.json
jq -e '.frontier_manifest_card_hashes_ok == true' DATASET_MIRROR_VALIDATION.json
```

The generated `README.md` is the dataset card. Upload the contents of
`/tmp/vela-dataset-mirror` to a Hugging Face dataset repository or an
equivalent archive. Do not edit scientific readiness language after
generation unless the underlying frontier state and release manifest
also changed.

Recommended repository layout:

```text
README.md                         # generated dataset card
dataset_infos.json                # Hugging Face-style metadata
DATASET_MIRROR_MANIFEST.json
DATASET_MIRROR_VALIDATION.json
DATASET_MIRROR_VALIDATION.md
frontier-anti-amyloid-translation.manifest.json
frontier-anti-amyloid-translation.manifest.md
frontier-bbb-child-draft.manifest.json
frontier-bbb-child-draft.manifest.md
frontier-gbm-egfrviii-translation.manifest.json
frontier-gbm-egfrviii-translation.manifest.md
frontier-pediatric-hgg.manifest.json
frontier-pediatric-hgg.manifest.md
RELEASE_MANIFEST.json
CITATION.cff
LICENSE-APACHE
LICENSE-MIT
SHA256SUMS
RELEASE_ASSETS_SHA256SUMS
OPEN_SCIENTIFIC_STATE.md
neuro-translation-atlas-manifest.yaml
neuro-translation-atlas-snapshot.json
neuro-translation-atlas-index.html
anti-amyloid-translation.json
anti-amyloid-translation-proof-packet.tar.gz
bbb-child-draft-frontier.json
bbb-child-draft-proof-packet.tar.gz
bbb-child-draft-review-packet.v1.json
bbb-child-draft-review-packet.md
anti-amyloid-decision-brief.v1.json
anti-amyloid-decision-brief-projection.json
anti-amyloid-frontier-card.md
anti-amyloid-frontier-package.md
anti-amyloid-outside-review-2026-q2.md
anti-amyloid-outside-review-launch-2026-q2.md
outside-review-return-template.md
outside-review-action-map-template.md
anti-amyloid-outside-review-completion-validation.json
anti-amyloid-outside-review-completion-validation.md
anti-amyloid-human-reviewer-handoff.json
anti-amyloid-human-reviewer-handoff.md
anti-amyloid-human-reviewer-execution-checklist.json
anti-amyloid-human-reviewer-execution-checklist.md
anti-amyloid-decision-review-ledger.template.json
anti-amyloid-decision-review-ledger.template.md
anti-amyloid-human-reviewer-handoff-validation.json
anti-amyloid-human-reviewer-handoff-validation.md
anti-amyloid-human-reviewer-completion-validation.json
anti-amyloid-human-reviewer-completion-validation.md
gbm-egfrviii-strict-signal-human-handoff.json
gbm-egfrviii-strict-signal-human-handoff.md
gbm-egfrviii-strict-signal-execution-checklist.json
gbm-egfrviii-strict-signal-execution-checklist.md
gbm-egfrviii-strict-signal-human-handoff-validation.json
gbm-egfrviii-strict-signal-human-handoff-validation.md
gbm-egfrviii-strict-signal-completion-validation.json
gbm-egfrviii-strict-signal-completion-validation.md
pediatric-hgg-cleanup-packet.json
PEDIATRIC_HGG_CLEANUP_PACKET.md
pediatric-hgg-cleanup-lanes.json
PEDIATRIC_HGG_CLEANUP_LANES.md
pediatric-hgg-cleanup-packet-validation.json
pediatric-hgg-cleanup-packet-validation.md
pediatric-hgg-cleanup-packet.tar.gz
pediatric-hgg-human-handoff.json
pediatric-hgg-human-handoff.md
pediatric-hgg-execution-checklist.json
pediatric-hgg-execution-checklist.md
pediatric-hgg-human-handoff-validation.json
pediatric-hgg-human-handoff-validation.md
pediatric-hgg-cleanup-completion-validation.json
pediatric-hgg-cleanup-completion-validation.md
anti-amyloid-review-work.json
anti-amyloid-review-work.md
gbm-egfrviii-review-work.json
gbm-egfrviii-review-work.md
pediatric-hgg-review-work.json
pediatric-hgg-review-work.md
workbench-review-work-snapshot-validation.json
workbench-review-work-snapshot-validation.md
frontier-portfolio-readiness.json
frontier-portfolio-readiness.md
decision-grade-completion-audit.json
decision-grade-completion-audit.md
SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json
SCIENTIFIC_STATE_ARTIFACT_CONTRACT.md
DECISION_GRADE_NEXT_ACTIONS.json
DECISION_GRADE_NEXT_ACTIONS.md
cold-reviewer-packet.tar.gz
source-freshness-anti-amyloid-translation.json
trust-audit-anti-amyloid-translation.json
```

`DATASET_MIRROR_VALIDATION.json` and `.md` record read-only validation
for the dataset-style mirror: mirrored file hashes, source release checksum presence, machine-readable not-decision-ready projection status, and the no-mutation boundary. They do not count as outside review or state work.
`DATASET_MIRROR_MANIFEST.json` also binds the dataset card itself as
`readme: "README.md"` with `readme_sha256`, so the Hugging Face-facing
entrypoint is part of the mirror integrity contract.
`DATASET_MIRROR_VALIDATION.json` records `readme_hash_matches: true`
when the generated dataset card still matches that manifest hash.
`dataset_infos.json` records Hugging Face-style metadata for artifact
paths, roles, hashes, release version, and the non-review boundary using
schema `vela.huggingface_dataset_infos.v0.1`.
`DATASET_MIRROR_MANIFEST.json` binds it as
`dataset_infos == "dataset_infos.json"` with `dataset_infos_sha256`, and
`DATASET_MIRROR_VALIDATION.json` records `dataset_infos_hash_matches:
true` when the metadata still matches.
`DATASET_MIRROR_MANIFEST.json` also binds four per-frontier dataset
mirror cards through `frontier_manifest_cards`,
`frontier_manifest_card_count`, and `frontier_manifest_cards_valid`.
`DATASET_MIRROR_VALIDATION.json` records
`frontier_manifest_card_hashes_ok: true` when those card files still
match the manifest. The cards use
`vela.dataset_frontier_manifest_card.v0.1` and remain read-only mirror
metadata, not review or decision readiness.
The outer public release-set manifest also exposes
`dataset_readme`, `dataset_readme_sha256`, and
`dataset_mirror_validation_readme_hash_matches`, plus `dataset_infos`,
`dataset_infos_sha256`, and
`dataset_mirror_validation_dataset_infos_hash_matches`, and the four
`dataset_frontier_manifest_cards`, so a public download consumer can
see dataset-card, dataset metadata, and per-frontier card integrity
without opening the nested mirror manifest first.

`SCIENTIFIC_STATE_ARTIFACT_CONTRACT.json` is mirrored so a dataset
consumer can distinguish state, proof, handoff, validation, queue,
mirror, and citation artifacts before assigning authority to any file.

`DECISION_GRADE_NEXT_ACTIONS.json` is mirrored so a dataset consumer can inspect the ordered, read-only list of remaining human, outside-review, frontier cleanup, and release-certification actions. It does not complete the actions it lists.

`CITATION.cff` is copied from the release assets into the dataset-style
mirror. It provides software citation metadata only. Scientific use
should also cite the inspected frontier release, snapshot hash, proof
packet, and mirror access date.

The dataset mirror carries `LICENSE-APACHE` and `LICENSE-MIT` at the
repository root. These are copied from the release assets so a Hugging
Face-style mirror exposes software license text without requiring a
consumer to inspect the nested GitHub release pack.

`anti-amyloid-decision-brief-projection.json` is generated by
`vela decision-brief --json`. It carries the machine-readable decision-readiness status and blockers alongside the curated decision
brief, so a mirror consumer does not infer readiness from package
presence.

Dataset card requirements:

- Lead with the frontier scope and current decision boundary.
- State that the package is not medical advice.
- Link the GitHub release tag that produced the mirror.
- Include the `RELEASE_MANIFEST.json` checksum and verification
  commands.
- Preserve the license fields from `frontier.yaml`.
- State that hub mirrors are transport, not authority.

If the mirror accepts a smaller file set, include at minimum the
frontier JSON, proof packet, manifest, checksum file, frontier card,
frontier package, outside-review trail, and outside-review launch plan.
Include `frontier-portfolio-readiness.json` when the mirror is meant to
show the broader multi-frontier release path, including review-work lane
totals sourced from `vela review-work --json`. Include the
`neuro-translation-atlas-*` files when the mirror is meant to expose the
actual read-only Atlas composition, not only the portfolio summary.
Include the human reviewer handoff and execution checklist when the
mirror is meant to carry the next human-gated review path.
Include `anti-amyloid-outside-review-completion-validation.json` and
`.md` when the mirror is meant to carry the current R1-R4
outside-review completion state.

## Citation

For software metadata, start with `CITATION.cff`. For the
anti-amyloid frontier, also cite the release tag plus the frontier card:

```text
Vela contributors. Anti-amyloid translation frontier. Vela release
<tag>. Frontier state package, proof packet, and review trail.
```

Include:

- GitHub release URL.
- Hub `vfr_*` entry if published.
- Snapshot hash from `RELEASE_MANIFEST.json` or proof status.
- Access date for mirrors.

Do not cite Vela as resolving the science. Cite it as a reviewable
frontier state package.

## License

Repository code is dual-licensed Apache-2.0 OR MIT. See
`LICENSE-APACHE` and `LICENSE-MIT`.

The anti-amyloid frontier manifest declares:

```yaml
license:
  content: CC-BY-4.0
  code: Apache-2.0
  data: varies
```

Source papers, regulatory documents, trial records, and external data
retain their original terms. Vela stores source identity, locators,
evidence spans, and artifact records; it should not redistribute
license-restricted source bytes unless the artifact license permits it.

## Release gate

Before publishing:

```bash
./tests/test-anti-amyloid-frontier-package-card.sh
./tests/test-cold-reviewer-packet.sh
./tests/test-cold-reviewer-packet-validation.sh
./tests/test-dataset-mirror-package.sh
./tests/test-outside-review-completion-validation.sh
./tests/test-human-reviewer-handoff.sh
./tests/test-human-reviewer-handoff-validation.sh
./tests/test-human-reviewer-authority-boundary.sh
./tests/test-human-reviewer-completion-validation.sh
./tests/test-anti-amyloid-decision-review-ledger.sh
./tests/test-gbm-strict-signal-review-packet.sh
./tests/test-strict-signal-review-packet-validation.sh
./tests/test-strict-signal-return-validation.sh
./tests/test-strict-signal-action-map-validation.sh
./tests/test-gbm-strict-signal-human-handoff.sh
./tests/test-gbm-strict-signal-human-handoff-validation.sh
./tests/test-gbm-strict-signal-completion-validation.sh
./tests/test-pediatric-hgg-cleanup-packet.sh
./tests/test-pediatric-hgg-cleanup-packet-validation.sh
./tests/test-pediatric-hgg-cleanup-return-validation.sh
./tests/test-pediatric-hgg-cleanup-action-map-validation.sh
./tests/test-pediatric-hgg-human-handoff.sh
./tests/test-pediatric-hgg-human-handoff-validation.sh
./tests/test-pediatric-hgg-cleanup-completion-validation.sh
./tests/test-workbench-review-work-snapshot-validation.sh
./tests/test-release-check-clean-tree-gate.sh
./tests/test-release-bundle-manifest.sh /tmp/vela-release-assets
./scripts/validate-workbench-review-work-snapshots.sh /tmp/vela-release-assets
vela check projects/anti-amyloid-translation --strict --json
```

For a full local release candidate, run:

```bash
./scripts/release-check.sh
```

The full gate is intentionally heavier. It covers the broader protocol
surface, not just the anti-amyloid package. It only certifies a release from a clean checkout. If it reports pre-existing release-surface edits
or uncommitted worktree changes, the packaged artifacts may still be
useful for review, but the release is not certified.
