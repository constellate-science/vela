# AI attribution: AI-drafted proposals, human-certified events

This doc names the doctrine Vela's substrate already enforces:
**proposals can be drafted by anyone, including AI agents;
canonical events are signed by named reviewers.** A human (or
named agent under explicit authority) certifies, the substrate
records.

## Why this exists

Timothy Gowers's 2026-05-08 blog post "A recent experience with
ChatGPT-5.5-Pro" describes ChatGPT-5.5-Pro producing
PhD-level research in two hours of guided interaction. Gowers
asks:

> Perhaps there should be a different repository where AI-produced
> results can live...results would be included only if a human
> mathematician was prepared to certify that they were correct,
> or, better still, that they had been formalized by a proof
> assistant.

Vela's substrate has carried `actor.type: "human" | "agent"` on
every event since v0.55. The v0.75 Carina spec adds a
`Proof` primitive (Lean / Coq / Isabelle / Agda / Metamath /
Rocq) for the formalization slot. v0.76 adds an Agent4Science
review-packet adapter and the `examples/sidon-sets/` reference
frontier showing the chain end-to-end. This doc makes the
doctrine explicit so a reader knows what the substrate
guarantees and what it leaves open.

## The actor split

Every `StateProposal` and `StateEvent` carries an `actor`
block:

```json
"actor": {
  "id": "agent:research-bot-2026-05-09",
  "type": "agent"
}
```

or

```json
"actor": {
  "id": "reviewer:will-blair",
  "type": "human"
}
```

The `type` field is one of `"human"` or `"agent"`. The substrate
does not enforce the boundary; reviewer discipline does. The
convention:

- **`agent:<name>` actors draft proposals.** They run agent
  inboxes (`scout`, `compile-notes`, `compile-data`), emit
  `finding.add` proposals from external runtimes (ScienceClaw,
  Agent Discourse, Agent4Science), and surface candidate
  verdicts. They never sign accept events without explicit
  human authority.
- **`reviewer:<name>` actors sign accept events.** A human at
  the keyboard (or a named agent acting under a delegated key)
  inspects the proposal, decides, and writes the event. The
  signature on the event is the bind.

Agent inboxes use the convention `agent:<role>-bot-<date>` so
the date pins which version of the agent emitted the work. The
substrate never silently re-attributes an event; if a verdict
was written by the wrong actor, the fix is a new event with a
new attribution, not an in-place edit.

## The four-event chain

The smallest demonstrable instance lives in `examples/early-ad/`
on finding `vf_8f2d8f546976dcb3`. Four events compose a full
AI-draft to human-certified chain:

```
asserted        vev_b4908222150d4693
                actor:    reviewer:will-blair
                kind:     finding.add
                payload:  {assertion, evidence_spans: []}
                before:   sha256:0000...
                after:    sha256:9f6a...

reviewed        vev_8cb9b3daa9db5064  needs_revision
                actor:    reviewer:will-blair
                kind:     finding.review
                payload:  {status: "needs_revision", reason: "..."}
                before:   sha256:9f6a...
                after:    sha256:9f6a...

span_repaired   vev_3790dc7f05c5f13a
                actor:    agent:vela-curation-bot-2026-05-09
                kind:     finding.span_repaired
                payload:  {evidence_span: {section, text}}
                before:   sha256:9f6a...
                after:    sha256:decf...

reviewed        vev_50ecd1186170042f  accepted
                actor:    reviewer:will-blair
                kind:     finding.review
                payload:  {status: "accepted"}
                before:   sha256:decf...
                after:    sha256:decf...
```

The agent (`agent:vela-curation-bot-2026-05-09`) drafts the span
repair; the human (`reviewer:will-blair`) accepts. The
before/after hashes weld byte-for-byte across the chain.
Replay re-derives the same finding state from the events alone.

The Sidon-set example (`examples/sidon-sets/`) carries the same
shape on a non-biology domain: an `agent:research-bot-2026-05-09`
asserts the AI-drafted improvement, the human reviewer files a
`needs_revision` verdict gated on a Lean stub, and the
proof-script artifact lands as the certification slot the
v0.75 Carina `Proof` primitive points at.

## The certification model

A canonical event is a certificate. Its three load-bearing
fields:

1. **`actor.id` + `actor.type`**: who is making the claim.
   `human` actors are accountable to themselves; `agent`
   actors are accountable to whoever runs the agent.
2. **`reason`**: why this certification is being recorded. Free
   text, but every event in production has one.
3. **`signature`** (Ed25519 over the canonical preimage): the
   binding. Proposals can be drafted; events are signed.

For findings whose certification is provable rather than just
asserted, the v0.75 `Proof` primitive carries:

- `tool` (one of `lean4`, `coq`, `isabelle`, `agda`, `metamath`,
  `rocq`, `other`).
- `tool_version`.
- `script_locator` (content-addressed pointer to the proof
  script).
- `verifier_output_hash` (sha256 of the verifier's success
  output).
- `verified_at` (RFC3339).
- `target_finding_id`.

The `verifier_output_hash` is what makes the certification
falsifiable: a third party re-runs the tool against the script,
checks the output hash matches, and either confirms or refutes
the certification. The substrate does not run Lean; it records
who ran Lean against what, when.

## What the substrate guarantees

- **Append-only event log.** No event is ever mutated.
  Corrections enter as new events with new attributions.
- **Replay determinism.** Given the same event log + same
  Carina kernel digest, Rust + Python reducers produce
  byte-identical finding-state digests. See
  `crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs`.
- **Hash-welded chain.** Each event's `before_hash` equals the
  previous event's `after_hash` for the same target. Any
  insertion or deletion breaks the chain; integrity check
  catches it.
- **Actor visibility at every layer.** The Workbench inbox,
  the public site, the proof packet, and the `vela lineage`
  CLI all surface `actor.type` and `actor.id`.

## What the substrate does NOT decide

These are community / journal / partnership questions, not
substrate questions:

- **Credit assignment.** Vela records who drafted what and who
  certified what. It does not decide how authorship,
  acknowledgment, or co-author lines should read on a
  preprint or publication.
- **Acceptance policy.** Whether a particular venue (a journal,
  arXiv, a registry) accepts AI-drafted findings, or under
  what conditions, is the venue's call. Vela makes the chain
  inspectable so the venue can make an informed decision.
- **Trust roots.** Whether `agent:research-bot-2026-05-09` is
  trustworthy is a reviewer-time question. Vela carries the
  attribution; the reviewer reads the chain and decides.
- **Truth.** Vela does not adjudicate truth. It records who
  certified what, against what evidence, against what proof
  artifact. Lean (or Coq, etc.) is the truth-checker for
  formalized claims; reviewer judgment is the
  truth-checker for everything else.

## How a venue should consume Vela output

1. Fetch the proof packet for the frontier of interest.
2. Filter findings by `actor.type` history. A venue that
   accepts only "human-certified" findings keeps only those
   with at least one `actor.type: "human"` accept event on
   the chain.
3. For findings carrying a `Proof` primitive, re-run the
   verifier on `script_locator` and check that the output
   hash matches `verifier_output_hash`.
4. The venue's editorial policy decides what to do with
   findings that have only agent-actor accepts. Vela does not
   pre-filter.

## How a reviewer should treat AI-drafted proposals

1. Read the `actor` block. If it says `type: "agent"`, treat
   the content as a draft, not a verdict.
2. Inspect the supporting evidence. The Carina `Evidence`
   primitive points at content-addressed sources; verify the
   locator.
3. If the proposal claims formalization, check the `Proof`
   primitive. Re-run Lean / Coq / Isabelle / etc. on the
   referenced script. Check the verifier output hash matches.
4. Sign the accept event under your own reviewer key only
   after steps 1 to 3 pass. Your signature is the certificate.

## What changed when

- **v0.55**: actor.type field on every event.
- **v0.65**: agent reviewer convention
  `agent:<role>-bot-<date>` adopted across the BBB curation
  wave.
- **v0.74**: README opens with the four-event chain (early-AD)
  showing AI-draft + human-certified.
- **v0.75**: Carina `Proof` primitive added (Gowers-shaped).
- **v0.76**: Agent4Science review-packet adapter; Sidon-set
  reference frontier; this doc.
- **v0.77+ (planned)**: site surface for "human-certified" vs
  "AI-proposed" filter on `/frontiers/<slug>`.

## See also

- Gowers, T. "A recent experience with ChatGPT-5.5-Pro."
  gowers.wordpress.com, 2026-05-08.
- `docs/PROTOCOL.md`. Normative event semantics.
- `docs/CARINA.md` §v0.3. The Proof primitive.
- `docs/PROTOCOL.md`. The canonical event log walkthrough.
- `docs/RELAY.md`. The four adapter shapes that produce
  AI-drafted proposals.
- `examples/early-ad/`. The first reference chain.
- `examples/sidon-sets/`. The mathematical reference chain.
