# Governance and incentives

> The structure that keeps the protocol neutral while the operation can
> sustain itself, and the incentives that make a producer want to leave verified state behind. This
> states the model and maps each element to what already exists in the substrate versus what is
> future. It does not claim future parts are built.

## The split

- **Open protocol + reference implementation + public commons.** The spec, the reference
  implementation, and the verified public frontiers are open. Anyone can run the verifier, replay a
  frontier from genesis, and check that accepted state equals what the signed log reduces to. No
  trust rests on a hosted service or a private party. This is built: the protocol is a pure library,
  the gate (`vela-verify`, the four-check trust gate, `deliverable_grade`) is frozen and public, and
  `vela reproduce` / `vela frontier materialize` are byte-deterministic.
- **Commercial managed infrastructure + private branches.** A company can run hosted hubs, private
  frontier worktrees, and sealed branches without owning the protocol. The visibility and access
  tiers that make this possible are built (public / private / sealed visibility, access tiers,
  scoped provenance, `frontier.forked_from`). The managed offering itself is future and is Will's.
- **Foundation-style neutrality.** The truth-bearing decisions stay key-custody human decisions, and
  no model sits in any trust path. This is enforced in code today (acceptance is a signed
  key-custody event; `assert_not_in_lineage` keeps activity out of accepted state; an AI cannot
  sign). The legal foundation structure is future and is Will's.

The dividing line is sharp and already real in the code: anything truth-bearing is open and
replayable; anything operational can be commercial. The protocol cannot be captured because its
verdicts are reproducible by anyone from the public log.

## Why neutrality is mechanical, not promised

A governance promise is only as good as its enforcement. Here it is mechanical:

- Acceptance of a state transition is a signature under a human's key, checked on replay. A hosted
  operator cannot fabricate acceptance without the key, and a forged event fails replay.
- The reducer is a pure fold and the loader is the reducer (no second read path), so a hosted view
  that diverges from the log is detectable by anyone who replays.
- A receipt is provenance, never a verdict. Registering a witness does not accept a claim.

These are the frozen primitives (see `PROTOCOL.md`); governance is their consequence, not a
separate layer.

## Incentive design

What makes a producer leave verified state behind instead of keeping a private result:

- **Venue-native export.** A verified result should leave Vela in the form the producer's venue
  already accepts: an OEIS comment, an arXiv-ready statement, a GitHub or mathlib contribution. The
  OEIS bridge and the release/DOI archive exist; per-venue export adapters are partial.
- **Automatic attribution for partial contributions.** A producer who discharges one obligation, or
  contributes one reusable lemma or a verified bound, is credited for exactly that, because the
  dependency structure is mechanical (`Attempt.depends_on`, `Transfer`, the dependency oracle). What
  rests on a contribution is measured, not litigated. Built: the oracle and transfer registry. The
  retro-attribution surface over them is partial.
- **Citable releases.** A frontier state can be tagged as an immutable, content-addressed release
  (`vela frontier release`, `vfrr_`) and archived with a DOI. Built.
- **Private priority.** A producer can keep a result in a private or sealed branch, time-stamped and
  replayable, and publish later without losing priority. The visibility tiers are built; the priority
  proof is their consequence.

The throughline: the substrate already makes contribution measurable and replayable, which is the
precondition for crediting it. The unbuilt parts are export adapters and the commercial wrapper, not
the trust core.

## What is deliberately not decided here

Legal entity, license choice between specific OSI licenses, and the commercial pricing model are
Will's and a future call. This document fixes the technical shape of neutrality (already enforced in
code) and the incentive surfaces (mostly built), so those business decisions can be made later
without reopening the trust model.
