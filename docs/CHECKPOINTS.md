# Signed checkpoints (design, deferred)

Status: **specified, not implemented.** Implementation is deliberately
deferred until a frontier's event log exceeds ~50,000 events; the largest
live log today is ~1,300 events and replays in well under a second. This
document exists so the format is decided *before* the first log that
needs it, not during the incident that demands it.

## Problem

Replay cost grows linearly with the log (`replay_from_genesis` is O(N)
since v0.105), and the log is stored as one JSON file per event. At
hundreds of events this is invisible; at hundreds of thousands it means
slow loads, slow `vela check`, and a heavy clone for every new consumer.
Git solved the same problem with packfiles; Vela's analogue is the
checkpoint: a **signed, replayable waypoint** in the event log.

## The record

```json
{
  "schema": "vela.checkpoint.v0.1",
  "checkpoint_id": "vcp_<sha256(canonical_body_with_id_empty)[:16]>",
  "vfr_id": "vfr_…",
  "event_log_hash": "<events::event_log_hash of events[0..=n]>",
  "snapshot_hash": "<events::snapshot_hash of the replayed state at n>",
  "event_count": 50000,
  "last_event_id": "vev_…",
  "prev_checkpoint": "vcp_… | null",
  "created_at": "RFC3339",
  "signature": "<Ed25519 over canonical bytes, signature field empty>",
  "signer_pubkey_hex": "<the frontier owner's registered key>"
}
```

Every field is already computable with existing kernel functions:
`events::event_log_hash`, `events::snapshot_hash`, and the canonical-JSON
content-address rule used by every other `v*_` id. The `vela.lock`
fields (`snapshot_hash`, `event_log_hash`) are precisely a checkpoint
without the signature or the chain — the lock is the degenerate latest
checkpoint, which is why this design adds no new hash semantics.

## Semantics

- **Replay-from-checkpoint.** A consumer that trusts checkpoint `vcp_X`
  loads the materialized state whose `snapshot_hash` matches, then
  replays only `events[n..]`. Trust is explicit: you trust the OWNER KEY
  that signed the checkpoint, exactly as you trust a registry manifest.
  Full replay from genesis remains available to anyone, always — a
  checkpoint accelerates verification, it never replaces it.
- **The chain.** `prev_checkpoint` forms a hash-linked chain back to
  genesis. Verifying a checkpoint chain = verifying each link's
  signature + recomputing the two hashes at each waypoint. Cost is
  O(N) once, then O(delta) forever after.
- **Log segments.** With checkpoints in place, events between two
  checkpoints can be packed into one append-only JSONL segment file
  (`events/segment-<vcp_id>.jsonl`), replacing thousands of per-event
  files. Per-event files remain the write format for the active tail;
  packing is a maintenance operation (`vela frontier pack`, future),
  byte-stable and reversible since events are content-addressed.
- **Earliest-wins discipline.** Checkpoints are append-only; a
  checkpoint is never edited or replaced. A bad checkpoint is abandoned
  (the chain forks past it), never rewritten — same rule as every other
  signed record in the protocol.

## Non-goals

- No checkpoint authority other than the frontier owner key (a second
  producer signs their OWN checkpoints over the same log).
- No compression/dedup cleverness in v0.1 — JSONL segments are plain.
- No change to event ids, event signing, or the reducer. A checkpoint
  is derived state; the log remains the only source of truth.

## Trigger to implement

Any frontier crossing 50k events, or measured `vela check` replay time
crossing ~5s on the reference machine, whichever comes first.
