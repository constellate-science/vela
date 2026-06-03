# Vela transparency log (P2)

RFC 6962-style Merkle transparency log over each frontier's append-only event
log. The unit of trust is the **event content-address preimage**: a log leaf is
exactly the bytes whose SHA-256 is an event's `vev_` id
(`vela_protocol::events::event_content_preimage_bytes`). The leaf excludes the
event's `id`, `signature`, and `schema_artifact_id`, so it is immune to
legitimate re-signing and reproducible byte-for-byte by any independent
implementation that can produce `vela.canonical-json/v1`.

This is the load-bearing minimal core: a signed tree head, inclusion proofs, and
consistency proofs — everything a client needs to verify membership and
append-only growth without trusting the hub. Witness co-signing (defeating
split-view) is the documented next phase (§4).

## 1. Endpoints

All read-only, cacheable, served by `vela-hub` over the existing
`frontier_events` projection. `merkle_root`, `inclusion_proof`,
`consistency_proof`, and their verifiers live in
`crates/vela-protocol/src/merkle.rs` (RFC 6962 §2.1; exhaustive property tests).

### `GET /entries/{vfr}/log/sth` — signed tree head

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

### `GET /entries/{vfr}/log/proof/{event_id}` — inclusion proof

Returns `{leaf_index, tree_size, root_hash, audit_path: [hex…]}`. The verifier
rebuilds the leaf preimage from event content, then reconstructs the root from
the leaf + audit path alone (`verify_inclusion`) and checks it equals the signed
STH root.

### `GET /entries/{vfr}/log/consistency?first={m}&second={n}` — consistency proof

`second` defaults to the current length. Returns `{first_size, second_size,
first_root, second_root, consistency_proof: [hex…]}`. Lets a verifier holding an
older signed STH (size `m`) confirm the log only **grew** — never forked or
rewrote history — before trusting a newer STH (size `n`). `verify_consistency`
reconstructs both roots from the proof alone.

## 2. Independent verifier

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

## 3. Trust model

- **Pin the hub key out of band.** The STH advertises a pubkey; a malicious hub
  could advertise its own. Pinning (`/.well-known/vela` on first use, stored by
  the verifier) is what binds the log to an identity.
- **Save STHs to detect rewrites.** A single STH proves the current root is
  signed; it does not prove the hub never rewrote history. Saving an STH and
  later running a consistency proof against it does. Witnesses (§4) remove the
  need for each client to do this.
- **Split-view is still possible until witnesses exist.** A hub can show
  consistent-but-divergent logs to different clients. Only independent witnesses
  co-signing STHs close this.

## 4. Witness co-signing — designed, not yet built (recruitment-gated)

A witness is an independent party that periodically fetches a hub's STH,
verifies it (and consistency vs. the last STH it saw), and **co-signs** it. A
verifier that pins a set of witness keys and requires ≥k co-signatures cannot be
shown a split view, because the witnesses would have to collude.

Design (deliberately not deployed until a real second signer exists — shipping a
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
  witness signs — so a cosignature is pinned to a specific issuance.
- **`GET /entries/{vfr}/log/witnesses?tree_size=&root_hash=`** returns the
  stored cosignatures with enough fields (`log_id, tree_size, root_hash,
  timestamp`) for a verifier to rebuild each `sth` and check each cosignature
  against an out-of-band-pinned witness set.
- Self-authenticating writes (Ed25519-verified, must match a real issued STH);
  trusting *which* witnesses is the verifier's out-of-band job.

Only **recruiting the first independent witness host** is external. The protocol
and storage are specified above and slot into the existing dual-arm db + axum
handler patterns.

## 5. Not in scope here

- STH anchoring to a public chain/log for independent timestamping (P4).
- Chunk-dedup of bulk objects (P3 — measure first; the CAS stub breaks the typed
  materializer).
- Proof-Carrying-Knowledge / constant-size DAG verification (research, P4+).
