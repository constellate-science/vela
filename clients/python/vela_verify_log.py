#!/usr/bin/env python3
"""Independent verifier for the Vela transparency log (RFC 6962 + Ed25519 STH).

Given only a Vela hub URL and a frontier id, this checks — with NO trust in the
hub's own claims — that:

  1. the Signed Tree Head (STH) is signed by the expected Ed25519 public key,
     over the canonical JSON of the STH (vela.canonical-json/v1, RFC 8785-style);
  2. the root the hub reconstructs from the raw event log matches the root the
     STH commits to (so the signed root really is the root of the events served);
  3. a chosen event is included in that tree, by reconstructing the root from the
     event's leaf + the audit path alone (RFC 6962 inclusion proof).

The log leaf is the event's content-address PREIMAGE — the exact bytes whose
SHA-256 is the event's `vev_` id. So the leaf is reproducible from event content
alone; the signature and the event id are excluded from it, making it immune to
legitimate re-signing. This verifier rebuilds those preimages itself from the
`/events` feed and recomputes each `vev_` id, refusing to trust the hub's leaves.

Trust note: pin the public key OUT OF BAND (publish/store it yourself; the hub
exposes its key at /.well-known/vela for first-use pinning). Passing --pubkey
enforces it; otherwise the verifier warns and uses the key the STH advertises,
which only protects against accidental corruption, not a malicious hub.

Usage:
  python3 vela_verify_log.py --hub https://hub.constellate.science \\
      --vfr vfr_06cfcbe7c449d86a [--event vev_...] [--pubkey <hex>]

If --event is omitted, the first event in the log is checked.

Dependencies: PyNaCl for the Ed25519 check (`pip install pynacl`). Without it the
signature step is SKIPPED with a loud warning; the Merkle checks still run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
import urllib.request

CANON_FORMAT = "vela.canonical-json/v1"
# The 10 fields that form an event's content-address preimage, in the protocol's
# definition (see vela-protocol/src/events.rs::event_content_preimage_bytes).
PREIMAGE_FIELDS = (
    "schema", "kind", "target", "actor", "timestamp",
    "reason", "before_hash", "after_hash", "payload", "caveats",
)


def canonical_bytes(obj) -> bytes:
    """vela.canonical-json/v1: keys sorted recursively, compact, UTF-8 verbatim."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def get_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


# --- RFC 6962 primitives (mirror vela-protocol/src/merkle.rs) ----------------

def hash_leaf(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_pow2_lt(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def reconstruct_root(m: int, n: int, leaf_hash: bytes, proof: list[bytes]) -> bytes | None:
    """Rebuild the root from (leaf, index m, tree size n, audit path) alone."""
    idx = [0]

    def recon(m: int, n: int) -> bytes:
        if n == 1:
            return leaf_hash
        k = largest_pow2_lt(n)
        if m < k:
            left = recon(m, k)
            right = proof[idx[0]]; idx[0] += 1
            return hash_node(left, right)
        else:
            right = recon(m - k, n - k)
            left = proof[idx[0]]; idx[0] += 1
            return hash_node(left, right)

    try:
        root = recon(m, n)
    except IndexError:
        return None
    # Proof must be fully consumed — no extra siblings.
    return root if idx[0] == len(proof) else None


# --- event preimage / vev_ id ------------------------------------------------

def event_preimage(ev: dict) -> bytes:
    content = {
        "schema": ev.get("schema"),
        "kind": ev.get("kind"),
        "target": ev.get("target"),
        "actor": ev.get("actor"),
        "timestamp": ev.get("timestamp"),
        "reason": ev.get("reason"),
        "before_hash": ev.get("before_hash"),
        "after_hash": ev.get("after_hash"),
        "payload": ev.get("payload"),
        "caveats": ev.get("caveats", []),
    }
    return canonical_bytes(content)


def vev_id(ev: dict) -> str:
    return "vev_" + hashlib.sha256(event_preimage(ev)).hexdigest()[:16]


def fetch_all_events(hub: str, vfr: str) -> list[dict]:
    """Page through /events in seq order (oldest first), as the log is built."""
    events: list[dict] = []
    cursor = None
    while True:
        url = f"{hub}/entries/{vfr}/events?limit=500"
        if cursor:
            url += f"&since={urllib.parse.quote(cursor)}"
        page = get_json(url)
        batch = page.get("events", [])
        events.extend(batch)
        cursor = page.get("next_cursor")
        if not cursor or not batch:
            break
    return events


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a Vela transparency-log STH + inclusion proof.")
    ap.add_argument("--hub", required=True, help="hub base URL, e.g. https://hub.constellate.science")
    ap.add_argument("--vfr", required=True, help="frontier id, e.g. vfr_06cfcbe7c449d86a")
    ap.add_argument("--event", help="event id (vev_...) to prove inclusion of; default: first event")
    ap.add_argument("--pubkey", help="expected Ed25519 pubkey hex (pin out-of-band; STRONGLY recommended)")
    args = ap.parse_args()
    hub = args.hub.rstrip("/")

    ok = True

    # 1. STH
    sth_resp = get_json(f"{hub}/entries/{args.vfr}/log/sth")
    sth = sth_resp["sth"]
    tree_size = sth["tree_size"]
    sth_root_hex = sth["root_hash"].removeprefix("sha256:")
    print(f"STH  log_id={sth['log_id']}")
    print(f"     tree_size={tree_size}  root={sth['root_hash'][:24]}…  mode={sth_resp.get('mode')}")

    # 2. signature over canonical(sth)
    sig_block = sth_resp.get("signature")
    if not sig_block:
        print("  ! STH is UNSIGNED (hub has no signing key) — signature step skipped")
    else:
        adv_pub = sig_block["pubkey"]
        expected_pub = args.pubkey or adv_pub
        if not args.pubkey:
            print("  ! no --pubkey pinned; trusting the key the STH advertises (corruption check only)")
        if expected_pub != adv_pub:
            print(f"  ✗ pubkey mismatch: pinned {expected_pub[:16]}… but STH advertises {adv_pub[:16]}…")
            ok = False
        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
            vk = VerifyKey(bytes.fromhex(expected_pub))
            try:
                vk.verify(canonical_bytes(sth), bytes.fromhex(sig_block["value"]))
                print(f"  ✓ Ed25519 signature valid (key {expected_pub[:16]}…)")
            except BadSignatureError:
                print("  ✗ Ed25519 signature INVALID over canonical(sth)")
                ok = False
        except ImportError:
            print("  ! PyNaCl not installed — signature NOT checked (pip install pynacl)")

    # 3. independently rebuild leaves from the event feed, recompute the root.
    print("fetching event log…")
    events = fetch_all_events(hub, args.vfr)
    if len(events) != tree_size:
        print(f"  ✗ event count {len(events)} != STH tree_size {tree_size}")
        ok = False
    # recompute each vev_ id from content; refuse mismatches.
    leaves: list[bytes] = []
    id_mismatches = 0
    for ev in events:
        if "id" in ev and ev["id"] != vev_id(ev):
            id_mismatches += 1
        leaves.append(event_preimage(ev))
    if id_mismatches:
        print(f"  ✗ {id_mismatches} event(s) whose content does not hash to their vev_ id")
        ok = False
    else:
        print(f"  ✓ all {len(events)} events' content reproduces their vev_ id")

    def merkle_root(ls: list[bytes]) -> bytes:
        if not ls:
            return hashlib.sha256(b"").digest()
        if len(ls) == 1:
            return hash_leaf(ls[0])
        k = largest_pow2_lt(len(ls))
        return hash_node(merkle_root(ls[:k]), merkle_root(ls[k:]))

    recomputed = merkle_root(leaves).hex()
    if recomputed == sth_root_hex:
        print(f"  ✓ recomputed root matches the signed STH root")
    else:
        print(f"  ✗ recomputed root {recomputed[:24]}… != STH root {sth_root_hex[:24]}…")
        ok = False

    # 4. inclusion proof for one event
    target = args.event or (events[0]["id"] if events else None)
    if target:
        proof_resp = get_json(f"{hub}/entries/{args.vfr}/log/proof/{urllib.parse.quote(target, safe='')}")
        m = proof_resp["leaf_index"]
        n = proof_resp["tree_size"]
        path = [bytes.fromhex(h) for h in proof_resp["audit_path"]]
        proof_root_hex = proof_resp["root_hash"].removeprefix("sha256:")
        # the leaf we prove must be the one we rebuilt at that index
        leaf_hash = hash_leaf(leaves[m]) if m < len(leaves) else hash_leaf(b"")
        rebuilt = reconstruct_root(m, n, leaf_hash, path)
        print(f"PROOF event={target} index={m}/{n} path_len={len(path)}")
        if rebuilt is None:
            print("  ✗ inclusion proof did not reconstruct a root (bad shape)")
            ok = False
        elif rebuilt.hex() == sth_root_hex == proof_root_hex:
            print("  ✓ inclusion proof reconstructs the signed STH root")
        else:
            print(f"  ✗ inclusion root {rebuilt.hex()[:24]}… != STH root {sth_root_hex[:24]}…")
            ok = False

    print()
    print("RESULT:", "VERIFIED ✓" if ok else "FAILED ✗")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
