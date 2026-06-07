#!/usr/bin/env python3
"""Canonical-hashing conformance for the Python content-addressing path.

Pins the load-bearing Python function `vela_verify_log.canonical_bytes` (the
one that recomputes each `vev_` id and refuses to trust the hub's leaves)
against `conformance/canonical-hashing.json`, byte-for-byte and by SHA-256.

This is the Python mirror of `crates/vela-protocol/tests/canonical_hashing_conformance.rs`.
Both pin the same vectors, so the Rust id-minter and the Python re-verifier
produce identical content-addresses.

Usage:
    ./verify_canonical_hashing.py
Exit codes: 0 = all vectors match, 1 = a divergence, 2 = invocation error.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
# Import the REAL load-bearing canonicalizer, not a reimplementation.
sys.path.insert(0, str(REPO / "clients" / "python"))
try:
    from vela_verify_log import canonical_bytes  # type: ignore
except Exception as e:  # noqa: BLE001
    print(f"could not import vela_verify_log.canonical_bytes: {e}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    vectors_path = HERE / "canonical-hashing.json"
    doc = json.loads(vectors_path.read_text(encoding="utf-8"))
    if doc.get("format_id") != "vela.canonical-json/v1":
        print("vector file pins the wrong format id", file=sys.stderr)
        return 2
    vectors = doc.get("vectors", [])
    if not vectors:
        print("no vectors to check", file=sys.stderr)
        return 2

    failures = 0
    for v in vectors:
        name = v.get("name", "<unnamed>")
        got_bytes = canonical_bytes(v["input"])
        got_canon = got_bytes.decode("utf-8")
        got_sha = hashlib.sha256(got_bytes).hexdigest()
        if got_canon != v["canonical"]:
            failures += 1
            print(f"FAIL {name}: canonical diverged\n  want: {v['canonical']}\n  got:  {got_canon}")
        elif got_sha != v["sha256"]:
            failures += 1
            print(f"FAIL {name}: sha256 diverged\n  want: {v['sha256']}\n  got:  {got_sha}")
        else:
            print(f"ok   {name}")

    print(f"\ncanonical-hashing: {len(vectors)} vectors, {failures} FAILED")
    if failures:
        print("CANONICAL-JSON DRIFT -- the Python content-address path no longer "
              "matches the pinned vela.canonical-json/v1 form (Rust will mint "
              "different ids than Python re-verifies).")
        return 1
    print("Python content-address path conforms to vela.canonical-json/v1: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
