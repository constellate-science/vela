#!/usr/bin/env python3
"""Cross-impl conformance for the `vat_` Attempt content-address.

Recomputes each pinned vector in `conformance/attempt-id.json` from its
canonical body and asserts it matches the expected `vat_` id. This is the
Python mirror of `attempt::tests::cross_impl_pinned_id` in
`crates/vela-protocol/src/attempt.rs`: both pin the same vector, so the Rust
id-minter and the Python ledger producer derive identical content-addresses.

The id preimage is the canonical JSON (sorted keys, no whitespace) of the
Attempt body with `attempt_id`, `signature`, and `signer_pubkey_hex` zeroed;
the id is `vat_` + sha256(preimage)[:16].

Usage:
    ./verify_attempt_id.py
Exit codes: 0 = all vectors match, 1 = a divergence, 2 = invocation error.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def canonical_bytes(obj) -> bytes:
    """Sorted-key, whitespace-free JSON — the protocol's canonical form."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def vat_id(body: dict) -> str:
    preimage = dict(body)
    preimage["attempt_id"] = ""
    preimage["signature"] = ""
    preimage["signer_pubkey_hex"] = ""
    return "vat_" + hashlib.sha256(canonical_bytes(preimage)).hexdigest()[:16]


def main() -> int:
    fixture = HERE / "attempt-id.json"
    try:
        data = json.loads(fixture.read_text())
    except FileNotFoundError:
        print(f"fixture not found: {fixture}", file=sys.stderr)
        return 2

    failures = 0
    for vec in data["vectors"]:
        name = vec["name"]
        body = vec["body"]
        # Cross-check the pinned canonical preimage string too.
        preimage = dict(body)
        preimage["attempt_id"] = ""
        preimage["signature"] = ""
        preimage["signer_pubkey_hex"] = ""
        got_preimage = canonical_bytes(preimage).decode("utf-8")
        if got_preimage != vec["canonical_preimage"]:
            print(f"[{name}] preimage mismatch:\n  got:      {got_preimage}\n  expected: {vec['canonical_preimage']}")
            failures += 1
        got = vat_id(body)
        if got != vec["expected_attempt_id"]:
            print(f"[{name}] id mismatch: got {got}, expected {vec['expected_attempt_id']}")
            failures += 1
        else:
            print(f"[{name}] OK {got}")

    if failures:
        print(f"FAIL: {failures} divergence(s)", file=sys.stderr)
        return 1
    print("all attempt-id vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
