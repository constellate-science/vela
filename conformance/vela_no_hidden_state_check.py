#!/usr/bin/env python3
"""
Executable no-hidden-state conformance check for Vela v0.9.

Input: a JSON export with:
  {
    "state": {...},
    "observation_packets": [
      {
        "output_path": "claims.vf_1.status",
        "output": "T",
        "output_hash": "... optional ...",
        "presentation_root": "...",
        "lineage_root": "...",
        "view_root": "...",
        "evaluator_id": "belnap_support"
      }
    ],
    "field_roles": {
      "claims.vf_1.status": "status",
      "claims.vf_1.kappa": "confidence"
    }
  }

Predicate:
  Let A be every JSON path whose declared role or path name is authoritative
  scientific state: status, confidence, kappa, trust, frontier, cost,
  bottleneck, bilattice, structural_delta, support, refute.

  The export passes iff every p in A has exactly one observation packet with
  output_path=p, the packet contains the required replay roots/evaluator fields,
  and canonical_hash(packet.output) equals canonical_hash(value_at(state,p)).

  Anything displayed as scientific state without a replayable observation packet
  is hidden state and fails conformance.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

AUTHORITATIVE_ROLES = {
    "status", "confidence", "kappa", "trust", "frontier", "cost", "bottleneck",
    "bilattice", "structural_delta", "support", "refute", "decision_delta",
}
AUTHORITATIVE_NAME_RE = re.compile(
    r"(^|[._-])(status|confidence|kappa|trust|frontier|cost|bottleneck|bilattice|structural_delta|support|refute|decision_delta)([._-]|$)",
    re.I,
)
REQUIRED_PACKET_FIELDS = {
    "output_path", "output", "presentation_root", "lineage_root", "view_root", "evaluator_id"
}


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def h(obj: Any) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def walk(obj: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            yield from walk(v, path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}.{i}" if prefix else str(i)
            yield from walk(v, path)
    else:
        yield prefix, obj


def role_of(path: str, field_roles: Dict[str, str]) -> str | None:
    if path in field_roles:
        return field_roles[path]
    # Support prefix role inheritance: claims.vf.status can be declared at claims.vf.
    parts = path.split(".")
    for i in range(len(parts), 0, -1):
        pfx = ".".join(parts[:i])
        if pfx in field_roles:
            return field_roles[pfx]
    return None


def authoritative_paths(state: Any, field_roles: Dict[str, str]) -> Dict[str, Any]:
    out = {}
    for path, val in walk(state):
        role = role_of(path, field_roles)
        if role in AUTHORITATIVE_ROLES or AUTHORITATIVE_NAME_RE.search(path):
            out[path] = val
    return out


def check_export(doc: Dict[str, Any]) -> List[str]:
    state = doc.get("state", {})
    packets = doc.get("observation_packets", [])
    roles = doc.get("field_roles", {})
    errors: List[str] = []

    auth = authoritative_paths(state, roles)
    packets_by_path: Dict[str, List[Dict[str, Any]]] = {}
    for pkt in packets:
        p = pkt.get("output_path")
        if isinstance(p, str):
            packets_by_path.setdefault(p, []).append(pkt)

    for path, val in sorted(auth.items()):
        ps = packets_by_path.get(path, [])
        if len(ps) != 1:
            errors.append(f"{path}: expected exactly one observation packet, found {len(ps)}")
            continue
        pkt = ps[0]
        missing = sorted(REQUIRED_PACKET_FIELDS - set(pkt))
        if missing:
            errors.append(f"{path}: packet missing fields {missing}")
            continue
        if h(pkt.get("output")) != h(val):
            errors.append(
                f"{path}: packet output hash {h(pkt.get('output'))} does not match state value hash {h(val)}"
            )
        if pkt.get("output_hash") and pkt["output_hash"] != h(pkt.get("output")):
            errors.append(f"{path}: declared output_hash does not match canonical output")

    for pkt in packets:
        p = pkt.get("output_path")
        if p and p not in auth:
            # Non-authoritative packets are allowed, but they do not satisfy the no-hidden-state obligation.
            pass

    return errors


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("json_export")
    args = ap.parse_args()
    doc = json.loads(Path(args.json_export).read_text())
    errors = check_export(doc)
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        raise SystemExit(1)
    print("PASS: no hidden authoritative scientific state fields")


if __name__ == "__main__":
    main()
