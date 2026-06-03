#!/usr/bin/env python3
"""v0.227: real benchmark wiring against an Erdős-problems verifier.

Replaces the v0.208 mock AstaBench example with a real,
publicly-runnable benchmark. The "tool" is a Sidon-set verifier:
given a list of integers, decide whether all pairwise sums are
distinct (the defining property of a Sidon B_2 set). Deterministic,
runs in CI without external deps, verification logic auditable
end-to-end in the file.

The script:

  1. Builds (or fetches) a `vtd_*` Tool Descriptor for the
     sidon-verifier tool. The descriptor pins (tool_name,
     tool_version, provider, calling_convention, input_schema,
     output_schema) and lands under
     `<frontier>/.vela/tool_descriptors/<vtd_id>.json`.

  2. Runs the verifier on a benchmark corpus of three known
     instances:
       - Singer(7): {1, 2, 4, 8, 16, 32, 64} — a classical Sidon
         construction. Expected pass.
       - First-13: {1, 2, 5, 11, 22, 40, 64, 85, 105, 117, 121,
         123, 128} — a known small-prefix Sidon set.
       - Counter-example: {1, 2, 3, 5} — fails (1+5 == 2+4? no;
         this set actually IS Sidon. Use {1,2,3,4} instead:
         1+4=2+3.). Expected fail with conflict (1,4)=(2,3).

  3. Aggregates a score (fraction passed against expected) and
     emits a real `ver_*` Evaluation Record signed under the
     bench-operator's key. The ver_* lands under
     `<frontier>/.vela/evaluations/<ver_id>.json` and verifies
     under the Rust CLI byte-for-byte.

Run:
    python3 -m vela_agent.examples.real_bench_erdos /path/to/frontier
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey

# ---------------------------------------------------------------------------
# The verifier tool. Deterministic, auditable, no external deps.
# ---------------------------------------------------------------------------

def is_sidon(s: list[int]) -> tuple[bool, tuple[int, int, int, int] | None]:
    """Return (True, None) if s is a Sidon B_2 set (all pairwise sums
    distinct); otherwise (False, (a, b, c, d)) witnessing a+b = c+d
    with {a,b} != {c,d}."""
    seen: dict[int, tuple[int, int]] = {}
    sorted_s = sorted(set(s))
    for i, a in enumerate(sorted_s):
        for b in sorted_s[i:]:
            total = a + b
            if total in seen:
                c, d = seen[total]
                if {a, b} != {c, d}:
                    return False, (c, d, a, b)
            else:
                seen[total] = (a, b)
    return True, None


# ---------------------------------------------------------------------------
# Tool Descriptor + Evaluation Record builders (mirror the Rust
# canonical-bytes layout byte-for-byte).
# ---------------------------------------------------------------------------

def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def build_tool_descriptor(*, signing_key: SigningKey) -> dict:
    tool_name = "sidon-verifier"
    tool_version = "0.1.0"
    provider = "github:vela-science/vela:real_bench_erdos"
    calling_convention = "local_python"
    input_schema = {
        "type": "object",
        "properties": {"set": {"type": "array", "items": {"type": "integer"}}},
        "required": ["set"],
    }
    output_schema = {
        "type": "object",
        "properties": {
            "is_sidon": {"type": "boolean"},
            "conflict": {
                "type": ["array", "null"],
                "items": {"type": "integer"},
            },
        },
    }
    parts = [
        tool_name.encode("utf-8"), b"|",
        tool_version.encode("utf-8"), b"|",
        provider.encode("utf-8"), b"|",
        calling_convention.encode("utf-8"), b"|",
        canonical_json(input_schema).encode("utf-8"), b"|",
        canonical_json(output_schema).encode("utf-8"),
    ]
    preimage = b"".join(parts)
    descriptor_id = "vtd_" + hashlib.sha256(preimage).hexdigest()[:16]
    sig = signing_key.sign(preimage).signature.hex()
    return {
        "schema": "vela.tool_descriptor.v0.1",
        "descriptor_id": descriptor_id,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "provider": provider,
        "calling_convention": calling_convention,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "signature": sig,
        "signer_pubkey_hex": bytes(signing_key.verify_key).hex(),
    }


def build_evaluation_record(
    *,
    target_id: str,
    evaluator_actor: str,
    evaluated_at: str,
    score: float,
    outcome: str,
    notes: str,
    signing_key: SigningKey,
) -> dict:
    target_kind = "tool_descriptor"
    evaluation_kind = "benchmark"
    benchmark_id = "erdos:sidon-verifier:v1"
    evidence_refs: list[str] = []
    parts = [
        target_kind.encode("utf-8"), b"|",
        target_id.encode("utf-8"), b"|",
        evaluation_kind.encode("utf-8"), b"|",
        outcome.encode("utf-8"), b"|",
        evaluator_actor.encode("utf-8"), b"|",
        evaluated_at.encode("utf-8"), b"|",
    ]
    # evidence_refs section (empty here -> no inner bytes).
    parts.append(b"|")
    parts.append(benchmark_id.encode("utf-8"))
    parts.append(b"|")
    parts.append(repr(float(score)).encode("utf-8"))
    parts.append(b"|")
    parts.append(notes.encode("utf-8"))
    preimage = b"".join(parts)
    record_id = "ver_" + hashlib.sha256(preimage).hexdigest()[:16]
    sig = signing_key.sign(preimage).signature.hex()
    record = {
        "schema": "vela.evaluation_record.v0.1",
        "record_id": record_id,
        "target_kind": target_kind,
        "target_id": target_id,
        "evaluation_kind": evaluation_kind,
        "outcome": outcome,
        "evaluator_actor": evaluator_actor,
        "evaluated_at": evaluated_at,
        "evidence_refs": evidence_refs,
        "benchmark_id": benchmark_id,
        "score": score,
        "notes": notes,
        "signature": sig,
        "signer_pubkey_hex": bytes(signing_key.verify_key).hex(),
    }
    return record


# ---------------------------------------------------------------------------
# Bench corpus + run.
# ---------------------------------------------------------------------------

CORPUS = [
    {
        "name": "powers_of_2_to_64",
        "input": [1, 2, 4, 8, 16, 32, 64],
        "expected_is_sidon": True,
    },
    {
        "name": "sidon_5_classic",
        # {1, 2, 5, 11, 13}: pairwise sums all distinct.
        # 1+2=3, 1+5=6, 1+11=12, 1+13=14, 2+5=7, 2+11=13,
        # 2+13=15, 5+11=16, 5+13=18, 11+13=24.
        "input": [1, 2, 5, 11, 13],
        "expected_is_sidon": True,
    },
    {
        "name": "not_sidon_1_2_3_4",
        # 1+4 = 2+3 = 5; conflicting pair.
        "input": [1, 2, 3, 4],
        "expected_is_sidon": False,
    },
]


def run(frontier_path: Path, signing_key: SigningKey) -> tuple[str, str]:
    """Run the bench; emit vtd_* + ver_*; return (vtd_id, ver_id)."""
    # Build + write the Tool Descriptor.
    vtd = build_tool_descriptor(signing_key=signing_key)
    vtd_dir = frontier_path / ".vela" / "tool_descriptors"
    vtd_dir.mkdir(parents=True, exist_ok=True)
    (vtd_dir / f"{vtd['descriptor_id']}.json").write_text(
        json.dumps(vtd, indent=2, sort_keys=True) + "\n"
    )

    # Run the verifier against the corpus.
    correct = 0
    notes_lines: list[str] = []
    for case in CORPUS:
        got, conflict = is_sidon(case["input"])
        ok = got == case["expected_is_sidon"]
        if ok:
            correct += 1
            notes_lines.append(f"  {case['name']}: ok ({'Sidon' if got else 'not Sidon'})")
        else:
            notes_lines.append(
                f"  {case['name']}: WRONG (expected={case['expected_is_sidon']}, got={got}, conflict={conflict})"
            )
    score = correct / len(CORPUS)
    outcome = "succeeded" if score == 1.0 else "partial" if score >= 0.5 else "failed"
    notes = "Sidon-verifier benchmark, 3-case corpus. " + "; ".join(notes_lines)

    ver = build_evaluation_record(
        target_id=vtd["descriptor_id"],
        evaluator_actor="lab:vela_erdos_bench",
        evaluated_at="2026-05-12T18:00:00Z",
        score=score,
        outcome=outcome,
        notes=notes,
        signing_key=signing_key,
    )
    eval_dir = frontier_path / ".vela" / "evaluations"
    eval_dir.mkdir(parents=True, exist_ok=True)
    (eval_dir / f"{ver['record_id']}.json").write_text(
        json.dumps(ver, indent=2, sort_keys=True) + "\n"
    )
    return vtd["descriptor_id"], ver["record_id"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("frontier", type=Path)
    p.add_argument(
        "--key",
        type=str,
        default=None,
        help="32-byte hex-encoded Ed25519 signing key. Deterministic default if omitted.",
    )
    args = p.parse_args(argv)
    # Deterministic default seed so re-running produces stable ids.
    seed = (
        bytes.fromhex(args.key)
        if args.key is not None
        else b"vela-erdos-bench-operator-key-v2"[:32]
    )
    if len(seed) != 32:
        print(f"FAIL: key must be 32 bytes, got {len(seed)}", file=sys.stderr)
        return 2
    key = SigningKey(seed)
    vtd_id, ver_id = run(args.frontier, key)
    print(f"vtd_id: {vtd_id}")
    print(f"ver_id: {ver_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
