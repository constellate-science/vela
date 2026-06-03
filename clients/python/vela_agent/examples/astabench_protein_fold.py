#!/usr/bin/env python3
"""v0.208: example AstaBench protein-fold bench against a vtd_*.

Mocks the actual fold call (we are not running protein folding in
CI). Produces a real `ver_*` Evaluation Record targeting a real
`vtd_*` Tool Descriptor under the bench operator's signing key.

Run:
    python -m vela_agent.examples.astabench_protein_fold /path/to/frontier \\
        --tool-descriptor vtd_d50b932e406862a6
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from nacl.signing import SigningKey

from vela_agent import BenchSession


def mock_protein_fold(input_obj: dict) -> dict:
    """Stand-in for a real protein-folding tool call.

    Returns a deterministic PDB-shaped output based on a sha256 of
    the input sequence so the example is reproducible.
    """
    seq = input_obj.get("sequence", "")
    fingerprint = hashlib.sha256(seq.encode("utf-8")).hexdigest()[:16]
    return {
        "pdb": f"HEADER    mock-fold {fingerprint}\nATOM      1  N   MET A   1\nEND\n",
        "tm_score": round(0.50 + len(seq) % 50 / 100.0, 3),
        "fingerprint": fingerprint,
    }


def run(frontier_path: Path, tool_descriptor: str, signing_key: SigningKey) -> str:
    bench = BenchSession(
        tool_descriptor_id=tool_descriptor,
        benchmark_id="astabench:protein-fold:v1",
        evaluator_actor="lab:vela_bench_demo",
        signing_key=signing_key,
        frontier_path=frontier_path,
    )

    # Three test sequences. In a real bench the harness would feed
    # the AstaBench corpus; we use three fixed inputs so the
    # example is deterministic.
    samples = [
        {"sequence": "MASETLKDVAA"},
        {"sequence": "MKVLWAALLVTFLAGCQA"},
        {"sequence": "MKVLILACLVALALAR"},
    ]
    scores = []
    for s in samples:
        out = bench.run(input_obj=s, invoke=mock_protein_fold)
        scores.append(out["tm_score"])

    mean_tm = round(sum(scores) / len(scores), 3)
    outcome = "succeeded" if mean_tm >= 0.50 else "partial"

    ver_id = bench.record_result(
        score=mean_tm,
        outcome=outcome,
        notes=(
            f"AstaBench protein-fold demo. 3 sequences, mean TM-score "
            f"{mean_tm:.3f}. Mock harness (no real folding executed); "
            f"the ver_* records the bench-call structure, not real "
            f"scientific evaluation."
        ),
    )
    return ver_id


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("frontier", type=Path)
    p.add_argument(
        "--tool-descriptor",
        required=True,
        help="vtd_* id the bench targets",
    )
    args = p.parse_args(argv)
    key = SigningKey.generate()
    ver_id = run(args.frontier, args.tool_descriptor, key)
    print(f"ver_id: {ver_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
