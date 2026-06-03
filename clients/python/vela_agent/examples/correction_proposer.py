#!/usr/bin/env python3
"""correction_proposer — proposes a confidence revision on a contested
finding under aggregate_kind `correction.batch`.

Submits two proposals in a single pack: (a) lower the confidence of
the contested finding; (b) add a contradicting evidence pointer.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nacl.signing import SigningKey

from vela_agent import VelaAgent


def run(frontier_path: Path, frontier_id: str, signing_key: SigningKey) -> tuple[str, str]:
    agent = VelaAgent(
        model_name="claude-opus-4.7",
        model_version="claude-opus-4.7-20260411",
        frontier_path=frontier_path,
        signing_key=signing_key,
        actor="agent:correction_proposer",
        frontier_id=frontier_id,
    )
    agent.open_run(prompt="propose a confidence correction on a contested finding")

    agent.record_tool_call(
        tool_name="find_contradicting_evidence",
        input_obj={"finding_id": "vf_sample_lecanemab_apoe4"},
        output_obj={
            "hits": ["10.1234/contradiction"],
            "summary_excerpt": "Cohort study with opposing direction",
        },
        duration_ms=1_100,
        tokens=720,
    )

    agent.add_proposal(
        kind="confidence.update",
        payload={
            "finding_id": "vf_sample_lecanemab_apoe4",
            "delta": -0.12,
            "reason": "Contradicting evidence from 2025 cohort study (DOI 10.1234/contradiction).",
        },
    )
    agent.add_proposal(
        kind="evidence.add",
        payload={
            "finding_id": "vf_sample_lecanemab_apoe4",
            "evidence_kind": "contradicting",
            "source_doi": "10.1234/contradiction",
        },
    )

    vaa, vsd = agent.submit_diff_pack(
        summary="Correction-proposer: confidence revision + contradicting evidence pointer.",
        aggregate_kind="correction.batch",
    )
    return vaa, vsd


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("frontier", type=Path)
    p.add_argument("--frontier-id", required=True)
    args = p.parse_args(argv)
    key = SigningKey.generate()
    vaa, vsd = run(args.frontier, args.frontier_id, key)
    print(f"vaa_id: {vaa}")
    print(f"vsd_id: {vsd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
