#!/usr/bin/env python3
"""literature_scout — minimal agent that proposes a new finding from
a sample arxiv abstract.

Records two tool calls (`search_arxiv`, `fetch_abstract`) and submits
a single-proposal Scientific Diff Pack with `aggregate_kind =
finding.add`. The Diff Pack carries the vaa_* attestation so a
reviewer reading the pack can trace which model produced the
proposal under what prompt.

Run:
    python -m vela_agent.examples.literature_scout /path/to/frontier
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nacl.signing import SigningKey

from vela_agent import VelaAgent, open_trajectory
from vela_agent.primitives import TrajectoryStepKind


def run(frontier_path: Path, frontier_id: str, signing_key: SigningKey) -> tuple[str, str, str]:
    agent = VelaAgent(
        model_name="claude-opus-4.7",
        model_version="claude-opus-4.7-20260411",
        frontier_path=frontier_path,
        signing_key=signing_key,
        actor="agent:literature_scout",
        frontier_id=frontier_id,
    )
    agent.open_run(prompt="propose a new finding from the sample arxiv abstract")

    # Two tool calls: a search + a fetch.
    agent.record_tool_call(
        tool_name="search_arxiv",
        input_obj={"query": "anti-amyloid lecanemab subset 2024"},
        output_obj={"hits": ["arXiv:2410.12345"], "count": 1},
        duration_ms=420,
        tokens=180,
    )
    agent.record_tool_call(
        tool_name="fetch_abstract",
        input_obj={"arxiv_id": "arXiv:2410.12345"},
        output_obj={
            "title": "Lecanemab efficacy in apoE4 homozygotes — 2024 subset analysis",
            "abstract_excerpt": "...",
        },
        duration_ms=180,
        tokens=420,
    )

    # Propose a finding.
    vpr = agent.add_proposal(
        kind="finding.add",
        payload={
            "assertion": {
                "text": "Lecanemab shows reduced ARIA-E incidence in apoE4 non-carriers vs homozygotes",
                "assertion_type": "claim",
            },
            "provenance": {
                "title": "Lecanemab efficacy in apoE4 homozygotes — 2024 subset analysis",
                "doi": None,
                "pmid": None,
            },
            "confidence": {"value": 0.62, "n_sources": 1},
        },
    )

    vaa, vsd = agent.submit_diff_pack(
        summary="Literature-scout proposal: lecanemab apoE4 subset finding.",
        aggregate_kind="finding.add",
    )

    # Also open a small trajectory showing the search path.
    traj = open_trajectory(
        target_findings=[],
        deposited_by="agent:literature_scout",
        notes="Search path for the lecanemab apoE4 subset finding.",
    )
    traj.append(
        kind=TrajectoryStepKind.QUESTION,
        description="Does lecanemab efficacy differ by apoE4 genotype in 2024 data?",
    )
    traj.append(
        kind=TrajectoryStepKind.TOOL,
        description="search_arxiv for `anti-amyloid lecanemab subset 2024`",
    )
    traj.append(
        kind=TrajectoryStepKind.DATA,
        description="fetched abstract of arXiv:2410.12345",
    )
    traj.append(
        kind=TrajectoryStepKind.MODEL,
        description="claude-opus-4.7 drafted the finding text under vaa_*",
        references=[vaa],
    )
    traj.append(
        kind=TrajectoryStepKind.OUTPUT,
        description=f"proposed finding under {vpr}; bundled in {vsd}",
        references=[vsd, vpr],
    )
    traj.save_to_frontier(frontier_path)
    return vaa, vsd, traj.id


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("frontier", type=Path)
    p.add_argument("--frontier-id", required=True)
    args = p.parse_args(argv)
    key = SigningKey.generate()
    vaa, vsd, vtr = run(args.frontier, args.frontier_id, key)
    print(f"vaa_id: {vaa}")
    print(f"vsd_id: {vsd}")
    print(f"vtr_id: {vtr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
