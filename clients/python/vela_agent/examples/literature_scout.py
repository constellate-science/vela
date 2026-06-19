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

from vela_agent import VelaAgent


def run(frontier_path: Path, frontier_id: str, signing_key: SigningKey) -> tuple[str, str]:
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
    agent.add_proposal(
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
