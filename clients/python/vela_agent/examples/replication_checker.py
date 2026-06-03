#!/usr/bin/env python3
"""replication_checker — opens a trajectory with the full Question /
Data / Tool / Output / Review step taxonomy, then submits a status
diff pack flagging the replication outcome.

The trajectory exercises v0.194's vision-taxonomy kinds; the diff
pack exercises v0.193's `aggregate_kind = evidence.refresh` pattern.
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
        actor="agent:replication_checker",
        frontier_id=frontier_id,
    )
    agent.open_run(prompt="replicate the lecanemab apoE4 subset finding")
    agent.record_tool_call(
        tool_name="run_replication_protocol",
        input_obj={
            "target_finding": "vf_sample_lecanemab_apoe4",
            "n_attempts": 3,
        },
        output_obj={
            "n_successes": 2,
            "n_failures": 1,
            "notes": "1 attempt failed on small-cohort variance",
        },
        duration_ms=2_400,
        tokens=900,
    )

    vpr_status = agent.add_proposal(
        kind="finding.update_replication_state",
        payload={
            "finding_id": "vf_sample_lecanemab_apoe4",
            "new_state": "partial_replication",
            "evidence": {"n_successes": 2, "n_failures": 1},
        },
    )

    vaa, vsd = agent.submit_diff_pack(
        summary="Replication-checker: 2/3 successes on lecanemab apoE4 finding.",
        aggregate_kind="evidence.refresh",
    )

    traj = open_trajectory(
        target_findings=[],
        deposited_by="agent:replication_checker",
        notes="Replication run on lecanemab apoE4 subset finding.",
    )
    traj.append(
        kind=TrajectoryStepKind.QUESTION,
        description="Does the lecanemab apoE4 subset finding replicate at n=3?",
    )
    traj.append(
        kind=TrajectoryStepKind.PROTOCOL,
        description="Three independent replication attempts; standard cohort filter.",
    )
    traj.append(
        kind=TrajectoryStepKind.DATA,
        description="Cohort: 2024 trial subset, n=120 apoE4 carriers.",
    )
    traj.append(
        kind=TrajectoryStepKind.TOOL,
        description="run_replication_protocol with n_attempts=3",
    )
    traj.append(
        kind=TrajectoryStepKind.OUTPUT,
        description="2/3 successes; 1 failure attributed to small-cohort variance.",
        references=[vsd, vpr_status],
    )
    traj.append(
        kind=TrajectoryStepKind.REVIEW,
        description="Pending human reviewer accept/reject; agent attestation under vaa_*.",
        references=[vaa],
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
