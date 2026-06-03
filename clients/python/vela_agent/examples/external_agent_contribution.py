#!/usr/bin/env python3
"""External agent contribution example.

The example uses the same local review boundary as a human reviewer:
it reads frontier policy, claims one task, records one pending proposal,
links a vaa_* agent attestation to a Scientific Diff Pack, and leaves
the task awaiting review. It does not accept its own output.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from vela_agent.primitives import AgentAttestation, ToolCall, sha256_hex


DEFAULT_KEY_HEX = "00" * 32


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_hash(value: Any) -> str:
    return sha256_hex(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _run(args: list[str]) -> tuple[dict[str, Any], int]:
    start = time.monotonic()
    completed = subprocess.run(args, check=True, capture_output=True, text=True)
    duration_ms = int((time.monotonic() - start) * 1000)
    text = completed.stdout.strip() or "{}"
    try:
        return json.loads(text), duration_ms
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"command did not return JSON: {' '.join(args)}") from exc


def _pick_task(tasks: dict[str, Any], requested: str | None) -> str:
    if requested:
        return requested
    for task in tasks.get("tasks", []):
        if task.get("status") == "eligible":
            return task["id"]
    raise RuntimeError("no eligible task found; pass --task-id")


def _write_attestation(
    *,
    frontier: Path,
    actor: str,
    model_name: str,
    model_version: str,
    signing_key_hex: str,
    started_at: str,
    finished_at: str,
    prompt: str,
    tool_calls: list[ToolCall],
    output: dict[str, Any],
) -> AgentAttestation:
    key = SigningKey(bytes.fromhex(signing_key_hex))
    attestation = AgentAttestation.build(
        key=key,
        agent_actor=actor,
        model_name=model_name,
        model_version=model_version,
        started_at=started_at,
        finished_at=finished_at,
        total_tokens=0,
        tool_calls=tool_calls,
        output_hashes=[_json_hash(output)],
        prompt_hash=sha256_hex(prompt),
    )
    out_dir = frontier / ".vela" / "agent_attestations"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{attestation.attestation_id}.json"
    with out.open("w", encoding="utf-8") as handle:
        json.dump(attestation.to_json(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    attestation.verify()
    return attestation


def _write_artifact_packet(
    *,
    frontier: Path,
    actor: str,
    task_id: str,
    locator: str,
    source_record_count: int,
) -> tuple[Path, dict[str, Any]]:
    assertion = (
        "External agent draft: fixture source identity should be reviewed before "
        "any frontier claim changes."
    )
    suffix = sha256_hex(f"{actor}:{task_id}:{locator}")[:12]
    artifact_id = f"agent_artifact_{suffix}"
    claim_id = f"agent_claim_{suffix}"
    need_id = f"agent_gap_{suffix}"
    packet = {
        "schema": "carina.artifact_packet.v0.1",
        "packet_id": f"cap_{sha256_hex(f'external-agent:{actor}:{task_id}:{locator}')[:16]}",
        "producer": {
            "kind": "agent",
            "id": actor,
            "name": "External agent contribution example",
        },
        "topic": "agent_contribution.source_material",
        "created_at": "2026-05-14T00:00:00Z",
        "artifacts": [
            {
                "id": artifact_id,
                "kind": "model_output",
                "title": "External agent source-material draft",
                "locator": f"agent:external-contribution:{task_id}",
                "content_hash": f"sha256:{sha256_hex(assertion)}",
                "parents": [],
                "metadata": {
                    "task_id": task_id,
                    "source_locator": locator,
                    "source_record_count": source_record_count,
                    "review_boundary": "source material until accepted by local review",
                },
            }
        ],
        "candidate_claims": [
            {
                "id": claim_id,
                "assertion": assertion,
                "assertion_type": "methodological",
                "evidence_artifact_ids": [artifact_id],
                "source_refs": [locator],
                "conditions": [
                    "Agent contribution kit fixture. This is source material, not accepted scientific state."
                ],
                "confidence": 0.2,
                "caveats": [
                    "Human review is required before this draft affects frontier state."
                ],
            }
        ],
        "open_needs": [
            {
                "id": need_id,
                "question": "Which source locator and evidence span should a reviewer inspect before accepting this agent draft?",
                "rationale": "Agent output is useful only when a local reviewer can connect it to source-grounded frontier state.",
            }
        ],
        "caveats": [
            "Agent output is source material until reviewer acceptance.",
            "This example demonstrates contribution mechanics, not a scientific conclusion.",
        ],
    }
    out_dir = frontier / ".vela" / "agent_packets"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "external-agent-contribution-packet.json"
    with out.open("w", encoding="utf-8") as handle:
        json.dump(packet, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return out, packet


def run(args: argparse.Namespace) -> dict[str, Any]:
    frontier = args.frontier.resolve()
    vela = args.vela
    actor = args.actor
    started_at = _now()

    frontier_doc = frontier / "FRONTIER.md"
    prompt = "\n".join(
        [
            "Read FRONTIER.md.",
            "Run vela doctor.",
            "List source inbox and tasks.",
            "Claim one eligible task.",
            "Inspect declared sources.",
            "Draft proposals only as source material.",
            "Submit a Scientific Diff Pack.",
            "Run Evidence CI.",
            "Build a review packet.",
            "Do not accept your own output.",
        ]
    )
    if frontier_doc.is_file():
        prompt = f"{frontier_doc.read_text(encoding='utf-8')}\n\n{prompt}"

    tool_calls: list[ToolCall] = []

    def run_tool(tool_name: str, command: list[str]) -> dict[str, Any]:
        payload, duration_ms = _run(command)
        tool_calls.append(
            ToolCall(
                tool_name=tool_name,
                input_hash=sha256_hex(" ".join(command)),
                output_hash=_json_hash(payload),
                duration_ms=duration_ms,
            )
        )
        return payload

    doctor = run_tool("vela doctor", [vela, "doctor", str(frontier), "--json"])
    tasks = run_tool(
        "vela task list",
        [vela, "task", "list", str(frontier), "--status", "eligible", "--json"],
    )
    source_inbox = run_tool(
        "vela source-inbox list",
        [vela, "source-inbox", "list", str(frontier), "--json"],
    )
    task_id = _pick_task(tasks, args.task_id)
    task = run_tool("vela task show", [vela, "task", "show", str(frontier), task_id, "--json"])
    run_tool(
        "vela task claim",
        [vela, "task", "claim", str(frontier), task_id, "--reviewer", actor, "--json"],
    )
    workspace = run_tool(
        "vela task workspace init",
        [vela, "task", "workspace", "init", str(frontier), task_id, "--json"],
    )

    locator = "declared source"
    records = source_inbox.get("records") or []
    if records:
        locator = records[0].get("locator") or records[0].get("title") or locator

    artifact_packet_path, artifact_packet = _write_artifact_packet(
        frontier=frontier,
        actor=actor,
        task_id=task_id,
        locator=locator,
        source_record_count=source_inbox.get("total", 0),
    )
    runtime_import = run_tool(
        "vela runtime-adapter run",
        [
            vela,
            "runtime-adapter",
            "run",
            str(frontier),
            "scienceclaw-artifact-v1",
            "--input",
            str(artifact_packet_path),
            "--actor",
            actor,
            "--json",
        ],
    )
    proposal_ids = runtime_import["proposal_ids"]
    if not proposal_ids:
        raise RuntimeError("runtime import did not create reviewable proposals")
    proposal_id = proposal_ids[0]

    attestation_output = {
        "task_id": task_id,
        "proposal_id": proposal_id,
        "proposal_ids": proposal_ids,
        "artifact_packet_id": artifact_packet["packet_id"],
        "runtime_run_id": runtime_import["run_id"],
        "frontier": str(frontier),
        "source_records": source_inbox.get("total", 0),
    }
    attestation = _write_attestation(
        frontier=frontier,
        actor=actor,
        model_name=args.model_name,
        model_version=args.model_version,
        signing_key_hex=args.signing_key_hex,
        started_at=started_at,
        finished_at=_now(),
        prompt=prompt,
        tool_calls=tool_calls,
        output=attestation_output,
    )

    draft_pack = frontier / ".vela" / "diff_packs" / "agent-contribution-draft.json"
    pack = run_tool(
        "vela diff-pack create",
        [
            vela,
            "diff-pack",
            "create",
            str(frontier),
            "--proposals",
            ",".join(proposal_ids),
            "--summary",
            "External agent source-material proposal for human review.",
            "--aggregate-kind",
            "agent.proposal_set",
            "--agent-run",
            attestation.attestation_id,
            "--out",
            str(draft_pack),
            "--json",
        ],
    )
    pack_id = pack["pack_id"]
    pack_path = frontier / ".vela" / "diff_packs" / f"{pack_id}.json"
    if draft_pack != pack_path:
        if pack_path.exists():
            pack_path.unlink()
        draft_pack.rename(pack_path)

    verify = run_tool(
        "vela diff-pack verify",
        [vela, "diff-pack", "verify", str(pack_path), "--json"],
    )
    evidence_ci = run_tool(
        "vela diff-pack validate",
        [vela, "diff-pack", "validate", str(frontier), pack_id, "--evidence-ci", "--json"],
    )
    run_tool(
        "vela task set-status",
        [vela, "task", "set-status", str(frontier), task_id, "--status", "awaiting_review", "--json"],
    )
    review_packet = run_tool(
        "vela review-packet build",
        [
            vela,
            "review-packet",
            "build",
            str(frontier),
            task_id,
            "--out",
            str(frontier / "review" / "agent-contribution-review.md"),
            "--json",
        ],
    )

    return {
        "ok": True,
        "frontier": str(frontier),
        "doctor_ok": doctor.get("ok"),
        "task_id": task_id,
        "task_objective": task.get("objective"),
        "workspace": workspace.get("workspace_path"),
        "proposal_id": proposal_id,
        "proposal_ids": proposal_ids,
        "artifact_packet_id": artifact_packet["packet_id"],
        "artifact_packet_path": str(artifact_packet_path),
        "runtime_run_id": runtime_import["run_id"],
        "runtime_run_path": runtime_import.get("run_path"),
        "runtime_duplicate_packet": runtime_import.get("idempotency", {}).get(
            "duplicate_packet"
        ),
        "runtime_skipped_existing_proposals": runtime_import.get("idempotency", {}).get(
            "skipped_existing_proposals", []
        ),
        "artifact_proposals": runtime_import["artifact_proposals"],
        "finding_proposals": runtime_import["finding_proposals"],
        "gap_proposals": runtime_import["gap_proposals"],
        "agent_attestation_id": attestation.attestation_id,
        "diff_pack_id": pack_id,
        "diff_pack_path": str(pack_path),
        "verify_ok": verify.get("ok"),
        "evidence_ci_ok": evidence_ci.get("ok"),
        "review_packet": review_packet.get("out"),
        "accepted_state": "unchanged",
        "next": [
            f"vela diff-pack inspect {frontier} {pack_id} --json",
            f"vela workbench {frontier} --port 3741 --no-open",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("frontier", type=Path)
    parser.add_argument("--vela", default="vela")
    parser.add_argument("--task-id")
    parser.add_argument("--actor", default="agent:external-contributor")
    parser.add_argument("--model-name", default="external-agent")
    parser.add_argument("--model-version", default="local-example")
    parser.add_argument("--signing-key-hex", default=DEFAULT_KEY_HEX)
    ns = parser.parse_args(argv)
    result = run(ns)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
