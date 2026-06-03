"""End-to-end tests for VelaAgent against a fixture frontier directory.

These are the tests `scripts/test-agent-sdk.sh` blesses with a green
gate: open a run, queue proposals, record tool calls, submit a diff
pack, and prove every artifact lands on disk in the expected shape
and verifies under the agent's signing key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from vela_agent import VelaAgent, open_trajectory
from vela_agent.primitives import (
    AgentAttestation,
    ScientificDiffPack,
    ToolCall,
    TrajectoryStepKind,
)


FRONTIER_ID = "vfr_5076e7b3ff8e6b0f"


def _fresh_frontier(tmp_path: Path) -> Path:
    fr = tmp_path / "fixture-frontier"
    fr.mkdir()
    (fr / "frontier.json").write_text(json.dumps({"frontier_id": FRONTIER_ID}))
    return fr


def test_full_run_writes_signed_artifacts(tmp_path: Path) -> None:
    fr = _fresh_frontier(tmp_path)
    key = SigningKey.generate()
    agent = VelaAgent(
        model_name="claude-opus-4.7",
        model_version="claude-opus-4.7-20260411",
        frontier_path=fr,
        signing_key=key,
        actor="agent:test_runner",
    )
    agent.open_run(prompt="propose something useful")
    agent.record_tool_call(
        tool_name="search_arxiv",
        input_obj={"q": "test"},
        output_obj={"hits": []},
        duration_ms=100,
        tokens=10,
    )
    vpr = agent.add_proposal(
        kind="finding.add",
        payload={"assertion": {"text": "test finding"}, "confidence": 0.5},
    )
    assert vpr.startswith("vpr_")
    assert agent.queued_proposal_ids == [vpr]

    vaa, vsd = agent.submit_diff_pack(
        summary="Test pack from SDK unit test.",
        aggregate_kind="finding.add",
    )
    assert vaa.startswith("vaa_")
    assert vsd.startswith("vsd_")
    assert not agent.open

    # Artifacts on disk.
    vaa_path = fr / ".vela" / "agent_attestations" / f"{vaa}.json"
    vsd_path = fr / ".vela" / "diff_packs" / f"{vsd}.json"
    vpr_path = fr / ".vela" / "agent_proposals" / f"{vpr}.json"
    assert vaa_path.is_file()
    assert vsd_path.is_file()
    assert vpr_path.is_file()

    # Verify each artifact.
    att_raw = json.loads(vaa_path.read_text())
    att = AgentAttestation(
        schema=att_raw["schema"],
        attestation_id=att_raw["attestation_id"],
        agent_actor=att_raw["agent_actor"],
        model_name=att_raw["model_name"],
        model_version=att_raw["model_version"],
        started_at=att_raw["started_at"],
        finished_at=att_raw["finished_at"],
        total_tokens=att_raw["total_tokens"],
        tool_calls=[ToolCall(**tc) for tc in att_raw["tool_calls"]],
        output_hashes=att_raw["output_hashes"],
        signature=att_raw["signature"],
        signer_pubkey_hex=att_raw["signer_pubkey_hex"],
        prompt_hash=att_raw.get("prompt_hash"),
        parent_attestation=att_raw.get("parent_attestation"),
    )
    att.verify()

    pack_raw = json.loads(vsd_path.read_text())
    pack = ScientificDiffPack(
        schema=pack_raw["schema"],
        pack_id=pack_raw["pack_id"],
        frontier_id=pack_raw["frontier_id"],
        created_at=pack_raw["created_at"],
        summary=pack_raw["summary"],
        proposals=pack_raw["proposals"],
        aggregate_kind=pack_raw["aggregate_kind"],
        agent_run=pack_raw.get("agent_run"),
        parent_pack=pack_raw.get("parent_pack"),
        applied_event_id=pack_raw.get("applied_event_id"),
        signature=pack_raw.get("signature"),
        signer_pubkey_hex=pack_raw.get("signer_pubkey_hex"),
    )
    pack.verify()
    assert pack.agent_run == att.attestation_id
    assert pack.proposals == [vpr]


def test_open_run_twice_raises(tmp_path: Path) -> None:
    fr = _fresh_frontier(tmp_path)
    agent = VelaAgent(
        model_name="m",
        model_version="v",
        frontier_path=fr,
        signing_key=SigningKey.generate(),
        actor="agent:t",
    )
    agent.open_run()
    with pytest.raises(RuntimeError):
        agent.open_run()


def test_actor_must_be_namespaced(tmp_path: Path) -> None:
    fr = _fresh_frontier(tmp_path)
    with pytest.raises(ValueError):
        VelaAgent(
            model_name="m",
            model_version="v",
            frontier_path=fr,
            signing_key=SigningKey.generate(),
            actor="reviewer:human",
        )


def test_submit_without_open_raises(tmp_path: Path) -> None:
    fr = _fresh_frontier(tmp_path)
    agent = VelaAgent(
        model_name="m",
        model_version="v",
        frontier_path=fr,
        signing_key=SigningKey.generate(),
        actor="agent:t",
    )
    with pytest.raises(RuntimeError):
        agent.submit_diff_pack(summary="x", aggregate_kind="y")


def test_trajectory_cites_vaa_and_vsd(tmp_path: Path) -> None:
    fr = _fresh_frontier(tmp_path)
    key = SigningKey.generate()
    agent = VelaAgent(
        model_name="m",
        model_version="v",
        frontier_path=fr,
        signing_key=key,
        actor="agent:t",
    )
    agent.open_run()
    agent.add_proposal(kind="finding.add", payload={"x": 1})
    vaa, vsd = agent.submit_diff_pack(summary="test", aggregate_kind="finding.add")

    traj = open_trajectory(target_findings=[], deposited_by="agent:t")
    traj.append(kind=TrajectoryStepKind.MODEL, description="model run", references=[vaa])
    traj.append(kind=TrajectoryStepKind.OUTPUT, description="output", references=[vsd])
    saved = traj.save_to_frontier(fr)
    assert saved.is_file()
    blob = json.loads(saved.read_text())
    refs = {r for step in blob["steps"] for r in step["references"]}
    assert vaa in refs
    assert vsd in refs


def test_frontier_id_inferred_from_frontier_json(tmp_path: Path) -> None:
    fr = _fresh_frontier(tmp_path)
    key = SigningKey.generate()
    agent = VelaAgent(
        model_name="m",
        model_version="v",
        frontier_path=fr,
        signing_key=key,
        actor="agent:t",
    )
    # Frontier id was not passed explicitly; agent must resolve it.
    agent.open_run()
    agent.add_proposal(kind="finding.add", payload={"x": 1})
    _, vsd = agent.submit_diff_pack(summary="test", aggregate_kind="finding.add")
    pack_path = fr / ".vela" / "diff_packs" / f"{vsd}.json"
    pack = json.loads(pack_path.read_text())
    assert pack["frontier_id"] == FRONTIER_ID


def test_missing_frontier_id_raises(tmp_path: Path) -> None:
    fr = tmp_path / "bare-frontier"
    fr.mkdir()
    agent = VelaAgent(
        model_name="m",
        model_version="v",
        frontier_path=fr,
        signing_key=SigningKey.generate(),
        actor="agent:t",
    )
    agent.open_run()
    agent.add_proposal(kind="finding.add", payload={"x": 1})
    with pytest.raises(RuntimeError):
        agent.submit_diff_pack(summary="x", aggregate_kind="y")
