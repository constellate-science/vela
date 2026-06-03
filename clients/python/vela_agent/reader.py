"""v0.214: agent read-side. Read existing artifacts from a Vela
frontier without going through the Rust binary.

The v0.196 SDK gives an agent a write surface (`VelaAgent`,
`BenchSession`, `open_trajectory`). The v0.214 reader gives the same
agent a complementary read surface — pull existing Diff Packs,
Attestations, Trajectories, Tool Descriptors, and Evaluations from a
frontier's `.vela/` tree so a multi-turn LLM session can reason
about prior context before submitting.

Substrate-honest framing: this is a pure read helper. It does not
mutate anything, does not verify signatures (callers can re-run
`vela diff-pack verify` etc. for that), and does not auto-promote
SDK stubs to canonical proposals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


def _vela_dir(frontier_path: Path | str) -> Path:
    p = Path(frontier_path)
    if p.is_dir():
        return p / ".vela"
    parent = p.parent or Path(".")
    return parent / ".vela"


def _read_json(path: Path) -> Optional[dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _list_dir(dir_path: Path, prefix: str) -> list[dict[str, Any]]:
    """List every `*.json` file in `dir_path` whose stem starts with
    `prefix` (e.g. "vsd_", "vaa_"). Returns the parsed bodies in
    file-name order; silently skips parse failures."""
    if not dir_path.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for entry in sorted(dir_path.iterdir()):
        if entry.suffix != ".json":
            continue
        stem = entry.stem
        if not stem.startswith(prefix):
            continue
        body = _read_json(entry)
        if body is not None:
            out.append(body)
    return out


@dataclass
class VelaReader:
    """Read-side companion to `VelaAgent`. Resolves frontier-local
    artifacts under `.vela/`.

    All methods are pure: no mutation, no network calls, no
    signature verification. The caller is responsible for
    re-verifying anything they pull through Rust CLI or the SDK's
    `primitives.AgentAttestation.verify()`.
    """

    frontier_path: Path

    def __init__(self, frontier_path: Path | str) -> None:
        self.frontier_path = Path(frontier_path)

    # ---- Diff Packs ------------------------------------------------------

    def get_pack(self, vsd_id: str) -> Optional[dict[str, Any]]:
        """Return the Diff Pack body for `vsd_id`, or None if missing."""
        if not vsd_id.startswith("vsd_"):
            raise ValueError(f"vsd_id must start with `vsd_`, got `{vsd_id}`")
        return _read_json(_vela_dir(self.frontier_path) / "diff_packs" / f"{vsd_id}.json")

    def list_packs(self) -> list[dict[str, Any]]:
        """List every Diff Pack on disk."""
        return _list_dir(_vela_dir(self.frontier_path) / "diff_packs", "vsd_")

    def list_pending_packs(self) -> list[dict[str, Any]]:
        """List Diff Packs that have not yet been applied. A pack is
        pending if it has a signature but no `applied_event_id`."""
        return [
            p
            for p in self.list_packs()
            if p.get("signature") and not p.get("applied_event_id")
        ]

    # ---- Agent Attestations ---------------------------------------------

    def get_attestation(self, vaa_id: str) -> Optional[dict[str, Any]]:
        if not vaa_id.startswith("vaa_"):
            raise ValueError(f"vaa_id must start with `vaa_`, got `{vaa_id}`")
        return _read_json(
            _vela_dir(self.frontier_path) / "agent_attestations" / f"{vaa_id}.json"
        )

    def list_attestations(self) -> list[dict[str, Any]]:
        return _list_dir(_vela_dir(self.frontier_path) / "agent_attestations", "vaa_")

    def list_attestations_by_actor(self, agent_actor: str) -> list[dict[str, Any]]:
        """List attestations whose `agent_actor` matches exactly."""
        return [a for a in self.list_attestations() if a.get("agent_actor") == agent_actor]

    # ---- Trajectories ----------------------------------------------------

    def get_trajectory(self, vtr_id: str) -> Optional[dict[str, Any]]:
        if not vtr_id.startswith("vtr_"):
            raise ValueError(f"vtr_id must start with `vtr_`, got `{vtr_id}`")
        return _read_json(_vela_dir(self.frontier_path) / "trajectories" / f"{vtr_id}.json")

    def list_trajectories(self) -> list[dict[str, Any]]:
        return _list_dir(_vela_dir(self.frontier_path) / "trajectories", "vtr_")

    # ---- Tool Descriptors ------------------------------------------------

    def get_tool_descriptor(self, vtd_id: str) -> Optional[dict[str, Any]]:
        if not vtd_id.startswith("vtd_"):
            raise ValueError(f"vtd_id must start with `vtd_`, got `{vtd_id}`")
        return _read_json(
            _vela_dir(self.frontier_path) / "tool_descriptors" / f"{vtd_id}.json"
        )

    def list_tool_descriptors(self) -> list[dict[str, Any]]:
        return _list_dir(_vela_dir(self.frontier_path) / "tool_descriptors", "vtd_")

    # ---- Evaluation Records ----------------------------------------------

    def get_evaluation(self, ver_id: str) -> Optional[dict[str, Any]]:
        if not ver_id.startswith("ver_"):
            raise ValueError(f"ver_id must start with `ver_`, got `{ver_id}`")
        return _read_json(_vela_dir(self.frontier_path) / "evaluations" / f"{ver_id}.json")

    def list_evaluations(self) -> list[dict[str, Any]]:
        return _list_dir(_vela_dir(self.frontier_path) / "evaluations", "ver_")

    def list_evaluations_for_target(self, target_id: str) -> list[dict[str, Any]]:
        """List evaluations targeting a specific substrate id."""
        return [e for e in self.list_evaluations() if e.get("target_id") == target_id]

    # ---- Aggregated view -------------------------------------------------

    def frontier_summary(self) -> dict[str, int]:
        """Quick counts for "what's on this frontier?" — useful as
        the first call in a multi-turn agent session."""
        return {
            "diff_packs": len(self.list_packs()),
            "pending_packs": len(self.list_pending_packs()),
            "attestations": len(self.list_attestations()),
            "trajectories": len(self.list_trajectories()),
            "tool_descriptors": len(self.list_tool_descriptors()),
            "evaluations": len(self.list_evaluations()),
        }
