"""Trajectory helpers — open a vtr_*, append vts_* steps with the
full v0.194 taxonomy, save the result to .vela/trajectories/.

Mirrors `crates/vela-protocol/src/bundle.rs::Trajectory` for the
subset of behavior an SDK consumer needs: content-addressed id +
append-only step list + JSON persistence. The reducer-side
`trajectory.step_appended` event arm is a substrate concern and
remains the canonical write path; the SDK produces a freestanding
trajectory document that can be imported or attached as-is.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .primitives import (
    TrajectoryStep,
    TrajectoryStepKind,
    trajectory_content_address,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TrajectoryHandle:
    """In-memory handle to a trajectory under construction.

    The id is fixed at construction; steps are appended and the whole
    thing can be flushed to disk with `save_to_frontier`. The order of
    appends is preserved — the substrate guarantees deposit order in
    `steps[]`, not step-id order.
    """

    id: str
    target_findings: list[str]
    deposited_by: str
    created: str
    steps: list[TrajectoryStep] = field(default_factory=list)
    notes: str = ""

    def append(
        self,
        *,
        kind: TrajectoryStepKind | str,
        description: str,
        actor: str | None = None,
        at: str | None = None,
        references: list[str] | None = None,
    ) -> TrajectoryStep:
        if isinstance(kind, str):
            kind = TrajectoryStepKind(kind)
        step_at = at or _now()
        step_actor = actor or self.deposited_by
        step = TrajectoryStep.make(
            trajectory_id=self.id,
            kind=kind,
            description=description,
            at=step_at,
            actor=step_actor,
            references=list(references or []),
        )
        self.steps.append(step)
        return step

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_findings": list(self.target_findings),
            "deposited_by": self.deposited_by,
            "created": self.created,
            "steps": [s.to_json() for s in self.steps],
            "notes": self.notes,
        }

    def save_to_frontier(self, frontier_path: Path | str) -> Path:
        frontier_path = Path(frontier_path)
        out_dir = frontier_path / ".vela" / "trajectories"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{self.id}.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, indent=2, sort_keys=True)
            f.write("\n")
        return path


def open_trajectory(
    *,
    target_findings: list[str],
    deposited_by: str,
    created: str | None = None,
    notes: str = "",
) -> TrajectoryHandle:
    """Open a new trajectory with a content-addressed id.

    `target_findings` are `vf_*` ids the trajectory is the search path
    for. May be empty when the trajectory does not yet lead anywhere;
    the substrate accepts orphan trajectories (a search that found
    nothing is still substrate-honest evidence).
    """
    created = created or _now()
    if not deposited_by:
        raise ValueError("deposited_by cannot be empty")
    for vf in target_findings:
        if not vf.startswith("vf_"):
            raise ValueError(
                f"target_findings entries must start with `vf_`, got `{vf}`"
            )
    tid = trajectory_content_address(target_findings, deposited_by, created)
    return TrajectoryHandle(
        id=tid,
        target_findings=list(target_findings),
        deposited_by=deposited_by,
        created=created,
        notes=notes,
    )
