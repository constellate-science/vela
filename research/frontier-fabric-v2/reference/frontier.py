#!/usr/bin/env python3
"""Adapter-relative frontier maps over the finite ranked lineage kernel."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from canonical import content_id, digest
from kernel import Presentation, active_environments, compile_gamma, supported


@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    adapter_id: str
    target_cell: str
    kind: str
    context: dict[str, Any]
    discharge_evaluator_id: str
    verifier_profile_id: str
    generator_id: str
    dependencies: tuple[str, ...]
    rationale: str

    @staticmethod
    def make(
        *,
        adapter_id: str,
        target_cell: str,
        kind: str,
        context: dict[str, Any],
        discharge_evaluator_id: str,
        verifier_profile_id: str,
        generator_id: str,
        dependencies: Iterable[str] = (),
        rationale: str = "",
    ) -> "Obligation":
        core = {
            "adapter_id": adapter_id,
            "target_cell": target_cell,
            "kind": kind,
            "context": context,
            "discharge_evaluator_id": discharge_evaluator_id,
            "verifier_profile_id": verifier_profile_id,
            "generator_id": generator_id,
            "dependencies": sorted(set(dependencies)),
            "rationale": rationale,
        }
        return Obligation(
            content_id("vobl_", core),
            adapter_id,
            target_cell,
            kind,
            context,
            discharge_evaluator_id,
            verifier_profile_id,
            generator_id,
            tuple(core["dependencies"]),
            rationale,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "adapter_id": self.adapter_id,
            "target_cell": self.target_cell,
            "kind": self.kind,
            "context": self.context,
            "discharge_evaluator_id": self.discharge_evaluator_id,
            "verifier_profile_id": self.verifier_profile_id,
            "generator_id": self.generator_id,
            "dependencies": list(self.dependencies),
            "rationale": self.rationale,
        }


def _support_value(cell: str, presentation: Presentation, disabled: Iterable[str]) -> bool:
    if cell not in presentation.cell_ranks:
        return False
    return supported(compile_gamma(presentation)[cell], disabled)


def obligation_discharged(
    obligation: Obligation, presentation: Presentation, disabled: Iterable[str]
) -> bool:
    if obligation.discharge_evaluator_id != "vela.support-exists.v1":
        raise ValueError("unsupported discharge evaluator")
    return _support_value(obligation.target_cell, presentation, disabled)


def obligation_status(
    obligation: Obligation, presentation: Presentation, disabled: Iterable[str]
) -> str:
    """Return `latent`, `open`, or `discharged`.

    Dependency cells act as a visibility frontier. An obligation is latent until
    all prerequisite cells are active, open once it is actionable, and
    discharged once its target cell is active. The target takes precedence so a
    historical route remains recognized even if a stricter view later hides a
    prerequisite that was only used to expose the work item.
    """
    if obligation_discharged(obligation, presentation, disabled):
        return "discharged"
    if all(_support_value(cell, presentation, disabled) for cell in obligation.dependencies):
        return "open"
    return "latent"


def build_frontier_map(
    presentation: Presentation,
    obligations: Iterable[Obligation],
    disabled: Iterable[str] = (),
) -> dict[str, Any]:
    rows = []
    for obligation in sorted(obligations, key=lambda item: item.obligation_id):
        rows.append(
            {
                **obligation.to_json(),
                "status": obligation_status(obligation, presentation, disabled),
            }
        )
    payload = {
        "presentation_root": presentation.presentation_root(),
        "disabled_atoms": sorted(set(disabled)),
        "obligations": rows,
    }
    return {
        "frontier_map_root": content_id("vfm_", payload),
        **payload,
        "open_obligations": [
            row["obligation_id"] for row in rows if row["status"] == "open"
        ],
        "latent_obligations": [
            row["obligation_id"] for row in rows if row["status"] == "latent"
        ],
        "discharged_obligations": [
            row["obligation_id"]
            for row in rows
            if row["status"] == "discharged"
        ],
    }


def frontier_transition(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Explain how the actionable frontier moved between two map roots."""
    before_rows = {row["obligation_id"]: row for row in before["obligations"]}
    after_rows = {row["obligation_id"]: row for row in after["obligations"]}
    ids = sorted(set(before_rows) | set(after_rows))
    transitions = []
    for obligation_id in ids:
        old = before_rows.get(obligation_id, {}).get("status", "absent")
        new = after_rows.get(obligation_id, {}).get("status", "absent")
        if old != new:
            transitions.append(
                {"obligation_id": obligation_id, "before": old, "after": new}
            )
    payload = {
        "before_frontier_map_root": before["frontier_map_root"],
        "after_frontier_map_root": after["frontier_map_root"],
        "transitions": transitions,
    }
    return {**payload, "transition_digest": digest(payload)}


def verify_positive_gap_monotonicity(
    before_presentation: Presentation,
    after_presentation: Presentation,
    obligations: Iterable[Obligation],
    disabled: Iterable[str] = (),
) -> None:
    """A positive append cannot reopen a discharged monotone-support obligation.

    It may expose a successor obligation by moving it from `latent` to `open`.
    That is frontier migration, not loss of knowledge.
    """
    before = build_frontier_map(before_presentation, obligations, disabled)
    after = build_frontier_map(after_presentation, obligations, disabled)
    before_status = {row["obligation_id"]: row["status"] for row in before["obligations"]}
    after_status = {row["obligation_id"]: row["status"] for row in after["obligations"]}
    reopened = [
        obligation_id
        for obligation_id, status in before_status.items()
        if status == "discharged" and after_status.get(obligation_id) != "discharged"
    ]
    if reopened:
        raise AssertionError(f"positive append reopened obligations: {reopened}")


def body_to_head_graph(presentation: Presentation) -> dict[str, set[str]]:
    graph = {cell: set() for cell in presentation.cell_ranks}
    for clause in presentation.clauses:
        for body_cell in clause.body:
            graph.setdefault(body_cell, set()).add(clause.head)
    return graph


def forward_cone(presentation: Presentation, starts: Iterable[str]) -> set[str]:
    graph = body_to_head_graph(presentation)
    seen = set(starts)
    stack = list(starts)
    while stack:
        cell = stack.pop()
        for next_cell in graph.get(cell, ()):
            if next_cell not in seen:
                seen.add(next_cell)
                stack.append(next_cell)
    return seen


def active_supported_cells(
    presentation: Presentation, disabled: Iterable[str]
) -> set[str]:
    gamma = compile_gamma(presentation)
    return {
        cell for cell, polynomial in gamma.items() if supported(polynomial, disabled)
    }


def structural_delta(
    before: Presentation, after: Presentation, disabled: Iterable[str] = ()
) -> dict[str, Any]:
    before_cells = active_supported_cells(before, disabled)
    after_cells = active_supported_cells(after, disabled)
    added = sorted(after_cells - before_cells)
    removed = sorted(before_cells - after_cells)
    return {
        "before_presentation_root": before.presentation_root(),
        "after_presentation_root": after.presentation_root(),
        "newly_supported_cells": added,
        "no_longer_supported_cells": removed,
        "delta_digest": digest({"added": added, "removed": removed}),
    }


def verify_extension_locality(
    before: Presentation,
    after: Presentation,
    appended_heads: Iterable[str],
    disabled: Iterable[str] = (),
) -> None:
    delta = structural_delta(before, after, disabled)
    cone = forward_cone(after, appended_heads)
    changed = set(delta["newly_supported_cells"]) | set(
        delta["no_longer_supported_cells"]
    )
    if not changed.issubset(cone):
        raise AssertionError(f"changed outside forward cone: {sorted(changed - cone)}")


def gap_identifiability_witness(
    presentation: Presentation,
    universe_a: Iterable[Obligation],
    universe_b: Iterable[Obligation],
) -> dict[str, Any]:
    map_a = build_frontier_map(presentation, universe_a)
    map_b = build_frontier_map(presentation, universe_b)
    if map_a["presentation_root"] != map_b["presentation_root"]:
        raise AssertionError("state roots differ")
    if map_a["open_obligations"] == map_b["open_obligations"]:
        raise AssertionError("universes do not induce distinct gaps")
    return {
        "same_presentation_root": map_a["presentation_root"],
        "universe_a_root": map_a["frontier_map_root"],
        "universe_b_root": map_b["frontier_map_root"],
        "open_a": map_a["open_obligations"],
        "open_b": map_b["open_obligations"],
        "conclusion": "gaps require a declared obligation universe",
    }


def route_summary(
    presentation: Presentation, cell: str, disabled: Iterable[str] = ()
) -> dict[str, Any]:
    polynomial = compile_gamma(presentation)[cell]
    return {
        "cell_id": cell,
        "historical_environments": active_environments(polynomial, ()),
        "active_environments": active_environments(polynomial, disabled),
    }
