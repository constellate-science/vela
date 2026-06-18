#!/usr/bin/env python3
"""Sidon witness, claim, cell, clause, and observation helpers."""
from __future__ import annotations

from typing import Any

from canonical import content_id, digest
from kernel import Clause, Presentation, active_environments, compile_gamma, lineage_root, supported

SEQUENCE = "oeis:A309370"
CONTEXT = "binary-cube-sidon-exact-v1"
RULE_ATOM = "rule:vela.sidon.lower-bound.v1"


def validate_shape(witness: dict[str, Any]) -> tuple[int, list[tuple[int, ...]]]:
    if witness.get("kind") != "sidon":
        raise ValueError("witness kind must be sidon")
    n = witness.get("n")
    points_raw = witness.get("points")
    if not isinstance(n, int) or n <= 0 or not isinstance(points_raw, list) or not points_raw:
        raise ValueError("invalid n or empty points")
    points: list[tuple[int, ...]] = []
    for point in points_raw:
        if not isinstance(point, list) or len(point) != n or any(bit not in (0, 1) for bit in point):
            raise ValueError("each point must be a binary vector of length n")
        points.append(tuple(point))
    if len(set(points)) != len(points):
        raise ValueError("points must be distinct")
    if witness.get("claimed_size") != len(points):
        raise ValueError("claimed_size must equal point count")
    return n, points


def verify_pairsum_set(witness: dict[str, Any]) -> tuple[bool, str]:
    try:
        _, points = validate_shape(witness)
    except ValueError as exc:
        return False, str(exc)
    seen: set[tuple[int, ...]] = set()
    for i in range(len(points)):
        for j in range(i, len(points)):
            total = tuple(a + b for a, b in zip(points[i], points[j]))
            if total in seen:
                return False, f"duplicate pair sum at pair ({i},{j})"
            seen.add(total)
    return True, f"{len(seen)} pair sums unique"


def verify_base3_sort(witness: dict[str, Any]) -> tuple[bool, str]:
    try:
        n, points = validate_shape(witness)
    except ValueError as exc:
        return False, str(exc)
    powers = [3**i for i in range(n)]
    encoded: list[int] = []
    for i in range(len(points)):
        for j in range(i, len(points)):
            encoded.append(sum((points[i][k] + points[j][k]) * powers[k] for k in range(n)))
    encoded.sort()
    if any(a == b for a, b in zip(encoded, encoded[1:])):
        return False, "duplicate base-3 pair-sum encoding"
    return True, f"{len(encoded)} sorted encodings unique"


def claim(n: int, k: int) -> dict[str, Any]:
    return {
        "namespace": "oeis",
        "sequence": "A309370",
        "context": CONTEXT,
        "n": n,
        "relation": ">=",
        "value": k,
        "polarity": "support",
    }


def witness_cell(artifact_digest: str) -> str:
    return content_id("vsc_", {"kind": "verified_sidon_witness", "artifact_digest": artifact_digest})


def bound_cell(n: int, k: int) -> str:
    return content_id("vsc_", {"kind": "sidon_lower_bound", "claim": claim(n, k)})


def append_verified_route(
    presentation: Presentation,
    *,
    n: int,
    k: int,
    artifact_digest: str,
    claim_digest: str,
    verification_atoms: list[str],
    accepted_event_id: str,
) -> tuple[str, str]:
    wcell = witness_cell(artifact_digest)
    bcell = bound_cell(n, k)
    presentation.cell_ranks.setdefault(wcell, 0)
    presentation.cell_ranks.setdefault(bcell, 1)
    witness_clause = Clause.make(
        head=wcell,
        head_rank=0,
        body=[],
        atoms=["artifact:" + artifact_digest, *verification_atoms, "acceptance-event:" + accepted_event_id],
        accepted_event_id=accepted_event_id,
    )
    bound_clause = Clause.make(
        head=bcell,
        head_rank=1,
        body=[wcell],
        atoms=["statement:" + claim_digest, RULE_ATOM],
        accepted_event_id=accepted_event_id,
    )
    presentation.clauses.extend([witness_clause, bound_clause])
    presentation.accepted_events.append(accepted_event_id)
    presentation.validate()
    return wcell, bcell


def best_bounds(presentation: Presentation, disabled_atoms: set[str]) -> list[dict[str, Any]]:
    gamma = compile_gamma(presentation)
    candidates: dict[int, list[tuple[int, str]]] = {}
    # Cell metadata is encoded in the accepted bound clauses' statement atoms;
    # keep a direct registry in the clause body for this narrow profile by
    # matching against every possible (n,k) named in presentation metadata.
    for cell_id, meta in presentation.cell_metadata.items():
        if meta.get("kind") != "sidon_lower_bound":
            continue
        if supported(gamma[cell_id], disabled_atoms):
            candidates.setdefault(meta["n"], []).append((meta["k"], cell_id))
    out: list[dict[str, Any]] = []
    for n, rows in sorted(candidates.items()):
        best = max(k for k, _ in rows)
        cells = sorted(cell for k, cell in rows if k == best)
        out.append({"n": n, "best_lower_bound": best, "supported_cell_ids": cells})
    return out


def register_bound_metadata(presentation: Presentation, n: int, k: int) -> None:
    presentation.cell_metadata[bound_cell(n, k)] = {"kind": "sidon_lower_bound", "n": n, "k": k}
