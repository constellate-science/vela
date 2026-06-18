#!/usr/bin/env python3
"""Finite, positive, ranked Scientific State Kernel reference semantics.

This is a small executable realization of the checked v0.9 kernel. It preserves
bag lineage in N[X], derives correlation-safe minimal environments through env,
and separates historical append from active-view restriction.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import product
from typing import Any, Iterable

from canonical import content_id

Monomial = tuple[str, ...]               # sorted bag of atoms; duplicates retained
Polynomial = dict[Monomial, int]         # finite map monomial -> Nat coefficient


def poly_zero() -> Polynomial:
    return {}


def poly_one() -> Polynomial:
    return {(): 1}


def poly_atom(atom: str) -> Polynomial:
    return {(atom,): 1}


def poly_add(left: Polynomial, right: Polynomial) -> Polynomial:
    out = dict(left)
    for mono, coeff in right.items():
        out[mono] = out.get(mono, 0) + coeff
        if out[mono] == 0:
            del out[mono]
    return out


def poly_mul(left: Polynomial, right: Polynomial) -> Polynomial:
    if not left or not right:
        return {}
    out: Polynomial = {}
    for lm, lc in left.items():
        for rm, rc in right.items():
            mono = tuple(sorted(lm + rm))
            out[mono] = out.get(mono, 0) + lc * rc
    return out


def poly_product(polys: Iterable[Polynomial]) -> Polynomial:
    out = poly_one()
    for p in polys:
        out = poly_mul(out, p)
    return out


def poly_to_json(poly: Polynomial) -> list[dict[str, Any]]:
    return [
        {"atoms": list(mono), "coefficient": coeff}
        for mono, coeff in sorted(poly.items(), key=lambda item: (len(item[0]), item[0], item[1]))
    ]


@dataclass(frozen=True)
class Clause:
    clause_id: str
    head: str
    head_rank: int
    body: tuple[str, ...]
    atoms: tuple[str, ...]
    accepted_event_id: str

    @staticmethod
    def make(*, head: str, head_rank: int, body: Iterable[str], atoms: Iterable[str], accepted_event_id: str) -> "Clause":
        body_t = tuple(sorted(body))
        atoms_t = tuple(sorted(atoms))
        core = {
            "head": head,
            "head_rank": head_rank,
            "body": list(body_t),
            "atoms": list(atoms_t),
            "accepted_event_id": accepted_event_id,
        }
        return Clause(
            clause_id=content_id("vlc_", core),
            head=head,
            head_rank=head_rank,
            body=body_t,
            atoms=atoms_t,
            accepted_event_id=accepted_event_id,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id,
            "head": self.head,
            "head_rank": self.head_rank,
            "body": list(self.body),
            "atoms": list(self.atoms),
            "accepted_event_id": self.accepted_event_id,
        }


@dataclass
class Presentation:
    cell_ranks: dict[str, int]
    clauses: list[Clause]
    accepted_events: list[str]
    cell_metadata: dict[str, dict[str, Any]]

    def validate(self) -> None:
        if len(set(self.accepted_events)) != len(self.accepted_events):
            raise ValueError("duplicate accepted event")
        seen_clause_ids: set[str] = set()
        for clause in self.clauses:
            if clause.clause_id in seen_clause_ids:
                raise ValueError("duplicate clause")
            seen_clause_ids.add(clause.clause_id)
            if self.cell_ranks.get(clause.head) != clause.head_rank:
                raise ValueError("clause head rank disagrees with cell rank")
            for body_cell in clause.body:
                if body_cell not in self.cell_ranks:
                    raise ValueError(f"unknown body cell: {body_cell}")
                if self.cell_ranks[body_cell] >= clause.head_rank:
                    raise ValueError("presentation is not strictly ranked")
            if clause.accepted_event_id not in self.accepted_events:
                raise ValueError("clause references unaccepted event")

    def canonical_clauses(self) -> list[dict[str, Any]]:
        return [c.to_json() for c in sorted(self.clauses, key=lambda c: (c.head_rank, c.head, c.clause_id))]

    def presentation_root(self) -> str:
        self.validate()
        return content_id("vpr_", {
            "accepted_events": self.accepted_events,
            "cell_ranks": dict(sorted(self.cell_ranks.items())),
            "cell_metadata": {k: self.cell_metadata[k] for k in sorted(self.cell_metadata)},
            "clauses": self.canonical_clauses(),
        })

    def circuit_root(self) -> str:
        self.validate()
        return content_id("vcr_", self.canonical_clauses())

    def to_json(self) -> dict[str, Any]:
        self.validate()
        return {
            "cell_ranks": dict(sorted(self.cell_ranks.items())),
            "cell_metadata": {k: self.cell_metadata[k] for k in sorted(self.cell_metadata)},
            "accepted_events": list(self.accepted_events),
            "clauses": self.canonical_clauses(),
        }

    @staticmethod
    def from_json(value: dict[str, Any]) -> "Presentation":
        clauses = [
            Clause(
                clause_id=row["clause_id"],
                head=row["head"],
                head_rank=int(row["head_rank"]),
                body=tuple(row["body"]),
                atoms=tuple(row["atoms"]),
                accepted_event_id=row["accepted_event_id"],
            )
            for row in value["clauses"]
        ]
        presentation = Presentation(
            cell_ranks={k: int(v) for k, v in value["cell_ranks"].items()},
            clauses=clauses,
            accepted_events=list(value["accepted_events"]),
            cell_metadata=dict(value.get("cell_metadata", {})),
        )
        presentation.validate()
        return presentation


def compile_gamma(presentation: Presentation) -> dict[str, Polynomial]:
    presentation.validate()
    gamma: dict[str, Polynomial] = {cell: poly_zero() for cell in presentation.cell_ranks}
    for clause in sorted(presentation.clauses, key=lambda c: (c.head_rank, c.head, c.clause_id)):
        atom_poly = {tuple(clause.atoms): 1}
        body_poly = poly_product(gamma[cell] for cell in clause.body)
        term = poly_mul(atom_poly, body_poly)
        gamma[clause.head] = poly_add(gamma[clause.head], term)
    return gamma


def lineage_root(gamma: dict[str, Polynomial]) -> str:
    normalized = {
        cell: poly_to_json(poly)
        for cell, poly in sorted(gamma.items())
    }
    return content_id("vlr_", normalized)


def minimal_environments(poly: Polynomial) -> list[list[str]]:
    envs = sorted({tuple(sorted(set(mono))) for mono in poly}, key=lambda e: (len(e), e))
    minimal: list[tuple[str, ...]] = []
    for env in envs:
        eset = set(env)
        if any(set(existing).issubset(eset) for existing in minimal):
            continue
        minimal.append(env)
    return [list(env) for env in minimal]


def active_environments(poly: Polynomial, disabled_atoms: Iterable[str]) -> list[list[str]]:
    disabled = set(disabled_atoms)
    return [env for env in minimal_environments(poly) if disabled.isdisjoint(env)]


def supported(poly: Polynomial, disabled_atoms: Iterable[str]) -> bool:
    return bool(active_environments(poly, disabled_atoms))


def active_view_root(disabled_atoms: Iterable[str], policy_id: str = "vela.view.public.v1") -> str:
    return content_id("vav_", {
        "policy_id": policy_id,
        "disabled_atoms": sorted(set(disabled_atoms)),
    })


def is_hitting_set(environments: Iterable[Iterable[str]], atoms: Iterable[str]) -> bool:
    envs = [set(e) for e in environments]
    attack = set(atoms)
    return bool(envs) and all(bool(env.intersection(attack)) for env in envs)


def repair_completes_environment(
    historical_environments: Iterable[Iterable[str]],
    disabled_atoms: Iterable[str],
    newly_active_atoms: Iterable[str],
) -> bool:
    disabled = set(disabled_atoms) - set(newly_active_atoms)
    return any(disabled.isdisjoint(set(env)) for env in historical_environments)


def evaluator_digest(evaluator_id: str, semantics: str) -> str:
    return content_id("veval_", {"id": evaluator_id, "semantics": semantics})
