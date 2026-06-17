#!/usr/bin/env python3
"""
Executable v0.9 Scientific State Kernel fixture.

Concrete math wedge:
  S0 = {0,1,4} is a 3-element Sidon set in [0,4].
  Therefore B_2([0,4]) >= 3.
  Translation by +10 preserves Sidon, yielding {10,11,14} in [10,14].

The fixture exercises:
  presentation -> Gamma -> view -> observation packet -> hitting-set challenge -> repair.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from fractions import Fraction
import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Set, FrozenSet, Any

Atom = str
Cell = str
Monomial = Tuple[Atom, ...]
Poly = List[Monomial]
Env = FrozenSet[FrozenSet[Atom]]


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha(obj: Any) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def sidon(xs: List[int]) -> bool:
    sums: Dict[int, Tuple[int, int]] = {}
    for i, a in enumerate(xs):
        for b in xs[i:]:
            s = a + b
            if s in sums:
                return False
            sums[s] = (a, b)
    return True


def add_poly(p: Poly, q: Poly) -> Poly:
    return p + q


def mul_poly(p: Poly, q: Poly) -> Poly:
    return [tuple(list(a) + list(b)) for a in p for b in q]


def atom_poly(atoms: Iterable[Atom]) -> Poly:
    return [tuple(atoms)]


def prod_polys(polys: Iterable[Poly]) -> Poly:
    acc: Poly = [tuple()]
    for p in polys:
        acc = mul_poly(acc, p)
    return acc


def env(poly: Poly) -> Env:
    return frozenset(frozenset(m) for m in poly)


def active_envs(poly: Poly, active: Set[Atom]) -> Env:
    return frozenset(e for e in env(poly) if e <= active)


def kappa(poly: Poly, active: Set[Atom], weights: Dict[Atom, Fraction]) -> Fraction:
    envs = active_envs(poly, active)
    if not envs:
        return Fraction(0, 1)
    best = Fraction(0, 1)
    for e in envs:
        prod = Fraction(1, 1)
        for a in sorted(e):
            prod *= weights[a]
        best = max(best, prod)
    return best


def tropical_cost(poly: Poly, active: Set[Atom], costs: Dict[Atom, int]) -> int | None:
    envs = active_envs(poly, active)
    if not envs:
        return None
    return min(sum(costs[a] for a in e) for e in envs)


def bottleneck(poly: Poly, active: Set[Atom], weights: Dict[Atom, Fraction]) -> Fraction:
    envs = active_envs(poly, active)
    if not envs:
        return Fraction(0, 1)
    vals = []
    for e in envs:
        vals.append(min([weights[a] for a in e], default=Fraction(1, 1)))
    return max(vals)


@dataclass(frozen=True)
class Clause:
    id: str
    head: Cell
    body: Tuple[Cell, ...]
    atoms: Tuple[Atom, ...]
    persistent: bool = True


def compile_gamma(clauses: List[Clause], ranks: Dict[Cell, int]) -> Dict[Cell, Poly]:
    gamma: Dict[Cell, Poly] = {c: [] for c in ranks}
    cells = sorted(ranks, key=lambda c: ranks[c])
    for h in cells:
        acc: Poly = []
        for r in clauses:
            if r.head != h:
                continue
            term = mul_poly(atom_poly(r.atoms), prod_polys(gamma[b] for b in r.body))
            acc = add_poly(acc, term)
        gamma[h] = acc
    return gamma


def hits_all(challenge: Set[Atom], envs: Env) -> bool:
    return bool(envs) and all(challenge & set(e) for e in envs)


def killed_by(challenge: Set[Atom], poly: Poly, active: Set[Atom]) -> bool:
    return hits_all(challenge, active_envs(poly, active))


def repair_restores(repair_atoms: Set[Atom], poly: Poly, active: Set[Atom]) -> bool:
    repaired = active | repair_atoms
    return bool(active_envs(poly, repaired))


def packet(kind: str, cell: Cell, gamma: Dict[Cell, Poly], active: Set[Atom], weights, costs) -> Dict[str, Any]:
    poly = gamma[cell]
    if kind == "belnap_support":
        out: Any = "T" if active_envs(poly, active) else "N"
    elif kind == "kappa":
        out = str(kappa(poly, active, weights))
    elif kind == "cost":
        out = tropical_cost(poly, active, costs)
    elif kind == "bottleneck":
        out = str(bottleneck(poly, active, weights))
    elif kind == "minimal_envs":
        out = sorted([sorted(e) for e in active_envs(poly, active)])
    else:
        raise ValueError(kind)
    pkt = {
        "kind": kind,
        "cell": cell,
        "presentation_root": None,
        "lineage_root": None,
        "view_root": sha(sorted(active)),
        "output": out,
    }
    pkt["output_hash"] = sha(out)
    return pkt


def build_fixture() -> Dict[str, Any]:
    assert sidon([0, 1, 4])
    assert sidon([0, 2, 5])
    assert sidon([10, 11, 14])

    cells = {
        "c_w014": "S0={0,1,4} is Sidon in [0,4]",
        "c_lb3": "There exists a 3-element Sidon set in [0,4]; hence B2([0,4]) >= 3",
        "c_t014": "S0+10={10,11,14} is Sidon in [10,14]",
    }
    atoms = {
        "a_w014": "verifier receipt for {0,1,4} Sidon",
        "a_w025": "repair verifier receipt for {0,2,5} Sidon",
        "a_lb_rule": "accepted extraction rule: Sidon witness of size 3 implies lower bound >=3",
        "a_translate_rule": "accepted translation construction +10",
        "a_translate_theorem": "proof receipt: translation preserves Sidon",
    }
    ranks = {"c_w014": 0, "c_lb3": 1, "c_t014": 1}

    base_clauses = [
        Clause("r_w014", "c_w014", tuple(), ("a_w014",)),
        Clause("r_lb3", "c_lb3", ("c_w014",), ("a_lb_rule",)),
        Clause("r_t014", "c_t014", ("c_w014",), ("a_translate_rule", "a_translate_theorem")),
    ]
    repaired_clauses = base_clauses + [Clause("r_w025", "c_w014", tuple(), ("a_w025",))]

    weights = {
        "a_w014": Fraction(99, 100),
        "a_w025": Fraction(98, 100),
        "a_lb_rule": Fraction(1, 1),
        "a_translate_rule": Fraction(1, 1),
        "a_translate_theorem": Fraction(1, 1),
    }
    costs = {
        "a_w014": 1,
        "a_w025": 1,
        "a_lb_rule": 1,
        "a_translate_rule": 1,
        "a_translate_theorem": 1,
    }

    gamma0 = compile_gamma(base_clauses, ranks)
    all_atoms = set(atoms)
    challenge = {"a_w014"}
    active_after_challenge = all_atoms - challenge
    gamma1 = compile_gamma(repaired_clauses, ranks)

    packets_before = [packet(k, "c_lb3", gamma0, all_atoms, weights, costs) for k in ["belnap_support", "kappa", "cost", "bottleneck", "minimal_envs"]]
    packets_after_challenge = [packet(k, "c_lb3", gamma0, active_after_challenge, weights, costs) for k in ["belnap_support", "minimal_envs"]]
    packets_after_repair = [packet(k, "c_lb3", gamma1, active_after_challenge, weights, costs) for k in ["belnap_support", "minimal_envs"]]

    presentation = {
        "cells": cells,
        "atoms": atoms,
        "ranks": ranks,
        "base_clauses": [asdict(c) for c in base_clauses],
        "repair_clause": asdict(repaired_clauses[-1]),
    }
    presentation_root = sha(presentation)
    lineage_root_base = sha({k: [list(m) for m in v] for k, v in gamma0.items()})
    lineage_root_repaired = sha({k: [list(m) for m in v] for k, v in gamma1.items()})
    for pkt in packets_before:
        pkt["presentation_root"] = presentation_root
        pkt["lineage_root"] = lineage_root_base
    for pkt in packets_after_challenge:
        pkt["presentation_root"] = presentation_root
        pkt["lineage_root"] = lineage_root_base
    for pkt in packets_after_repair:
        pkt["presentation_root"] = presentation_root
        pkt["lineage_root"] = lineage_root_repaired

    return {
        "fixture": "vela_v09_sidon_lower_bound_kernel_fixture",
        "presentation_root": presentation_root,
        "lineage_root_base": lineage_root_base,
        "lineage_root_repaired": lineage_root_repaired,
        "presentation": presentation,
        "gamma_base": {k: [list(m) for m in v] for k, v in gamma0.items()},
        "gamma_repaired": {k: [list(m) for m in v] for k, v in gamma1.items()},
        "view_default_active_atoms": sorted(all_atoms),
        "challenge": sorted(challenge),
        "view_after_challenge_active_atoms": sorted(active_after_challenge),
        "active_envs_before_for_c_lb3": sorted([sorted(e) for e in active_envs(gamma0["c_lb3"], all_atoms)]),
        "challenge_kills_c_lb3": killed_by(challenge, gamma0["c_lb3"], all_atoms),
        "active_envs_after_challenge_for_c_lb3": sorted([sorted(e) for e in active_envs(gamma0["c_lb3"], active_after_challenge)]),
        "repair_atoms": ["a_w025"],
        "repair_restores_c_lb3": repair_restores({"a_w025"}, gamma1["c_lb3"], active_after_challenge),
        "active_envs_after_repair_for_c_lb3": sorted([sorted(e) for e in active_envs(gamma1["c_lb3"], active_after_challenge)]),
        "observation_packets_before": packets_before,
        "observation_packets_after_challenge": packets_after_challenge,
        "observation_packets_after_repair": packets_after_repair,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/mnt/data/vela_v09_sidon_kernel_fixture.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    fx = build_fixture()
    if args.check:
        assert fx["challenge_kills_c_lb3"] is True
        assert fx["repair_restores_c_lb3"] is True
        assert fx["observation_packets_before"][0]["output"] == "T"
        assert fx["observation_packets_after_challenge"][0]["output"] == "N"
        assert fx["observation_packets_after_repair"][0]["output"] == "T"
    Path(args.out).write_text(json.dumps(fx, indent=2, sort_keys=True))
    print(args.out)


if __name__ == "__main__":
    main()
