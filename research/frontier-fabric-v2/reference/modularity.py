#!/usr/bin/env python3
"""Conservative composition of independent domain presentations."""
from __future__ import annotations

from kernel import Presentation, compile_gamma


def disjoint_union(left: Presentation, right: Presentation) -> Presentation:
    """Form the independent union of two presentations.

    The operation deliberately rejects shared cell and event namespaces. Cross-
    domain dependence must enter through an explicit accepted bridge clause,
    never through accidental identifier collision.
    """
    left.validate()
    right.validate()
    shared_cells = set(left.cell_ranks) & set(right.cell_ranks)
    shared_events = set(left.accepted_events) & set(right.accepted_events)
    if shared_cells:
        raise ValueError(f"shared cells in independent union: {sorted(shared_cells)}")
    if shared_events:
        raise ValueError(f"shared events in independent union: {sorted(shared_events)}")
    result = Presentation(
        cell_ranks={**left.cell_ranks, **right.cell_ranks},
        clauses=[*left.clauses, *right.clauses],
        accepted_events=[*left.accepted_events, *right.accepted_events],
        cell_metadata={**left.cell_metadata, **right.cell_metadata},
        admitted_profiles=sorted(set(left.admitted_profiles) | set(right.admitted_profiles)),
    )
    result.validate()
    return result


def verify_conservative_extension(left: Presentation, right: Presentation) -> Presentation:
    """Check that adding an independent adapter presentation changes neither side."""
    merged = disjoint_union(left, right)
    left_gamma = compile_gamma(left)
    right_gamma = compile_gamma(right)
    merged_gamma = compile_gamma(merged)
    for cell, polynomial in left_gamma.items():
        if merged_gamma[cell] != polynomial:
            raise AssertionError(f"left lineage changed at {cell}")
    for cell, polynomial in right_gamma.items():
        if merged_gamma[cell] != polynomial:
            raise AssertionError(f"right lineage changed at {cell}")
    return merged
