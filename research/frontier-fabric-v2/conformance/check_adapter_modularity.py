#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from canonical import content_id
from kernel import Clause, Presentation, cell_id
from modularity import verify_conservative_extension


def singleton(profile: str, label: str) -> Presentation:
    claim = {"kind": "fixture", "label": label}
    context = {"domain": profile}
    cell = cell_id(
        profile_id=profile,
        claim=claim,
        context=context,
        polarity="support",
        cell_kind="fixture",
    )
    event = content_id("vev_", {"profile": profile, "label": label})
    clause = Clause.make(
        head=cell,
        head_rank=0,
        body=[],
        atoms=[f"artifact:{label}", f"acceptance:{event}"],
        accepted_event_id=event,
        profile_id=profile,
    )
    presentation = Presentation(
        cell_ranks={cell: 0},
        clauses=[clause],
        accepted_events=[event],
        cell_metadata={cell: {"profile_id": profile, "claim": claim, "context": context}},
        admitted_profiles=[profile],
    )
    presentation.validate()
    return presentation


formal = singleton("formal-math", "theorem-A")
simulation = singleton("numerical-simulation", "solution-B")
merged = verify_conservative_extension(formal, simulation)
assert len(merged.cell_ranks) == 2
assert len(merged.clauses) == 2
assert set(merged.admitted_profiles) == {"formal-math", "numerical-simulation"}
print("PASS independent adapter addition is conservative until an explicit bridge is accepted")
