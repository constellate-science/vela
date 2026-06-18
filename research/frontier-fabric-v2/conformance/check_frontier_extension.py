#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from frontier import verify_extension_locality, verify_positive_gap_monotonicity
from kernel import Presentation

fixture = json.loads((ROOT / "fixtures" / "frontier-extension.json").read_text())
before = Presentation.from_json(fixture["presentation_before"])
after = Presentation.from_json(fixture["presentation_final"])
cells = fixture["cells"]

verify_extension_locality(before, after, [cells["heat_alpha_02"]])

# The actionable frontier advances rather than disappearing: alpha=.2 closes
# and its declared successor alpha=.3 becomes visible.
before_status = {
    row["target_cell"]: row["status"] for row in fixture["frontier_before"]["obligations"]
}
after_status = {
    row["target_cell"]: row["status"] for row in fixture["frontier_after"]["obligations"]
}
assert before_status[cells["heat_alpha_02"]] == "open"
assert before_status[cells["heat_alpha_03"]] == "latent"
assert after_status[cells["heat_alpha_02"]] == "discharged"
assert after_status[cells["heat_alpha_03"]] == "open"
assert len(fixture["frontier_before"]["open_obligations"]) == 1
assert len(fixture["frontier_before"]["latent_obligations"]) == 1
assert len(fixture["frontier_after"]["open_obligations"]) == 1

transitions = {
    row["obligation_id"]: (row["before"], row["after"])
    for row in fixture["frontier_transition"]["transitions"]
}
assert set(transitions.values()) == {("open", "discharged"), ("latent", "open")}

added = set(fixture["structural_delta"]["newly_supported_cells"])
assert cells["heat_alpha_02"] in added
assert cells["heat_coverage"] in added
assert cells["heat_alpha_03"] not in added

print("PASS frontier migration, gap closure, successor exposure, and forward-cone locality")
