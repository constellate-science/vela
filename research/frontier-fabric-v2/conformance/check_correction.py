#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
fixture = json.loads((ROOT / "fixtures" / "frontier-extension.json").read_text())
cells = fixture["cells"]


def support(stage, cell):
    return next(
        row["supported"]
        for row in fixture["observations"][stage]["canonical_output"]["cells"]
        if row["cell_id"] == cell
    )


assert not support("before", cells["heat_alpha_02"])
assert not support("before", cells["heat_alpha_03"])
assert support("after", cells["heat_alpha_02"])
assert support("after", cells["heat_coverage"])
assert not support("after", cells["heat_alpha_03"])
assert not support("restricted", cells["heat_alpha_02"])
assert not support("restricted", cells["heat_coverage"])
assert not support("restricted", cells["heat_alpha_03"])
assert support("repaired", cells["heat_alpha_02"])
assert support("repaired", cells["heat_coverage"])
assert not support("repaired", cells["heat_alpha_03"])

restricted_status = {
    row["target_cell"]: row["status"]
    for row in fixture["frontier_restricted"]["obligations"]
}
repaired_status = {
    row["target_cell"]: row["status"]
    for row in fixture["frontier_repaired"]["obligations"]
}
assert restricted_status[cells["heat_alpha_02"]] == "open"
assert restricted_status[cells["heat_alpha_03"]] == "latent"
assert repaired_status[cells["heat_alpha_02"]] == "discharged"
assert repaired_status[cells["heat_alpha_03"]] == "open"

print("PASS append -> frontier advance -> restrict -> frontier retreat -> repair")
