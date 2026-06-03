#!/usr/bin/env python3
# Pairs with W1.7 (v0.66): the Python loader at
# `clients/python/vela_loader.py` must rehydrate
# `manifest.dependencies.frontiers_v2` into `project.dependencies`,
# exactly the way `crates/vela-protocol/src/repo.rs::load_vela_repo`
# does on the Rust side. Without it, a Python replay of the event log
# cannot resolve cross-frontier link references.
#
# This test loads the early-AD biomarker calibration project, which in
# v0.59 declared an anti-amyloid bridge dependency
# (vfr_5076e7b3ff8e6b0f), and confirms the Python loader sees it. It
# also confirms the event log replays cleanly (the v0.65 + v0.66 review
# verdicts are accepted findings).

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running both as `python3 -m pytest …` from repo root and as
# `python3 tests/test_loader_frontiers_v2.py` from inside the package.
_HERE = Path(__file__).resolve().parent
_PACKAGE_DIR = _HERE.parent
if str(_PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_DIR))

from vela_loader import load_frontier_repo  # noqa: E402

_REPO_ROOT = _PACKAGE_DIR.parent.parent
_PROJECT = _REPO_ROOT / "projects" / "early-ad-biomarker-calibration"


def test_dependencies_rehydrated_from_yaml() -> None:
    repo = load_frontier_repo(str(_PROJECT))
    deps = repo["project"]["dependencies"]
    assert isinstance(deps, list) and len(deps) >= 1, (
        "expected at least one entry under project.dependencies, got "
        f"{deps!r}"
    )
    vfr_ids = {d.get("vfr_id") for d in deps}
    assert "vfr_5076e7b3ff8e6b0f" in vfr_ids, (
        "anti-amyloid bridge (vfr_5076e7b3ff8e6b0f) not rehydrated from "
        f"frontier.yaml; saw {sorted(vfr_ids)!r}"
    )

    bridge = next(d for d in deps if d.get("vfr_id") == "vfr_5076e7b3ff8e6b0f")
    assert bridge.get("source") == "vela.hub"
    assert bridge.get("name") == "anti-amyloid-translation"
    assert bridge.get("locator"), "bridge dep missing locator"
    assert bridge.get("pinned_snapshot_hash"), "bridge dep missing pinned_snapshot_hash"


def test_events_and_accepted_findings() -> None:
    repo = load_frontier_repo(str(_PROJECT))
    events = repo["events"]
    assert isinstance(events, list) and len(events) > 0, (
        "expected non-empty events list after split-repo load"
    )

    accepted = [
        f
        for f in repo["findings"]
        if (f.get("flags") or {}).get("review_state") == "accepted"
    ]
    assert len(accepted) >= 4, (
        f"expected at least 4 accepted findings after replay, got "
        f"{len(accepted)} (review_states: "
        f"{[ (f.get('flags') or {}).get('review_state') for f in repo['findings']]})"
    )


def test_frontier_id_loaded() -> None:
    repo = load_frontier_repo(str(_PROJECT))
    assert repo["frontier_id"] == "vfr_a22c9022674a2304"


if __name__ == "__main__":
    # Lightweight runner so `python3 test_loader_frontiers_v2.py` works
    # even if pytest is unavailable in the local env.
    failures = 0
    for fn in (
        test_dependencies_rehydrated_from_yaml,
        test_events_and_accepted_findings,
        test_frontier_id_loaded,
    ):
        try:
            fn()
            print(f"ok   · {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL · {fn.__name__}: {e}")
        except Exception as e:
            failures += 1
            print(f"ERR  · {fn.__name__}: {type(e).__name__}: {e}")
    raise SystemExit(0 if failures == 0 else 1)
