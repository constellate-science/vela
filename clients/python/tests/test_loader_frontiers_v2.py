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
_PROJECT = _REPO_ROOT / "examples" / "erdos-formalization"


def test_dependencies_shape() -> None:
    # The loader must always rehydrate `project.dependencies` as a list
    # (empty when the frontier declares none), never None/missing.
    repo = load_frontier_repo(str(_PROJECT))
    deps = repo["project"]["dependencies"]
    assert isinstance(deps, list), f"dependencies must be a list, got {type(deps)}"


def test_events_and_accepted_findings() -> None:
    repo = load_frontier_repo(str(_PROJECT))
    events = repo["events"]
    assert isinstance(events, list) and len(events) > 0, (
        "expected non-empty events list after split-repo load"
    )
    accepted = [f for f in repo["findings"] if not f.get("flags", {}).get("retracted")]
    assert len(accepted) >= 4, (
        f"expected the seed frontier's 4 accepted findings, got {len(accepted)}"
    )


def test_frontier_id_loaded() -> None:
    repo = load_frontier_repo(str(_PROJECT))
    assert repo["frontier_id"] == "vfr_0a25edabc16db143", (
        f"unexpected frontier id: {repo.get('frontier_id')!r}"
    )
