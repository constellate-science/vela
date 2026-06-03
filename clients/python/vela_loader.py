#!/usr/bin/env python3
# Vela Python loader for split-repo frontiers (stdlib-only).
#
# Mirror of `crates/vela-protocol/src/repo.rs::load_vela_repo` for the
# subset of behaviour a Python script needs: walk a `.vela/` tree on
# disk, read the JSON-per-file objects (findings, events, proposals,
# review events, confidence updates), parse the yaml manifest at
# `frontier.yaml`, and rehydrate `project.dependencies` from
# `dependencies.frontiers_v2` so cross-frontier link references can be
# resolved by a Python replay just like the Rust loader does on every
# load (v0.59).
#
# The returned dict shape is intentionally similar to the
# `serde_json::to_value(&Project)` output the Rust loader would
# produce, but only populates the fields a Python replay needs:
#
#   {
#     "project": {
#       "name": str,
#       "description": str,
#       "dependencies": [ProjectDependency-shaped dicts],
#     },
#     "frontier_id": str | None,
#     "findings": [genesis FindingBundle dicts, with reducer mutations
#                  applied during replay],
#     "events": [StateEvent dicts],
#     "proposals": [StateProposal dicts],
#     "review_events": [ReviewEvent dicts],
#     "confidence_updates": [ConfidenceUpdate dicts],
#     "manifest": {raw parsed frontier.yaml},
#     "negative_results": [],
#     "trajectories": [],
#     "artifacts": [],
#   }
#
# Honest gaps relative to the Rust loader:
#   - Does not parse `vela.lock`, `actors.json`, `peers.json`,
#     `proof-state.json`, `signatures/`, `replications/`, `datasets/`,
#     `code-artifacts/`, `predictions/`, `resolutions/`, or
#     `artifacts/`. The Rust loader hydrates all of these.
#   - Does not run `materialize_trajectories_and_nulls_from_events` or
#     `materialize_evidence_atom_locators_from_events` (v0.55, v0.56).
#   - Does not process the `.vela/links/manifest.json` redistributor.
#   - Does not call `project::recompute_stats`.
#   - The yaml parser handles only the known shape of `frontier.yaml`
#     in the Vela repo. It is not a general-purpose yaml parser.
#
# These are bounded gaps: the cross-impl reducer fixture test exercises
# the reducer (which is the protocol surface), and this loader's job is
# only to feed it. If a downstream Python tool needs a missing field, it
# can extend this loader without touching Rust.

from __future__ import annotations

import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

# Reducer is colocated; vela_reducer.py defines apply_event over the
# same dict shape this loader produces.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from vela_reducer import apply_event  # noqa: E402


# Recognized frontier.yaml top-level scalar keys we care about.
_PROJECT_DEP_FIELDS = (
    "name",
    "source",
    "version",
    "pinned_hash",
    "vfr_id",
    "locator",
    "pinned_snapshot_hash",
)


def _try_pyyaml_load(text: str) -> Any | None:
    """Return parsed yaml via pyyaml if available, else None."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    return yaml.safe_load(text)


def _parse_scalar(raw: str) -> Any:
    """Translate a yaml scalar token into a Python value.

    Handles null/~/empty, true/false, ints, floats, single- or
    double-quoted strings, and bare strings. Sufficient for the
    manifest's known shape.
    """
    s = raw.strip()
    if s == "" or s in ("null", "~"):
        return None
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    if (s.startswith("'") and s.endswith("'") and len(s) >= 2) or (
        s.startswith('"') and s.endswith('"') and len(s) >= 2
    ):
        return s[1:-1]
    # int
    try:
        return int(s)
    except ValueError:
        pass
    # float
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _hand_yaml_load(text: str) -> dict:
    """Hand-rolled parser for the known frontier.yaml shape.

    Supports:
      - top-level scalar key: value pairs
      - nested mappings via indentation (2 spaces per level)
      - flow-style empty list `[]`
      - block-style list of scalars (lines like `  - item`)
      - block-style list of maps (a `- key: value` line followed by
        further `  key: value` lines indented under the dash)

    This is just enough for `frontier.yaml`. It is not a full yaml
    parser.
    """

    # Tokenize into (indent, content) pairs, dropping comments and blank
    # lines. We expand tabs to two spaces for indent counting.
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw.lstrip().startswith("#"):
            continue
        expanded = raw.replace("\t", "  ")
        stripped = expanded.lstrip(" ")
        indent = len(expanded) - len(stripped)
        # strip trailing inline comment if present and not inside quotes
        # (frontier.yaml does not use inline comments, but be safe)
        if " #" in stripped and "'" not in stripped and '"' not in stripped:
            stripped = stripped.split(" #", 1)[0].rstrip()
        lines.append((indent, stripped))

    pos = 0

    def parse_block(base_indent: int) -> Any:
        nonlocal pos
        # Decide list vs mapping by looking at the first line at this indent.
        if pos >= len(lines):
            return None
        indent, content = lines[pos]
        if indent < base_indent:
            return None
        if content.startswith("- "):
            return parse_list(base_indent)
        return parse_mapping(base_indent)

    def parse_mapping(base_indent: int) -> dict:
        nonlocal pos
        out: dict = {}
        while pos < len(lines):
            indent, content = lines[pos]
            if indent < base_indent:
                break
            if indent > base_indent:
                # malformed indent; treat as part of previous key
                pos += 1
                continue
            if content.startswith("- "):
                # caller mistakenly entered a list context; stop
                break
            # key: value
            if ":" not in content:
                pos += 1
                continue
            key, _, rest = content.partition(":")
            key = key.strip()
            value_part = rest.strip()
            pos += 1
            if value_part == "":
                # nested block
                if pos < len(lines) and lines[pos][0] > base_indent:
                    out[key] = parse_block(lines[pos][0])
                else:
                    out[key] = None
            elif value_part == "[]":
                out[key] = []
            elif value_part == "{}":
                out[key] = {}
            else:
                out[key] = _parse_scalar(value_part)
        return out

    def parse_list(base_indent: int) -> list:
        nonlocal pos
        out: list = []
        while pos < len(lines):
            indent, content = lines[pos]
            if indent < base_indent:
                break
            if indent != base_indent or not content.startswith("- "):
                break
            item_body = content[2:].strip()
            pos += 1
            if ":" in item_body and not (
                item_body.startswith("'") or item_body.startswith('"')
            ):
                # list-of-mappings: first kv pair lives on the dash
                # line, subsequent pairs are indented further.
                first_key, _, first_val = item_body.partition(":")
                node: dict = {}
                first_key = first_key.strip()
                first_val = first_val.strip()
                if first_val == "":
                    # nested block under the first key
                    if pos < len(lines) and lines[pos][0] > base_indent:
                        node[first_key] = parse_block(lines[pos][0])
                    else:
                        node[first_key] = None
                else:
                    node[first_key] = _parse_scalar(first_val)
                # consume sibling kv pairs at indent base_indent + 2
                child_indent = base_indent + 2
                while pos < len(lines):
                    cindent, ccontent = lines[pos]
                    if cindent < child_indent:
                        break
                    if cindent != child_indent or ccontent.startswith("- "):
                        break
                    if ":" not in ccontent:
                        pos += 1
                        continue
                    ckey, _, crest = ccontent.partition(":")
                    ckey = ckey.strip()
                    cval = crest.strip()
                    pos += 1
                    if cval == "":
                        if pos < len(lines) and lines[pos][0] > child_indent:
                            node[ckey] = parse_block(lines[pos][0])
                        else:
                            node[ckey] = None
                    elif cval == "[]":
                        node[ckey] = []
                    else:
                        node[ckey] = _parse_scalar(cval)
                out.append(node)
            else:
                # list-of-scalars
                out.append(_parse_scalar(item_body))
        return out

    if not lines:
        return {}
    return parse_mapping(lines[0][0])


def parse_frontier_yaml(text: str) -> dict:
    """Parse `frontier.yaml` into a dict.

    Prefers pyyaml if it is installed; falls back to the hand-rolled
    parser above for the known manifest shape.
    """
    parsed = _try_pyyaml_load(text)
    if parsed is None:
        parsed = _hand_yaml_load(text)
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _read_json_dir(path: Path) -> list[dict]:
    """Read every `*.json` file in a directory, sorted by filename."""
    if not path.is_dir():
        return []
    out: list[dict] = []
    for child in sorted(path.iterdir()):
        if child.suffix != ".json":
            continue
        try:
            out.append(json.loads(child.read_text()))
        except (OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"failed to read {child}: {e}") from e
    return out


def _normalize_dependency(entry: Any) -> dict:
    """Coerce a frontiers_v2 list entry into ProjectDependency shape."""
    if not isinstance(entry, dict):
        return {}
    out: dict = {}
    for key in _PROJECT_DEP_FIELDS:
        out[key] = entry.get(key)
    return out


def load_frontier_repo(path: str) -> dict:
    """Load a Vela split-repo frontier from ``path`` into a dict.

    ``path`` is the project root (the directory that contains
    ``frontier.yaml`` and the ``.vela/`` tree). The returned dict has
    `project.dependencies` populated from `dependencies.frontiers_v2`
    in the manifest, mirroring the Rust loader's v0.59 behaviour, and
    `events` replayed through the reducer so finding state reflects
    every recorded review, annotation, retraction, and cascade.
    """
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"not a directory: {root}")

    vela_dir = root / ".vela"
    if not vela_dir.is_dir():
        raise FileNotFoundError(
            f"missing .vela/ tree under {root}; not a split-repo frontier"
        )

    # Manifest (frontier.yaml). Optional; only the new split layout
    # carries it. The Rust loader treats it as optional too.
    manifest: dict = {}
    manifest_path = root / "frontier.yaml"
    if manifest_path.is_file():
        manifest = parse_frontier_yaml(manifest_path.read_text())

    # Cross-frontier dependencies from manifest.dependencies.frontiers_v2.
    deps_block = (manifest.get("dependencies") or {}) if isinstance(manifest, dict) else {}
    raw_deps = deps_block.get("frontiers_v2") or []
    if not isinstance(raw_deps, list):
        raw_deps = []
    dependencies = [_normalize_dependency(d) for d in raw_deps]

    # Project metadata.
    project_name = (
        manifest.get("name") if isinstance(manifest, dict) else None
    ) or root.name
    project_description = (
        manifest.get("description") if isinstance(manifest, dict) else ""
    ) or ""
    frontier_id = manifest.get("frontier_id") if isinstance(manifest, dict) else None

    # Findings (genesis state for the reducer).
    findings = _read_json_dir(vela_dir / "findings")

    # Events / proposals / reviews / confidence-updates.
    events = _read_json_dir(vela_dir / "events")
    proposals = _read_json_dir(vela_dir / "proposals")
    review_events = _read_json_dir(vela_dir / "reviews")
    confidence_updates = _read_json_dir(vela_dir / "confidence-updates")

    # v0.105.8: actors and signatures are persisted as flat JSON
    # files (.vela/actors.json, .vela/signatures.json), not split
    # into per-record files. Surface both as top-level keys so a
    # Python consumer can verify signatures or check actor
    # registration without re-reading the .vela tree directly.
    actors = _read_json_array_file(vela_dir / "actors.json")
    signatures = _read_json_array_file(vela_dir / "signatures.json")

    # Reducer state. Matches the dict the Python reducer expects.
    state = {
        "findings": deepcopy(findings),
        "negative_results": [],
        "trajectories": [],
        "artifacts": [],
        "evidence_atoms": [],
        # v0.105.8: replications and predictions accumulate via the
        # v0.70 deposit reducer arms. Pre-v0.105.8 the loader's
        # returned dict stripped these keys even though the reducer
        # populated state["replications"] / state["predictions"]
        # mid-replay. Initialize them up front so the reducer
        # doesn't have to setdefault and so a downstream caller
        # can reliably read d["replications"].
        "replications": [],
        "predictions": [],
    }

    for event in events:
        try:
            apply_event(state, event)
        except ValueError as e:
            raise RuntimeError(
                f"reducer failed on event {event.get('id', '?')} "
                f"({event.get('kind', '?')}): {e}"
            ) from e

    return {
        "project": {
            "name": project_name,
            "description": project_description,
            "dependencies": dependencies,
        },
        "frontier_id": frontier_id,
        "findings": state["findings"],
        "negative_results": state["negative_results"],
        "trajectories": state["trajectories"],
        "artifacts": state["artifacts"],
        "evidence_atoms": state["evidence_atoms"],
        "replications": state["replications"],
        "predictions": state["predictions"],
        "actors": actors,
        "signatures": signatures,
        "events": events,
        "proposals": proposals,
        "review_events": review_events,
        "confidence_updates": confidence_updates,
        "manifest": manifest,
    }


def _read_json_array_file(path: Path) -> list[dict]:
    """Read a flat JSON array file, returning [] when absent or empty."""
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    return []


def _main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: vela_loader.py <project-dir>", file=sys.stderr)
        return 2
    repo = load_frontier_repo(argv[1])
    summary = {
        "name": repo["project"]["name"],
        "frontier_id": repo["frontier_id"],
        "dependencies": [d.get("vfr_id") for d in repo["project"]["dependencies"]],
        "findings": len(repo["findings"]),
        "events": len(repo["events"]),
        "proposals": len(repo["proposals"]),
        "accepted_findings": sum(
            1
            for f in repo["findings"]
            if (f.get("flags") or {}).get("review_state") == "accepted"
        ),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
