#!/usr/bin/env python3
"""
Vela conformance verifier.

Runs the canonical Python reducer (`clients/python/vela_reducer.py`)
against every fixture in `conformance/fixtures/` and reports per-fixture
pass/fail.

The Python reducer already implements the contract documented in
`conformance/README.md`: parse `(genesis_findings, event_log,
expected_states)`, apply per-kind mutation rules, build the effect-row
shape, assert deep equality with `expected_states`. This script is a
thin wrapper that exposes that contract as a public test runner an
external implementation can mirror.

Usage:
    ./verify.py
    ./verify.py --fixtures-dir <other-dir>
    ./verify.py --reducer-script <other-reducer.py>

Exit codes:
    0 = all fixtures pass
    1 = at least one fixture fails
    2 = invocation error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _check_manifest(fixtures_dir: Path) -> int:
    """v0.107.4: integrity preflight.

    Reads `fixtures.manifest.json` and verifies the SHA-256 of every
    listed fixture against its recorded digest. Refuses to run if any
    fixture has been tampered with. Closes THREAT_MODEL.md A12
    (integrity half; signed-manifest variant is a future cycle).

    Returns 0 if every fixture matches the manifest, 2 if the manifest
    is missing or any fixture's digest drifts. Skips with a one-line
    note when the manifest is absent (older fixture sets predate the
    manifest format and remain runnable; new sets ship with one).
    """
    manifest_path = fixtures_dir / "fixtures.manifest.json"
    if not manifest_path.is_file():
        print(
            f"  note: no fixtures.manifest.json at {manifest_path}; "
            f"skipping integrity preflight (older fixture set)"
        )
        return 0
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        print(f"  fail: fixtures.manifest.json is not valid JSON: {e}", file=sys.stderr)
        return 2
    if manifest.get("schema") != "vela.conformance-fixtures-manifest.v1":
        print(
            f"  fail: fixtures.manifest.json has wrong schema: "
            f"{manifest.get('schema')!r}",
            file=sys.stderr,
        )
        return 2
    drift = []
    for entry in manifest.get("fixtures", []):
        name = entry.get("path", "")
        expected_digest = entry.get("sha256", "")
        expected_bytes = entry.get("bytes", -1)
        path = fixtures_dir / name
        if not path.is_file():
            drift.append(f"{name}: missing on disk")
            continue
        bytes_on_disk = path.read_bytes()
        if len(bytes_on_disk) != expected_bytes:
            drift.append(
                f"{name}: size {len(bytes_on_disk)} != manifest {expected_bytes}"
            )
            continue
        actual_digest = "sha256:" + hashlib.sha256(bytes_on_disk).hexdigest()
        if actual_digest != expected_digest:
            drift.append(f"{name}: sha256 drift")
    if drift:
        print(
            "  fail: fixture integrity preflight detected drift:",
            file=sys.stderr,
        )
        for d in drift:
            print(f"    - {d}", file=sys.stderr)
        return 2
    print(f"  ok: integrity preflight ({len(manifest.get('fixtures', []))} fixtures)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Vela conformance verifier.")
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    default_reducer = repo_root / "clients" / "python" / "vela_reducer.py"
    parser.add_argument(
        "--reducer-script",
        default=str(default_reducer),
        help="Python reducer script that implements the conformance contract",
    )
    parser.add_argument(
        "--fixtures-dir",
        default=str(here / "fixtures"),
        help="directory containing cascade-fixture-*.json",
    )
    args = parser.parse_args()

    fixtures_dir = Path(args.fixtures_dir)
    if not fixtures_dir.is_dir():
        print(f"fixtures dir not found: {fixtures_dir}", file=sys.stderr)
        return 2

    reducer_script = Path(args.reducer_script)
    if not reducer_script.exists():
        print(f"reducer script not found: {reducer_script}", file=sys.stderr)
        return 2

    # v0.107.4: integrity preflight. Refuses to run if any fixture's
    # bytes drift from the recorded SHA-256 in fixtures.manifest.json.
    rc = _check_manifest(fixtures_dir)
    if rc != 0:
        return rc

    # Delegate to the canonical Python reducer's --json mode.
    cmd = [sys.executable, str(reducer_script), str(fixtures_dir), "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        print(f"failed to invoke reducer: {e}", file=sys.stderr)
        return 2

    if result.returncode not in (0, 1):
        print(f"reducer invocation failed (exit {result.returncode})", file=sys.stderr)
        if result.stderr.strip():
            print(result.stderr, file=sys.stderr)
        return 2

    try:
        report = json.loads(result.stdout)
    except Exception as e:
        print(f"failed to parse reducer output: {e}", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        return 2

    fixtures = report.get("fixtures", [])
    print(f"vela conformance · {len(fixtures)} fixtures")
    failed = 0
    for f in fixtures:
        ok = bool(f.get("ok"))
        status = "ok  " if ok else "FAIL"
        path = f.get("path", "?")
        # Compact summary line: counts + cascade depth.
        summary = (
            f"{f.get('findings', 0)}/{f.get('findings', 0)}"
            f" findings,"
            f" {f.get('events', 0)} events"
            f", cascade depth {f.get('cascade_depth', 0)}"
        )
        print(f"  {status}  {Path(path).name}  ·  {summary}")
        if not ok:
            failed += 1
            for diff in f.get("diffs", []):
                print(f"           ! {diff}")

    print()
    if failed == 0:
        print(f"vela conformance: ok ({len(fixtures)}/{len(fixtures)})  [python]")
    else:
        print(f"vela conformance: FAIL ({failed}/{len(fixtures)} failed)  [python]")
        return 1

    # Second implementation: the TypeScript reducer. Gating it here is
    # what keeps it from silently drifting — an unrun reducer rots (the
    # retired `vela_reducer.mjs` fell three fixture_versions behind
    # precisely because nothing exercised it). Requires Node 23+ (native
    # TypeScript). If `node` is absent we warn and skip rather than fail,
    # so the suite still runs in Python-only environments.
    ts_rc = _run_ts_reducer(repo_root, fixtures_dir)
    if ts_rc == 2:
        print("  note: typescript reducer skipped (node not found); python-only run")
        return 0
    if ts_rc != 0:
        print("vela conformance: FAIL  [typescript]")
        return 1
    print("vela conformance: ok  [typescript]")
    print("\nvela conformance: ok — python + typescript agree with the rust reference")
    return 0


def _run_ts_reducer(repo_root: Path, fixtures_dir: Path) -> int:
    """Run the TypeScript reducer over the fixtures. Returns 0 (ok),
    1 (mismatch/error), or 2 (node unavailable → skip)."""
    ts_reducer = repo_root / "clients" / "typescript" / "vela_reducer.ts"
    if not ts_reducer.exists():
        print(f"  note: typescript reducer not found at {ts_reducer}")
        return 2
    try:
        result = subprocess.run(
            ["node", str(ts_reducer), str(fixtures_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"  typescript reducer invocation failed: {e}", file=sys.stderr)
        return 1
    if result.returncode != 0:
        if result.stdout.strip():
            print(result.stdout)
        if result.stderr.strip():
            print(result.stderr, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
