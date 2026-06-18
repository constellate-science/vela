#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
work="$repo_root/research/frontier-fabric-v2"
PYTHONPATH="$work/reference" python3 "$work/conformance/run_all.py"
