#!/usr/bin/env bash
set -euo pipefail

if ! command -v lake >/dev/null 2>&1; then
  echo "lake is not installed. Install elan/Lean first, then rerun this script." >&2
  exit 1
fi

lake update
lake exe cache get
lake build Vela.CoreTheorems
