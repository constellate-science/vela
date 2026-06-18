#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference"))
from sidon import verify_pairsum_set

witness = json.load(sys.stdin)
passed, detail = verify_pairsum_set(witness)
print(json.dumps({"method_family": "pair-sum-hash-set", "passed": passed, "detail": detail}, sort_keys=True))
raise SystemExit(0 if passed else 1)
