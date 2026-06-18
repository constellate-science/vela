#!/usr/bin/env python3
from __future__ import annotations
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
commands=[
 [sys.executable,str(ROOT/'reference'/'build_adapters.py')],
 [sys.executable,str(ROOT/'reference'/'generate_fixture.py')],
 [sys.executable,str(ROOT/'conformance'/'check_adapters.py')],
 [sys.executable,str(ROOT/'conformance'/'check_adapter_modularity.py')],
 [sys.executable,str(ROOT/'conformance'/'check_fixture_schema.py')],
 [sys.executable,str(ROOT/'conformance'/'check_packets.py')],
 [sys.executable,str(ROOT/'conformance'/'check_gap_identifiability.py')],
 [sys.executable,str(ROOT/'conformance'/'check_transfer_lanes.py')],
 [sys.executable,str(ROOT/'conformance'/'check_frontier_extension.py')],
 [sys.executable,str(ROOT/'conformance'/'check_correction.py')],
 [sys.executable,str(ROOT/'conformance'/'check_no_hidden_state.py')],
 [sys.executable,str(ROOT/'conformance'/'check_negative.py')],
]
for cmd in commands:
    print('+',' '.join(cmd));subprocess.run(cmd,cwd=ROOT,check=True)
print('PASS all Frontier Fabric v2 conformance checks')
