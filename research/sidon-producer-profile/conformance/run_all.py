#!/usr/bin/env python3
from __future__ import annotations
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
commands=[
 [sys.executable,str(ROOT/'reference'/'generate_fixture.py')],
 [sys.executable,str(ROOT/'conformance'/'check_schema.py')],
 [sys.executable,str(ROOT/'conformance'/'check_verifier_executables.py')],
 [sys.executable,str(ROOT/'conformance'/'check_fixture.py')],
 [sys.executable,str(ROOT/'conformance'/'check_no_hidden_state.py'),str(ROOT/'fixtures'/'state-export-pass.json')],
 [sys.executable,str(ROOT/'conformance'/'check_adoption_gate.py')],
]
for cmd in commands:
    print('+',' '.join(cmd)); subprocess.run(cmd,cwd=ROOT,check=True)
# The negative no-hidden-state fixture must fail.
neg=subprocess.run([sys.executable,str(ROOT/'conformance'/'check_no_hidden_state.py'),str(ROOT/'fixtures'/'state-export-fail.json')],cwd=ROOT,text=True,capture_output=True)
if neg.returncode==0: raise SystemExit('FAIL: invalid no-hidden-state fixture was accepted')
print('PASS: invalid no-hidden-state fixture rejected')
print('PASS: all breakthrough-slice conformance checks')
