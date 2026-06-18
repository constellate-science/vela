#!/usr/bin/env python3
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
positive=json.loads((ROOT/'fixtures'/'sidon-n4-route-a.json').read_text())
negative=json.loads(json.dumps(positive)); negative['points'][0]=[0,0,0,1]
for script in (ROOT/'verifiers'/'sidon_pairsum_set.py',ROOT/'verifiers'/'sidon_base3_sort.py'):
    pos=subprocess.run([sys.executable,str(script)],input=json.dumps(positive),text=True,capture_output=True)
    if pos.returncode!=0 or not json.loads(pos.stdout)['passed']:
        raise AssertionError(f'{script.name} rejected positive fixture: {pos.stdout} {pos.stderr}')
    neg=subprocess.run([sys.executable,str(script)],input=json.dumps(negative),text=True,capture_output=True)
    if neg.returncode==0 or json.loads(neg.stdout)['passed']:
        raise AssertionError(f'{script.name} accepted negative fixture')
print('PASS: two packaged Sidon verifier executables agree on positive and semantic-negative fixtures')
