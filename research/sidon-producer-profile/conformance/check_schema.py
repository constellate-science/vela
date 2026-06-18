#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
import jsonschema

ROOT=Path(__file__).resolve().parents[1]
schema=json.loads((ROOT/'schema'/'sidon-producer-profile-v1.schema.json').read_text())
fixture=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'fixtures'/'sidon-root-pinned-loop.json'
data=json.loads(fixture.read_text())
validator=jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker())
errors=[]
for packet in data['packets']:
    for error in validator.iter_errors(packet):
        errors.append((packet.get('packet_id'),error.json_path,error.message))
if errors:
    for pid,path,msg in errors:
        print(f'FAIL {pid} {path}: {msg}',file=sys.stderr)
    raise SystemExit(1)
print(f"PASS: {len(data['packets'])} packets satisfy strict Sidon Producer Profile schema")
