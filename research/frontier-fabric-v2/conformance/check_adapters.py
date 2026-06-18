#!/usr/bin/env python3
import json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'reference'))
from adapters import validate_adapter,adapter_capability_packet
schema=json.loads((ROOT/'schema'/'domain-adapter-v2.schema.json').read_text());validator=Draft202012Validator(schema)
files=sorted((ROOT/'adapters').glob('*.adapter.json'))
if len(files)<8:raise SystemExit('expected at least 8 adapters')
for path in files:
    value=json.loads(path.read_text());validator.validate(value);validate_adapter(value);adapter_capability_packet(value)
print(f'PASS {len(files)} DomainAdapter manifests')
