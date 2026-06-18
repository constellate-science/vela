#!/usr/bin/env python3
import json
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1]
schema=json.loads((ROOT/'schema'/'frontier-fabric-fixture-v2.schema.json').read_text());fixture=json.loads((ROOT/'fixtures'/'frontier-extension.json').read_text());Draft202012Validator(schema).validate(fixture)
print('PASS fixture schema')
