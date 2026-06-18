#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];f=json.loads((ROOT/'fixtures'/'frontier-extension.json').read_text());w=f['gap_identifiability']
assert w['same_presentation_root']==f['frontier_before']['presentation_root']
assert w['open_a']!=w['open_b'] and not w['open_a'] and w['open_b']
print('PASS gap-identifiability counterexample')
