#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'reference'))
from packets import verify_signed_packet
f=json.loads((ROOT/'fixtures'/'frontier-extension.json').read_text())
packets=[f['certified_transfer'],f['model_candidate'],f['target_receipt'],f['challenge'],f['view_decision'],f['repair'],f['natural_law_candidate'],*f['observations'].values()]
for p in packets:verify_signed_packet(p)
print(f'PASS {len(packets)} signed packets')
