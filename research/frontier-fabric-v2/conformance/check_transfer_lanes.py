#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'reference'))
from kernel import Presentation,compile_gamma,supported
from models import verify_model_noninterference
f=json.loads((ROOT/'fixtures'/'frontier-extension.json').read_text());verify_model_noninterference(f['model_candidate']);verify_model_noninterference(f['natural_law_candidate'])
assert f['certified_transfer']['lane']=='certified' and f['certified_transfer']['certificate']['verifier_preserving']
p0=Presentation.from_json(f['presentation_before']);p1=Presentation.from_json(f['presentation_final']);cells=f['cells'];g0=compile_gamma(p0);g1=compile_gamma(p1)
assert supported(g0[cells['sidon_translated']],[]) and supported(g1[cells['sidon_translated']],[])
assert not supported(g0[cells['heat_alpha_02']],[]) and supported(g1[cells['heat_alpha_02']],[])
print('PASS certified and target-checked transfer lanes; exploratory models remain state-neutral')
