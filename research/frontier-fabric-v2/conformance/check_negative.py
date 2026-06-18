#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'reference'))
from observations import no_hidden_state_check
f=json.loads((ROOT/'fixtures'/'frontier-extension.json').read_text());bad=json.loads((ROOT/'fixtures'/'state-export-fail.json').read_text())
try:no_hidden_state_check(bad,list(f['observations'].values()))
except AssertionError:print('PASS hidden-state negative fixture rejected')
else:raise SystemExit('FAIL hidden state accepted')
# Model output may not claim certified transfer.
bad_candidate=dict(f['model_candidate']);bad_candidate['state_effect']='append'
from models import verify_model_noninterference
try:verify_model_noninterference(bad_candidate)
except AssertionError:print('PASS model-authority negative fixture rejected')
else:raise SystemExit('FAIL model authority accepted')
