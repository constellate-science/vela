#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'reference'))
from observations import no_hidden_state_check
f=json.loads((ROOT/'fixtures'/'frontier-extension.json').read_text());no_hidden_state_check(f['state_export'],list(f['observations'].values()))
print('PASS no-hidden-state export')
