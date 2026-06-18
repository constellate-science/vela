#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(); p.add_argument('scorecard',nargs='?',default=str(ROOT/'metrics'/'adoption-scorecard.json')); p.add_argument('--enforce',choices=['loop','protocol','foundation']); args=p.parse_args()
score=json.loads(Path(args.scorecard).read_text()); c=score['counts']; stages=score['stages']
results={}
for stage,req in stages.items():
    checks={}
    for key,value in req.items():
        if key.endswith('_max'):
            source=key[:-4]; checks[key]=c[source]<=value
        else: checks[key]=c[key]>=value
    results[stage]={'passed':all(checks.values()),'checks':checks}
print(json.dumps({'counts':c,'stages':results},indent=2,sort_keys=True))
if args.enforce and not results[args.enforce]['passed']: raise SystemExit(1)
