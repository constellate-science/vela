#!/usr/bin/env python3
"""Retained producer adapter for the Sidon frontier.

The adapter is generic at the process boundary: task JSON goes to the solver on
stdin, one witness JSON returns on stdout. It consumes an authoritative
ObservationPacket when available. `bounds.json` is supported only as a
transitional read and is explicitly marked non-counting for the adoption gate.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shlex, subprocess, sys, tempfile, urllib.request
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parents[2] / 'research' / 'sidon-producer-profile'
sys.path.insert(0,str(ROOT/'reference'))
from canonical import digest
from packets import verify_signed_packet
from sidon import verify_base3_sort, verify_pairsum_set

DEFAULT_SOURCE='https://raw.githubusercontent.com/constellate-science/vela/main/frontiers/sidon-sets/bounds.json'

def die(msg,code=1): print(f'retained-producer: {msg}',file=sys.stderr); raise SystemExit(code)
def load_json(location):
    if location.startswith(('https://','http://')):
        with urllib.request.urlopen(location,timeout=20) as r: return json.loads(r.read())
    return json.loads(Path(location).read_text())
def atomic_write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_suffix(path.suffix+'.tmp'); tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n'); os.replace(tmp,path)
def extract_state(source,n):
    if source.get('packet_type')=='observation':
        verify_signed_packet(source)
        row=next((r for r in source['canonical_output']['bounds'] if r['n']==n),None)
        if row is None: die(f'observation has no n={n}')
        base={
          'observation_id':source['packet_id'],'presentation_root':source['presentation_root'],'circuit_root':source['circuit_root'],
          'lineage_root':source['lineage_root'],'active_view_root':source['active_view_root'],'evaluator_id':source['evaluator_id'],
          'evaluator_inputs_digest':digest(source['evaluator_inputs']),'canonical_output_digest':digest(source['canonical_output'])
        }
        return base,int(row['best_lower_bound']),True,source['frontier_id']
    root=source.get('generated_from',{}).get('source_event_log_hash')
    if not root: die('source is neither an ObservationPacket nor a bounds feed with source_event_log_hash')
    row=next((r for r in source.get('bounds',[]) if r.get('n')==n),None)
    if row is None: die(f'bounds feed has no n={n}')
    oid=source.get('observation_packet_id') or 'vop_transition_'+hashlib.sha256(json.dumps(source,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    base={'observation_id':oid,'presentation_root':root,'circuit_root':'transition:unavailable','lineage_root':'transition:unavailable','active_view_root':'transition:unavailable','evaluator_id':'transition:bounds-json','evaluator_inputs_digest':digest({'n':n}),'canonical_output_digest':digest(source.get('bounds',[]))}
    return base,int(row['best_lower_bound']),False,source.get('frontier_id')

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--source',default=DEFAULT_SOURCE); ap.add_argument('--n',type=int,required=True); ap.add_argument('--solver-cmd',required=True)
    ap.add_argument('--cursor',default='.vela-sidon-producer-cursor.json'); ap.add_argument('--dry-run',action='store_true'); ap.add_argument('--force',action='store_true')
    ap.add_argument('--allow-tie',action='store_true'); ap.add_argument('--submit-command',default=None,help='shell command template with {witness}, {observation_id}, {presentation_root}')
    args=ap.parse_args(); source=load_json(args.source); base,current,authoritative,frontier_id=extract_state(source,args.n)
    cursor_path=Path(args.cursor); cursor=json.loads(cursor_path.read_text()) if cursor_path.exists() else {}
    if cursor.get('last_consumed_observation_id')==base['observation_id'] and not args.force:
        print(json.dumps({'ok':True,'action':'no_op','reason':'observation_unchanged','base_state':base},indent=2)); return
    task={'schema_version':'vela.sidon-producer-adapter.v1','frontier_id':frontier_id,'base_state':base,'target':{'sequence':'oeis:A309370','n':args.n},'objective':{'kind':'strict_improvement','current':current,'required_minimum':current+1},'verifier_contract':'vela.sidon.gate.v1'}
    cmd=shlex.split(args.solver_cmd)
    if not cmd: die('empty solver command')
    run=subprocess.run(cmd,input=json.dumps(task),text=True,capture_output=True)
    if run.returncode!=0: die(f'solver failed: {run.stderr.strip()}',20)
    try: witness=json.loads(run.stdout)
    except json.JSONDecodeError as exc: die(f'solver stdout is not one JSON witness: {exc}',21)
    a,da=verify_pairsum_set(witness); b,db=verify_base3_sort(witness)
    if not (a and b): die(f'local diverse verification failed: {da}; {db}',22)
    if witness.get('n')!=args.n: die('solver returned wrong dimension',23)
    size=int(witness['claimed_size'])
    if size<current or (size==current and not args.allow_tie): die(f'candidate {size} does not improve current {current}',24)
    preview={'schema_version':'vela.sidon-result-preview.v1','frontier_id':frontier_id,'base_state':base,'claim':{'sequence':'oeis:A309370','n':args.n,'relation':'>=','value':size},'artifact_digest':digest(witness),'artifact':witness,'local_verification':[{'method':'pair-sum-hash-set','passed':a,'detail':da},{'method':'base3-encode-sort','passed':b,'detail':db}],'delta':size-current,'authoritative_observation_consumed':authoritative}
    if args.dry_run:
        print(json.dumps({'ok':True,'action':'dry_run','counts_toward_adoption_gate':False,'task':task,'result_preview':preview},indent=2)); return
    if not authoritative: die('refusing counted submission from transitional bounds feed; consume an authoritative ObservationPacket',25)
    if not args.submit_command: die('authoritative submission requires --submit-command; no hidden legacy rebasing',26)
    with tempfile.NamedTemporaryFile('w',suffix='.json',delete=False) as f: json.dump(witness,f); witness_path=f.name
    rendered=args.submit_command.format(witness=shlex.quote(witness_path),observation_id=shlex.quote(base['observation_id']),presentation_root=shlex.quote(base['presentation_root']))
    submitted=subprocess.run(rendered,shell=True,text=True,capture_output=True); os.unlink(witness_path)
    if submitted.returncode!=0: die(f'submission failed:\n{submitted.stdout}\n{submitted.stderr}',27)
    new_cursor={'schema':'vela.retained-producer-cursor.v2','last_consumed_observation_id':base['observation_id'],'base_state':base,'frontier_id':frontier_id,'n':args.n,'artifact_digest':preview['artifact_digest'],'candidate_size':size,'submission_stdout':submitted.stdout.strip()}
    atomic_write(cursor_path,new_cursor); print(json.dumps({'ok':True,'action':'submitted','cursor':new_cursor},indent=2))
if __name__=='__main__': main()
