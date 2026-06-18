#!/usr/bin/env python3
"""Executable No Hidden State Conformance Law for exported authoritative values.

Predicate: every authoritative field outside an ObservationPacket must have a
sibling `_state` binding to exactly one signed ObservationPacket and JSON pointer;
the pointer must resolve to the emitted value; the packet must carry the complete
root/evaluator/replay set and its output digest must match canonical_output.
"""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'reference'))
from canonical import digest
from packets import verify_signed_packet

AUTHORITATIVE_KEYS={
 'status','verification_status','confidence','kappa','trust','verification_cost',
 'frontier_delta','best_lower_bound','bilattice','conflict_degree'
}
REQUIRED_PACKET_FIELDS={
 'presentation_root','circuit_root','lineage_root','active_view_root','evaluator_id',
 'evaluator_inputs','canonical_output','replay_receipt'
}

def pointer_get(value,pointer):
    if not pointer.startswith('/'):
        raise AssertionError('JSON pointer must start with /')
    cur=value
    for raw in pointer.split('/')[1:]:
        token=raw.replace('~1','/').replace('~0','~')
        cur=cur[int(token)] if isinstance(cur,list) else cur[token]
    return cur

def scan(value,path='$'):
    found=[]
    if isinstance(value,dict):
        state=value.get('_state',{})
        for key,child in value.items():
            if key=='_state': continue
            cpath=f'{path}.{key}'
            if key in AUTHORITATIVE_KEYS:
                binding=state.get(key)
                if not isinstance(binding,dict):
                    raise AssertionError(f'{cpath}: authoritative value has no _state binding')
                found.append((cpath,child,binding))
            found.extend(scan(child,cpath))
    elif isinstance(value,list):
        for i,child in enumerate(value): found.extend(scan(child,f'{path}[{i}]'))
    return found

def main():
    path=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'fixtures'/'state-export-pass.json'
    export=json.loads(path.read_text())
    packets=export.get('observation_packets',[])
    by_id={p['packet_id']:p for p in packets}
    if len(by_id)!=len(packets): raise AssertionError('duplicate observation packet ids')
    for packet in packets:
        verify_signed_packet(packet)
        missing=REQUIRED_PACKET_FIELDS-packet.keys()
        if missing: raise AssertionError(f"{packet['packet_id']}: missing {sorted(missing)}")
        if packet['replay_receipt']['output_digest']!=digest(packet['canonical_output']):
            raise AssertionError(f"{packet['packet_id']}: canonical output digest mismatch")
    subject={k:v for k,v in export.items() if k!='observation_packets'}
    values=scan(subject)
    if not values: raise AssertionError('no authoritative values found')
    for path_text,emitted,binding in values:
        pid=binding.get('observation_packet_id'); pointer=binding.get('output_pointer')
        packet=by_id.get(pid)
        if packet is None: raise AssertionError(f'{path_text}: unknown observation packet {pid}')
        if not isinstance(pointer,str) or not pointer.startswith('/canonical_output'):
            raise AssertionError(f'{path_text}: output pointer must address canonical_output')
        replayed=pointer_get(packet,pointer)
        if replayed!=emitted: raise AssertionError(f'{path_text}: emitted {emitted!r} != replayed {replayed!r}')
    print(f'PASS: no-hidden-state predicate reproduced {len(values)} authoritative value(s)')

if __name__=='__main__': main()
