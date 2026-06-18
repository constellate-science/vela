#!/usr/bin/env python3
from __future__ import annotations
from typing import Any,Iterable
from canonical import digest
from kernel import Presentation,Clause
from packets import signed_packet
LANES={'certified','target_checked','exploratory'}
def make_transfer_packet(*,lane:str,source_cells:list[str],target_cell:str,source_contexts:list[dict[str,Any]],target_context:dict[str,Any],assumptions:list[str],certificate:dict[str,Any]|None,required_target_receipts:list[str],preserved_coordinates:list[str],lost_coordinates:list[str],key,actor:str,actor_kind:str)->dict[str,Any]:
    if lane not in LANES:raise ValueError('unknown lane')
    if lane=='certified' and not certificate:raise ValueError('certified transfer requires certificate')
    if lane!='certified' and certificate and certificate.get('verifier_preserving'):raise ValueError('verifier-preserving certificate must be certified')
    return signed_packet('transfer',{'lane':lane,'source_cells':sorted(set(source_cells)),'target_cell':target_cell,'source_contexts':source_contexts,'target_context':target_context,'assumptions':sorted(set(assumptions)),'certificate':certificate,'required_target_receipts':sorted(set(required_target_receipts)),'preserved_coordinates':sorted(set(preserved_coordinates)),'lost_coordinates':sorted(set(lost_coordinates)),'state_effect':'append_eligible_after_human_acceptance' if lane=='certified' else 'none_until_target_receipts_and_human_acceptance'},key,actor,actor_kind)
def transfer_append_eligible(t:dict[str,Any],receipts:Iterable[dict[str,Any]],human_acceptance:bool)->bool:
    if not human_acceptance:return False
    if t['lane']=='certified':
        c=t.get('certificate') or {};return bool(c.get('verifier_preserving') and c.get('passed'))
    if t['lane']=='target_checked':
        req=set(t.get('required_target_receipts',[]));passed={r['receipt_kind'] for r in receipts if r.get('passed')};return req.issubset(passed)
    return False
def append_transfer_clause(p:Presentation,*,transfer:dict[str,Any],head_rank:int,accepted_event_id:str,profile_id:str,target_receipts:Iterable[dict[str,Any]],human_acceptance:bool)->Clause:
    receipts=list(target_receipts)
    if not transfer_append_eligible(transfer,receipts,human_acceptance):raise ValueError('not append eligible')
    if any(p.cell_ranks.get(c,-1)>=head_rank for c in transfer['source_cells']):raise ValueError('rank violation')
    atoms=[f'transfer:{transfer["packet_id"]}',f'acceptance:{accepted_event_id}',*[f'assumption:{a}' for a in transfer.get('assumptions',[])]]
    if transfer.get('certificate'):atoms.append('certificate:'+digest(transfer['certificate']))
    atoms += [f'target-receipt:{r["packet_id"]}' for r in receipts if r.get('passed')]
    return Clause.make(head=transfer['target_cell'],head_rank=head_rank,body=transfer['source_cells'],atoms=atoms,accepted_event_id=accepted_event_id,profile_id=profile_id)
