#!/usr/bin/env python3
from __future__ import annotations
from typing import Any,Iterable
from canonical import content_id,digest
from kernel import Presentation,compile_gamma,lineage_root,active_view_root,supported,minimal_environments,active_environments
from packets import signed_packet
VIEW_POLICY_ID='vela.view.public.v2'
def roots(p:Presentation,disabled:Iterable[str])->dict[str,str]:
    g=compile_gamma(p);return {'presentation_root':p.presentation_root(),'circuit_root':p.circuit_root(),'lineage_root':lineage_root(g),'active_view_root':active_view_root(disabled,VIEW_POLICY_ID)}
def evaluate_support(p:Presentation,disabled:Iterable[str],cells:Iterable[str])->dict[str,Any]:
    g=compile_gamma(p);rows=[]
    for c in sorted(cells):
        poly=g.get(c,{})
        rows.append({'cell_id':c,'supported':supported(poly,disabled),'historical_minimal_environments':minimal_environments(poly),'active_minimal_environments':active_environments(poly,disabled),'metadata':p.cell_metadata.get(c,{})})
    return {'cells':rows}
def make_observation(p:Presentation,disabled:Iterable[str],cells:list[str],key,actor:str)->dict[str,Any]:
    rs=roots(p,disabled);eid='vela.support-and-environments.v2';inputs={'cells':sorted(cells),'disabled_atoms':sorted(set(disabled)),'view_policy_id':VIEW_POLICY_ID};out=evaluate_support(p,disabled,cells);receipt={'input_roots_digest':digest(rs),'evaluator_id':eid,'evaluator_digest':content_id('veval_',{'id':eid,'version':2}),'inputs_digest':digest(inputs),'output_digest':digest(out)}
    return signed_packet('observation',{**rs,'evaluator_id':eid,'evaluator_inputs':inputs,'canonical_output':out,'replay_receipt':receipt},key,actor,'hub')
def verify_observation(o:dict[str,Any],p:Presentation,disabled:Iterable[str])->None:
    for k,v in roots(p,disabled).items():
        if o.get(k)!=v:raise AssertionError(f'observation root mismatch {k}')
    out=evaluate_support(p,disabled,o['evaluator_inputs']['cells'])
    if o.get('canonical_output')!=out:raise AssertionError('observation output mismatch')
    if o['replay_receipt']['output_digest']!=digest(out):raise AssertionError('output digest mismatch')
def no_hidden_state_check(export:dict[str,Any],observations:list[dict[str,Any]])->None:
    by_id={o['packet_id']:o for o in observations};required={'presentation_root','circuit_root','lineage_root','active_view_root'}
    for value in export.get('authoritative_values',[]):
        oid=value.get('observation_packet_id')
        if oid not in by_id:raise AssertionError(f'authoritative value lacks observation packet: {value.get("name")}')
        o=by_id[oid]
        if not required.issubset(o):raise AssertionError('packet missing roots')
        if value.get('canonical_value_digest')!=digest(value.get('value')):raise AssertionError('value digest mismatch')
        if value.get('value')!=o['canonical_output']:raise AssertionError('value not reproduced')
