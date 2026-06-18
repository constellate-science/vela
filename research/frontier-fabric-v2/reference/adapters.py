#!/usr/bin/env python3
from __future__ import annotations
from typing import Any
from canonical import content_id,digest
from frontier import Obligation
EVIDENCE_CLASSES={'exact','replay','trace','estimate','attestation'}
TRANSFER_LANES={'certified','target_checked','exploratory'}
MODEL_CLASSES={'none','language_model','graph_model','neural_operator','symbolic_regression','universal_differential_equation','natural_law_model','generative_model'}
def adapter_id(body:dict[str,Any])->str: return content_id('vadp_',body)
def validate_adapter(a:dict[str,Any])->None:
    req={'schema_version','adapter_id','name','domain_profile_id','evidence_class','context_dimensions','compiler_id','verifier_profiles','obligation_generators','candidate_generators','transfer_lanes','observation_evaluators','capabilities'}
    if req-a.keys(): raise ValueError(f'adapter missing fields: {sorted(req-a.keys())}')
    if a['schema_version']!='vela.domain-adapter.v2': raise ValueError('adapter schema version')
    if a['evidence_class'] not in EVIDENCE_CLASSES: raise ValueError('unknown evidence class')
    if not set(a['transfer_lanes']).issubset(TRANSFER_LANES): raise ValueError('unknown transfer lane')
    for g in a['candidate_generators']:
        if g['model_class'] not in MODEL_CLASSES: raise ValueError('unknown candidate generator class')
        if g.get('state_effect')!='none': raise ValueError('candidate generators must be state-neutral')
    body={k:v for k,v in a.items() if k!='adapter_id'}
    if a['adapter_id']!=adapter_id(body): raise ValueError('adapter id mismatch')
def generate_obligations(a:dict[str,Any],target_cells:dict[str,str],context:dict[str,Any])->list[Obligation]:
    validate_adapter(a); out=[]
    for g in a['obligation_generators']:
        for name in g['targets']:
            if name not in target_cells: continue
            out.append(Obligation.make(adapter_id=a['adapter_id'],target_cell=target_cells[name],kind=g['kind'],context=context,discharge_evaluator_id=g['discharge_evaluator_id'],verifier_profile_id=g['verifier_profile_id'],generator_id=g['generator_id'],dependencies=[target_cells.get(d, d) for d in g.get('dependencies', [])],rationale=g['rationale']))
    return out
def adapter_capability_packet(a:dict[str,Any])->dict[str,Any]:
    validate_adapter(a); p={'adapter_id':a['adapter_id'],'domain_profile_id':a['domain_profile_id'],'evidence_class':a['evidence_class'],'capabilities':a['capabilities'],'transfer_lanes':a['transfer_lanes'],'verifier_profiles':a['verifier_profiles'],'obligation_generator_ids':[x['generator_id'] for x in a['obligation_generators']],'candidate_generator_ids':[x['generator_id'] for x in a['candidate_generators']],'evaluator_ids':[x['evaluator_id'] for x in a['observation_evaluators']]}
    return {**p,'capability_digest':digest(p)}
