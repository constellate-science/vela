#!/usr/bin/env python3
from __future__ import annotations
from typing import Any
from canonical import digest
from packets import signed_packet
ALLOWED={'language_model','graph_model','neural_operator','symbolic_regression','universal_differential_equation','natural_law_model','generative_model'}
def validate_model_manifest(m:dict[str,Any])->None:
    req={'model_id','model_class','weights_root','code_root','training_data_roots','domain_of_validity','calibration_receipt_ids','known_failure_modes','output_contract','producer_kind'}
    if req-m.keys():raise ValueError(f'model manifest missing {sorted(req-m.keys())}')
    if m['model_class'] not in ALLOWED:raise ValueError('unknown model class')
    if m['producer_kind']!='model':raise ValueError('producer kind')
def make_candidate(*,manifest:dict[str,Any],base_observation_root:str,source_cells:list[str],target_cell:str,target_context:dict[str,Any],proposed_artifact:dict[str,Any],assumptions:list[str],transfer_lane:str,key,actor:str)->dict[str,Any]:
    validate_model_manifest(manifest)
    if transfer_lane not in {'target_checked','exploratory'}:raise ValueError('model transfer cannot be certified without external certificate')
    return signed_packet('candidate',{'model_id':manifest['model_id'],'model_class':manifest['model_class'],'base_observation_root':base_observation_root,'source_cells':sorted(set(source_cells)),'target_cell':target_cell,'target_context':target_context,'proposed_artifact':proposed_artifact,'proposed_artifact_digest':digest(proposed_artifact),'assumptions':sorted(set(assumptions)),'transfer_lane':transfer_lane,'required_target_receipts':manifest['output_contract']['required_target_receipts'],'state_effect':'none','authority_claim':'proposal_only'},key,actor,'model')
def verify_model_noninterference(c:dict[str,Any])->None:
    if c.get('signer_kind')!='model':raise AssertionError('not model candidate')
    if c.get('state_effect')!='none':raise AssertionError('model candidate mutates state')
    if c.get('authority_claim')!='proposal_only':raise AssertionError('model claims authority')
    if 'accepted_event_id' in c:raise AssertionError('model contains accepted event')
