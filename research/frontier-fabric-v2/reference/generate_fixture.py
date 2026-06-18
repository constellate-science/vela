#!/usr/bin/env python3
from __future__ import annotations
import copy,json,math
from pathlib import Path
from canonical import content_id,digest
from kernel import Presentation,Clause,cell_id,compile_gamma,active_environments,is_hitting_set
from packets import deterministic_private_key,signed_packet,verify_signed_packet
from adapters import generate_obligations,validate_adapter
from frontier import (build_frontier_map, frontier_transition, gap_identifiability_witness, route_summary, structural_delta, verify_extension_locality, verify_positive_gap_monotonicity)
from models import make_candidate,verify_model_noninterference
from transfer import make_transfer_packet,append_transfer_clause
from observations import make_observation,verify_observation,no_hidden_state_check,VIEW_POLICY_ID
from verifiers import verify_translation_preserves_sidon,verify_heat_candidate,heat_solution

ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/'fixtures';FIX.mkdir(exist_ok=True)
AD=ROOT/'adapters'

def load(name:str):return json.loads((AD/name).read_text())
def add_cell(p:Presentation,cid:str,rank:int,profile:str,kind:str,claim:dict,context:dict,evidence_class:str|None,evidence_label:str):
    p.cell_ranks[cid]=rank;p.cell_metadata[cid]={'profile_id':profile,'cell_kind':kind,'claim':claim,'context':context,'evidence_class':evidence_class,'evidence_label':evidence_label}
def append_clause(p:Presentation,clause:Clause,event:str):
    if event not in p.accepted_events:p.accepted_events.append(event)
    p.clauses.append(clause);p.validate()
def packet_acceptance(target_packet_id:str,event:str,key,actor:str):
    return signed_packet('acceptance',{'target_packet_id':target_packet_id,'decision':'accepted','accepted_event_id':event,'authority_set_id':'fixture:human'},key,actor,'human')

def main():
    human=deterministic_private_key('human');hub=deterministic_private_key('hub');model=deterministic_private_key('model');verifier=deterministic_private_key('verifier')
    exact=load('exact_combinatorics.adapter.json');sim=load('numerical_simulation.adapter.json');m_eval=load('model_evaluation.adapter.json')
    for a in [exact,sim,m_eval]:validate_adapter(a)
    p=Presentation.empty();p.admitted_profiles=['exact-combinatorics','numerical-simulation']
    # --- exact transfer lane: Sidon translation ---
    s_claim={'kind':'sidon_witness','points':[[0],[1],[4]]};s_ctx={'problem':'sidon_Z','parameter':'source'}
    t_claim={'kind':'sidon_witness','points':[[10],[11],[14]]};t_ctx={'problem':'sidon_Z','parameter':'translated'}
    s_cell=cell_id(profile_id='exact-combinatorics',claim=s_claim,context=s_ctx,polarity='support',cell_kind='verified_witness')
    t_cell=cell_id(profile_id='exact-combinatorics',claim=t_claim,context=t_ctx,polarity='support',cell_kind='verified_witness')
    add_cell(p,s_cell,0,'exact-combinatorics','verified_witness',s_claim,s_ctx,'exact','exact_verified')
    add_cell(p,t_cell,1,'exact-combinatorics','verified_witness',t_claim,t_ctx,'exact','exact_verified')
    e_s=content_id('vev_',{'kind':'accept','cell':s_cell});append_clause(p,Clause.make(head=s_cell,head_rank=0,body=[],atoms=['artifact:sidon-014','verifier:pair-sum','acceptance:'+e_s],accepted_event_id=e_s,profile_id='exact-combinatorics'),e_s)
    cert=verify_translation_preserves_sidon([[0],[1],[4]],[10])
    tx=make_transfer_packet(lane='certified',source_cells=[s_cell],target_cell=t_cell,source_contexts=[s_ctx],target_context=t_ctx,assumptions=['translation-is-componentwise-in-Z'],certificate=cert,required_target_receipts=[],preserved_coordinates=['exact_verification'],lost_coordinates=[],key=verifier,actor='verifier:translation',actor_kind='verifier')
    e_t=content_id('vev_',{'kind':'accept-transfer','packet':tx['packet_id']});acc_t=packet_acceptance(tx['packet_id'],e_t,human,'human:maintainer')
    append_clause(p,append_transfer_clause(p,transfer=tx,head_rank=1,accepted_event_id=e_t,profile_id='exact-combinatorics',target_receipts=[],human_acceptance=True),e_t)
    # --- replay domain before model transfer ---
    c01={'kind':'heat_solution','equation':'u_t=alpha*u_xx','alpha':'0.1'};c02={'kind':'heat_solution','equation':'u_t=alpha*u_xx','alpha':'0.2'};c03={'kind':'heat_solution','equation':'u_t=alpha*u_xx','alpha':'0.3'};ccov={'kind':'parameter_coverage','alphas':['0.1','0.2']}
    ctx01={'equations':'heat-1d','parameters':{'alpha':'0.1'},'initial_conditions':'sin(pi*x)','mesh':'analytic-fixture','solver':'reference','tolerance':'1e-9'}
    ctx02={**ctx01,'parameters':{'alpha':'0.2'}};ctx03={**ctx01,'parameters':{'alpha':'0.3'}};ctxcov={'equations':'heat-1d','parameters':{'alpha_set':['0.1','0.2']},'initial_conditions':'sin(pi*x)','mesh':'analytic-fixture','solver':'coverage','tolerance':'1e-9'}
    h01=cell_id(profile_id='numerical-simulation',claim=c01,context=ctx01,polarity='support',cell_kind='replay_solution')
    h02=cell_id(profile_id='numerical-simulation',claim=c02,context=ctx02,polarity='support',cell_kind='replay_solution')
    h03=cell_id(profile_id='numerical-simulation',claim=c03,context=ctx03,polarity='support',cell_kind='replay_solution')
    hcov=cell_id(profile_id='numerical-simulation',claim=ccov,context=ctxcov,polarity='support',cell_kind='coverage')
    add_cell(p,h01,0,'numerical-simulation','replay_solution',c01,ctx01,'replay','replay_confirmed');add_cell(p,h02,1,'numerical-simulation','replay_solution',c02,ctx02,'replay','replay_confirmed');add_cell(p,h03,1,'numerical-simulation','replay_solution',c03,ctx03,'replay','replay_confirmed');add_cell(p,hcov,2,'numerical-simulation','coverage',ccov,ctxcov,'replay','replay_confirmed')
    e01=content_id('vev_',{'kind':'accept','cell':h01});append_clause(p,Clause.make(head=h01,head_rank=0,body=[],atoms=['artifact:heat-a01','receipt:semantic-a01','acceptance:'+e01],accepted_event_id=e01,profile_id='numerical-simulation'),e01)
    ecov=content_id('vev_',{'kind':'coverage-rule','cell':hcov});append_clause(p,Clause.make(head=hcov,head_rank=2,body=[h01,h02],atoms=['rule:coverage-both-alphas','acceptance:'+ecov],accepted_event_id=ecov,profile_id='numerical-simulation'),ecov)
    p_before=copy.deepcopy(p)
    # Declared dark matter: adapter says alpha=.2 is in scope and currently uncovered.
    obligations=generate_obligations(sim,{'heat_alpha_02':h02,'heat_alpha_03':h03},ctx02);fm_before=build_frontier_map(p,obligations)
    gap_witness=gap_identifiability_witness(p,[],obligations)
    obs_before=make_observation(p,[],[h01,h02,h03,hcov],hub,'hub:fixture');verify_observation(obs_before,p,[])
    # Neural operator candidate is proposal-only.
    model_manifest={'model_id':'model:heat-neural-operator-v1','model_class':'neural_operator','weights_root':'sha256:fixture-weights','code_root':'sha256:fixture-code','training_data_roots':['sha256:heat-alpha-01'],'domain_of_validity':{'equation':'heat-1d','alpha_interval':['0.05','0.25'],'initial_condition':'sin(pi*x)'},'calibration_receipt_ids':['calibration:fixture'],'known_failure_modes':['out-of-distribution boundary conditions','long-time drift'],'output_contract':{'required_target_receipts':['semantic_replay']},'producer_kind':'model'}
    samples=[]
    for x in ['0.25','0.5','0.75']:
        for t in ['0.1','0.4']:
            u=heat_solution(0.2,float(x),float(t));samples.append({'x':x,'t':t,'u':format(u,'.15g')})
    candidate=make_candidate(manifest=model_manifest,base_observation_root=obs_before['packet_id'],source_cells=[h01],target_cell=h02,target_context=ctx02,proposed_artifact={'kind':'operator_prediction','samples':samples},assumptions=['same-equation-family','alpha-within-declared-domain'],transfer_lane='target_checked',key=model,actor='model:heat-operator');verify_model_noninterference(candidate)
    if p.presentation_root()!=p_before.presentation_root():raise AssertionError('candidate mutated state')
    target_result=verify_heat_candidate(0.2,samples,1e-9)
    target_receipt=signed_packet('target_receipt',{'candidate_packet_id':candidate['packet_id'],'receipt_kind':'semantic_replay','passed':target_result['passed'],'result':target_result,'claim_digest':digest(c02),'artifact_digest':candidate['proposed_artifact_digest'],'verifier_id':'heat-analytic-replay-v1'},verifier,'verifier:heat','verifier')
    tx2=make_transfer_packet(lane='target_checked',source_cells=[h01],target_cell=h02,source_contexts=[ctx01],target_context=ctx02,assumptions=['operator-generalizes-within-declared-alpha-range'],certificate=None,required_target_receipts=['semantic_replay'],preserved_coordinates=['replay_semantics'],lost_coordinates=['exact_source_equivalence'],key=model,actor='model:heat-operator',actor_kind='model')
    e02=content_id('vev_',{'kind':'accept-target-checked','candidate':candidate['packet_id'],'receipt':target_receipt['packet_id']});acc02=packet_acceptance(candidate['packet_id'],e02,human,'human:maintainer')
    append_clause(p,append_transfer_clause(p,transfer=tx2,head_rank=1,accepted_event_id=e02,profile_id='numerical-simulation',target_receipts=[target_receipt],human_acceptance=True),e02)
    verify_extension_locality(p_before,p,[h02])
    delta=structural_delta(p_before,p);verify_positive_gap_monotonicity(p_before,p,obligations);fm_after=build_frontier_map(p,obligations);fm_shift=frontier_transition(fm_before,fm_after);obs_after=make_observation(p,[],[h01,h02,h03,hcov],hub,'hub:fixture');verify_observation(obs_after,p,[])
    # Restrict: challenge the target receipt atom. Then append a repair route.
    disabled={f'target-receipt:{target_receipt["packet_id"]}'};fm_restricted=build_frontier_map(p,obligations,disabled);obs_restricted=make_observation(p,disabled,[h01,h02,h03,hcov],hub,'hub:fixture');verify_observation(obs_restricted,p,disabled)
    envs=active_environments(compile_gamma(p)[h02],[])
    if not is_hitting_set(envs,disabled):raise AssertionError('challenge does not hit all h02 routes')
    challenge=signed_packet('challenge',{'base_observation_id':obs_after['packet_id'],'target_cell_id':h02,'proposed_disabled_atoms':sorted(disabled),'hits_every_active_environment':True,'state_effect':'none_until_view_decision'},human,'human:challenger','human')
    view=signed_packet('view_decision',{'challenge_packet_id':challenge['packet_id'],'decision':'accepted','view_policy_id':VIEW_POLICY_ID,'resulting_disabled_atoms':sorted(disabled),'state_effect':'restrict'},human,'human:maintainer','human')
    # Alternative verifier receipt and accepted route repair the active state without deleting history.
    target_receipt2=signed_packet('target_receipt',{'candidate_packet_id':candidate['packet_id'],'receipt_kind':'semantic_replay','passed':True,'result':{**target_result,'method':'independent-grid-replay'},'claim_digest':digest(c02),'artifact_digest':candidate['proposed_artifact_digest'],'verifier_id':'heat-independent-replay-v2'},verifier,'verifier:heat2','verifier')
    tx3=make_transfer_packet(lane='target_checked',source_cells=[h01],target_cell=h02,source_contexts=[ctx01],target_context=ctx02,assumptions=['operator-generalizes-within-declared-alpha-range'],certificate=None,required_target_receipts=['semantic_replay'],preserved_coordinates=['replay_semantics'],lost_coordinates=['exact_source_equivalence'],key=model,actor='model:heat-operator',actor_kind='model')
    e03=content_id('vev_',{'kind':'repair-append','receipt':target_receipt2['packet_id']});acc03=packet_acceptance(candidate['packet_id'],e03,human,'human:maintainer')
    append_clause(p,append_transfer_clause(p,transfer=tx3,head_rank=1,accepted_event_id=e03,profile_id='numerical-simulation',target_receipts=[target_receipt2],human_acceptance=True),e03)
    fm_repaired=build_frontier_map(p,obligations,disabled);obs_repaired=make_observation(p,disabled,[h01,h02,h03,hcov],hub,'hub:fixture');verify_observation(obs_repaired,p,disabled)
    repair=signed_packet('repair',{'target_cell_id':h02,'prior_observation_id':obs_restricted['packet_id'],'repaired_observation_id':obs_repaired['packet_id'],'new_route_receipt_id':target_receipt2['packet_id'],'restores_target':True,'state_effect':'none; append already changed historical state'},human,'human:maintainer','human')
    # Natural-law model candidate remains exploratory and cannot close an obligation.
    nlm_manifest={'model_id':'model:natural-law-heat-v1','model_class':'natural_law_model','weights_root':'sha256:nlm-weights','code_root':'sha256:nlm-code','training_data_roots':['sha256:heat-trajectories'],'domain_of_validity':{'system':'heat-like-diffusion','regime':'fixture-only'},'calibration_receipt_ids':[],'known_failure_modes':['spurious symbolic law','non-identifiability','distribution shift'],'output_contract':{'required_target_receipts':['semantic_replay','heldout_prediction']},'producer_kind':'model'}
    nlm=make_candidate(manifest=nlm_manifest,base_observation_root=obs_after['packet_id'],source_cells=[h01,h02],target_cell=content_id('vcell_',{'claim':'candidate-law'}),target_context={'system':'heat-like-diffusion'},proposed_artifact={'kind':'candidate_law','expression':'u_t = alpha * u_xx'},assumptions=['observed-regime-is-representative'],transfer_lane='exploratory',key=model,actor='model:natural-law');verify_model_noninterference(nlm)
    # No-hidden-state export.
    export={'authoritative_values':[{'name':'frontier-state','value':obs_repaired['canonical_output'],'canonical_value_digest':digest(obs_repaired['canonical_output']),'observation_packet_id':obs_repaired['packet_id']}]};no_hidden_state_check(export,[obs_before,obs_after,obs_restricted,obs_repaired])
    packets=[tx,acc_t,obs_before,candidate,target_receipt,tx2,acc02,obs_after,obs_restricted,challenge,view,target_receipt2,tx3,acc03,obs_repaired,repair,nlm]
    for packet in packets:verify_signed_packet(packet)
    trace=[]
    for label,obs in [('before',obs_before),('after_target_check',obs_after),('restricted',obs_restricted),('repaired',obs_repaired)]:
        trace.append({'stage':label,'support':{row['cell_id']:row['supported'] for row in obs['canonical_output']['cells']}})
    fixture={'schema_version':'vela.frontier-fabric.fixture.v2','adapters':[exact['adapter_id'],sim['adapter_id'],m_eval['adapter_id']],'cells':{'sidon_source':s_cell,'sidon_translated':t_cell,'heat_alpha_01':h01,'heat_alpha_02':h02,'heat_alpha_03':h03,'heat_coverage':hcov},'presentation_before':p_before.to_json(),'presentation_final':p.to_json(),'frontier_before':fm_before,'frontier_after':fm_after,'frontier_restricted':fm_restricted,'frontier_repaired':fm_repaired,'frontier_transition':fm_shift,'gap_identifiability':gap_witness,'certified_transfer':tx,'model_candidate':candidate,'target_receipt':target_receipt,'structural_delta':delta,'challenge':challenge,'view_decision':view,'repair':repair,'natural_law_candidate':nlm,'observations':{'before':obs_before,'after':obs_after,'restricted':obs_restricted,'repaired':obs_repaired},'trace':trace,'state_export':export,'route_summaries':{'heat_alpha_02':route_summary(p,h02,disabled),'heat_alpha_03':route_summary(p,h03,disabled),'coverage':route_summary(p,hcov,disabled)}}
    (FIX/'frontier-extension.json').write_text(json.dumps(fixture,indent=2,sort_keys=True)+'\n')
    (FIX/'state-export-pass.json').write_text(json.dumps(export,indent=2,sort_keys=True)+'\n')
    fail={'authoritative_values':[{'name':'hidden-frontier-score','value':{'score':'0.91'},'canonical_value_digest':digest({'score':'0.91'}),'observation_packet_id':'missing'}]}
    (FIX/'state-export-fail.json').write_text(json.dumps(fail,indent=2,sort_keys=True)+'\n')
    print('PASS fixture generated')
    print('trace',[(x['stage'],list(x['support'].values())) for x in trace])

if __name__=='__main__':main()
