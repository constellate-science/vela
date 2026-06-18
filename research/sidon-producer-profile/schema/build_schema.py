#!/usr/bin/env python3
import json
from pathlib import Path

ID64 = {"type":"string","pattern":"^v[a-z0-9]+_[0-9a-f]{64}$"}
SHA = {"type":"string","pattern":"^sha256:[0-9a-f]{64}$"}
ROOT = {"type":"string","pattern":"^v(?:pr|cr|lr|av)_[0-9a-f]{64}$"}
STR = {"type":"string","minLength":1}
OBJ = {"type":"object"}
ARR_STR = {"type":"array","items":STR,"uniqueItems":True}

def closed(required, properties):
    return {"type":"object","required":required,"properties":properties,"additionalProperties":False}

signature=closed(["algorithm","value"],{
    "algorithm":{"const":"ed25519"},
    "value":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"},
})
state=closed([
    "observation_id","presentation_root","circuit_root","lineage_root","active_view_root",
    "evaluator_id","evaluator_inputs_digest","canonical_output_digest"
],{
    "observation_id":ID64,"presentation_root":ROOT,"circuit_root":ROOT,"lineage_root":ROOT,"active_view_root":ROOT,
    "evaluator_id":STR,"evaluator_inputs_digest":SHA,"canonical_output_digest":SHA,
})
base={
    "type":"object",
    "required":["schema_version","packet_type","packet_id","signer_actor","signer_public_key","created_at","signature"],
    "properties":{
        "schema_version":{"const":"vela.sidon-producer-profile.v1"},
        "packet_type":STR,
        "packet_id":ID64,
        "signer_actor":STR,
        "signer_public_key":{"type":"string","pattern":"^[A-Za-z0-9+/]{43}=$"},
        "created_at":{"type":"string","format":"date-time"},
        "signature":{"$ref":"#/$defs/signature"},
    }
}

def packet(ptype, required, props):
    return {
        "allOf":[
            {"$ref":"#/$defs/base"},
            {"type":"object","required":["packet_type",*required],"properties":{"packet_type":{"const":ptype},**props}},
        ],
        "unevaluatedProperties":False,
    }

schema={
 "$schema":"https://json-schema.org/draft/2020-12/schema",
 "$id":"https://constellate.science/schema/vela-sidon-producer-profile-v1.json",
 "title":"Vela Sidon Producer Profile v1 packet",
 "oneOf":[],
 "$defs":{"signature":signature,"stateCommitment":state,"base":base}
}

schema["$defs"]["observation"] = packet("observation",[
 "frontier_id","presentation_root","circuit_root","lineage_root","active_view_root","evaluator_id","evaluator_inputs","canonical_output","replay_receipt"
],{
 "frontier_id":STR,"presentation_root":ROOT,"circuit_root":ROOT,"lineage_root":ROOT,"active_view_root":ROOT,
 "evaluator_id":STR,"evaluator_inputs":OBJ,"canonical_output":OBJ,
 "replay_receipt":closed(["receipt_id","input_roots_digest","evaluator_digest","output_digest","caused_by_event_id","circuit_semantics"],{
   "receipt_id":ID64,"input_roots_digest":SHA,"evaluator_digest":ID64,"output_digest":SHA,
   "caused_by_event_id":{"type":["string","null"]},"circuit_semantics":STR,
 }),
})

schema["$defs"]["task"] = packet("task",[
 "frontier_id","base_state","task_id","cell_target","objective","verifier_contract","required_result_schema","lease"
],{
 "frontier_id":STR,"base_state":{"$ref":"#/$defs/stateCommitment"},"task_id":ID64,
 "cell_target":closed(["sequence","n"],{"sequence":{"const":"oeis:A309370"},"n":{"type":"integer","minimum":1}}),
 "objective":closed(["kind","current","required_minimum"],{
   "kind":{"enum":["strict_improvement","independent_confirmation"]},"current":{"type":"integer","minimum":0},"required_minimum":{"type":"integer","minimum":0},
 }),
 "verifier_contract":{"const":"vela.sidon.gate.v1"},"required_result_schema":{"const":"vela.sidon-witness.v1"},
 "lease":closed(["state_effect","required"],{"state_effect":{"const":"none"},"required":{"type":"boolean"}}),
})

schema["$defs"]["result"] = packet("result",[
 "frontier_id","task_id","base_state","producer_actor","claim","claim_digest","artifact","artifact_digest","certificate_kind"
],{
 "frontier_id":STR,"task_id":ID64,"base_state":{"$ref":"#/$defs/stateCommitment"},"producer_actor":STR,
 "claim":OBJ,"claim_digest":SHA,"artifact":OBJ,"artifact_digest":SHA,"certificate_kind":{"const":"sidon-witness-v1"},
})

attachment=closed(["receipt_id","result_packet_id","method_family","executable_id","executable_digest","claim_digest","artifact_digest","passed","detail"],{
 "receipt_id":ID64,"result_packet_id":ID64,"method_family":STR,"executable_id":STR,"executable_digest":SHA,
 "claim_digest":SHA,"artifact_digest":SHA,"passed":{"type":"boolean"},"detail":STR,
})
probe=closed(["probe_id","mutation_id","original_artifact_digest","mutated_artifact_digest","verifier_results","passed"],{
 "probe_id":ID64,"mutation_id":STR,"original_artifact_digest":SHA,"mutated_artifact_digest":SHA,
 "verifier_results":{"type":"array","minItems":2,"items":closed(["method_family","executable_digest","accepted_mutation","detail"],{
   "method_family":STR,"executable_digest":SHA,"accepted_mutation":{"type":"boolean"},"detail":STR,
 })},"passed":{"type":"boolean"},
})
schema["$defs"]["gate"] = packet("gate_receipt",[
 "frontier_id","result_packet_id","base_state","claim_digest","artifact_digest","attachments","verification_diversity","claim_match_check","adversarial_probes","gate_status"
],{
 "frontier_id":STR,"result_packet_id":ID64,"base_state":{"$ref":"#/$defs/stateCommitment"},"claim_digest":SHA,"artifact_digest":SHA,
 "attachments":{"type":"array","minItems":2,"items":attachment},
 "verification_diversity":closed(["distinct_method_families","distinct_executable_digests","interpretation"],{
   "distinct_method_families":{"type":"boolean"},"distinct_executable_digests":{"type":"boolean"},"interpretation":STR,
 }),
 "claim_match_check":closed(["claim_digest_matches","artifact_digest_matches"],{"claim_digest_matches":{"type":"boolean"},"artifact_digest_matches":{"type":"boolean"}}),
 "adversarial_probes":{"type":"array","minItems":3,"items":probe},
 "gate_status":{"enum":["verified","needs_verification","refuted"]},
})

schema["$defs"]["acceptance"] = packet("acceptance",[
 "frontier_id","result_packet_id","gate_receipt_id","reviewer_actor","result_base_state","decision_state","staleness_resolution","accepted_event_id","decision","append_contract","reason"
],{
 "frontier_id":STR,"result_packet_id":ID64,"gate_receipt_id":ID64,"reviewer_actor":STR,
 "result_base_state":{"$ref":"#/$defs/stateCommitment"},"decision_state":{"$ref":"#/$defs/stateCommitment"},
 "staleness_resolution":{"enum":["fresh","stale_revalidated_as_improvement","stale_revalidated_as_confirmation"]},
 "accepted_event_id":ID64,"decision":{"const":"accepted"},"append_contract":OBJ,"reason":STR,
})

envs={"type":"array","items":{"type":"array","items":STR,"uniqueItems":True},"uniqueItems":True}
schema["$defs"]["support"] = packet("support_function",[
 "frontier_id","cell_id","presentation_root","circuit_root","historical_lineage_root","active_view_root","historical_minimal_environments","active_minimal_environments","support_function_digest"
],{
 "frontier_id":STR,"cell_id":ID64,"presentation_root":ROOT,"circuit_root":ROOT,"historical_lineage_root":ROOT,"active_view_root":ROOT,
 "historical_minimal_environments":envs,"active_minimal_environments":envs,"support_function_digest":SHA,
})

schema["$defs"]["challenge"] = packet("challenge",[
 "frontier_id","base_state","target_cell_id","support_function_packet_id","proposed_disabled_atoms","hitting_set_receipt","proposed_kill","state_effect","reason","challenger_actor"
],{
 "frontier_id":STR,"base_state":{"$ref":"#/$defs/stateCommitment"},"target_cell_id":ID64,"support_function_packet_id":ID64,
 "proposed_disabled_atoms":ARR_STR,"hitting_set_receipt":closed(["active_environment_count","hits_every_active_environment"],{
   "active_environment_count":{"type":"integer","minimum":1},"hits_every_active_environment":{"type":"boolean"},
 }),"proposed_kill":{"type":"boolean"},"state_effect":{"const":"none_until_view_decision"},"reason":STR,"challenger_actor":STR,
})

schema["$defs"]["view"] = packet("view_decision",[
 "frontier_id","base_state","challenge_packet_id","reviewer_actor","decision","view_policy_id","prior_disabled_atoms","resulting_disabled_atoms","resulting_active_view_root","reason"
],{
 "frontier_id":STR,"base_state":{"$ref":"#/$defs/stateCommitment"},"challenge_packet_id":ID64,"reviewer_actor":STR,"decision":{"const":"accepted"},
 "view_policy_id":{"const":"vela.view.public.v1"},"prior_disabled_atoms":ARR_STR,"resulting_disabled_atoms":ARR_STR,"resulting_active_view_root":ROOT,"reason":STR,
})

schema["$defs"]["repair"] = packet("repair",[
 "frontier_id","prior_observation_id","repaired_observation_id","target_cell_id","prior_support_function_packet_id","repaired_support_function_packet_id","repair_kind","new_active_environments","restores_target","state_effect"
],{
 "frontier_id":STR,"prior_observation_id":ID64,"repaired_observation_id":ID64,"target_cell_id":ID64,
 "prior_support_function_packet_id":ID64,"repaired_support_function_packet_id":ID64,
 "repair_kind":{"const":"accepted_alternative_route"},"new_active_environments":envs,"restores_target":{"type":"boolean"},
 "state_effect":{"const":"none; append acceptance already changed historical lineage"},
})

for name in ["observation","task","result","gate","acceptance","support","challenge","view","repair"]:
    schema["oneOf"].append({"$ref":f"#/$defs/{name}"})

out=Path(__file__).with_name('sidon-producer-profile-v1.schema.json')
out.write_text(json.dumps(schema,indent=2,sort_keys=True)+'\n')
print(out)
