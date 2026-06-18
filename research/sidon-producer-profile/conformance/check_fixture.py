#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'reference'))
from canonical import digest
from kernel import Presentation, active_environments, active_view_root, compile_gamma, is_hitting_set, lineage_root, minimal_environments
from packets import verify_signed_packet
from profile import VIEW_POLICY_ID, state_commitment, verify_observation_replay


def fail(msg):
    raise AssertionError(msg)


def packet_index(packets):
    by_id={p['packet_id']:p for p in packets}
    if len(by_id)!=len(packets): fail('duplicate packet ids')
    return by_id


def main():
    path=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'fixtures'/'sidon-root-pinned-loop.json'
    fx=json.loads(path.read_text())
    packets=fx['packets']; by_id=packet_index(packets)
    for p in packets: verify_signed_packet(p)
    observations_by_id={p['packet_id']:p for p in packets if p['packet_type']=='observation'}

    tasks={p['task_id']:p for p in packets if p['packet_type']=='task'}
    for task in tasks.values():
        base_obs=observations_by_id.get(task['base_state']['observation_id'])
        if not base_obs or state_commitment(base_obs)!=task['base_state']: fail('task base_state does not name an exact observation')
    for result in [p for p in packets if p['packet_type']=='result']:
        task=tasks.get(result['task_id'])
        if not task: fail('result references missing task')
        if result['base_state']!=task['base_state']: fail('result changed root-pinned base state')
        if result['producer_actor']!=result['signer_actor']: fail('producer actor/signer mismatch')

    for gate in [p for p in packets if p['packet_type']=='gate_receipt']:
        result=by_id.get(gate['result_packet_id'])
        if not result or result['packet_type']!='result': fail('gate references missing result')
        if gate['base_state']!=result['base_state']: fail('gate changed result base state')
        if gate['claim_digest']!=result['claim_digest'] or gate['artifact_digest']!=result['artifact_digest']:
            fail('gate not bound to exact claim/artifact')
        if gate['gate_status']!='verified': fail('fixture gate is not verified')
        methods={a['method_family'] for a in gate['attachments']}
        executables={a['executable_digest'] for a in gate['attachments']}
        if len(methods)<2 or len(executables)<2: fail('gate lacks algorithmically diverse verifier paths')
        if 'not a claim of statistical or organizational independence' not in gate['verification_diversity']['interpretation']:
            fail('gate overstates verifier independence')
        if not all(a['passed'] for a in gate['attachments']): fail('positive artifact failed a verifier')
        probe_ids={p['mutation_id'] for p in gate['adversarial_probes']}
        if 'single-bit-pairsum-collision-v1' not in probe_ids: fail('semantic adversarial probe missing')
        for probe in gate['adversarial_probes']:
            if not probe['passed'] or any(v['accepted_mutation'] for v in probe['verifier_results']):
                fail('negative control was accepted')

    acceptances=[p for p in packets if p['packet_type']=='acceptance']
    for acc in acceptances:
        result=by_id.get(acc['result_packet_id']); gate=by_id.get(acc['gate_receipt_id'])
        if not result or not gate: fail('acceptance chain missing result/gate')
        if gate['result_packet_id']!=result['packet_id'] or gate['gate_status']!='verified': fail('acceptance bypassed gate')
        if acc['reviewer_actor']!=acc['signer_actor']: fail('acceptance not signed by named reviewer')
        decision_obs=observations_by_id.get(acc['decision_state']['observation_id'])
        if not decision_obs or state_commitment(decision_obs)!=acc['decision_state']:
            fail('acceptance decision_state does not name an exact observation')
        if acc['result_base_state']!=result['base_state']:
            fail('acceptance rewrote result base state')
        fresh=result['base_state']['observation_id']==acc['decision_state']['observation_id']
        if fresh and acc['staleness_resolution']!='fresh': fail('fresh result mislabeled stale')
        if (not fresh) and not acc['staleness_resolution'].startswith('stale_revalidated_'):
            fail('stale result silently rebased')
    stale=[a for a in acceptances if a['staleness_resolution']=='stale_revalidated_as_confirmation']
    if len(stale)!=1: fail('fixture must exercise exactly one explicit stale confirmation')

    observations=[]; snapshots={s['name']:s for s in fx['snapshots']}
    for snap in fx['snapshots']:
        presentation=Presentation.from_json(snap['presentation'])
        disabled=set(snap['disabled_atoms'])
        obs=by_id[snap['observation_packet_id']]
        verify_observation_replay(obs,presentation,disabled)
        observations.append(obs)
        gamma=compile_gamma(presentation)
        if obs['lineage_root']!=lineage_root(gamma): fail('lineage root mismatch')

    trace=[next(r['best_lower_bound'] for r in o['canonical_output']['bounds'] if r['n']==4) for o in observations]
    if trace!=fx['expected']['best_bound_trace']: fail(f'bound trace mismatch: {trace}')

    before=by_id[snapshots['two_routes_bound_7']['observation_packet_id']]
    after=by_id[snapshots['accepted_restriction_falls_back_to_6']['observation_packet_id']]
    for field in ('presentation_root','circuit_root','lineage_root'):
        if before[field]!=after[field]: fail(f'restrict mutated historical {field}')
    if before['active_view_root']==after['active_view_root']: fail('accepted restriction did not change view root')

    challenge=by_id[fx['expected']['challenge_packet_id']]
    decision=by_id[fx['expected']['view_decision_packet_id']]
    support=by_id[challenge['support_function_packet_id']]
    if challenge['state_effect']!='none_until_view_decision': fail('challenge packet illegally mutates state')
    if not is_hitting_set(support['active_minimal_environments'],challenge['proposed_disabled_atoms']):
        fail('challenge atoms are not a hitting set')
    if decision['challenge_packet_id']!=challenge['packet_id'] or decision['decision']!='accepted':
        fail('restriction lacks human-signed view decision')
    expected_disabled=set(decision['prior_disabled_atoms']).union(challenge['proposed_disabled_atoms'])
    if set(decision['resulting_disabled_atoms'])!=expected_disabled:
        fail('view decision added or omitted atoms outside the accepted challenge')
    if decision['resulting_active_view_root']!=active_view_root(expected_disabled, VIEW_POLICY_ID):
        fail('view decision does not commit to its exact resulting atom set')
    if decision['resulting_active_view_root']!=after['active_view_root']: fail('view decision root mismatch')

    # Recompute the challenged and repaired support functions from their snapshots.
    target=fx['expected']['target_cell_id']
    challenged_p=Presentation.from_json(snapshots['accepted_restriction_falls_back_to_6']['presentation'])
    challenged_disabled=set(snapshots['accepted_restriction_falls_back_to_6']['disabled_atoms'])
    challenged_gamma=compile_gamma(challenged_p)
    if active_environments(challenged_gamma[target],challenged_disabled): fail('hitting-set restriction failed to kill target')
    repaired_p=Presentation.from_json(snapshots['alternative_route_repairs_bound_7']['presentation'])
    repaired_disabled=set(snapshots['alternative_route_repairs_bound_7']['disabled_atoms'])
    repaired_gamma=compile_gamma(repaired_p)
    if not active_environments(repaired_gamma[target],repaired_disabled): fail('append repair failed to restore target')

    repair=by_id[fx['expected']['repair_packet_id']]
    if repair['state_effect']!='none; append acceptance already changed historical lineage': fail('repair packet hides a mutation')
    if not repair['restores_target']: fail('repair receipt does not report restoration')

    # The lineage is actually cross-cell composed, not a flat route list.
    final_p=Presentation.from_json(snapshots['alternative_route_repairs_bound_7']['presentation'])
    bound_clauses=[c for c in final_p.clauses if c.head==target]
    if not bound_clauses or any(len(c.body)!=1 for c in bound_clauses):
        fail('bound cell is not derived through a witness-cell dependency')
    if any(final_p.cell_ranks[c.body[0]]!=0 or c.head_rank!=1 for c in bound_clauses):
        fail('witness-to-bound dependency violates ranked profile')
    final_gamma=compile_gamma(final_p)
    final_envs=minimal_environments(final_gamma[target])
    for env in final_envs:
        if not any(atom.startswith('artifact:sha256:') for atom in env):
            fail('composed bound environment lost witness artifact provenance')
        if 'rule:vela.sidon.lower-bound.v1' not in env:
            fail('composed bound environment lost rule atom')

    # Presentation extensions are conservative: earlier accepted events and clauses survive.
    snap_order=['genesis_bound_6','route_a_bound_7','two_routes_bound_7','accepted_restriction_falls_back_to_6','alternative_route_repairs_bound_7']
    previous_events=set(); previous_clauses=set()
    for name in snap_order:
        p=Presentation.from_json(snapshots[name]['presentation'])
        events=set(p.accepted_events); clauses={c.clause_id for c in p.clauses}
        if not previous_events.issubset(events) or not previous_clauses.issubset(clauses): fail('append deleted historical presentation content')
        previous_events,previous_clauses=events,clauses

    print('PASS: sharpened Vela Sidon breakthrough fixture')
    print(f'  packets={len(packets)} observations={len(observations)} trace={trace}')
    print('  composed lineage, root pinning, explicit staleness, human restrict, kill, repair, and replay verified')

if __name__=='__main__': main()
