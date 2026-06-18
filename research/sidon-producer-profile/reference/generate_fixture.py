#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from canonical import content_id, digest
from kernel import Presentation, compile_gamma, lineage_root
from packets import deterministic_private_key, public_key_b64, verify_signed_packet
from profile import (
    FRONTIER_ID,
    append_acceptance,
    make_acceptance,
    make_challenge,
    make_gate_receipt,
    make_observation,
    make_repair,
    make_result,
    make_support_function,
    make_task,
    make_view_decision,
    verify_observation_replay,
)
from sidon import append_verified_route, bound_cell, claim, register_bound_metadata

ROOT = Path(__file__).resolve().parents[1]

WITNESS_BASE = {
    "kind": "sidon",
    "n": 4,
    "claimed_size": 6,
    "points": [
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [1, 1, 1, 0],
        [1, 0, 0, 1],
    ],
}

WITNESS_A = {
    "kind": "sidon",
    "n": 4,
    "claimed_size": 7,
    "points": [
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [1, 1, 1, 0],
        [1, 0, 0, 1],
        [0, 1, 1, 1],
    ],
}

WITNESS_B = {
    "kind": "sidon",
    "n": 4,
    "claimed_size": 7,
    "points": [
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [1, 1, 1, 0],
        [0, 1, 0, 1],
        [1, 0, 1, 1],
    ],
}


def public_key_record(actor, key):
    return {"actor": actor, "public_key": public_key_b64(key)}


def snapshot(name: str, presentation: Presentation, disabled: set[str], observation: dict) -> dict:
    return {
        "name": name,
        "presentation": presentation.to_json(),
        "disabled_atoms": sorted(disabled),
        "observation_packet_id": observation["packet_id"],
    }


def best(observation: dict, n: int = 4) -> int:
    return next(row["best_lower_bound"] for row in observation["canonical_output"]["bounds"] if row["n"] == n)


def main() -> None:
    keys = {
        "task": deterministic_private_key("task-issuer"),
        "producer_a": deterministic_private_key("producer-alpha"),
        "producer_b": deterministic_private_key("producer-beta"),
        "gate": deterministic_private_key("gate"),
        "reviewer": deterministic_private_key("human-reviewer"),
        "observer": deterministic_private_key("observer"),
        "challenger": deterministic_private_key("challenger"),
    }

    presentation = Presentation(cell_ranks={}, clauses=[], accepted_events=[], cell_metadata={})
    disabled: set[str] = set()
    packets: list[dict] = []
    snapshots: list[dict] = []

    # Genesis is an already accepted corpus state. It is not a producer packet in
    # this profile; the fixture commits to the imported event and route explicitly.
    base_artifact = digest(WITNESS_BASE)
    base_claim = digest(claim(4, 6))
    base_event = content_id("vev_", {"fixture_genesis": "A309370-n4-k6", "artifact": base_artifact})
    register_bound_metadata(presentation, 4, 6)
    append_verified_route(
        presentation,
        n=4,
        k=6,
        artifact_digest=base_artifact,
        claim_digest=base_claim,
        verification_atoms=[
            "verifier:fixture-genesis-pairsum",
            "verifier:fixture-genesis-base3",
            "probe:fixture-genesis-negative-controls",
            "gate:fixture-genesis",
        ],
        accepted_event_id=base_event,
    )

    sf6_0 = make_support_function(
        presentation, disabled, cell_id=bound_cell(4, 6),
        key=keys["observer"], actor="hub:observer", step=0,
    )
    obs0 = make_observation(
        presentation, disabled, [sf6_0], caused_by_event_id=base_event,
        key=keys["observer"], actor="hub:observer", step=1,
    )
    packets.extend([sf6_0, obs0])
    verify_observation_replay(obs0, presentation, disabled)
    snapshots.append(snapshot("genesis_bound_6", presentation, disabled, obs0))

    # Two producers start from the same root. A lands first. B is deliberately
    # stale at acceptance and must be re-evaluated as an independent confirmation.
    task_a = make_task(obs0, n=4, objective_kind="strict_improvement", key=keys["task"], actor="hub:task-issuer", step=2)
    task_b = make_task(obs0, n=4, objective_kind="strict_improvement", key=keys["task"], actor="hub:task-issuer", step=3)
    result_a = make_result(task_a, WITNESS_A, key=keys["producer_a"], actor="producer:alpha", step=4)
    result_b = make_result(task_b, WITNESS_B, key=keys["producer_b"], actor="producer:beta", step=5)
    gate_a = make_gate_receipt(result_a, key=keys["gate"], actor="hub:gate", step=6)
    gate_b = make_gate_receipt(result_b, key=keys["gate"], actor="hub:gate", step=7)
    packets.extend([task_a, task_b, result_a, result_b, gate_a, gate_b])

    acc_a = make_acceptance(
        result_a, gate_a, obs0,
        key=keys["reviewer"], actor="reviewer:human", step=8,
        allow_confirmation=False,
    )
    packets.append(acc_a)
    _, cell7 = append_acceptance(presentation, result_a, gate_a, acc_a)
    sf7_a = make_support_function(presentation, disabled, cell_id=cell7, key=keys["observer"], actor="hub:observer", step=9)
    obs1 = make_observation(presentation, disabled, [sf7_a], caused_by_event_id=acc_a["accepted_event_id"], key=keys["observer"], actor="hub:observer", step=10)
    packets.extend([sf7_a, obs1])
    verify_observation_replay(obs1, presentation, disabled)
    snapshots.append(snapshot("route_a_bound_7", presentation, disabled, obs1))

    acc_b = make_acceptance(
        result_b, gate_b, obs1,
        key=keys["reviewer"], actor="reviewer:human", step=11,
        allow_confirmation=True,
    )
    packets.append(acc_b)
    append_acceptance(presentation, result_b, gate_b, acc_b)
    sf7_ab = make_support_function(presentation, disabled, cell_id=cell7, key=keys["observer"], actor="hub:observer", step=12)
    obs2 = make_observation(presentation, disabled, [sf7_ab], caused_by_event_id=acc_b["accepted_event_id"], key=keys["observer"], actor="hub:observer", step=13)
    packets.extend([sf7_ab, obs2])
    verify_observation_replay(obs2, presentation, disabled)
    snapshots.append(snapshot("two_routes_bound_7", presentation, disabled, obs2))

    # A ChallengePacket is non-authoritative. The human-signed ViewDecision is
    # the lawful restrict operation.
    attack_a = "verifier:" + gate_a["attachments"][1]["receipt_id"]
    attack_b = "verifier:" + gate_b["attachments"][1]["receipt_id"]
    challenge = make_challenge(
        obs2, sf7_ab, [attack_a, attack_b],
        key=keys["challenger"], actor="challenger:gamma", step=14,
    )
    view_decision, disabled = make_view_decision(
        obs2, challenge, disabled,
        key=keys["reviewer"], actor="reviewer:human", step=15,
    )
    packets.extend([challenge, view_decision])
    sf7_disabled = make_support_function(presentation, disabled, cell_id=cell7, key=keys["observer"], actor="hub:observer", step=16)
    obs3 = make_observation(presentation, disabled, [sf7_disabled], caused_by_event_id=view_decision["packet_id"], key=keys["observer"], actor="hub:observer", step=17)
    packets.extend([sf7_disabled, obs3])
    verify_observation_replay(obs3, presentation, disabled)
    snapshots.append(snapshot("accepted_restriction_falls_back_to_6", presentation, disabled, obs3))

    # Repair is an append of a newly verified route. The RepairPacket is a
    # proof-carrying explanation of restoration, not a hidden mutation.
    task_r = make_task(obs3, n=4, objective_kind="strict_improvement", key=keys["task"], actor="hub:task-issuer", step=18)
    result_r = make_result(task_r, WITNESS_A, key=keys["producer_a"], actor="producer:alpha", step=19)
    gate_r = make_gate_receipt(result_r, key=keys["gate"], actor="hub:gate", step=20)
    acc_r = make_acceptance(result_r, gate_r, obs3, key=keys["reviewer"], actor="reviewer:human", step=21, allow_confirmation=False)
    packets.extend([task_r, result_r, gate_r, acc_r])
    append_acceptance(presentation, result_r, gate_r, acc_r)
    sf7_repaired = make_support_function(presentation, disabled, cell_id=cell7, key=keys["observer"], actor="hub:observer", step=22)
    obs4 = make_observation(presentation, disabled, [sf7_repaired], caused_by_event_id=acc_r["accepted_event_id"], key=keys["observer"], actor="hub:observer", step=23)
    repair = make_repair(obs3, obs4, sf7_disabled, sf7_repaired, key=keys["observer"], actor="hub:observer", step=24)
    packets.extend([sf7_repaired, obs4, repair])
    verify_observation_replay(obs4, presentation, disabled)
    snapshots.append(snapshot("alternative_route_repairs_bound_7", presentation, disabled, obs4))

    for packet in packets:
        verify_signed_packet(packet)

    trace = [best(o) for o in (obs0, obs1, obs2, obs3, obs4)]
    assert trace == [6, 7, 7, 6, 7], trace
    assert acc_a["staleness_resolution"] == "fresh"
    assert acc_b["staleness_resolution"] == "stale_revalidated_as_confirmation"
    assert acc_r["staleness_resolution"] == "fresh"
    assert repair["restores_target"] is True

    fixture = {
        "schema": "vela.sidon-root-pinned-loop.fixture.v2",
        "frontier_id": FRONTIER_ID,
        "description": "Composed-lineage Sidon producer loop with concurrent root-pinned tasks, explicit stale resolution, human-authorized restriction, hitting-set kill, and append repair.",
        "genesis": {
            "accepted_event_id": base_event,
            "artifact_digest": base_artifact,
            "bound_cell_id": bound_cell(4, 6),
        },
        "public_keys": [
            public_key_record("hub:task-issuer", keys["task"]),
            public_key_record("producer:alpha", keys["producer_a"]),
            public_key_record("producer:beta", keys["producer_b"]),
            public_key_record("hub:gate", keys["gate"]),
            public_key_record("reviewer:human", keys["reviewer"]),
            public_key_record("hub:observer", keys["observer"]),
            public_key_record("challenger:gamma", keys["challenger"]),
        ],
        "witnesses": {"base": WITNESS_BASE, "route_a": WITNESS_A, "route_b": WITNESS_B},
        "packets": packets,
        "snapshots": snapshots,
        "expected": {
            "best_bound_trace": trace,
            "target_cell_id": cell7,
            "challenge_packet_id": challenge["packet_id"],
            "view_decision_packet_id": view_decision["packet_id"],
            "repair_packet_id": repair["packet_id"],
            "challenged_atoms": sorted([attack_a, attack_b]),
            "route_b_staleness_resolution": acc_b["staleness_resolution"],
            "historical_lineage_unchanged_by_restrict": True,
            "repair_restores": True,
        },
    }

    out = ROOT / "fixtures" / "sidon-root-pinned-loop.json"
    out.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")
    for name, witness in (("base", WITNESS_BASE), ("route-a", WITNESS_A), ("route-b", WITNESS_B)):
        (ROOT / "fixtures" / f"sidon-n4-{name}.json").write_text(json.dumps(witness, indent=2) + "\n")

    # Transitional feed for the retained-producer adapter.
    bounds = {
        "schema": "vela.frontier-bounds.v1",
        "frontier": "sidon-sets-fixture",
        "frontier_id": FRONTIER_ID,
        "generated_from": {"source_event_log_hash": obs0["presentation_root"]},
        "observation_packet_id": obs0["packet_id"],
        "bounds": [{"n": 4, "best_lower_bound": 6, "accepted": True, "finding_id": "vf_fixture_n4_k6"}],
    }
    (ROOT / "fixtures" / "bounds-small.json").write_text(json.dumps(bounds, indent=2, sort_keys=True) + "\n")

    state_export = {
        "schema": "vela.authoritative-state-export.v1",
        "frontier": {
            "id": FRONTIER_ID,
            "bounds": [{
                "n": 4,
                "best_lower_bound": 7,
                "_state": {
                    "best_lower_bound": {
                        "observation_packet_id": obs4["packet_id"],
                        "output_pointer": "/canonical_output/bounds/0/best_lower_bound",
                    }
                },
            }],
        },
        "observation_packets": [o for o in packets if o["packet_type"] == "observation"],
    }
    (ROOT / "fixtures" / "state-export-pass.json").write_text(json.dumps(state_export, indent=2, sort_keys=True) + "\n")
    fail_export = json.loads(json.dumps(state_export))
    del fail_export["frontier"]["bounds"][0]["_state"]
    (ROOT / "fixtures" / "state-export-fail.json").write_text(json.dumps(fail_export, indent=2, sort_keys=True) + "\n")

    print("PASS: generated sharpened Sidon root-pinned fixture")
    print("  trace:", " -> ".join(map(str, trace)))
    print("  packets:", len(packets))
    print("  historical lineage:", lineage_root(compile_gamma(presentation)))
    print("  fixture:", out)


if __name__ == "__main__":
    main()
