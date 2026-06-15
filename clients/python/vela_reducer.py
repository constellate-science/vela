#!/usr/bin/env python3
# Vela reducer — second implementation, stdlib-only.
#
# What this proves: the per-kind reducer mutation rules are protocol,
# not Rust artifact. Two implementations of the reducer (this Python
# one and the Rust one in `crates/vela-protocol/src/reducer.rs`) must
# produce byte-equivalent post-replay finding state from the same
# canonical event log on the same genesis findings. If they don't,
# one of them is wrong.
#
# Usage:
#   python3 vela_reducer.py /path/to/cascade-fixture-00.json
#   python3 vela_reducer.py /path/to/fixtures/dir/   # walks all *.json
#   python3 vela_reducer.py --json /path/to/fixture.json
#
# Exit codes:
#   0  — every fixture's expected_states matched after Python replay
#   1  — at least one fixture mismatched (cross-implementation drift)
#   2  — fixture directory empty, malformed, or unreadable
#
# This implementation deliberately uses only Python stdlib so a
# reviewer can read it end to end and reason about whether it's doing
# the same thing the Rust reducer does. The matching Rust source is
# documented inline next to each apply_* function.
#
# Doctrine reference (events.rs::validate_event_payload + reducer.rs):
#   "two implementations of the reducer must agree on the mutation
#    rules per kind" — this script is the second implementation.
#
# Fixture schema: vela.science/schema/cross-impl-reducer-fixture/v3
# Generator: crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs

from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Per-kind reducer rules ─────────────────────────────────────────────
#
# Each function mirrors a `fn apply_finding_*` in the Rust source at
# crates/vela-protocol/src/reducer.rs. The mutation rules are kept in
# sync by the cross-impl fixture test:
#   crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs
# If the Rust source changes a mutation rule, the fixture's
# expected_states drifts; if Python doesn't drift the same way, this
# script returns exit 1.


# ReviewState → contested mapping. Mirrors `ReviewState::implies_contested`
# in bundle.rs:1278-1288.
_CONTESTED_REVIEW_STATES = {"contested", "needs_revision", "rejected"}


def _find_finding(state: list[dict], finding_id: str) -> dict | None:
    for f in state:
        if f.get("id") == finding_id:
            return f
    return None


def _ensure_flags(f: dict) -> dict:
    if "flags" not in f or not isinstance(f["flags"], dict):
        f["flags"] = {}
    return f["flags"]


def _ensure_annotations(f: dict) -> list:
    if "annotations" not in f or not isinstance(f["annotations"], list):
        f["annotations"] = []
    return f["annotations"]


def _ensure_confidence(f: dict) -> dict:
    if "confidence" not in f or not isinstance(f["confidence"], dict):
        f["confidence"] = {}
    return f["confidence"]


def apply_finding_asserted(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_asserted.
    For v0.3+ frontiers a genesis event may carry the finding inline at
    payload.finding; for legacy frontiers the finding is already in
    state from genesis and this is a no-op.
    """
    payload = event.get("payload") or {}
    finding = payload.get("finding")
    if not finding:
        return
    if any(f.get("id") == finding.get("id") for f in state):
        return
    state.append(deepcopy(finding))


def apply_finding_reviewed(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_reviewed.
    Sets flags.review_state from the snake_case status; sets
    flags.contested per ReviewState::implies_contested.
    Accepts both 'accepted' and 'approved' (Rust accepts both).
    """
    payload = event.get("payload") or {}
    status = payload.get("status")
    if not isinstance(status, str):
        raise ValueError("finding.reviewed missing payload.status")
    finding_id = event.get("target", {}).get("id")
    f = _find_finding(state, finding_id)
    if f is None:
        raise ValueError(f"finding.reviewed targets unknown finding {finding_id}")
    flags = _ensure_flags(f)
    if status in ("accepted", "approved"):
        flags["review_state"] = "accepted"
        flags["contested"] = False
    elif status == "contested":
        flags["review_state"] = "contested"
        flags["contested"] = True
    elif status == "needs_revision":
        flags["review_state"] = "needs_revision"
        flags["contested"] = True
    elif status == "rejected":
        flags["review_state"] = "rejected"
        flags["contested"] = True
    else:
        raise ValueError(f"unsupported review status {status!r}")


def apply_finding_annotation(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_annotation.
    Idempotent on annotation_id. Adds an Annotation with id, text,
    author=event.actor.id, timestamp=event.timestamp.
    """
    payload = event.get("payload") or {}
    text = payload.get("text")
    annotation_id = payload.get("annotation_id")
    if not isinstance(text, str) or not isinstance(annotation_id, str):
        raise ValueError("annotation event missing text or annotation_id")
    finding_id = event.get("target", {}).get("id")
    f = _find_finding(state, finding_id)
    if f is None:
        raise ValueError(f"annotation event targets unknown finding {finding_id}")
    annotations = _ensure_annotations(f)
    if any(a.get("id") == annotation_id for a in annotations):
        return
    annotations.append(
        {
            "id": annotation_id,
            "text": text,
            "author": (event.get("actor") or {}).get("id", ""),
            "timestamp": event.get("timestamp", ""),
            "provenance": payload.get("provenance"),
        }
    )


def apply_finding_confidence_revised(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_confidence_revised.
    Sets confidence.score, basis, method=expert_judgment.
    """
    payload = event.get("payload") or {}
    new_score = payload.get("new_score")
    previous = payload.get("previous_score", 0.0)
    if not isinstance(new_score, (int, float)):
        raise ValueError("finding.confidence_revised missing payload.new_score")
    finding_id = event.get("target", {}).get("id")
    f = _find_finding(state, finding_id)
    if f is None:
        raise ValueError(f"confidence_revised targets unknown finding {finding_id}")
    conf = _ensure_confidence(f)
    conf["score"] = float(new_score)
    conf["basis"] = (
        f"expert revision from {float(previous):.3f} to {float(new_score):.3f}: "
        f"{event.get('reason', '')}"
    )
    conf["method"] = "expert_judgment"


def apply_finding_rejected(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_rejected. Sets contested=true."""
    finding_id = event.get("target", {}).get("id")
    f = _find_finding(state, finding_id)
    if f is None:
        raise ValueError(f"finding.rejected targets unknown finding {finding_id}")
    _ensure_flags(f)["contested"] = True


def apply_finding_retracted(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_retracted. Sets retracted=true."""
    finding_id = event.get("target", {}).get("id")
    f = _find_finding(state, finding_id)
    if f is None:
        raise ValueError(f"finding.retracted targets unknown finding {finding_id}")
    _ensure_flags(f)["retracted"] = True


def apply_finding_dependency_invalidated(state: list[dict], event: dict) -> None:
    """Mirror of reducer.rs::apply_finding_dependency_invalidated.
    Sets contested=true and appends a deterministic annotation whose
    id encodes the upstream cascade event and the depth.

    Rust shape:
      annotation_id = format!("ann_dep_{}_{}", &event.id[4..], depth);
    The "vev_" prefix on event.id is stripped by [4..] — Python does
    the same with [4:].
    """
    payload = event.get("payload") or {}
    upstream = payload.get("upstream_finding_id", "?")
    depth = payload.get("depth", 1)
    finding_id = event.get("target", {}).get("id")
    f = _find_finding(state, finding_id)
    if f is None:
        raise ValueError(
            f"finding.dependency_invalidated targets unknown finding {finding_id}"
        )
    _ensure_flags(f)["contested"] = True
    event_id = event.get("id", "")
    if event_id.startswith("vev_"):
        event_tail = event_id[4:]
    else:
        event_tail = event_id
    annotation_id = f"ann_dep_{event_tail}_{depth}"
    annotations = _ensure_annotations(f)
    if any(a.get("id") == annotation_id for a in annotations):
        return
    annotations.append(
        {
            "id": annotation_id,
            "text": f"Upstream {upstream} retracted (cascade depth {depth}).",
            "author": (event.get("actor") or {}).get("id", ""),
            "timestamp": event.get("timestamp", ""),
            "provenance": None,
        }
    )


# v0.49+v0.50+v0.51+v0.53 mirror functions: each mutates the appropriate
# sub-collection inside the ReducerState dict.


def apply_negative_result_asserted(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    nr = payload.get("negative_result")
    if not nr:
        return
    if any(n.get("id") == nr.get("id") for n in state):
        return
    state.append(deepcopy(nr))


def apply_negative_result_reviewed(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    status = payload.get("status")
    if not isinstance(status, str):
        raise ValueError("negative_result.reviewed missing payload.status")
    nr_id = event.get("target", {}).get("id")
    nr = next((n for n in state if n.get("id") == nr_id), None)
    if nr is None:
        raise ValueError(f"negative_result.reviewed targets unknown id {nr_id}")
    if status in ("accepted", "approved"):
        nr["review_state"] = "accepted"
    elif status in ("contested", "needs_revision", "rejected"):
        nr["review_state"] = status
    else:
        raise ValueError(f"unsupported review status {status!r}")


def apply_negative_result_retracted(state: list[dict], event: dict) -> None:
    nr_id = event.get("target", {}).get("id")
    nr = next((n for n in state if n.get("id") == nr_id), None)
    if nr is None:
        raise ValueError(f"negative_result.retracted targets unknown id {nr_id}")
    nr["retracted"] = True


def apply_trajectory_created(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    traj = payload.get("trajectory")
    if not traj:
        return
    if any(t.get("id") == traj.get("id") for t in state):
        return
    state.append(deepcopy(traj))


def apply_trajectory_step_appended(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    parent_id = payload.get("parent_trajectory_id")
    if not isinstance(parent_id, str):
        raise ValueError("trajectory.step_appended missing parent_trajectory_id")
    traj = next((t for t in state if t.get("id") == parent_id), None)
    if traj is None:
        raise ValueError(f"trajectory.step_appended targets unknown {parent_id}")
    step = payload.get("step")
    if not isinstance(step, dict) or "id" not in step:
        raise ValueError("trajectory.step_appended missing payload.step.id")
    if "steps" not in traj or not isinstance(traj["steps"], list):
        traj["steps"] = []
    if any(s.get("id") == step["id"] for s in traj["steps"]):
        return
    traj["steps"].append(deepcopy(step))


def apply_trajectory_reviewed(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    status = payload.get("status")
    if not isinstance(status, str):
        raise ValueError("trajectory.reviewed missing payload.status")
    traj_id = event.get("target", {}).get("id")
    traj = next((t for t in state if t.get("id") == traj_id), None)
    if traj is None:
        raise ValueError(f"trajectory.reviewed targets unknown id {traj_id}")
    if status in ("accepted", "approved"):
        traj["review_state"] = "accepted"
    elif status in ("contested", "needs_revision", "rejected"):
        traj["review_state"] = status
    else:
        raise ValueError(f"unsupported review status {status!r}")


def apply_trajectory_retracted(state: list[dict], event: dict) -> None:
    traj_id = event.get("target", {}).get("id")
    traj = next((t for t in state if t.get("id") == traj_id), None)
    if traj is None:
        raise ValueError(f"trajectory.retracted targets unknown id {traj_id}")
    traj["retracted"] = True


def apply_artifact_asserted(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    artifact = payload.get("artifact")
    if not artifact:
        return
    if any(a.get("id") == artifact.get("id") for a in state):
        return
    state.append(deepcopy(artifact))


def apply_artifact_reviewed(state: list[dict], event: dict) -> None:
    payload = event.get("payload") or {}
    status = payload.get("status")
    if not isinstance(status, str):
        raise ValueError("artifact.reviewed missing payload.status")
    artifact_id = event.get("target", {}).get("id")
    artifact = next((a for a in state if a.get("id") == artifact_id), None)
    if artifact is None:
        raise ValueError(f"artifact.reviewed targets unknown id {artifact_id}")
    if status in ("accepted", "approved"):
        artifact["review_state"] = "accepted"
    elif status in ("contested", "needs_revision", "rejected"):
        artifact["review_state"] = status
    else:
        raise ValueError(f"unsupported review status {status!r}")


def apply_artifact_retracted(state: list[dict], event: dict) -> None:
    artifact_id = event.get("target", {}).get("id")
    artifact = next((a for a in state if a.get("id") == artifact_id), None)
    if artifact is None:
        raise ValueError(f"artifact.retracted targets unknown id {artifact_id}")
    artifact["retracted"] = True


def apply_tier_set(state: dict, event: dict) -> None:
    """v0.51: tier.set re-classifies access_tier on a finding,
    negative_result, or trajectory. The state arg here is the full
    ReducerState dict so the dispatcher can route to the right
    collection.
    """
    payload = event.get("payload") or {}
    obj_type = payload.get("object_type")
    obj_id = payload.get("object_id")
    new_tier = payload.get("new_tier")
    if not isinstance(obj_type, str) or not isinstance(obj_id, str) or not isinstance(new_tier, str):
        raise ValueError(
            "tier.set requires payload.{object_type, object_id, new_tier}"
        )
    if new_tier not in ("public", "restricted", "classified"):
        raise ValueError(f"tier.set invalid new_tier {new_tier!r}")
    if obj_type == "finding":
        collection = state["findings"]
    elif obj_type == "negative_result":
        collection = state["negative_results"]
    elif obj_type == "trajectory":
        collection = state["trajectories"]
    elif obj_type == "artifact":
        collection = state["artifacts"]
    else:
        raise ValueError(f"tier.set unsupported object_type {obj_type!r}")
    obj = next((o for o in collection if o.get("id") == obj_id), None)
    if obj is None:
        raise ValueError(f"tier.set targets unknown {obj_type} {obj_id}")
    obj["access_tier"] = new_tier


def apply_evidence_atom_locator_repaired(state: dict, event: dict) -> None:
    """v0.56: Mechanical evidence-atom locator repair.

    Mutates ``state['evidence_atoms'][i]['locator']`` and clears the
    "missing evidence locator" caveat. Does not touch ``findings``.
    The cross-impl post-replay digest covers ``findings[]`` only, so a
    reducer that drops this arm still passes the cross-impl
    byte-equivalence check on findings; this arm is implemented for
    completeness and so a Python-side replay over the full event log
    yields the same evidence_atoms shape as the Rust reducer.
    """
    target = event.get("target") or {}
    if target.get("type") != "evidence_atom":
        raise ValueError(
            "evidence_atom.locator_repaired target.type must be 'evidence_atom'"
        )
    atom_id = target.get("id")
    if not atom_id:
        raise ValueError("evidence_atom.locator_repaired missing target.id")
    payload = event.get("payload") or {}
    locator = payload.get("locator")
    if not isinstance(locator, str) or not locator:
        raise ValueError(
            "evidence_atom.locator_repaired missing payload.locator"
        )
    atoms = state.get("evidence_atoms")
    if atoms is None:
        atoms = []
        state["evidence_atoms"] = atoms
    atom = next((a for a in atoms if a.get("id") == atom_id), None)
    if atom is None:
        raise ValueError(
            f"evidence_atom.locator_repaired targets unknown atom {atom_id!r}"
        )
    existing = atom.get("locator")
    if existing is not None and existing != locator:
        raise ValueError(
            f"evidence_atom {atom_id!r} already has locator {existing!r}, "
            f"refusing to overwrite with {locator!r}"
        )
    atom["locator"] = locator
    caveats = atom.get("caveats")
    if isinstance(caveats, list):
        atom["caveats"] = [c for c in caveats if c != "missing evidence locator"]


def apply_finding_span_repaired(findings: list[dict], event: dict) -> None:
    """v0.57: Mechanical finding-level span repair.

    Appends a ``{section, text}`` object to the named finding's
    ``evidence.evidence_spans``. Idempotent: re-applying with the same
    (section, text) pair is a no-op.
    """
    target = event.get("target") or {}
    if target.get("type") != "finding":
        raise ValueError(
            "finding.span_repaired target.type must be 'finding'"
        )
    finding_id = target.get("id")
    if not finding_id:
        raise ValueError("finding.span_repaired missing target.id")
    payload = event.get("payload") or {}
    section = payload.get("section")
    text = payload.get("text")
    if not isinstance(section, str) or not section:
        raise ValueError("finding.span_repaired missing payload.section")
    if not isinstance(text, str) or not text:
        raise ValueError("finding.span_repaired missing payload.text")
    finding = next((f for f in findings if f.get("id") == finding_id), None)
    if finding is None:
        raise ValueError(
            f"finding.span_repaired targets unknown finding {finding_id!r}"
        )
    spans = finding.setdefault("evidence", {}).setdefault("evidence_spans", [])
    already_present = any(
        s.get("section") == section and s.get("text") == text for s in spans
    )
    if not already_present:
        spans.append({"section": section, "text": text})


def apply_finding_entity_resolved(findings: list[dict], event: dict) -> None:
    """v0.57: Mechanical entity resolution on a finding.

    Sets canonical_id, resolution_method, resolution_provenance, and
    resolution_confidence on the named entity inside the target
    finding's assertion.entities array, and clears the entity's
    needs_review flag.
    """
    target = event.get("target") or {}
    if target.get("type") != "finding":
        raise ValueError("finding.entity_resolved target.type must be 'finding'")
    finding_id = target.get("id")
    payload = event.get("payload") or {}
    entity_name = payload.get("entity_name")
    source = payload.get("source")
    id_value = payload.get("id")
    confidence = payload.get("confidence")
    matched_name = payload.get("matched_name")
    method = payload.get("resolution_method", "manual")
    provenance = payload.get("resolution_provenance", "delegated_human_curation")
    if not all(isinstance(v, str) and v for v in [finding_id, entity_name, source, id_value]):
        raise ValueError("finding.entity_resolved missing required string fields")
    if not isinstance(confidence, (int, float)):
        raise ValueError("finding.entity_resolved missing payload.confidence")
    finding = next((f for f in findings if f.get("id") == finding_id), None)
    if finding is None:
        raise ValueError(
            f"finding.entity_resolved targets unknown finding {finding_id!r}"
        )
    entities = finding.get("assertion", {}).get("entities", [])
    entity = next((e for e in entities if e.get("name") == entity_name), None)
    if entity is None:
        raise ValueError(
            f"finding.entity_resolved entity {entity_name!r} not in finding {finding_id!r}"
        )
    canonical = {
        "source": source,
        "id": id_value,
        "confidence": float(confidence),
    }
    if isinstance(matched_name, str) and matched_name:
        canonical["matched_name"] = matched_name
    entity["canonical_id"] = canonical
    entity["resolution_method"] = method
    entity["resolution_provenance"] = provenance
    entity["resolution_confidence"] = float(confidence)
    entity["needs_review"] = False


def apply_finding_entity_added(findings: list[dict], event: dict) -> None:
    """v0.79: Append a new entity to a finding's assertion.entities.

    Idempotent on (finding_id, entity_name): re-applying with the same
    name + type is a no-op so federation re-sync stays clean. Mirrors
    reducer.rs::apply_finding_entity_added.
    """
    target = event.get("target") or {}
    if target.get("type") != "finding":
        raise ValueError(
            f"finding.entity_added target.type must be 'finding', got "
            f"{target.get('type')!r}"
        )
    finding_id = target.get("id")
    payload = event.get("payload") or {}
    entity_name = payload.get("entity_name")
    entity_type = payload.get("entity_type")
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding.entity_added missing target.id")
    if not isinstance(entity_name, str) or not entity_name:
        raise ValueError("finding.entity_added missing payload.entity_name")
    if not isinstance(entity_type, str) or not entity_type:
        raise ValueError("finding.entity_added missing payload.entity_type")
    finding = next((f for f in findings if f.get("id") == finding_id), None)
    if finding is None:
        raise ValueError(
            f"finding.entity_added targets unknown finding {finding_id!r}"
        )
    entities = finding.setdefault("assertion", {}).setdefault("entities", [])
    if any(e.get("name") == entity_name for e in entities):
        return
    entities.append(
        {
            "name": entity_name,
            "entity_type": entity_type,
            "identifiers": {},
            "canonical_id": None,
            "candidates": [],
            "aliases": [],
            "resolution_provenance": None,
            "resolution_confidence": 1.0,
            "resolution_method": None,
            "species_context": None,
            "needs_review": False,
        }
    )


# v0.70: replication / prediction deposits. Each arm appends a
# record to state["replications"] or state["predictions"] if the
# content-addressed id is not already present. Mirrors
# reducer.rs::apply_replication_deposited and
# reducer.rs::apply_prediction_deposited. These do not mutate
# state["findings"], so the cross-impl finding-effects digest is
# unaffected; the deposit collections themselves are not part of
# the cross-impl byte-equivalence promise (yet) but the Python
# arm exists so a fresh replay does not silently drop the deposit.
def apply_replication_deposited(state: dict, event: dict) -> None:
    payload = event.get("payload") or {}
    rep = payload.get("replication")
    if not isinstance(rep, dict):
        raise ValueError(
            "replication.deposited event missing payload.replication"
        )
    rep_id = rep.get("id")
    if not isinstance(rep_id, str) or not rep_id.startswith("vrep_"):
        raise ValueError(
            "replication.deposited payload.replication.id must start with 'vrep_'"
        )
    bucket = state.setdefault("replications", [])
    if any(r.get("id") == rep_id for r in bucket):
        return
    bucket.append(deepcopy(rep))


def apply_prediction_deposited(state: dict, event: dict) -> None:
    payload = event.get("payload") or {}
    pred = payload.get("prediction")
    if not isinstance(pred, dict):
        raise ValueError(
            "prediction.deposited event missing payload.prediction"
        )
    pred_id = pred.get("id")
    if not isinstance(pred_id, str) or not pred_id.startswith("vpred_"):
        raise ValueError(
            "prediction.deposited payload.prediction.id must start with 'vpred_'"
        )
    bucket = state.setdefault("predictions", [])
    if any(p.get("id") == pred_id for p in bucket):
        return
    bucket.append(deepcopy(pred))


def apply_event(state: dict, event: dict) -> None:
    """state is now a dict {findings, negative_results, trajectories,
    artifacts} so non-finding events have somewhere to land. The
    Rust reducer's apply_event signature is `&mut Project` which
    contains all three; this is the closest Python analogue.
    """
    kind = event.get("kind", "")
    if kind == "frontier.created":
        return  # structural anchor, no mutation
    elif kind == "finding.asserted":
        apply_finding_asserted(state["findings"], event)
    elif kind == "finding.reviewed":
        apply_finding_reviewed(state["findings"], event)
    elif kind in ("finding.noted", "finding.caveated"):
        apply_finding_annotation(state["findings"], event)
    elif kind == "finding.confidence_revised":
        apply_finding_confidence_revised(state["findings"], event)
    elif kind == "finding.rejected":
        apply_finding_rejected(state["findings"], event)
    elif kind == "finding.retracted":
        apply_finding_retracted(state["findings"], event)
    elif kind == "finding.dependency_invalidated":
        apply_finding_dependency_invalidated(state["findings"], event)
    elif kind == "negative_result.asserted":
        apply_negative_result_asserted(state["negative_results"], event)
    elif kind == "negative_result.reviewed":
        apply_negative_result_reviewed(state["negative_results"], event)
    elif kind == "negative_result.retracted":
        apply_negative_result_retracted(state["negative_results"], event)
    elif kind == "trajectory.created":
        apply_trajectory_created(state["trajectories"], event)
    elif kind == "trajectory.step_appended":
        apply_trajectory_step_appended(state["trajectories"], event)
    elif kind == "trajectory.reviewed":
        apply_trajectory_reviewed(state["trajectories"], event)
    elif kind == "trajectory.retracted":
        apply_trajectory_retracted(state["trajectories"], event)
    elif kind == "artifact.asserted":
        apply_artifact_asserted(state["artifacts"], event)
    elif kind == "artifact.reviewed":
        apply_artifact_reviewed(state["artifacts"], event)
    elif kind == "artifact.retracted":
        apply_artifact_retracted(state["artifacts"], event)
    elif kind == "tier.set":
        apply_tier_set(state, event)
    elif kind == "evidence_atom.locator_repaired":
        apply_evidence_atom_locator_repaired(state, event)
    elif kind == "finding.span_repaired":
        apply_finding_span_repaired(state["findings"], event)
    elif kind == "finding.entity_resolved":
        apply_finding_entity_resolved(state["findings"], event)
    elif kind == "finding.entity_added":
        apply_finding_entity_added(state["findings"], event)
    # v0.80: per-event attestation. No-op on findings; attestations
    # live as append-only canonical events pointing at a target
    # event id. The Rust mirror is reducer.rs:165.
    elif kind == "attestation.recorded":
        return
    # v0.39 + v0.59: federation events. Frontier-level observations,
    # not finding-state mutations. The Python mirror's finding-effects
    # digest covers state["findings"] only, so these are no-ops on
    # the cross-impl comparison; the events still append to
    # state["events"] via the caller.
    elif kind in (
        "frontier.synced_with_peer",
        "frontier.conflict_detected",
        "frontier.conflict_resolved",
    ):
        return
    # verifier attachment bound to a finding. Mutates the Project-level
    # state["verifier_attachments"] sidecar; a no-op on state["findings"]
    # (the cross-impl finding-effects digest covers findings only). The
    # Rust mirror is reducer.rs::apply_verifier_attachment_added.
    elif kind == "verifier_attachment.added":
        return
    # v0.67: bridge review verdict. Bridges live in `.vela/bridges/`
    # as a side table; the reducer arm is a no-op on
    # state["findings"]. Consumers project the verdict onto
    # Bridge.status by reading the most recent bridge.reviewed event
    # for that bridge_id. The Rust mirror is reducer.rs:169.
    elif kind == "bridge.reviewed":
        return
    # v0.70: replication / prediction deposits. Each appends a
    # record to state["replications"] or state["predictions"] if
    # the content-addressed id is not already present (idempotent
    # under re-application). No-op on state["findings"]; the
    # cross-impl finding-effects digest covers findings only. The
    # Rust mirrors are reducer.rs::apply_replication_deposited and
    # reducer.rs::apply_prediction_deposited.
    elif kind == "replication.deposited":
        apply_replication_deposited(state, event)
    elif kind == "prediction.deposited":
        apply_prediction_deposited(state, event)
    # v0.213: Released Diff Pack tracking. Both arms mutate
    # state["released_diff_packs"]. The Rust mirrors are
    # reducer.rs::apply_diff_pack_released and
    # reducer.rs::apply_diff_pack_reviewed.
    elif kind == "diff_pack.released":
        apply_diff_pack_released(state, event)
    elif kind == "diff_pack.reviewed":
        apply_diff_pack_reviewed(state, event)
    # v0.218: Verdict Conflict Resolution. The Rust mirror is
    # reducer.rs::apply_verdict_conflict_resolved. Idempotent on
    # conflict_id.
    elif kind == "verdict_conflict.resolved":
        apply_verdict_conflict_resolved(state, event)
    # Contradiction adjudication. The Rust mirror
    # (reducer.rs::apply_contradiction_resolved) upserts a Contradiction
    # into state["contradictions"], a side table outside the cross-impl
    # finding-effects digest. No-op on state["findings"], so a digest
    # no-op keeps the Python reducer byte-identical with Rust + the TS
    # reducer.
    elif kind == "contradiction.resolved":
        return
    # Supersession: flip flags.superseded on the OLD finding (target).
    # The replacement's body lives in the accepted proposal and enters
    # via loader genesis seeding, never via the reducer — the event
    # payload is deliberately thin. The Rust mirror is
    # reducer.rs::apply_finding_superseded. `superseded` is outside the
    # cross-impl finding-effects digest.
    elif kind == "finding.superseded":
        apply_finding_superseded(state["findings"], event)
    # Causal re-grading: replay assertion.causal_claim /
    # causal_evidence_grade from payload.after. Outside the
    # finding-effects digest. Rust mirror:
    # reducer.rs::apply_assertion_reinterpreted_causal.
    # Statement-faithfulness attestation: side-table upsert in Rust;
    # no-op on the finding-effects digest here. Rust mirror:
    # reducer.rs::apply_statement_attested.
    elif kind == "statement.attested":
        return
    # Obligation lease + priority registration: side-table upserts in
    # Rust; no-ops on the finding-effects digest here. Rust mirrors:
    # reducer.rs::apply_attempt_claimed / apply_statement_registered.
    elif kind in ("attempt.claimed", "statement.registered"):
        return
    elif kind == "assertion.reinterpreted_causal":
        apply_assertion_reinterpreted_causal(state["findings"], event)
    # Audit-only / writerless kinds (validated at emit, no projected
    # state on replay). Rust mirror: the explicit no-op arms in
    # reducer.rs.
    elif kind in (
        "prediction.expired_unresolved",
        "finding.threshold_set",
        "finding.threshold_met",
        "frontier.observation_reviewed",
        "correction_return.review",
        "research_trace.review",
        "key.revoke",
    ):
        return
    # Reviewer decision records (review.accepted / review.rejected /
    # review.revision_requested). Audit-only on the finding-effects digest:
    # they target a proposal, recording WHO decided and HOW. Proposal status
    # is a separate projection over these events, verified by
    # proposals::verify_proposal_decision_parity in Rust. The Rust mirror is
    # the explicit no-op arm in reducer.rs.
    elif kind in (
        "review.accepted",
        "review.rejected",
        "review.revision_requested",
    ):
        return
    else:
        raise ValueError(f"reducer: unsupported event kind {kind!r}")


def apply_verdict_conflict_resolved(state: dict, event: dict) -> None:
    """v0.218: append a VerdictConflict body to
    state["verdict_conflicts"]. The conflict body lives inline under
    event.payload.conflict. Idempotent on conflict_id."""
    payload = event.get("payload") or {}
    conflict = payload.get("conflict")
    if not isinstance(conflict, dict):
        raise ValueError(
            "verdict_conflict.resolved event missing payload.conflict object"
        )
    cid = conflict.get("conflict_id")
    if not cid or not cid.startswith("vdc_"):
        raise ValueError(
            f"verdict_conflict.resolved payload.conflict.conflict_id must start with 'vdc_', got {cid!r}"
        )
    bucket = state.setdefault("verdict_conflicts", [])
    if any(c.get("conflict_id") == cid for c in bucket):
        return
    bucket.append(deepcopy(conflict))


def apply_diff_pack_released(state: dict, event: dict) -> None:
    """v0.213: append a released-pack record to
    state["released_diff_packs"] when a diff_pack.released event lands.
    Idempotent on pack_id."""
    payload = event.get("payload") or {}
    pack_id = payload.get("pack_id")
    if not pack_id or not pack_id.startswith("vsd_"):
        raise ValueError(
            f"diff_pack.released event payload.pack_id must start with 'vsd_', got {pack_id!r}"
        )
    bucket = state.setdefault("released_diff_packs", [])
    if any(r.get("pack_id") == pack_id for r in bucket):
        return
    bucket.append(
        {
            "pack_id": pack_id,
            "frontier_id": payload.get("frontier_id", ""),
            "summary": payload.get("summary", ""),
            "aggregate_kind": payload.get("aggregate_kind", ""),
            "released_at": event.get("timestamp", ""),
            "released_event_id": event.get("id", ""),
        }
    )


def apply_diff_pack_reviewed(state: dict, event: dict) -> None:
    """v0.213: update the matching released-pack record with the verdict
    when a diff_pack.reviewed event lands. Creates a record on the fly if
    no prior release event was replayed (substrate-honest: hubs that
    receive verdict-only can still reconstruct sensible state)."""
    payload = event.get("payload") or {}
    pack_id = payload.get("pack_id")
    if not pack_id or not pack_id.startswith("vsd_"):
        raise ValueError(
            f"diff_pack.reviewed event payload.pack_id must start with 'vsd_', got {pack_id!r}"
        )
    verdict_str = payload.get("verdict")
    if not verdict_str or verdict_str not in (
        "accept",
        "accepted",
        "reject",
        "rejected",
        "revise",
        "revision",
        "needs_revision",
    ):
        raise ValueError(
            f"diff_pack.reviewed event payload.verdict must be accept|reject|revise, got {verdict_str!r}"
        )
    canonical_verdict = {
        "accept": "accept",
        "accepted": "accept",
        "reject": "reject",
        "rejected": "reject",
        "revise": "revise",
        "revision": "revise",
        "needs_revision": "revise",
    }[verdict_str]
    reviewer_actor = payload.get("reviewer_actor") or (event.get("actor") or {}).get(
        "id", ""
    )
    applied = list(payload.get("applied_members") or [])
    sdk_only = list(payload.get("sdk_only_members") or [])
    bucket = state.setdefault("released_diff_packs", [])
    rec = next((r for r in bucket if r.get("pack_id") == pack_id), None)
    if rec is None:
        rec = {
            "pack_id": pack_id,
            "frontier_id": payload.get("frontier_id", ""),
            "summary": "",
            "aggregate_kind": "",
            "released_at": event.get("timestamp", ""),
            "released_event_id": "",
        }
        bucket.append(rec)
    rec["verdict"] = canonical_verdict
    rec["verdict_event_id"] = event.get("id", "")
    rec["reviewer_actor"] = reviewer_actor
    rec["applied_members"] = applied
    rec["sdk_only_members"] = sdk_only


# ── Reducer-effects digest ─────────────────────────────────────────────
#
# Mirror of `finding_state` in
# crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs.
# Captures only the fields the reducer mutates so cross-impl agreement
# is testable without serializing the full Project struct.


def finding_effects(findings: list[dict]) -> list[dict]:
    sorted_state = sorted(findings, key=lambda f: f.get("id", ""))
    out = []
    for f in sorted_state:
        flags = f.get("flags") or {}
        review_state = flags.get("review_state") or "none"
        confidence = f.get("confidence") or {}
        annotations = f.get("annotations") or []
        annotation_ids = sorted(a.get("id", "") for a in annotations)
        score = float(confidence.get("score", 0.0))
        out.append(
            {
                "id": f.get("id", ""),
                "retracted": bool(flags.get("retracted", False)),
                "contested": bool(flags.get("contested", False)),
                "review_state": review_state,
                "confidence_score": f"{score:.6f}",
                "annotation_ids": annotation_ids,
                "access_tier": f.get("access_tier", "public"),
            }
        )
    return out


def negative_result_effects(nrs: list[dict]) -> list[dict]:
    sorted_state = sorted(nrs, key=lambda n: n.get("id", ""))
    return [
        {
            "id": n.get("id", ""),
            "retracted": bool(n.get("retracted", False)),
            "review_state": n.get("review_state") or "none",
            "access_tier": n.get("access_tier", "public"),
        }
        for n in sorted_state
    ]


def trajectory_effects(trajs: list[dict]) -> list[dict]:
    sorted_state = sorted(trajs, key=lambda t: t.get("id", ""))
    out = []
    for t in sorted_state:
        steps = t.get("steps") or []
        out.append(
            {
                "id": t.get("id", ""),
                "retracted": bool(t.get("retracted", False)),
                "review_state": t.get("review_state") or "none",
                "access_tier": t.get("access_tier", "public"),
                "step_ids": [s.get("id", "") for s in steps],
            }
        )
    return out


def artifact_effects(artifacts: list[dict]) -> list[dict]:
    sorted_state = sorted(artifacts, key=lambda a: a.get("id", ""))
    return [
        {
            "id": a.get("id", ""),
            "kind": a.get("kind", ""),
            "retracted": bool(a.get("retracted", False)),
            "review_state": a.get("review_state") or "none",
            "access_tier": a.get("access_tier", "public"),
        }
        for a in sorted_state
    ]


def replication_effects(replications: list[dict]) -> list[dict]:
    """v0.106.5: cross-impl digest per Replication. Mirrors
    crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs::replication_state.
    """
    sorted_state = sorted(replications, key=lambda r: r.get("id", ""))
    return [
        {
            "id": r.get("id", ""),
            "target_finding": r.get("target_finding", ""),
            "outcome": r.get("outcome", ""),
        }
        for r in sorted_state
    ]


def prediction_effects(predictions: list[dict]) -> list[dict]:
    """v0.106.5: cross-impl digest per Prediction. Mirrors
    crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs::prediction_state.
    """
    sorted_state = sorted(predictions, key=lambda p: p.get("id", ""))
    return [
        {
            "id": p.get("id", ""),
            "made_by": p.get("made_by", ""),
            "expired_unresolved": bool(p.get("expired_unresolved", False)),
        }
        for p in sorted_state
    ]


# Backward-compat alias for any caller still importing the v0.49 name.
def reducer_effects(findings: list[dict]) -> list[dict]:
    return finding_effects(findings)


# ── Fixture verification ───────────────────────────────────────────────


@dataclass
class FixtureResult:
    path: str
    frontier_idx: int
    findings: int = 0
    negative_results: int = 0
    trajectories: int = 0
    artifacts: int = 0
    replications: int = 0
    predictions: int = 0
    events: int = 0
    cascade_depth: int = 0
    matched: int = 0
    diffs: list[dict] = field(default_factory=list)
    ok: bool = False
    error: str | None = None


def _diff_collection(
    name: str,
    actual: list[dict],
    expected: list[dict],
    result: FixtureResult,
) -> None:
    actual_by_id = {r["id"]: r for r in actual}
    expected_by_id = {r["id"]: r for r in expected}
    all_ids = sorted(set(actual_by_id) | set(expected_by_id))
    for rid in all_ids:
        a = actual_by_id.get(rid)
        e = expected_by_id.get(rid)
        if a is None:
            result.diffs.append(
                {"collection": name, "id": rid, "issue": "missing in python output", "expected": e}
            )
        elif e is None:
            result.diffs.append(
                {"collection": name, "id": rid, "issue": "extra in python output", "actual": a}
            )
        elif a != e:
            result.diffs.append(
                {
                    "collection": name,
                    "id": rid,
                    "issue": "mismatch",
                    "expected": e,
                    "actual": a,
                }
            )
        else:
            result.matched += 1


def verify_fixture(path: Path) -> FixtureResult:
    result = FixtureResult(path=str(path), frontier_idx=-1)
    try:
        fx = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        result.error = f"unreadable fixture: {e}"
        return result
    fx_version = str(fx.get("fixture_version") or "")
    if fx_version not in ("1", "2", "3", "4"):
        result.error = (
            f"unsupported fixture_version {fx.get('fixture_version')!r}; "
            f"expected '1', '2', '3', or '4'"
        )
        return result
    result.frontier_idx = int(fx.get("frontier_idx", -1))
    stats = fx.get("stats") or {}
    result.findings = int(stats.get("findings", 0))
    result.negative_results = int(stats.get("negative_results", 0))
    result.trajectories = int(stats.get("trajectories", 0))
    result.artifacts = int(stats.get("artifacts", 0))
    result.replications = int(stats.get("replications", 0))
    result.predictions = int(stats.get("predictions", 0))
    result.events = int(stats.get("events", 0))
    result.cascade_depth = int(stats.get("cascade_depth", 0))

    state = {
        "findings": deepcopy(fx.get("genesis_findings") or []),
        "negative_results": [],
        "trajectories": [],
        "artifacts": [],
        "replications": [],
        "predictions": [],
    }
    event_log = fx.get("event_log") or []
    expected_findings = fx.get("expected_states") or []
    expected_nrs = fx.get("expected_negative_results") or []
    expected_trajs = fx.get("expected_trajectories") or []
    expected_artifacts = fx.get("expected_artifacts") or []
    expected_replications = fx.get("expected_replications") or []
    expected_predictions = fx.get("expected_predictions") or []

    for event in event_log:
        try:
            apply_event(state, event)
        except ValueError as e:
            result.error = (
                f"reducer error on event {event.get('id', '?')} "
                f"({event.get('kind', '?')}): {e}"
            )
            return result

    actual_findings = finding_effects(state["findings"])
    actual_nrs = negative_result_effects(state["negative_results"])
    actual_trajs = trajectory_effects(state["trajectories"])
    actual_artifacts = artifact_effects(state["artifacts"])
    actual_replications = replication_effects(state.get("replications", []))
    actual_predictions = prediction_effects(state.get("predictions", []))

    if fx_version == "1":
        # v1 fixtures don't carry access_tier in expected_states;
        # strip it from actual rows so the comparison doesn't false-fail.
        actual_findings = [
            {k: v for k, v in row.items() if k != "access_tier"} for row in actual_findings
        ]

    _diff_collection("findings", actual_findings, expected_findings, result)
    if fx_version in ("2", "3", "4"):
        _diff_collection("negative_results", actual_nrs, expected_nrs, result)
        _diff_collection("trajectories", actual_trajs, expected_trajs, result)
    if fx_version in ("3", "4"):
        _diff_collection("artifacts", actual_artifacts, expected_artifacts, result)
    if fx_version == "4":
        _diff_collection("replications", actual_replications, expected_replications, result)
        _diff_collection("predictions", actual_predictions, expected_predictions, result)

    total_expected = len(expected_findings)
    if fx_version in ("2", "3", "4"):
        total_expected += len(expected_nrs) + len(expected_trajs)
    if fx_version in ("3", "4"):
        total_expected += len(expected_artifacts)
    if fx_version == "4":
        total_expected += len(expected_replications) + len(expected_predictions)
    result.ok = not result.diffs and result.matched == total_expected
    return result


def render_text(results: list[FixtureResult]) -> str:
    lines: list[str] = []
    lines.append("vela reducer (python · stdlib · second implementation)")
    for r in results:
        status = "ok" if r.ok else "FAIL"
        total_expected = (
            r.findings
            + r.negative_results
            + r.trajectories
            + r.artifacts
            + r.replications
            + r.predictions
        )
        head = (
            f"  {status:<4} · frontier {r.frontier_idx:02} · "
            f"{r.matched}/{total_expected} ({r.findings}f/{r.negative_results}n/{r.trajectories}t/{r.artifacts}a/{r.replications}r/{r.predictions}p) · "
            f"{r.events} events · cascade depth {r.cascade_depth}"
        )
        lines.append(head)
        if r.error:
            lines.append(f"          error: {r.error}")
        for d in r.diffs[:5]:
            coll = d.get("collection", "")
            prefix = f"[{coll}] " if coll else ""
            lines.append(f"          · {prefix}{d.get('id', '?')}: {d.get('issue')}")
            if d.get("expected") and d.get("actual"):
                exp = d["expected"]
                act = d["actual"]
                for k in sorted(set(exp) | set(act)):
                    if exp.get(k) != act.get(k):
                        lines.append(
                            f"              {k}: expected={exp.get(k)!r} actual={act.get(k)!r}"
                        )
        if len(r.diffs) > 5:
            lines.append(f"          (… {len(r.diffs) - 5} more)")
    if all(r.ok for r in results):
        lines.append("")
        lines.append("reducer: ok")
        lines.append(
            "  every event-log replay through the python reducer produced"
        )
        lines.append(
            "  the same per-finding state the rust reducer produced. the"
        )
        lines.append(
            "  per-kind mutation rules are now confirmed across two"
        )
        lines.append(
            "  independent implementations."
        )
    return "\n".join(lines)


def collect_fixtures(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(target.glob("cascade-fixture-*.json"))
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Vela cross-implementation reducer — applies a canonical event log "
            "to genesis findings and asserts the post-replay state matches the "
            "Rust reducer's expected_states byte-for-byte."
        )
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Path to a fixture .json or a directory containing cascade-fixture-*.json",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a structured JSON report instead of human-readable output",
    )
    args = parser.parse_args(argv)

    fixtures = collect_fixtures(args.target)
    if not fixtures:
        print(f"error: no cascade-fixture-*.json found at {args.target}", file=sys.stderr)
        return 2

    results = [verify_fixture(p) for p in fixtures]

    if args.json:
        print(
            json.dumps(
                {
                    "ok": all(r.ok for r in results),
                    "fixtures": [
                        {
                            "path": r.path,
                            "frontier_idx": r.frontier_idx,
                            "ok": r.ok,
                            "findings": r.findings,
                            "negative_results": r.negative_results,
                            "trajectories": r.trajectories,
                            "events": r.events,
                            "cascade_depth": r.cascade_depth,
                            "matched": r.matched,
                            "diffs": r.diffs,
                            "error": r.error,
                        }
                        for r in results
                    ],
                    "verifier": "vela_reducer.py · python3 stdlib · second implementation",
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(render_text(results))

    return 0 if all(r.ok for r in results) else 1


def apply_finding_superseded(findings: list, event: dict) -> None:
    """Flip flags.superseded on the targeted (old) finding. Idempotent.
    The replacement finding does NOT enter here (thin payload; loader
    genesis seeding owns it). Rust mirror:
    reducer.rs::apply_finding_superseded."""
    finding_id = (event.get("target") or {}).get("id")
    for f in findings:
        if f.get("id") == finding_id:
            f.setdefault("flags", {})["superseded"] = True
            return
    raise ValueError(f"finding.superseded targets unknown finding {finding_id}")


def apply_assertion_reinterpreted_causal(findings: list, event: dict) -> None:
    """Replay the causal re-grading from payload.after ({claim, grade}).
    Rust mirror: reducer.rs::apply_assertion_reinterpreted_causal."""
    finding_id = (event.get("target") or {}).get("id")
    after = (event.get("payload") or {}).get("after") or {}
    claim = after.get("claim")
    if claim not in ("correlation", "mediation", "intervention"):
        raise ValueError(f"invalid causal claim {claim!r}")
    grade = after.get("grade")
    if grade is not None and grade not in (
        "rct",
        "quasi_experimental",
        "observational",
        "theoretical",
    ):
        raise ValueError(f"invalid causal evidence grade {grade!r}")
    for f in findings:
        if f.get("id") == finding_id:
            assertion = f.setdefault("assertion", {})
            assertion["causal_claim"] = claim
            if grade is not None:
                assertion["causal_evidence_grade"] = grade
            return
    raise ValueError(
        f"assertion.reinterpreted_causal targets unknown finding {finding_id}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
