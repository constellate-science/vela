"""Round-trip tests for the v0.193 / v0.195 primitive mirrors.

Each test fixes a deterministic input and asserts a stable id, so any
drift from the Rust canonical-bytes layout shows up here before it
reaches a real frontier.
"""

from __future__ import annotations

import json

import pytest
from nacl.signing import SigningKey

from vela_agent.primitives import (
    AgentAttestation,
    ScientificDiffPack,
    ToolCall,
    derive_proposal_id,
    normalize_text,
    sha256_hex,
)


# ---- ScientificDiffPack ----------------------------------------------------


def _pack_inputs() -> dict:
    return dict(
        frontier_id="vfr_5076e7b3ff8e6b0f",
        created_at="2026-05-11T00:00:00Z",
        summary="Test pack — bundles two proposals.",
        proposals=["vpr_a1", "vpr_b2"],
        aggregate_kind="finding.cluster_revision",
    )


def test_diff_pack_id_is_deterministic() -> None:
    p1 = ScientificDiffPack.build(**_pack_inputs())
    p2 = ScientificDiffPack.build(**_pack_inputs())
    assert p1.pack_id == p2.pack_id
    assert p1.pack_id.startswith("vsd_")
    assert len(p1.pack_id) == 4 + 16
    # Cross-impl pin: this exact pack_id is asserted in
    # crates/vela-protocol/src/scientific_diff.rs::cross_impl_python_sdk_pinned_id
    # — drift in either implementation flags both.
    assert p1.pack_id == "vsd_cd2a0071e7ffbffd"


def test_attestation_cross_impl_pinned_id() -> None:
    # Cross-impl pin: this attestation_id is asserted in
    # crates/vela-protocol/src/agent_attestation.rs::cross_impl_python_sdk_pinned_id.
    key = SigningKey(bytes(32))
    att = AgentAttestation.build(
        key=key,
        agent_actor="agent:cross_check",
        model_name="claude-opus-4.7",
        model_version="v1",
        started_at="2026-05-11T00:00:00Z",
        finished_at="2026-05-11T00:00:42Z",
        total_tokens=100,
        tool_calls=[
            ToolCall(
                tool_name="t",
                input_hash="a" * 64,
                output_hash="b" * 64,
                duration_ms=10,
            )
        ],
        output_hashes=["c" * 64],
        prompt_hash="d" * 64,
    )
    assert att.attestation_id == "vaa_db61cc709fc3e69b"
    assert (
        att.signer_pubkey_hex
        == "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
    )


def test_diff_pack_id_changes_with_proposal_order() -> None:
    p1 = ScientificDiffPack.build(**_pack_inputs())
    inputs = _pack_inputs()
    inputs["proposals"] = list(reversed(inputs["proposals"]))
    p2 = ScientificDiffPack.build(**inputs)
    assert p1.pack_id != p2.pack_id


def test_diff_pack_empty_proposals_rejected() -> None:
    with pytest.raises(ValueError):
        ScientificDiffPack.build(**(_pack_inputs() | {"proposals": []}))


def test_diff_pack_long_summary_rejected() -> None:
    with pytest.raises(ValueError):
        ScientificDiffPack.build(**(_pack_inputs() | {"summary": "x" * 281}))


def test_diff_pack_sign_then_verify() -> None:
    key = SigningKey.generate()
    pack = ScientificDiffPack.build(**_pack_inputs())
    pack.sign(key)
    pack.verify()
    # Tamper -> verify fails.
    pack.summary = "different"
    with pytest.raises(ValueError):
        pack.verify()


def test_diff_pack_json_round_trip() -> None:
    key = SigningKey.generate()
    pack = ScientificDiffPack.build(**_pack_inputs())
    pack.sign(key)
    blob = json.dumps(pack.to_json(), sort_keys=True)
    back = json.loads(blob)
    assert back["pack_id"] == pack.pack_id
    assert back["signature"] == pack.signature


# ---- AgentAttestation -----------------------------------------------------


def _attestation_inputs(key: SigningKey) -> dict:
    return dict(
        key=key,
        agent_actor="agent:test_scout",
        model_name="claude-opus-4.7",
        model_version="claude-opus-4.7-20260411",
        started_at="2026-05-11T00:00:00Z",
        finished_at="2026-05-11T00:00:42Z",
        total_tokens=12_500,
        tool_calls=[
            ToolCall(
                tool_name="search_arxiv",
                input_hash="a" * 64,
                output_hash="b" * 64,
                duration_ms=1_200,
            )
        ],
        output_hashes=["c" * 64],
        prompt_hash="d" * 64,
    )


def test_attestation_builds_and_verifies() -> None:
    key = SigningKey.generate()
    att = AgentAttestation.build(**_attestation_inputs(key))
    assert att.attestation_id.startswith("vaa_")
    assert len(att.attestation_id) == 4 + 16
    att.verify()


def test_attestation_agent_actor_namespaced() -> None:
    key = SigningKey.generate()
    inputs = _attestation_inputs(key)
    inputs["agent_actor"] = "reviewer:human"
    with pytest.raises(ValueError):
        AgentAttestation.build(**inputs)


def test_attestation_short_hash_rejected() -> None:
    key = SigningKey.generate()
    inputs = _attestation_inputs(key)
    inputs["output_hashes"] = ["short"]
    with pytest.raises(ValueError):
        AgentAttestation.build(**inputs)


def test_attestation_tampered_body_fails_verify() -> None:
    key = SigningKey.generate()
    att = AgentAttestation.build(**_attestation_inputs(key))
    att.model_name = "claude-haiku-2.5"
    with pytest.raises(ValueError):
        att.verify()


def test_attestation_json_round_trip() -> None:
    key = SigningKey.generate()
    att = AgentAttestation.build(**_attestation_inputs(key))
    blob = json.dumps(att.to_json(), sort_keys=True)
    parsed = json.loads(blob)
    assert parsed["attestation_id"] == att.attestation_id
    assert parsed["signer_pubkey_hex"] == att.signer_pubkey_hex


# ---- proposal id ----------------------------------------------------------


def test_proposal_id_is_dict_order_independent() -> None:
    a = derive_proposal_id(
        "finding.add", {"x": 1, "y": 2}, "2026-05-11T00:00:00Z", "agent:x"
    )
    b = derive_proposal_id(
        "finding.add", {"y": 2, "x": 1}, "2026-05-11T00:00:00Z", "agent:x"
    )
    assert a == b
    assert a.startswith("vpr_")


def test_normalize_text_collapses_whitespace_and_trims() -> None:
    # Mirror of Rust's normalize_text: lowercase + collapse whitespace
    # to single spaces + strip trailing `.;:!?`. The "?" sits after a
    # space here, so trim_end_matches removes only the "?" and the
    # trailing space remains, matching Rust.
    assert normalize_text("  HELLO   WORLD  ?") == "hello world "
    assert normalize_text("Hello, world?") == "hello, world"
    assert normalize_text("foo\tbar\nbaz") == "foo bar baz"


def test_sha256_hex_matches_known_value() -> None:
    assert sha256_hex("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
