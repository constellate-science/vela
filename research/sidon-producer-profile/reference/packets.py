#!/usr/bin/env python3
"""Signed packet envelope for the Vela Sidon Producer Profile v1."""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from canonical import canonical_bytes, content_id

SCHEMA_VERSION = "vela.sidon-producer-profile.v1"
PACKET_ID_DOMAIN = b"vela.packet-id.v1\x00"
SIGNATURE_DOMAIN = b"vela.packet-signature.v1\x00"

PREFIX = {
    "observation": "vop_",
    "task": "vtk_",
    "result": "vrs_",
    "gate_receipt": "vgr_",
    "acceptance": "vac_",
    "support_function": "vsf_",
    "challenge": "vch_",
    "view_decision": "vvd_",
    "repair": "vrp_",
}


def packet_body(packet: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in packet.items() if k not in {"packet_id", "signature"}}


def packet_id(packet_type: str, body: dict[str, Any]) -> str:
    if packet_type not in PREFIX:
        raise ValueError(f"unknown packet type: {packet_type}")
    # content_id already domain-separates canonical values. Include a second,
    # packet-specific label so packet IDs cannot collide semantically with
    # unrelated content-addressed objects using the same prefix.
    return content_id(PREFIX[packet_type], {
        "domain": PACKET_ID_DOMAIN.decode("latin1"),
        "packet_type": packet_type,
        "body": body,
    })


def signing_preimage(pid: str, body: dict[str, Any]) -> bytes:
    return SIGNATURE_DOMAIN + pid.encode("ascii") + b"\x00" + canonical_bytes(body)


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def signed_packet(
    packet_type: str,
    fields: dict[str, Any],
    private_key: Ed25519PrivateKey,
    actor: str,
) -> dict[str, Any]:
    if any(k in fields for k in ("packet_id", "signature", "schema_version", "packet_type", "signer_actor", "signer_public_key")):
        raise ValueError("reserved packet field supplied")
    body = {
        "schema_version": SCHEMA_VERSION,
        "packet_type": packet_type,
        "signer_actor": actor,
        "signer_public_key": public_key_b64(private_key),
        **fields,
    }
    pid = packet_id(packet_type, body)
    signature = private_key.sign(signing_preimage(pid, body))
    return {
        **body,
        "packet_id": pid,
        "signature": {
            "algorithm": "ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_signed_packet(packet: dict[str, Any]) -> None:
    ptype = packet.get("packet_type")
    if ptype not in PREFIX:
        raise AssertionError(f"unknown packet type: {ptype!r}")
    if packet.get("schema_version") != SCHEMA_VERSION:
        raise AssertionError("unsupported packet schema version")
    body = packet_body(packet)
    expected = packet_id(ptype, body)
    if packet.get("packet_id") != expected:
        raise AssertionError("packet id mismatch")
    signature = packet.get("signature", {})
    if signature.get("algorithm") != "ed25519":
        raise AssertionError("unsupported signature algorithm")
    try:
        raw_key = base64.b64decode(packet["signer_public_key"], validate=True)
        raw_sig = base64.b64decode(signature["value"], validate=True)
    except Exception as exc:
        raise AssertionError(f"invalid base64 in signed packet: {exc}") from exc
    if len(raw_key) != 32 or len(raw_sig) != 64:
        raise AssertionError("invalid Ed25519 key or signature length")
    Ed25519PublicKey.from_public_bytes(raw_key).verify(
        raw_sig,
        signing_preimage(expected, body),
    )


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(("vela-sidon-fixture:" + label).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)
