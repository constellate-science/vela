"""vela_agent — Python SDK for agents producing Vela substrate artifacts.

Composes the primitives so any LLM agent can submit a Scientific Diff
Pack (`vsd_*`) with an Agent Attestation envelope (`vaa_*`) in a handful
of lines. Mirrors the canonical-bytes id derivation and Ed25519 signing
from `crates/vela-protocol/src/scientific_diff.rs` and
`agent_attestation.rs` so a Python-emitted artifact verifies
byte-identically under the Rust loader.

Substrate-honesty: the SDK does not vouch for the correctness of the
agent's outputs. It packages them, signs them, and writes them to the
frontier's `.vela/` tree so a human reviewer can read, accept, or
reject through the same workbench surfaces a human-authored proposal
would pass through.

Public surface:
    VelaAgent          — run-lifecycle wrapper around vaa_* + vsd_*
    derive_proposal_id — content-addressed vpr_* from kind + payload
"""

from __future__ import annotations

from .bench import BenchSession
from .client import VelaAgent
from .reader import VelaReader
from .primitives import (
    AgentAttestation,
    ScientificDiffPack,
    derive_proposal_id,
    sha256_hex,
)

__all__ = [
    "VelaAgent",
    "VelaReader",
    "BenchSession",
    "AgentAttestation",
    "ScientificDiffPack",
    "derive_proposal_id",
    "sha256_hex",
]

__version__ = "0.337.0"
