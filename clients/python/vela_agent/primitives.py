"""Python mirrors of the v0.193 (vsd_*), v0.195 (vaa_*), and v0.194
trajectory (vtr_* / vts_*) primitives.

Every canonical-bytes layout in this module is a verbatim translation
of the Rust substrate's `preimage_bytes` methods:

  ScientificDiffPack -> crates/vela-protocol/src/scientific_diff.rs::preimage_bytes
  AgentAttestation   -> crates/vela-protocol/src/agent_attestation.rs::preimage_bytes
  TrajectoryStep     -> crates/vela-protocol/src/bundle.rs::TrajectoryStep::content_address
  Trajectory         -> crates/vela-protocol/src/bundle.rs::Trajectory::content_address

If a layout drifts here, the Python-produced ids will diverge from
the Rust-produced ids byte-for-byte. The accompanying tests round
trip fixed inputs and pin the expected ids so the divergence is
caught on the next run.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable

try:  # pragma: no cover - import guard
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError as exc:  # pragma: no cover - install error path
    raise ImportError(
        "vela_agent requires pynacl. Install with: pip install pynacl"
    ) from exc


SCIENTIFIC_DIFF_SCHEMA = "vela.scientific_diff.v0.1"
AGENT_ATTESTATION_SCHEMA = "vela.agent_attestation.v0.1"


def sha256_hex(data: bytes | str) -> str:
    """Return the lowercase hex sha256 digest of `data`."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalize_text(s: str) -> str:
    """Mirror of `FindingBundle::normalize_text` in Rust.

    Lowercase, collapse whitespace runs into single spaces, strip
    trailing `.`, `;`, `:`, `!`, `?`. The TrajectoryStep id derivation
    runs description through this so two semantically-identical steps
    do not collide on whitespace alone.
    """
    lower = s.lower()
    collapsed = " ".join(lower.split())
    return collapsed.rstrip(".;:!?")


# ---------------------------------------------------------------------------
# vsd_* — Scientific Diff Pack
# ---------------------------------------------------------------------------


@dataclass
class ScientificDiffPack:
    schema: str
    pack_id: str
    frontier_id: str
    created_at: str
    summary: str
    proposals: list[str]
    aggregate_kind: str
    agent_run: str | None = None
    parent_pack: str | None = None
    applied_event_id: str | None = None
    signature: str | None = None
    signer_pubkey_hex: str | None = None

    @staticmethod
    def build(
        frontier_id: str,
        created_at: str,
        summary: str,
        proposals: list[str],
        aggregate_kind: str,
        agent_run: str | None = None,
        parent_pack: str | None = None,
    ) -> "ScientificDiffPack":
        _validate_pack_inputs(
            frontier_id, summary, proposals, aggregate_kind, parent_pack, agent_run
        )
        pack = ScientificDiffPack(
            schema=SCIENTIFIC_DIFF_SCHEMA,
            pack_id="",
            frontier_id=frontier_id,
            created_at=created_at,
            summary=summary,
            proposals=list(proposals),
            aggregate_kind=aggregate_kind,
            agent_run=agent_run,
            parent_pack=parent_pack,
        )
        pack.pack_id = pack.derive_id()
        return pack

    def preimage_bytes(self) -> bytes:
        # Rust: scientific_diff.rs::preimage_bytes
        # Order: frontier_id | aggregate_kind | summary | created_at |
        #        proposals(,) | parent_pack? | agent_run?
        parts: list[bytes] = []
        parts.append(self.frontier_id.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.aggregate_kind.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.summary.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.created_at.encode("utf-8"))
        parts.append(b"|")
        for i, vpr in enumerate(self.proposals):
            if i > 0:
                parts.append(b",")
            parts.append(vpr.encode("utf-8"))
        parts.append(b"|")
        if self.parent_pack:
            parts.append(self.parent_pack.encode("utf-8"))
        parts.append(b"|")
        if self.agent_run:
            parts.append(self.agent_run.encode("utf-8"))
        return b"".join(parts)

    def derive_id(self) -> str:
        return "vsd_" + sha256_hex(self.preimage_bytes())[:16]

    def sign(self, key: SigningKey) -> None:
        sig = key.sign(self.preimage_bytes()).signature
        self.signature = sig.hex()
        self.signer_pubkey_hex = bytes(key.verify_key).hex()

    def verify(self) -> None:
        rederived = self.derive_id()
        if rederived != self.pack_id:
            raise ValueError(
                f"pack_id mismatch: declared {self.pack_id}, rebuilt {rederived}"
            )
        sig, pub = self.signature, self.signer_pubkey_hex
        if sig is None and pub is None:
            return
        if sig is None or pub is None:
            raise ValueError(
                "signature and signer_pubkey_hex must be set together"
            )
        verify = VerifyKey(bytes.fromhex(pub))
        try:
            verify.verify(self.preimage_bytes(), bytes.fromhex(sig))
        except BadSignatureError as e:
            raise ValueError(f"signature verify: {e}") from e

    def to_json(self) -> dict[str, Any]:
        out = asdict(self)
        return {k: v for k, v in out.items() if v is not None}


def _validate_pack_inputs(
    frontier_id: str,
    summary: str,
    proposals: list[str],
    aggregate_kind: str,
    parent_pack: str | None,
    agent_run: str | None,
) -> None:
    if not frontier_id.startswith("vfr_"):
        raise ValueError(
            f"frontier_id must start with `vfr_`, got `{frontier_id}`"
        )
    if not summary:
        raise ValueError("summary cannot be empty")
    if len(summary) > 280:
        raise ValueError("summary exceeds 280 chars")
    if not proposals:
        raise ValueError("a pack must bundle at least one proposal")
    for vpr in proposals:
        if not vpr.startswith("vpr_"):
            raise ValueError(
                f"every member must start with `vpr_`, got `{vpr}`"
            )
    if not aggregate_kind:
        raise ValueError("aggregate_kind cannot be empty")
    if parent_pack is not None and not parent_pack.startswith("vsd_"):
        raise ValueError(
            f"parent_pack must start with `vsd_`, got `{parent_pack}`"
        )
    if agent_run is not None and not agent_run.startswith("vaa_"):
        raise ValueError(
            f"agent_run must start with `vaa_`, got `{agent_run}`"
        )


# ---------------------------------------------------------------------------
# vaa_* — Agent Attestation Envelope
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    tool_name: str
    input_hash: str
    output_hash: str
    duration_ms: int


@dataclass
class AgentAttestation:
    schema: str
    attestation_id: str
    agent_actor: str
    model_name: str
    model_version: str
    started_at: str
    finished_at: str
    total_tokens: int
    tool_calls: list[ToolCall]
    output_hashes: list[str]
    signature: str
    signer_pubkey_hex: str
    prompt_hash: str | None = None
    parent_attestation: str | None = None

    @staticmethod
    def build(
        *,
        key: SigningKey,
        agent_actor: str,
        model_name: str,
        model_version: str,
        started_at: str,
        finished_at: str,
        total_tokens: int,
        tool_calls: Iterable[ToolCall],
        output_hashes: Iterable[str],
        prompt_hash: str | None = None,
        parent_attestation: str | None = None,
    ) -> "AgentAttestation":
        tool_calls = list(tool_calls)
        output_hashes = list(output_hashes)
        _validate_attestation_inputs(
            agent_actor=agent_actor,
            model_name=model_name,
            model_version=model_version,
            tool_calls=tool_calls,
            output_hashes=output_hashes,
            prompt_hash=prompt_hash,
            parent_attestation=parent_attestation,
        )
        envelope = AgentAttestation(
            schema=AGENT_ATTESTATION_SCHEMA,
            attestation_id="",
            agent_actor=agent_actor,
            model_name=model_name,
            model_version=model_version,
            started_at=started_at,
            finished_at=finished_at,
            total_tokens=total_tokens,
            tool_calls=tool_calls,
            output_hashes=output_hashes,
            signature="",
            signer_pubkey_hex=bytes(key.verify_key).hex(),
            prompt_hash=prompt_hash,
            parent_attestation=parent_attestation,
        )
        preimage = envelope.preimage_bytes()
        envelope.signature = key.sign(preimage).signature.hex()
        envelope.attestation_id = envelope.derive_id()
        return envelope

    def preimage_bytes(self) -> bytes:
        # Rust: agent_attestation.rs::preimage_bytes
        parts: list[bytes] = []
        parts.append(self.agent_actor.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.model_name.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.model_version.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.started_at.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.finished_at.encode("utf-8"))
        parts.append(b"|")
        parts.append(str(self.total_tokens).encode("utf-8"))
        parts.append(b"|")
        for i, tc in enumerate(self.tool_calls):
            if i > 0:
                parts.append(b",")
            parts.append(tc.tool_name.encode("utf-8"))
            parts.append(b":")
            parts.append(tc.input_hash.encode("utf-8"))
            parts.append(b":")
            parts.append(tc.output_hash.encode("utf-8"))
        parts.append(b"|")
        for i, h in enumerate(self.output_hashes):
            if i > 0:
                parts.append(b",")
            parts.append(h.encode("utf-8"))
        parts.append(b"|")
        if self.prompt_hash:
            parts.append(self.prompt_hash.encode("utf-8"))
        parts.append(b"|")
        if self.parent_attestation:
            parts.append(self.parent_attestation.encode("utf-8"))
        parts.append(b"|")
        parts.append(self.signer_pubkey_hex.encode("utf-8"))
        return b"".join(parts)

    def derive_id(self) -> str:
        h = hashlib.sha256()
        h.update(self.preimage_bytes())
        h.update(b"|")
        h.update(self.signature.encode("utf-8"))
        return "vaa_" + h.hexdigest()[:16]

    def verify(self) -> None:
        pubkey = VerifyKey(bytes.fromhex(self.signer_pubkey_hex))
        try:
            pubkey.verify(self.preimage_bytes(), bytes.fromhex(self.signature))
        except BadSignatureError as e:
            raise ValueError(f"signature verify: {e}") from e
        rederived = self.derive_id()
        if rederived != self.attestation_id:
            raise ValueError(
                f"attestation_id mismatch: declared {self.attestation_id}, "
                f"rebuilt {rederived}"
            )

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema": self.schema,
            "attestation_id": self.attestation_id,
            "agent_actor": self.agent_actor,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_tokens": self.total_tokens,
            "tool_calls": [asdict(tc) for tc in self.tool_calls],
            "output_hashes": self.output_hashes,
            "signature": self.signature,
            "signer_pubkey_hex": self.signer_pubkey_hex,
        }
        if self.prompt_hash is not None:
            out["prompt_hash"] = self.prompt_hash
        if self.parent_attestation is not None:
            out["parent_attestation"] = self.parent_attestation
        return out


def _validate_attestation_inputs(
    *,
    agent_actor: str,
    model_name: str,
    model_version: str,
    tool_calls: list[ToolCall],
    output_hashes: list[str],
    prompt_hash: str | None,
    parent_attestation: str | None,
) -> None:
    if not agent_actor.startswith("agent:"):
        raise ValueError(
            f"agent_actor must start with `agent:`, got `{agent_actor}`"
        )
    if not model_name:
        raise ValueError("model_name cannot be empty")
    if not model_version:
        raise ValueError("model_version cannot be empty")
    for h in output_hashes:
        if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
            raise ValueError(f"output_hash must be 64 hex chars, got `{h}`")
    for tc in tool_calls:
        for label, val in (("input_hash", tc.input_hash), ("output_hash", tc.output_hash)):
            if len(val) != 64 or not all(c in "0123456789abcdef" for c in val):
                raise ValueError(
                    f"tool_call.{label} must be 64 hex chars, got `{val}`"
                )
    if prompt_hash is not None:
        if len(prompt_hash) != 64 or not all(c in "0123456789abcdef" for c in prompt_hash):
            raise ValueError(f"prompt_hash must be 64 hex chars, got `{prompt_hash}`")
    if parent_attestation is not None and not parent_attestation.startswith("vaa_"):
        raise ValueError(
            f"parent_attestation must start with `vaa_`, got `{parent_attestation}`"
        )


# ---------------------------------------------------------------------------
# vtr_* / vts_* — Trajectory + TrajectoryStep
# ---------------------------------------------------------------------------


class TrajectoryStepKind(str, Enum):
    """v0.194 step taxonomy. Five legacy kinds plus the twelve
    vision-taxonomy kinds. Strings match the Rust `canonical()`
    output so JSON round-trips byte-identically with the substrate.
    """

    # Legacy (v0.50)
    HYPOTHESIS = "hypothesis"
    TRIED = "tried"
    RULED_OUT = "ruled_out"
    OBSERVED = "observed"
    REFINED = "refined"

    # v0.194 vision-taxonomy
    QUESTION = "question"
    CONTEXT = "context"
    DATA = "data"
    TOOL = "tool"
    MODEL = "model"
    EXPERT = "expert"
    DECISION = "decision"
    PROTOCOL = "protocol"
    OUTPUT = "output"
    REVIEW = "review"
    RISK = "risk"
    OUTCOME = "outcome"


@dataclass
class TrajectoryStep:
    id: str
    kind: TrajectoryStepKind
    description: str
    at: str
    actor: str
    references: list[str] = field(default_factory=list)

    @staticmethod
    def content_address(
        trajectory_id: str,
        kind: TrajectoryStepKind,
        description: str,
        at: str,
        actor: str,
    ) -> str:
        preimage = (
            f"{trajectory_id}|{kind.value}|{normalize_text(description)}|{at}|{actor}"
        )
        return "vts_" + sha256_hex(preimage)[:16]

    @staticmethod
    def make(
        trajectory_id: str,
        kind: TrajectoryStepKind,
        description: str,
        at: str,
        actor: str,
        references: list[str] | None = None,
    ) -> "TrajectoryStep":
        sid = TrajectoryStep.content_address(trajectory_id, kind, description, at, actor)
        return TrajectoryStep(
            id=sid,
            kind=kind,
            description=description,
            at=at,
            actor=actor,
            references=list(references or []),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "description": self.description,
            "at": self.at,
            "actor": self.actor,
            "references": self.references,
        }


def trajectory_content_address(
    target_findings: list[str], deposited_by: str, created: str
) -> str:
    sorted_targets = sorted(target_findings)
    preimage = f"{','.join(sorted_targets)}|{deposited_by}|{created}"
    return "vtr_" + sha256_hex(preimage)[:16]


# ---------------------------------------------------------------------------
# vpr_* — Proposal id derivation (SDK convenience)
# ---------------------------------------------------------------------------


def derive_proposal_id(kind: str, payload: dict[str, Any], proposed_at: str, actor: str) -> str:
    """Content-addressed proposal id derived from (kind, payload, at,
    actor). Sort-keys-stable JSON serialization makes the same dict
    always produce the same id, independent of ordering.

    The Rust substrate has a richer `StateProposal` shape with its own
    id derivation; SDK-side ids are an honest convention so the
    Scientific Diff Pack can reference proposals before the Rust CLI
    has signed them into canonical events. When `vela propose` later
    imports an SDK-emitted payload it can either accept the SDK id or
    rederive its own; v0.193 keeps both paths open.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    preimage = f"{kind}|{canonical}|{proposed_at}|{actor}"
    return "vpr_" + sha256_hex(preimage)[:16]
