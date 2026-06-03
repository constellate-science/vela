"""Vela v0.5 Python SDK.

A small, single-file client for `vela serve --http`. Wraps the read
endpoints (`/api/findings`, `/api/events`) and the signed write tools
(`propose_review`, `propose_note`, `propose_revise_confidence`,
`propose_retract`, `accept_proposal`, `reject_proposal`).

Idempotency is a substrate property: `propose_review` etc. compute the
content-addressed proposal_id locally, then send it to the server. A
retry with identical content returns the same `vpr_…` and the server
returns the existing record without duplication.

Doctrine: this SDK is the Python expression of the substrate's
canonical-JSON rule. Two implementations following only the documented
canonical-JSON spec produce byte-identical proposal_ids and signatures.

Dependencies: `requests` for HTTP, `cryptography` for Ed25519 signing.
Both are widely available. No build step.

Example:

    from vela import Frontier, Actor

    actor = Actor.load("~/.vela/actor.toml")
    f = Frontier.connect("http://localhost:3848")

    proposal = f.propose_review(
        finding_id="vf_...",
        status="contested",
        reason="conditions narrower than claim",
        actor=actor,
    )
    print(proposal.id, proposal.status)

    # Stream events past a cursor
    cursor = None
    for event in f.events_since(cursor):
        print(event.kind, event.target.id)
        cursor = event.id
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import requests

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
except ImportError:  # pragma: no cover - documented dependency
    raise ImportError(
        "vela-python requires `cryptography` for Ed25519 signing; install with `pip install cryptography`."
    )

PROPOSAL_SCHEMA = "vela.proposal.v0.1"


def _validate_provenance(provenance: dict) -> None:
    """Phase β (v0.6): client-side validation of structured provenance
    so callers fail fast with a clear message before signing. Mirrors
    server-side rule: must be a dict with at least one of doi/pmid/title.
    """
    if not isinstance(provenance, dict):
        raise ValueError("provenance must be a dict")
    has_id = any(
        provenance.get(k) and isinstance(provenance.get(k), str) and provenance[k].strip()
        for k in ("doi", "pmid", "title")
    )
    if not has_id:
        raise ValueError("provenance must include at least one of doi/pmid/title")


# ── Canonical JSON ──────────────────────────────────────────────────────────


def _canonicalize(value: Any) -> Any:
    """Recursively sort object keys; reject non-finite numbers.

    Mirrors the Rust implementation in `crates/vela-protocol/src/canonical.rs`.
    Two implementations following only this rule produce byte-identical output.
    """
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_canonicalize(v) for v in value]
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("canonical: non-finite float")
    return value


def to_canonical_bytes(value: Any) -> bytes:
    """Canonical UTF-8 encoding suitable for hashing and signing."""
    return json.dumps(
        _canonicalize(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(to_canonical_bytes(value)).hexdigest()


# ── Identity ────────────────────────────────────────────────────────────────


@dataclass
class Actor:
    """A registered Vela actor with an Ed25519 signing key.

    The CLI registers actors via `vela actor add`; this class loads the
    private-key file from disk and signs canonical preimages on demand.
    """

    id: str
    private_key_hex: str

    @classmethod
    def load(cls, config_path: str) -> "Actor":
        """Load an actor identity from a TOML/JSON config file.

        Expected shape (TOML or JSON):

            id = "reviewer:will-blair"
            private_key = "<hex>"
            # OR: private_key_path = "path/to/private.key"
        """
        path = Path(os.path.expanduser(config_path))
        text = path.read_text()
        if path.suffix == ".json":
            cfg = json.loads(text)
        else:
            cfg = _parse_toml_minimal(text)
        actor_id = cfg.get("id")
        if not actor_id:
            raise ValueError(f"actor config {path} missing `id`")
        priv = cfg.get("private_key")
        if priv is None:
            key_path = cfg.get("private_key_path")
            if not key_path:
                raise ValueError(f"actor config {path} missing private_key or private_key_path")
            priv = Path(os.path.expanduser(key_path)).read_text().strip()
        return cls(id=actor_id, private_key_hex=priv.strip())

    @classmethod
    def from_hex_key(cls, actor_id: str, private_key_hex: str) -> "Actor":
        return cls(id=actor_id, private_key_hex=private_key_hex.strip())

    def _signing_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.private_key_hex))

    def sign_bytes(self, data: bytes) -> str:
        return self._signing_key().sign(data).hex()


def _parse_toml_minimal(text: str) -> dict:
    """Minimal TOML parser sufficient for `id = "..."`-style configs.

    Avoids a tomllib dependency on Python <3.11. Handles only top-level
    string assignments — the SDK's actor config doesn't need anything else.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out[key.strip()] = val
    return out


# ── State objects ───────────────────────────────────────────────────────────


@dataclass
class Proposal:
    id: str
    finding_id: str
    status: str
    applied_event_id: str | None


@dataclass
class StateTarget:
    type: str
    id: str

    @classmethod
    def from_dict(cls, d: dict) -> "StateTarget":
        return cls(type=d["type"], id=d["id"])


@dataclass
class StateActor:
    id: str
    type: str

    @classmethod
    def from_dict(cls, d: dict) -> "StateActor":
        return cls(id=d["id"], type=d["type"])


@dataclass
class StateEvent:
    id: str
    kind: str
    target: StateTarget
    actor: StateActor
    timestamp: str
    reason: str
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, d: dict) -> "StateEvent":
        return cls(
            id=d["id"],
            kind=d["kind"],
            target=StateTarget.from_dict(d["target"]),
            actor=StateActor.from_dict(d["actor"]),
            timestamp=d["timestamp"],
            reason=d["reason"],
            payload=d.get("payload", {}),
        )


# ── Frontier client ─────────────────────────────────────────────────────────


class Frontier:
    """Connection to a `vela serve --http` instance.

    Read methods (`stats`, `findings`, `find`, `events_since`) require no
    identity. Write methods (`propose_*`, `accept`, `reject`) require an
    `Actor` registered via `vela actor add`.
    """

    def __init__(self, base_url: str, *, session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self._session = session or requests.Session()

    @classmethod
    def connect(cls, base_url: str) -> "Frontier":
        f = cls(base_url)
        # Eager-fetch /api/stats to validate the connection.
        f.stats()
        return f

    def _post_tool(self, name: str, args: dict) -> dict:
        r = self._session.post(
            f"{self.base_url}/api/tool",
            json={"name": name, "arguments": args},
            timeout=30,
        )
        # The server returns HTTP 500 for *tool-level* errors (bad signature,
        # tier rejection, etc.) with a structured `ok=false` body. Surface
        # those as VelaError, not HTTPError; only raise HTTPError for true
        # transport failures (404, 5xx without a tool body).
        try:
            body = r.json()
        except ValueError:
            r.raise_for_status()
            raise VelaError(f"tool {name}: non-JSON response (HTTP {r.status_code})")
        if not body.get("ok", False):
            err = body.get("error") or body.get("data") or {}
            text = err.get("text") if isinstance(err, dict) else err
            raise VelaError(f"tool {name} failed: {text}")
        return body["data"]

    # ── Reads ──────────────────────────────────────────────────────────

    def stats(self) -> dict:
        r = self._session.get(f"{self.base_url}/api/stats", timeout=30)
        r.raise_for_status()
        return r.json()

    def findings(self, *, query: str | None = None, limit: int = 50) -> dict:
        """Markdown search result (matches `/api/findings` shape).

        For a structured list of finding objects, prefer `list_findings()`
        which pulls the full project view from `/api/frontier`.
        """
        params: dict[str, str] = {"limit": str(limit)}
        if query:
            params["query"] = query
        r = self._session.get(f"{self.base_url}/api/findings", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def list_findings(self, *, limit: int | None = None) -> list[dict]:
        """Return the structured findings array from `/api/frontier`,
        optionally limited to the first `limit`. Suitable for picking
        target finding ids for write tools."""
        r = self._session.get(f"{self.base_url}/api/frontier", timeout=30)
        r.raise_for_status()
        body = r.json()
        items = body.get("findings", [])
        return items[:limit] if limit else items

    def find(self, finding_id: str) -> dict:
        r = self._session.get(f"{self.base_url}/api/findings/{finding_id}", timeout=30)
        r.raise_for_status()
        return r.json()

    def events_since(self, cursor: str | None = None, limit: int = 100) -> Iterator[StateEvent]:
        """Yield events from the canonical event log, paginating past
        `cursor` until the tail is reached."""
        while True:
            params: dict[str, str] = {"limit": str(limit)}
            if cursor:
                params["since"] = cursor
            r = self._session.get(f"{self.base_url}/api/events", params=params, timeout=30)
            r.raise_for_status()
            body = r.json()
            for raw in body.get("events", []):
                yield StateEvent.from_dict(raw)
            cursor = body.get("next_cursor")
            if cursor is None:
                return

    # ── Writes ─────────────────────────────────────────────────────────

    def _sign_proposal(
        self,
        kind: str,
        finding_id: str,
        actor: Actor,
        reason: str,
        payload: dict,
        created_at: str,
    ) -> tuple[str, str]:
        """Locally derive `vpr_…` and sign the canonical proposal preimage.
        Returns (proposal_id, signature_hex). The server re-derives both
        and rejects if they don't match.
        """
        # vpr_id preimage (Phase P: created_at excluded from content hash).
        id_preimage = {
            "schema": PROPOSAL_SCHEMA,
            "kind": kind,
            "target": {"type": "finding", "id": finding_id},
            "actor": {"id": actor.id, "type": "human"},
            "reason": reason,
            "payload": payload,
            "source_refs": [],
            "caveats": [],
        }
        proposal_id = "vpr_" + sha256_hex(id_preimage)[:16]
        # Signing preimage (full proposal incl. id + created_at).
        sign_preimage = {
            "schema": PROPOSAL_SCHEMA,
            "id": proposal_id,
            "kind": kind,
            "target": {"type": "finding", "id": finding_id},
            "actor": {"id": actor.id, "type": "human"},
            "created_at": created_at,
            "reason": reason,
            "payload": payload,
            "source_refs": [],
            "caveats": [],
        }
        signature = actor.sign_bytes(to_canonical_bytes(sign_preimage))
        return proposal_id, signature

    def propose_review(
        self,
        *,
        finding_id: str,
        status: str,
        reason: str,
        actor: Actor,
        created_at: str | None = None,
    ) -> Proposal:
        ts = created_at or datetime.now(timezone.utc).isoformat()
        _vpr, signature = self._sign_proposal(
            "finding.review",
            finding_id,
            actor,
            reason,
            {"status": status},
            ts,
        )
        data = self._post_tool(
            "propose_review",
            {
                "actor_id": actor.id,
                "target_finding_id": finding_id,
                "status": status,
                "reason": reason,
                "created_at": ts,
                "signature": signature,
            },
        )
        return Proposal(
            id=data["proposal_id"],
            finding_id=data["finding_id"],
            status=data["status"],
            applied_event_id=data.get("applied_event_id"),
        )

    def propose_note(
        self,
        *,
        finding_id: str,
        text: str,
        reason: str,
        actor: Actor,
        created_at: str | None = None,
        provenance: dict | None = None,
    ) -> Proposal:
        """Propose a `finding.note` annotation. Stays `pending_review`
        until accepted by a reviewer.

        `provenance` (Phase β, v0.6): optional structured source reference
        like `{"doi": "10.1234/x", "title": "..."}`. At least one of
        `doi`/`pmid`/`title` must be set when present. Reviewers can
        query annotations by these fields after the note is applied.
        """
        ts = created_at or datetime.now(timezone.utc).isoformat()
        payload: dict[str, Any] = {"text": text}
        if provenance is not None:
            _validate_provenance(provenance)
            payload["provenance"] = provenance
        _vpr, signature = self._sign_proposal(
            "finding.note",
            finding_id,
            actor,
            reason,
            payload,
            ts,
        )
        args: dict[str, Any] = {
            "actor_id": actor.id,
            "target_finding_id": finding_id,
            "text": text,
            "reason": reason,
            "created_at": ts,
            "signature": signature,
        }
        if provenance is not None:
            args["provenance"] = provenance
        data = self._post_tool("propose_note", args)
        return Proposal(
            id=data["proposal_id"],
            finding_id=data["finding_id"],
            status=data["status"],
            applied_event_id=data.get("applied_event_id"),
        )

    def propose_and_apply_note(
        self,
        *,
        finding_id: str,
        text: str,
        reason: str,
        actor: Actor,
        created_at: str | None = None,
        provenance: dict | None = None,
    ) -> Proposal:
        """Phase α (v0.6): one-call propose-and-apply for `finding.note`.

        Requires the actor to have `tier="auto-notes"` registered via
        `vela actor add --tier auto-notes`. Server-side check rejects
        non-tiered actors with a clear error.

        The signing preimage is identical to `propose_note`, so a retry
        with identical content returns the same `vpr_…` and the same
        `applied_event_id` — agent loops can retry idempotently.

        Returns a `Proposal` with `status="applied"` and `applied_event_id`
        populated on success.

        `provenance` (Phase β, v0.6): optional structured source reference;
        same shape as `propose_note`. The annotation that lands carries it
        as a typed field on the materialized `Annotation`.
        """
        ts = created_at or datetime.now(timezone.utc).isoformat()
        payload: dict[str, Any] = {"text": text}
        if provenance is not None:
            _validate_provenance(provenance)
            payload["provenance"] = provenance
        _vpr, signature = self._sign_proposal(
            "finding.note",
            finding_id,
            actor,
            reason,
            payload,
            ts,
        )
        args: dict[str, Any] = {
            "actor_id": actor.id,
            "target_finding_id": finding_id,
            "text": text,
            "reason": reason,
            "created_at": ts,
            "signature": signature,
        }
        if provenance is not None:
            args["provenance"] = provenance
        data = self._post_tool("propose_and_apply_note", args)
        return Proposal(
            id=data["proposal_id"],
            finding_id=data["finding_id"],
            status=data["status"],
            applied_event_id=data.get("applied_event_id"),
        )

    def propose_revise_confidence(
        self,
        *,
        finding_id: str,
        new_score: float,
        reason: str,
        actor: Actor,
        created_at: str | None = None,
    ) -> Proposal:
        ts = created_at or datetime.now(timezone.utc).isoformat()
        _vpr, signature = self._sign_proposal(
            "finding.confidence_revise",
            finding_id,
            actor,
            reason,
            {"new_score": new_score},
            ts,
        )
        data = self._post_tool(
            "propose_revise_confidence",
            {
                "actor_id": actor.id,
                "target_finding_id": finding_id,
                "new_score": new_score,
                "reason": reason,
                "created_at": ts,
                "signature": signature,
            },
        )
        return Proposal(
            id=data["proposal_id"],
            finding_id=data["finding_id"],
            status=data["status"],
            applied_event_id=data.get("applied_event_id"),
        )

    def propose_retract(
        self,
        *,
        finding_id: str,
        reason: str,
        actor: Actor,
        created_at: str | None = None,
    ) -> Proposal:
        ts = created_at or datetime.now(timezone.utc).isoformat()
        _vpr, signature = self._sign_proposal(
            "finding.retract",
            finding_id,
            actor,
            reason,
            {},
            ts,
        )
        data = self._post_tool(
            "propose_retract",
            {
                "actor_id": actor.id,
                "target_finding_id": finding_id,
                "reason": reason,
                "created_at": ts,
                "signature": signature,
            },
        )
        return Proposal(
            id=data["proposal_id"],
            finding_id=data["finding_id"],
            status=data["status"],
            applied_event_id=data.get("applied_event_id"),
        )

    def accept(self, proposal_id: str, *, reviewer: Actor, reason: str,
               timestamp: str | None = None) -> str:
        """Apply a pending proposal. Returns the resulting event_id."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        signature = reviewer.sign_bytes(
            to_canonical_bytes(
                {
                    "action": "accept",
                    "proposal_id": proposal_id,
                    "reviewer_id": reviewer.id,
                    "reason": reason,
                    "timestamp": ts,
                }
            )
        )
        data = self._post_tool(
            "accept_proposal",
            {
                "proposal_id": proposal_id,
                "reviewer_id": reviewer.id,
                "reason": reason,
                "timestamp": ts,
                "signature": signature,
            },
        )
        return data["applied_event_id"]

    def reject(self, proposal_id: str, *, reviewer: Actor, reason: str,
               timestamp: str | None = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        signature = reviewer.sign_bytes(
            to_canonical_bytes(
                {
                    "action": "reject",
                    "proposal_id": proposal_id,
                    "reviewer_id": reviewer.id,
                    "reason": reason,
                    "timestamp": ts,
                }
            )
        )
        self._post_tool(
            "reject_proposal",
            {
                "proposal_id": proposal_id,
                "reviewer_id": reviewer.id,
                "reason": reason,
                "timestamp": ts,
                "signature": signature,
            },
        )


class VelaError(Exception):
    pass


__all__ = [
    "Actor",
    "Frontier",
    "Proposal",
    "StateActor",
    "StateEvent",
    "StateTarget",
    "VelaError",
    "sha256_hex",
    "to_canonical_bytes",
]
