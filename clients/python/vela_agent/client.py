"""VelaAgent — the run-lifecycle wrapper around the three primitives.

Five-line shape:

    agent = VelaAgent(
        model_name="claude-opus-4.7",
        model_version="claude-opus-4.7-20260411",
        frontier_path=Path("examples/alzheimers-bbb"),
        signing_key=key,
        actor="agent:literature_scout",
    )
    agent.open_run(prompt="reconcile BBB-shared sister findings")
    agent.add_proposal(kind="finding.add", payload={...})
    agent.record_tool_call(tool_name="search_arxiv", input_obj={...}, output_obj={...}, duration_ms=1200)
    pack_id = agent.submit_diff_pack(summary="...", aggregate_kind="finding.cluster_revision")

submit_diff_pack closes the open run, writes the vaa_* envelope, and
emits a signed vsd_* Diff Pack that bundles every proposal queued
under the run. Both records land in the frontier's .vela/ tree:

    .vela/agent_attestations/<vaa_id>.json
    .vela/diff_packs/<vsd_id>.json
    .vela/agent_proposals/<vpr_id>.json   (one per queued proposal)

SDK stubs live under `.vela/agent_proposals/`, not `.vela/proposals/`:
the canonical-proposal directory is reserved for substrate-validated
`StateProposal` records walked by the Rust loader. SDK stubs are a
distinct primitive awaiting an import path.

The proposal JSON files are SDK-shape stubs; a downstream import path
(`vela propose --from-sdk-stub`) is a v0.197 / future-cycle concern.
The pack itself carries the canonical proposal ids and the vaa_*
link, so the substrate has every dependency wired before the import
path lands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from .primitives import (
    AgentAttestation,
    ScientificDiffPack,
    ToolCall,
    derive_proposal_id,
    sha256_hex,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class _QueuedProposal:
    proposal_id: str
    kind: str
    payload: dict[str, Any]
    proposed_at: str
    actor: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "vela.agent_sdk.proposal_stub.v0.1",
            "proposal_id": self.proposal_id,
            "kind": self.kind,
            "payload": self.payload,
            "proposed_at": self.proposed_at,
            "actor": self.actor,
            "meta": self.meta,
        }


@dataclass
class _OpenRun:
    prompt: str | None
    prompt_hash: str | None
    started_at: str
    parent_attestation: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    queued: list[_QueuedProposal] = field(default_factory=list)
    output_hashes: list[str] = field(default_factory=list)
    total_tokens: int = 0


class VelaAgent:
    """Run-lifecycle wrapper. Not thread-safe; one VelaAgent instance
    represents one logical agent producing artifacts for one frontier
    under one signing key. Multiple runs against the same agent are
    fine in sequence (open_run / submit_diff_pack / open_run / ...).
    """

    def __init__(
        self,
        *,
        model_name: str,
        model_version: str,
        frontier_path: Path | str,
        signing_key: SigningKey,
        actor: str,
        frontier_id: str | None = None,
    ) -> None:
        if not actor.startswith("agent:"):
            raise ValueError(f"actor must start with `agent:`, got `{actor}`")
        self.model_name = model_name
        self.model_version = model_version
        self.frontier_path = Path(frontier_path)
        self.signing_key = signing_key
        self.actor = actor
        self._frontier_id = frontier_id
        self._run: _OpenRun | None = None
        self._last_attestation_id: str | None = None

    # ---- run lifecycle ---------------------------------------------------

    def open_run(
        self,
        *,
        prompt: str | None = None,
        parent_attestation: str | None = None,
        started_at: str | None = None,
    ) -> None:
        if self._run is not None:
            raise RuntimeError("a run is already open; close it before opening another")
        prompt_hash = sha256_hex(prompt) if prompt else None
        self._run = _OpenRun(
            prompt=prompt,
            prompt_hash=prompt_hash,
            started_at=started_at or _now(),
            parent_attestation=parent_attestation,
        )

    def close_run(self) -> None:
        """Discard the open run without producing a diff pack. Useful
        when the agent decides mid-run there is nothing worth
        proposing.
        """
        self._run = None

    # ---- mutation under the open run -------------------------------------

    def add_proposal(
        self,
        *,
        kind: str,
        payload: dict[str, Any],
        meta: dict[str, Any] | None = None,
        proposed_at: str | None = None,
    ) -> str:
        run = self._require_run()
        proposed_at = proposed_at or _now()
        pid = derive_proposal_id(kind, payload, proposed_at, self.actor)
        run.queued.append(
            _QueuedProposal(
                proposal_id=pid,
                kind=kind,
                payload=payload,
                proposed_at=proposed_at,
                actor=self.actor,
                meta=dict(meta or {}),
            )
        )
        return pid

    def record_tool_call(
        self,
        *,
        tool_name: str,
        input_obj: Any,
        output_obj: Any,
        duration_ms: int,
        tokens: int = 0,
    ) -> None:
        run = self._require_run()
        run.tool_calls.append(
            ToolCall(
                tool_name=tool_name,
                input_hash=_hash_canonical(input_obj),
                output_hash=_hash_canonical(output_obj),
                duration_ms=duration_ms,
            )
        )
        run.total_tokens += tokens

    def record_output_artifact(self, artifact: Any, tokens: int = 0) -> str:
        """Hash an artifact the agent produced (e.g. a free-text
        finding draft, a JSON payload) and add its sha256 to the
        attestation's `output_hashes`. Returns the hash so the caller
        can stash it alongside the artifact.
        """
        run = self._require_run()
        h = _hash_canonical(artifact)
        run.output_hashes.append(h)
        run.total_tokens += tokens
        return h

    # ---- closing the run into vaa_* + vsd_* ------------------------------

    def submit_diff_pack(
        self,
        *,
        summary: str,
        aggregate_kind: str,
        finished_at: str | None = None,
        parent_pack: str | None = None,
        write: bool = True,
    ) -> tuple[str, str]:
        """Closes the open run, writes the vaa_* attestation and the
        vsd_* Diff Pack, and returns the (vaa_id, vsd_id) pair.

        Side effects when `write=True`:
          - writes .vela/agent_attestations/<vaa>.json
          - writes .vela/diff_packs/<vsd>.json
          - writes .vela/agent_proposals/<vpr>.json (one per queued)
        """
        run = self._require_run()
        finished_at = finished_at or _now()

        # Hash every queued proposal payload into output_hashes so the
        # attestation pins what the agent produced (in addition to
        # any explicitly-recorded artifacts).
        for q in run.queued:
            run.output_hashes.append(_hash_canonical(q.payload))

        attestation = AgentAttestation.build(
            key=self.signing_key,
            agent_actor=self.actor,
            model_name=self.model_name,
            model_version=self.model_version,
            started_at=run.started_at,
            finished_at=finished_at,
            total_tokens=run.total_tokens,
            tool_calls=run.tool_calls,
            output_hashes=run.output_hashes,
            prompt_hash=run.prompt_hash,
            parent_attestation=run.parent_attestation,
        )

        frontier_id = self._resolve_frontier_id()
        pack = ScientificDiffPack.build(
            frontier_id=frontier_id,
            created_at=finished_at,
            summary=summary,
            proposals=[q.proposal_id for q in run.queued],
            aggregate_kind=aggregate_kind,
            agent_run=attestation.attestation_id,
            parent_pack=parent_pack,
        )
        pack.sign(self.signing_key)

        if write:
            self._write_artifacts(attestation, pack, run.queued)

        self._last_attestation_id = attestation.attestation_id
        self._run = None
        return attestation.attestation_id, pack.pack_id

    # ---- introspection ---------------------------------------------------

    @property
    def open(self) -> bool:
        return self._run is not None

    @property
    def queued_proposal_ids(self) -> list[str]:
        if self._run is None:
            return []
        return [q.proposal_id for q in self._run.queued]

    @property
    def last_attestation_id(self) -> str | None:
        return self._last_attestation_id

    # ---- internals -------------------------------------------------------

    def _require_run(self) -> _OpenRun:
        if self._run is None:
            raise RuntimeError("no open run; call open_run() first")
        return self._run

    # ---- publish to hub ---------------------------------------------------

    def publish_to_hub(
        self,
        pack_id: str,
        *,
        hub_url: str = "https://vela-hub.fly.dev",
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        """POST a signed Scientific Diff Pack to a Vela hub.

        Reads the pack from `.vela/diff_packs/<pack_id>.json` and the
        member proposal stubs from `.vela/agent_proposals/` (the SDK
        location, not the canonical `.vela/proposals/`). Returns the
        hub's JSON response.

        The hub validates the signature, inserts into
        `registry_diff_packs` (idempotent on (pack_id, signature)),
        and returns the canonical pack id + whether the row was
        newly inserted.

        Substrate-honest: this is the federation handle. The pack
        becomes addressable at `<hub_url>/diff-packs/<pack_id>` once
        published. It does NOT auto-accept the pack — the verdict
        flow stays on v0.203 workbench + v0.205 promoter.
        """
        import json as _json
        import urllib.request

        pack_path = self.frontier_path / ".vela" / "diff_packs" / f"{pack_id}.json"
        if not pack_path.is_file():
            raise FileNotFoundError(
                f"pack {pack_id} not at {pack_path}; run submit_diff_pack first"
            )
        pack = _json.loads(pack_path.read_text(encoding="utf-8"))

        # Optionally include resolved proposal stubs for cross-impl
        # reviewer convenience. The hub doesn't store them separately
        # (the pack carries member ids), but echoing them in the body
        # lets the hub validate the SDK output shape.
        proposals = []
        stubs_dir = self.frontier_path / ".vela" / "agent_proposals"
        if stubs_dir.is_dir():
            for vpr in pack.get("proposals", []):
                p = stubs_dir / f"{vpr}.json"
                if p.is_file():
                    try:
                        proposals.append(_json.loads(p.read_text(encoding="utf-8")))
                    except Exception:
                        pass

        body = _json.dumps({"pack": pack, "proposals": proposals}).encode("utf-8")
        req = urllib.request.Request(
            f"{hub_url.rstrip('/')}/diff-packs",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                response_body = resp.read().decode("utf-8")
                return _json.loads(response_body)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            try:
                return _json.loads(err_body)
            except Exception:
                return {"ok": False, "status": e.code, "error": err_body}

    def _resolve_frontier_id(self) -> str:
        if self._frontier_id is not None:
            return self._frontier_id
        manifest = self.frontier_path / "frontier.json"
        if manifest.is_file():
            try:
                with manifest.open("rb") as f:
                    data = json.loads(f.read().decode("utf-8"))
                fid = (
                    data.get("frontier_id")
                    or data.get("project", {}).get("frontier_id")
                    or data.get("id")
                )
                if isinstance(fid, str) and fid.startswith("vfr_"):
                    return fid
            except (OSError, json.JSONDecodeError, AttributeError):
                pass
        manifest_yaml = self.frontier_path / "frontier.yaml"
        if manifest_yaml.is_file():
            try:
                text = manifest_yaml.read_text(encoding="utf-8")
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("frontier_id:"):
                        candidate = line.split(":", 1)[1].strip().strip('"').strip("'")
                        if candidate.startswith("vfr_"):
                            return candidate
            except OSError:
                pass
        raise RuntimeError(
            f"could not resolve frontier_id from {self.frontier_path}. "
            "Pass `frontier_id=...` to VelaAgent explicitly."
        )

    def _write_artifacts(
        self,
        attestation: AgentAttestation,
        pack: ScientificDiffPack,
        queued: list[_QueuedProposal],
    ) -> None:
        vela_dir = self.frontier_path / ".vela"
        att_dir = vela_dir / "agent_attestations"
        pack_dir = vela_dir / "diff_packs"
        prop_dir = vela_dir / "agent_proposals"
        for d in (att_dir, pack_dir, prop_dir):
            d.mkdir(parents=True, exist_ok=True)
        _write_json(att_dir / f"{attestation.attestation_id}.json", attestation.to_json())
        _write_json(pack_dir / f"{pack.pack_id}.json", pack.to_json())
        for q in queued:
            _write_json(prop_dir / f"{q.proposal_id}.json", q.to_json())


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _hash_canonical(obj: Any) -> str:
    """Sha256 of a canonical JSON encoding (or raw bytes/str).
    Sorted keys + separators=(',', ':') makes dict ordering irrelevant.
    """
    if isinstance(obj, (bytes, bytearray)):
        return sha256_hex(bytes(obj))
    if isinstance(obj, str):
        return sha256_hex(obj)
    return sha256_hex(json.dumps(obj, sort_keys=True, separators=(",", ":")))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
