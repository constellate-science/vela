"""v0.208: ToolUniverse / AstaBench bridge.

A BenchSession wraps a benchmark run against a tool descriptor
(`vtd_*`) and produces a signed Evaluation Record (`ver_*`) targeting
either the descriptor (for tool-level benchmarks) or a substrate
object (`vsd_*`, `vtr_*`, `vf_*`, `vpf_*`, `vaa_*`).

Substrate-honest framing: this module does not run benchmarks. It is
a Python helper for capturing a benchmark run's (input, output,
score, outcome) and packaging the result into the v0.200 `ver_*`
primitive. The caller drives the actual tool invocation; the
BenchSession records what happened.

Five-line shape:

    bench = BenchSession(
        tool_descriptor_id="vtd_d50b932e406862a6",
        benchmark_id="astabench:protein-fold:v1",
        evaluator_actor="lab:replication_site_42",
        signing_key=SigningKey.generate(),
        frontier_path="examples/early-ad",
    )
    output = bench.run(input_obj={"sequence": "MASE..."})   # caller runs the tool
    ver_id = bench.record_result(score=0.84, outcome="succeeded",
                                  notes="3/3 attempts; mean folding TM-score 0.84")
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from nacl.signing import SigningKey
except ImportError as exc:  # pragma: no cover
    raise ImportError("vela_agent.bench requires pynacl") from exc

from .primitives import sha256_hex


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# ver_* canonical bytes mirror (matches crates/vela-protocol/src/evaluation_record.rs)
# ---------------------------------------------------------------------------


def _ver_preimage_bytes(
    *,
    target_kind: str,
    target_id: str,
    evaluation_kind: str,
    outcome: str,
    evaluator_actor: str,
    evaluated_at: str,
    evidence_refs: list[str],
    benchmark_id: Optional[str],
    score: Optional[float],
    notes: Optional[str],
) -> bytes:
    """Mirror of the Rust EvaluationRecord::preimage_bytes layout."""
    parts: list[bytes] = []
    parts.append(target_kind.encode("utf-8"))
    parts.append(b"|")
    parts.append(target_id.encode("utf-8"))
    parts.append(b"|")
    parts.append(evaluation_kind.encode("utf-8"))
    parts.append(b"|")
    parts.append(outcome.encode("utf-8"))
    parts.append(b"|")
    parts.append(evaluator_actor.encode("utf-8"))
    parts.append(b"|")
    parts.append(evaluated_at.encode("utf-8"))
    parts.append(b"|")
    for i, r in enumerate(evidence_refs):
        if i > 0:
            parts.append(b",")
        parts.append(r.encode("utf-8"))
    parts.append(b"|")
    if benchmark_id:
        parts.append(benchmark_id.encode("utf-8"))
    parts.append(b"|")
    if score is not None:
        # Mirror Rust's {:?} debug format for f64.
        parts.append(repr(float(score)).encode("utf-8"))
    parts.append(b"|")
    if notes:
        parts.append(notes.encode("utf-8"))
    return b"".join(parts)


def _derive_ver_id(preimage: bytes) -> str:
    return "ver_" + hashlib.sha256(preimage).hexdigest()[:16]


# ---------------------------------------------------------------------------
# BenchSession
# ---------------------------------------------------------------------------


_VALID_OUTCOMES = {"succeeded", "failed", "partial", "inconclusive"}
_VALID_KINDS = {"replication", "benchmark", "validation", "peer_review"}
_VALID_TARGET_KINDS = {"vsd", "vtr", "vf", "vpf", "vtd", "vaa"}


@dataclass
class BenchRun:
    """Captures one tool invocation under a BenchSession."""

    input_obj: Any
    output_obj: Any
    duration_ms: int
    started_at: str
    finished_at: str


class BenchSession:
    """Wraps a benchmark run against a tool descriptor (`vtd_*`).

    The session does NOT execute the tool itself. The caller invokes
    the tool through whatever harness is appropriate (HTTP request,
    Python callable, subprocess, MCP server) and feeds the result
    back via `record_result`. The session is responsible for:

      - Tracking the descriptor + benchmark identity
      - Capturing one or more BenchRun records (input/output/duration)
      - Producing a signed `ver_*` Evaluation Record once
        `record_result` is called

    Multi-run usage: each `run()` invocation captures one tool call.
    The session aggregates them into a single `ver_*` at
    `record_result` time.
    """

    def __init__(
        self,
        *,
        tool_descriptor_id: str,
        benchmark_id: str,
        evaluator_actor: str,
        signing_key: SigningKey,
        frontier_path: Path | str,
        target_kind: str = "vtd",
    ) -> None:
        if not tool_descriptor_id.startswith("vtd_"):
            raise ValueError(
                f"tool_descriptor_id must start with `vtd_`, got `{tool_descriptor_id}`"
            )
        if target_kind not in _VALID_TARGET_KINDS:
            raise ValueError(
                f"target_kind must be one of {sorted(_VALID_TARGET_KINDS)}, got `{target_kind}`"
            )
        self.tool_descriptor_id = tool_descriptor_id
        self.benchmark_id = benchmark_id
        self.evaluator_actor = evaluator_actor
        self.signing_key = signing_key
        self.frontier_path = Path(frontier_path)
        self.target_kind = target_kind
        self.runs: list[BenchRun] = []

    def run(
        self,
        *,
        input_obj: Any,
        invoke: Optional[Callable[[Any], Any]] = None,
        output_obj: Optional[Any] = None,
    ) -> Any:
        """Capture one tool invocation.

        Two calling patterns:

          (a) pass `invoke=<callable>`: the session times the call,
              records the output;
          (b) pass `output_obj` directly: the caller invoked the tool
              elsewhere and is feeding the result in.

        Returns the output_obj.
        """
        started = _now()
        t0 = time.monotonic()
        if invoke is not None:
            output_obj = invoke(input_obj)
        elif output_obj is None:
            raise ValueError("either `invoke` callable or explicit `output_obj` required")
        finished = _now()
        duration_ms = int((time.monotonic() - t0) * 1000)
        self.runs.append(
            BenchRun(
                input_obj=input_obj,
                output_obj=output_obj,
                duration_ms=duration_ms,
                started_at=started,
                finished_at=finished,
            )
        )
        return output_obj

    def record_result(
        self,
        *,
        score: Optional[float] = None,
        outcome: str = "succeeded",
        notes: Optional[str] = None,
        target_id: Optional[str] = None,
        evidence_refs: Optional[list[str]] = None,
        write: bool = True,
    ) -> str:
        """Close the session and produce a signed `ver_*` record.

        Args:
            score: Optional numeric score (must be finite if provided).
            outcome: one of succeeded / failed / partial / inconclusive.
            notes: free-text notes attached to the record.
            target_id: by default the bench session targets the tool
                descriptor passed at construction. Override here to
                target a different substrate object (e.g. a Diff Pack
                the benchmark was indirectly evaluating).
            evidence_refs: extra references to fold into the record's
                evidence_refs field.
            write: write the resulting JSON to `.vela/evaluations/`.

        Returns:
            The content-addressed `ver_*` id.
        """
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"outcome must be one of {sorted(_VALID_OUTCOMES)}, got `{outcome}`"
            )
        if score is not None and (score != score or score in (float("inf"), float("-inf"))):
            # NaN / Inf check
            raise ValueError("score must be a finite number")
        target_id = target_id if target_id is not None else self.tool_descriptor_id
        # Validate prefix matches target_kind.
        expected_prefix = f"{self.target_kind}_"
        if not target_id.startswith(expected_prefix):
            raise ValueError(
                f"target_id must start with `{expected_prefix}` for target_kind `{self.target_kind}`, "
                f"got `{target_id}`"
            )

        evaluation_kind = "benchmark"
        evaluated_at = _now()
        # Fold each run's output_hash into evidence_refs so a reviewer
        # can audit what the benchmark actually saw.
        refs: list[str] = list(evidence_refs or [])
        for run in self.runs:
            output_hash = _hash_canonical(run.output_obj)
            refs.append(f"benchrun:{output_hash}")

        preimage = _ver_preimage_bytes(
            target_kind=self.target_kind,
            target_id=target_id,
            evaluation_kind=evaluation_kind,
            outcome=outcome,
            evaluator_actor=self.evaluator_actor,
            evaluated_at=evaluated_at,
            evidence_refs=refs,
            benchmark_id=self.benchmark_id,
            score=score,
            notes=notes,
        )
        record_id = _derive_ver_id(preimage)

        # Sign the preimage so a downstream reviewer can verify the
        # bench operator under their published pubkey.
        signature_bytes = self.signing_key.sign(preimage).signature
        signature = signature_bytes.hex()
        pubkey_hex = bytes(self.signing_key.verify_key).hex()

        record: dict[str, Any] = {
            "schema": "vela.evaluation_record.v0.1",
            "record_id": record_id,
            "target_kind": self.target_kind,
            "target_id": target_id,
            "evaluation_kind": evaluation_kind,
            "outcome": outcome,
            "evaluator_actor": self.evaluator_actor,
            "evaluated_at": evaluated_at,
        }
        if refs:
            record["evidence_refs"] = refs
        if self.benchmark_id:
            record["benchmark_id"] = self.benchmark_id
        if score is not None:
            record["score"] = score
        if notes:
            record["notes"] = notes
        record["signature"] = signature
        record["signer_pubkey_hex"] = pubkey_hex

        if write:
            eval_dir = self.frontier_path / ".vela" / "evaluations"
            eval_dir.mkdir(parents=True, exist_ok=True)
            path = eval_dir / f"{record_id}.json"
            with path.open("w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, sort_keys=True)
                f.write("\n")

        return record_id


def _hash_canonical(obj: Any) -> str:
    """Sha256 of a canonical JSON encoding (mirrors client.py helper)."""
    if isinstance(obj, (bytes, bytearray)):
        return sha256_hex(bytes(obj))
    if isinstance(obj, str):
        return sha256_hex(obj)
    return sha256_hex(json.dumps(obj, sort_keys=True, separators=(",", ":")))
