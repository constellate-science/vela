//! Tool registry — tools defined as data, separate from execution.
//! Borrowed from Codex (MIT) tool-as-data pattern.

use crate::permission::PermissionLevel;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
    pub permission_level: PermissionLevel,
    pub mutating: bool,
    pub caveats: Vec<String>,
}

/// All MCP tools registered in Vela
pub fn all_tools() -> Vec<ToolDefinition> {
    vec![
        tool(
            "frontier_stats",
            "Return frontier metadata and statistics: finding count, links, confidence distribution, gaps, categories, and review state.",
            json!({"type": "object", "properties": {}}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "search_findings",
            "Search findings by text content, entity name, entity type, or assertion type. Returns matching findings.",
            json!({"type": "object", "properties": {
                "query": {"type": "string"}, "entity": {"type": "string"},
                "entity_type": {"type": "string"}, "assertion_type": {"type": "string"},
                "limit": {"type": "integer"}
            }}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "get_finding",
            "Get a single finding by ID, including evidence, conditions, links, confidence, and provenance.",
            json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "get_finding_history",
            "v0.17: Return the chronological event log for one finding (asserted, reviewed, caveated, noted, confidence-revised, superseded, retracted). Use this to walk the supersedes chain, audit corrections, or detect that a target has been refined since you last linked to it.",
            json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Event order reflects timestamps as recorded; sort client-side if you need a different ordering.",
            ],
        ),
        tool(
            "list_gaps",
            "List findings flagged as candidate gap review leads.",
            json!({"type": "object", "properties": {}}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Candidate gap rankings are review leads, not guaranteed underexplored areas or experiment targets.",
            ],
        ),
        tool(
            "list_contradictions",
            "List contradiction and dispute links between findings.",
            json!({"type": "object", "properties": {}}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Automated contradiction links are candidates for review, not definitive disagreements.",
            ],
        ),
        tool(
            "check_pubmed",
            "Run a rough PubMed prior-art check for a hypothesis.",
            json!({"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
            PermissionLevel::ReadOnly,
            false,
            vec!["PubMed counts are rough prior-art signals, not proof of novelty."],
        ),
        tool(
            "propagate_retraction",
            "Simulate retraction cascade impact over declared dependency/support links.",
            json!({"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}),
            PermissionLevel::Dangerous,
            false,
            vec!["Retraction impact is simulated over declared links only."],
        ),
        tool(
            "trace_evidence_chain",
            "Trace evidence lineage for a finding, including support, dependency, contradiction, and chain strength.",
            json!({"type": "object", "properties": {
                "finding_id": {"type": "string"}, "depth": {"type": "integer"}
            }, "required": ["finding_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec!["Evidence-chain strength is heuristic and depends on declared links."],
        ),
        // Inbound counterpart to trace_evidence_chain: "what rests on
        // this finding?" Walks the reverse link graph. Distinct from
        // propagate_retraction (Dangerous, retraction-cascade framing) —
        // this is plain read-only navigation for agents orienting in a
        // frontier, especially when several frontiers are open at once.
        tool(
            "list_dependents",
            "List the findings that cite or rest on a given finding (its dependents — the inbound side of the link graph). Direct dependents cover every link type pointing at the target; set `transitive` to also return the full causal closure over `depends`/`supports` edges. Read-only navigation; for retraction-cascade impact use `propagate_retraction`.",
            json!({"type": "object", "properties": {
                "finding_id": {"type": "string"},
                "transitive": {"type": "boolean"},
                "limit": {"type": "integer"}
            }, "required": ["finding_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Dependents reflect declared links only; absence of a dependent is not proof nothing relies on the finding.",
                "Transitive closure follows depends/supports edges within this frontier; cross-frontier (vf_…@vfr_…) links are not traversed.",
            ],
        ),
        // One-shot orientation: the node plus its immediate graph
        // neighborhood (rests-on, dependents, sideways relations,
        // contradictions) in a single call, so an agent juggling
        // several frontiers needn't chain get_finding + trace + deps.
        tool(
            "context",
            "Return the local graph neighborhood of a finding in one call: the finding itself, what it rests on (outbound depends/supports/derived edges), what rests on it (inbound dependents), sideways relations (extends/improves/generalizes/specializes/supersedes), and its contradictions in both directions. Orientation for agents working across frontiers.",
            json!({"type": "object", "properties": {
                "finding_id": {"type": "string"},
                "limit": {"type": "integer"}
            }, "required": ["finding_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec!["Neighborhood relations are declared links, not adjudicated truth."],
        ),
        // The one-call problem briefing (the CodeGraph lesson for
        // frontier state): everything an agent needs to pick up a
        // problem without re-deriving it from prose — statement, gate
        // status, open obligations (gap-flagged findings), attempts,
        // dependents, and staleness — resolvable by problem number.
        tool(
            "frontier_explore",
            "One-call briefing for a single problem: resolve it by problem number (e.g. \"617\") or finding id, and return its statement, verification gate status, open obligations (gap-flagged findings — what is unproven / the current bottleneck / the next step), what it rests on, what depends on it, and staleness (the age of its most recent event). Built so an agent can pick up where the frontier left off without re-reading handoff notes. Read-only.",
            json!({"type": "object", "properties": {
                "problem": {"type": "string", "description": "Problem number, finding id, or a substring of the statement"}
            }, "required": ["problem"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Obligations and routes are stated work items, not adjudicated truth; the gate status reflects only what has been verified.",
                "Staleness is the age of the latest event on this finding, not a guarantee the state is current.",
            ],
        ),
        tool(
            "task_packet",
            "The agent ENTRY CONTRACT for a problem, in one call: statement, frontier state hashes, gate status, the ALLOWED OUTPUT TYPES (each mapped to the frozen verifier kind that checks it), failed-route memory (banked/exhausted channels — do not re-grind), open targets, the signed attempt ledger, and how to submit. An output is acceptable only if it is one of the allowed types with its verifier passing; strategy prose is not a state transition. Read-only.",
            json!({"type": "object", "properties": {
                "problem": {"type": "string", "description": "Problem number (e.g. \"617\"), finding id, or a statement substring"}
            }, "required": ["problem"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Closure routes are curated statements of what WOULD close the problem, not promises that it is closable.",
                "The failed-route rule is absolute: a banked obstruction is only reopened by a new counterexample or proof against the obstruction itself.",
            ],
        ),
        // T7: the typed claim-level edge layer (the FrontierGraph
        // substrate) and the first-class Contradiction object.
        tool(
            "frontier_graph",
            "Summarize the typed claim-level graph: node/edge counts and the per-kind breakdown over the T7 relation vocabulary (supports/contradicts/depends_on/derived_from/improves/generalizes/specializes/supersedes/extends/replicates). Pass `kind` to also return up to `limit` edges of that relation. Cross-frontier links resolve when served over a merged frontier directory.",
            json!({"type": "object", "properties": {
                "kind": {"type": "string"},
                "limit": {"type": "integer"}
            }}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Derived view over declared links; edges are candidate relations, not adjudicated truth.",
            ],
        ),
        tool(
            "contradictions",
            "List first-class candidate Contradiction objects (`vcx_`) derived from the typed graph, each with a resolution status (defaults to `candidate`) and an honest claim boundary. Distinct from `list_contradictions`, which lists raw contradiction links. Pass `as_of` (an ISO-8601 timestamp) for a bi-temporal query: only contradictions open in the world at that time.",
            json!({"type": "object", "properties": {
                "limit": {"type": "integer"},
                "as_of": {"type": "string"}
            }}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Candidate contradictions are auto-detected signals pending expert review, not adjudicated truth.",
                "Even reviewed contradictions record a named reviewer's judgment, not platform-adjudicated truth.",
            ],
        ),
        // The "deep" retrieval tier (DeepWiki pattern): multi-hop
        // traversal for synthesis, vs the single-hop `context` tool.
        tool(
            "deep_trace",
            "Deep multi-hop traversal from a finding across the typed graph, layered by hop distance — the synthesis counterpart to the single-hop `context` tool. Returns nodes grouped by hop, the edge-kind distribution, and contradictions found in the region. Bound by `max_hops` (default 3, max 8).",
            json!({"type": "object", "properties": {
                "finding_id": {"type": "string"},
                "max_hops": {"type": "integer"},
                "limit_per_hop": {"type": "integer"}
            }, "required": ["finding_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec!["Multi-hop relations are declared links, not adjudicated truth."],
        ),
        // Dependency-impact: the directional blast radius + the single
        // points of failure on a finding's support (the minimal cut).
        tool(
            "blast_radius",
            "The dependency-impact neighborhood of a finding (its \"blast radius\"): what it RESTS ON (upstream support), what RESTS ON IT (downstream — what would weaken if it moved), and the SINGLE POINTS OF FAILURE on its support (the minimal set whose removal collapses it). Resolve by finding id, problem number, or an assertion substring. `impact` selects up|down|both (default both); `kinds` is a comma-separated edge-kind filter (default the dependency kinds: supports, depends_on, derived_from, discharges). Read-only.",
            json!({"type": "object", "properties": {
                "finding": {"type": "string", "description": "Finding id, problem number, or an assertion substring"},
                "impact": {"type": "string", "description": "up | down | both (default both)"},
                "kinds": {"type": "string", "description": "comma-separated edge kinds; default the dependency kinds"}
            }, "required": ["finding"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Impact is STRUCTURAL over declared links: that a result is in the blast radius is not a claim it is wrong.",
                "Edges are candidate relations, not adjudicated truth.",
            ],
        ),
        // ORKG-style comparison: findings on a scoped problem lined up
        // against generic comparison properties as a table.
        tool(
            "frontier_compare",
            "Compare findings addressing the same scoped problem against a fixed set of generic properties (assertion_type, confidence, evidence_type, method, model_system, replication, human_data, clinical_trial, flags, year) as a side-by-side table. Scope with `query` (substring on the assertion), `assertion_type`, and/or an `ids` list; with none, compares the whole frontier up to `limit`.",
            json!({"type": "object", "properties": {
                "query": {"type": "string"},
                "assertion_type": {"type": "string"},
                "ids": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer"}
            }}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "A structured side-by-side of declared properties, not a ranking or adjudication.",
            ],
        ),
        // Nanopublication export: interchange with the FAIR /
        // semantic-web science ecosystem.
        tool(
            "nanopublication",
            "Export a finding as a nanopublication in TriG/RDF — the assertion, provenance, and publication-info named graphs of the nanopub.net standard — for interchange with the FAIR / semantic-web science ecosystem.",
            json!({"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec!["Derived interchange artifact; the canonical finding remains the vf_ object."],
        ),
        // Phase Q-r (v0.5): cursor-paginated read over the canonical
        // event log. Agent loops use this to learn when their proposals
        // were accepted, rejected, or had cascade events emitted on
        // their behalf. Public consumers use it to track frontier state
        // changes without re-reading the full log.
        tool(
            "list_events_since",
            "List canonical events from the event log strictly after `cursor` (a `vev_…` id), ordered chronologically. Returns events plus a `next_cursor` for further pagination, or null when the tail is reached. Omit `cursor` to start from the genesis event.",
            json!({"type": "object", "properties": {
                "cursor": {"type": "string"},
                "limit": {"type": "integer"}
            }}),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Cursor must reference an event currently in the log; out-of-sync clients should restart from the beginning.",
            ],
        ),
        // Phase Q-w (v0.5): write surface — propose-* and decision tools.
        // Each requires a registered actor and a verifying Ed25519 signature
        // over the canonical preimage. Idempotent under Phase P:
        // identical logical proposals produce the same `vpr_…` and a retry
        // returns the existing record without duplicating state.
        tool(
            "propose_review",
            "Propose a `finding.review` decision on a finding (status: accepted/approved/contested/needs_revision/rejected). Requires the actor's Ed25519 signature over the canonical proposal preimage. Idempotent: identical logical proposals return the same `vpr_…`.",
            json!({"type": "object", "properties": {
                "actor_id": {"type": "string"},
                "target_finding_id": {"type": "string"},
                "status": {"type": "string"},
                "reason": {"type": "string"},
                "created_at": {"type": "string"},
                "signature": {"type": "string"}
            }, "required": ["actor_id", "target_finding_id", "status", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec![
                "actor_id must be registered in `frontier.actors` via `vela actor add` before writes verify.",
            ],
        ),
        tool(
            "propose_note",
            "Propose attaching a `finding.note` annotation to a finding. Requires a registered actor and signature. Optional structured `provenance` (Phase β, v0.6): `{doi?, pmid?, title?, span?}` with at least one identifier. Stays `pending_review` until accepted.",
            json!({"type": "object", "properties": {
                "actor_id": {"type": "string"},
                "target_finding_id": {"type": "string"},
                "text": {"type": "string"},
                "reason": {"type": "string"},
                "created_at": {"type": "string"},
                "signature": {"type": "string"},
                "provenance": {
                    "type": "object",
                    "properties": {
                        "doi": {"type": "string"},
                        "pmid": {"type": "string"},
                        "title": {"type": "string"},
                        "span": {"type": "string"}
                    }
                }
            }, "required": ["actor_id", "target_finding_id", "text", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec!["Notes do not change finding state; they accrete review context."],
        ),
        // Phase α (v0.6): one-call propose-and-apply for `finding.note`,
        // gated on actor `tier="auto-notes"`. Halves the signing surface
        // for trusted bulk-note extractors. Identical signing preimage and
        // arguments as `propose_note`; idempotent under Phase P.
        tool(
            "propose_and_apply_note",
            "Propose AND apply a `finding.note` annotation in one signed call. Requires the actor to have `tier=\"auto-notes\"` registered (`vela actor add --tier auto-notes`). Optional structured `provenance` (Phase β). Idempotent: a retry with identical content returns the same `applied_event_id`.",
            json!({"type": "object", "properties": {
                "actor_id": {"type": "string"},
                "target_finding_id": {"type": "string"},
                "text": {"type": "string"},
                "reason": {"type": "string"},
                "created_at": {"type": "string"},
                "signature": {"type": "string"},
                "provenance": {
                    "type": "object",
                    "properties": {
                        "doi": {"type": "string"},
                        "pmid": {"type": "string"},
                        "title": {"type": "string"},
                        "span": {"type": "string"}
                    }
                }
            }, "required": ["actor_id", "target_finding_id", "text", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Requires actor.tier=auto-notes; calls from non-tiered actors are rejected.",
                "Notes still do not change finding state — they accrete review context.",
            ],
        ),
        tool(
            "propose_revise_confidence",
            "Propose a confidence revision (`finding.confidence_revise`) on a finding. `new_score` must be in [0.0, 1.0]. Requires a registered actor and signature.",
            json!({"type": "object", "properties": {
                "actor_id": {"type": "string"},
                "target_finding_id": {"type": "string"},
                "new_score": {"type": "number"},
                "reason": {"type": "string"},
                "created_at": {"type": "string"},
                "signature": {"type": "string"}
            }, "required": ["actor_id", "target_finding_id", "new_score", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Confidence revisions update score and basis; they do not change scope or evidence.",
            ],
        ),
        tool(
            "propose_retract",
            "Propose retracting a finding (`finding.retract`). Applying triggers per-dependent `finding.dependency_invalidated` events through the propagation graph. Requires a registered actor and signature.",
            json!({"type": "object", "properties": {
                "actor_id": {"type": "string"},
                "target_finding_id": {"type": "string"},
                "reason": {"type": "string"},
                "created_at": {"type": "string"},
                "signature": {"type": "string"}
            }, "required": ["actor_id", "target_finding_id", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Retraction propagates through declared dependency/support links; review impact before applying.",
            ],
        ),
        tool(
            "accept_proposal",
            "Apply a pending proposal as the named reviewer. The reviewer must be registered. Signature is over `{action: \"accept\", proposal_id, reviewer_id, reason, timestamp}` canonicalized. Idempotent: re-applying returns the same `applied_event_id`.",
            json!({"type": "object", "properties": {
                "proposal_id": {"type": "string"},
                "reviewer_id": {"type": "string"},
                "reason": {"type": "string"},
                "timestamp": {"type": "string"},
                "signature": {"type": "string"}
            }, "required": ["proposal_id", "reviewer_id", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Accepting an applied proposal returns its existing event_id; no duplicate event is emitted.",
            ],
        ),
        tool(
            "reject_proposal",
            "Reject a pending proposal as the named reviewer. The reviewer must be registered. Signature is over `{action: \"reject\", proposal_id, reviewer_id, reason, timestamp}` canonicalized.",
            json!({"type": "object", "properties": {
                "proposal_id": {"type": "string"},
                "reviewer_id": {"type": "string"},
                "reason": {"type": "string"},
                "timestamp": {"type": "string"},
                "signature": {"type": "string"}
            }, "required": ["proposal_id", "reviewer_id", "reason", "signature"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Rejection records the decision but emits no canonical event; rejected proposals stay on the proposal log.",
            ],
        ),
        // v0.206: write-side tools that bridge the vela_agent SDK.
        // Both require VELA_AGENT_KEY_HEX to be set in the server
        // environment so the substrate has an Ed25519 signing key
        // for the produced vaa_* + vsd_* artifacts.
        tool(
            "vela_agent_submit_diff_pack",
            "v0.206: one-shot agent submission. Signs a vaa_* Agent Attestation envelope + a vsd_* Scientific Diff Pack bundling N proposals, writes both to the frontier's .vela/ tree, and returns the resulting ids. Requires VELA_AGENT_KEY_HEX in the server env.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "agent_actor": {"type": "string", "description": "Must start with `agent:`."},
                "model_name": {"type": "string"},
                "model_version": {"type": "string"},
                "prompt": {"type": "string", "description": "Hashed server-side; not stored verbatim."},
                "started_at": {"type": "string"},
                "finished_at": {"type": "string"},
                "total_tokens": {"type": "integer"},
                "tool_calls": {"type": "array", "items": {"type": "object", "properties": {
                    "tool_name": {"type": "string"},
                    "input": {},
                    "output": {},
                    "duration_ms": {"type": "integer"}
                }}},
                "proposals": {"type": "array", "items": {"type": "object", "properties": {
                    "kind": {"type": "string"},
                    "payload": {}
                }, "required": ["kind", "payload"]}, "minItems": 1},
                "summary": {"type": "string"},
                "aggregate_kind": {"type": "string"},
                "parent_attestation": {"type": "string"},
                "parent_pack": {"type": "string"}
            }, "required": ["frontier_path", "agent_actor", "model_name", "model_version", "summary", "aggregate_kind", "proposals"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Refuses to operate without VELA_AGENT_KEY_HEX set; no silent unsigned submissions.",
                "Writes to .vela/agent_attestations/, .vela/diff_packs/, .vela/agent_proposals/ — does NOT pass through the canonical proposal reducer.",
                "Resulting pack is reviewer-pending until a reviewer issues a verdict via the local review queue + diff-pack promoter.",
            ],
        ),
        // An autonomous agent submits a SIGNED StateProposal to a remote hub.
        // Proposes only: the hub forces pending_review and a human reviewer
        // must accept through the strict gate (an AI never signs an accept).
        tool(
            "vela_agent_propose_to_hub",
            "Submit a signed StateProposal to a remote Vela hub over MCP. The agent signs with VELA_AGENT_KEY_HEX (the same canonical bytes the hub verifies) and POSTs to {hub}/entries/{vfr}/proposals. The proposal is authored by the agent's `agent:*` id and lands as pending_review; a human reviewer must accept it through the strict gate before it changes state. Proposes only — never accepts.",
            json!({"type": "object", "properties": {
                "hub": {"type": "string", "description": "Hub base URL (or set VELA_HUB env), e.g. https://hub.constellate.science"},
                "vfr": {"type": "string", "description": "The vfr_ frontier id on the hub."},
                "kind": {"type": "string", "description": "Proposal kind, e.g. finding.note, finding.caveat, finding.confidence_revise, finding.retract."},
                "target": {"type": "string", "description": "The vf_ finding id this change targets."},
                "reason": {"type": "string", "description": "Why this change — the reviewer reads this."},
                "actor": {"type": "string", "description": "The proposing actor id; must start with `agent:`. Defaults to agent:mcp."},
                "payload": {"description": "Kind-specific payload, e.g. {\"text\": \"…\"} for note/caveat, {\"confidence\": 0.5} for confidence_revise, {} for retract."}
            }, "required": ["vfr", "kind", "target", "reason"]}),
            PermissionLevel::Write,
            true,
            vec![
                "Refuses to operate without VELA_AGENT_KEY_HEX set; no silent unsigned submissions.",
                "Proposes only — the hub forces pending_review; a human reviewer accepts through the strict gate. An AI never signs an accept.",
                "A proposal self-signature binds authorship only; it confers no authority.",
            ],
        ),
        // v0.214: read-side tools. None require a signing key. They
        // give a multi-turn LLM session a way to inspect prior
        // context before composing a submission.
        tool(
            "vela_agent_frontier_summary",
            "v0.214: counts of every v0.193+ primitive on a frontier. Use as the first call in a multi-turn agent session to see what already exists before submitting new work.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"}
            }, "required": ["frontier_path"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_get_pack",
            "v0.214: fetch a Scientific Diff Pack body by id from a frontier's .vela/diff_packs/.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "pack_id": {"type": "string", "description": "vsd_<16hex>"}
            }, "required": ["frontier_path", "pack_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_list_packs",
            "v0.214: list every Scientific Diff Pack on a frontier. Set only_pending=true to filter to packs awaiting reviewer verdict.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "only_pending": {"type": "boolean"}
            }, "required": ["frontier_path"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_get_attestation",
            "v0.214: fetch an Agent Attestation envelope body by id from a frontier's .vela/agent_attestations/.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "attestation_id": {"type": "string", "description": "vaa_<16hex>"}
            }, "required": ["frontier_path", "attestation_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        // v0.220: parity read tools for tool descriptors, evaluation
        // records, and verdict conflicts. None require a signing key.
        tool(
            "vela_agent_get_tool_descriptor",
            "v0.220: fetch a Tool Descriptor body by id from a frontier's .vela/tool_descriptors/.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "descriptor_id": {"type": "string", "description": "vtd_<16hex>"}
            }, "required": ["frontier_path", "descriptor_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_get_evaluation",
            "v0.220: fetch an Evaluation Record body by id from a frontier's .vela/evaluations/.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "evaluation_id": {"type": "string", "description": "ver_<16hex>"}
            }, "required": ["frontier_path", "evaluation_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_list_evaluations",
            "v0.220: list every Evaluation Record on a frontier. Optionally filter by target Tool Descriptor.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "target_descriptor_id": {"type": "string", "description": "Optional vtd_<16hex> to filter on"}
            }, "required": ["frontier_path"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_get_conflict",
            "v0.220: fetch a resolved Verdict Conflict body by id from a frontier's .vela/verdict_conflicts/.",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "conflict_id": {"type": "string", "description": "vdc_<16hex>"}
            }, "required": ["frontier_path", "conflict_id"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
        tool(
            "vela_agent_list_conflicts",
            "v0.220: list every resolved Verdict Conflict on a frontier. Optionally filter by resolution_mode (majority, owner_override, escalation).",
            json!({"type": "object", "properties": {
                "frontier_path": {"type": "string"},
                "resolution_mode": {"type": "string", "description": "Optional filter: majority, owner_override, or escalation"}
            }, "required": ["frontier_path"]}),
            PermissionLevel::ReadOnly,
            false,
            vec![],
        ),
    ]
}

pub fn get_tool(name: &str) -> Option<ToolDefinition> {
    all_tools().into_iter().find(|tool| tool.name == name)
}

pub fn tool_caveats(name: &str) -> Vec<String> {
    get_tool(name).map(|tool| tool.caveats).unwrap_or_default()
}

/// Tools that COMMIT a pending proposal into accepted state (or apply
/// immediately). Reserved for the maintainer profile regardless of their
/// (coarser) `permission_level`. Keep in sync with the substrate accept gate:
/// these are the truth-bearing finalize actions an agent must never reach
/// through a draft session.
const FINALIZING_TOOLS: &[&str] = &[
    "accept_proposal",
    "reject_proposal",
    "propose_and_apply_note",
];

/// MCP exposure profile (memo §9.1). A served frontier scopes which tools an
/// agent can see and call. `MCP exposes tools; Vela governs state` — even the
/// maintainer profile only drafts proposals; accepted public state still
/// requires a key-custody human accept off the MCP surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpProfile {
    /// Inspect state, graph, provenance, tasks, schemas. The default.
    ReadOnly,
    /// Read + non-finalizing writes: runs, observations, draft findings,
    /// draft submissions (the `propose_*` surface).
    Draft,
    /// Everything the server exposes, including the finalizing tier.
    Maintainer,
}

impl McpProfile {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "read-only" | "readonly" | "read" => Ok(Self::ReadOnly),
            "draft" => Ok(Self::Draft),
            "maintainer" => Ok(Self::Maintainer),
            other => Err(format!(
                "unknown MCP profile `{other}`; valid: read-only (default), draft, maintainer"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Draft => "draft",
            Self::Maintainer => "maintainer",
        }
    }

    /// Whether this profile may expose AND execute `tool`. Read-only admits
    /// only non-mutating reads; draft admits the propose/draft writes but NOT
    /// the finalizing tools (accept/reject/apply, which commit accepted state)
    /// nor the `Dangerous` tier; maintainer admits all.
    ///
    /// Finalizing is a profile policy, not a property of `permission_level`:
    /// `accept_proposal` is a plain `Write` (it is not a destructive cascade
    /// like `propagate_retraction`), but committing a pending proposal into
    /// accepted state is a maintainer act. The draft tier creates submissions;
    /// it does not finalize them.
    pub fn allows(self, tool: &ToolDefinition) -> bool {
        match self {
            Self::ReadOnly => matches!(tool.permission_level, PermissionLevel::ReadOnly),
            Self::Draft => {
                !matches!(tool.permission_level, PermissionLevel::Dangerous)
                    && !FINALIZING_TOOLS.contains(&tool.name.as_str())
            }
            Self::Maintainer => true,
        }
    }
}

pub fn tools_for_profile(profile: McpProfile) -> Vec<ToolDefinition> {
    all_tools()
        .into_iter()
        .filter(|tool| profile.allows(tool))
        .collect()
}

fn tool_to_mcp_json(tool: &ToolDefinition) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.parameters,
        "metadata": {
            "permission_level": tool.permission_level,
            "mutating": tool.mutating,
            "caveats": tool.caveats,
        }
    })
}

pub fn mcp_tools_json() -> Value {
    Value::Array(all_tools().iter().map(tool_to_mcp_json).collect())
}

/// `tools/list` payload scoped to a profile (memo §9.1).
pub fn mcp_tools_json_for_profile(profile: McpProfile) -> Value {
    Value::Array(
        tools_for_profile(profile)
            .iter()
            .map(tool_to_mcp_json)
            .collect(),
    )
}

fn tool(
    name: &str,
    description: &str,
    parameters: Value,
    permission_level: PermissionLevel,
    mutating: bool,
    caveats: Vec<&str>,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters,
        permission_level,
        mutating,
        caveats: caveats.into_iter().map(str::to_string).collect(),
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn profiles_nest_and_readonly_excludes_writes() {
        let ro = tools_for_profile(McpProfile::ReadOnly);
        let draft = tools_for_profile(McpProfile::Draft);
        let maint = tools_for_profile(McpProfile::Maintainer);
        // read-only ⊆ draft ⊆ maintainer
        assert!(
            ro.len() < draft.len(),
            "read-only must be a strict subset of draft"
        );
        assert!(
            draft.len() < maint.len(),
            "draft must be a strict subset of maintainer"
        );
        assert_eq!(
            maint.len(),
            all_tools().len(),
            "maintainer exposes every tool"
        );
        // read-only admits no mutating tool
        assert!(
            ro.iter().all(|t| !t.mutating),
            "read-only must expose no mutating tool"
        );
        // the finalizing (Dangerous) tier is maintainer-only
        let dangerous_in_draft = draft.iter().any(|t| {
            matches!(
                t.permission_level,
                crate::permission::PermissionLevel::Dangerous
            )
        });
        assert!(
            !dangerous_in_draft,
            "draft must not expose the finalizing tier"
        );
        // accept/reject commit accepted state — maintainer-only, never draft,
        // even though they are plain `Write`.
        for finalize in FINALIZING_TOOLS {
            assert!(
                !draft.iter().any(|t| &t.name == finalize),
                "draft must not expose finalizing tool {finalize}"
            );
            assert!(
                maint.iter().any(|t| &t.name == finalize),
                "maintainer must expose finalizing tool {finalize}"
            );
        }
    }

    #[test]
    fn profile_parse_roundtrips() {
        assert_eq!(
            McpProfile::parse("read-only").unwrap(),
            McpProfile::ReadOnly
        );
        assert_eq!(
            McpProfile::parse("read_only").unwrap(),
            McpProfile::ReadOnly
        );
        assert_eq!(McpProfile::parse("draft").unwrap(), McpProfile::Draft);
        assert_eq!(
            McpProfile::parse("maintainer").unwrap(),
            McpProfile::Maintainer
        );
        assert!(McpProfile::parse("god-mode").is_err());
    }
}
