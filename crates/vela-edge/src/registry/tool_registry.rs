//! Tool registry — tools defined as data, separate from execution.
//! Borrowed from Codex (MIT) tool-as-data pattern.
//!
//! The surface is exactly ten tools. Each one owns a concept (orientation,
//! one finding, search, the graph, verification, drafting, deciding, agent
//! work, agent objects, external services); the dispatch in
//! `vela-cli/src/server/serve.rs` maps each onto the underlying analysis
//! functions. Schemas are strict: closed sets are enums, actor ids carry
//! patterns, required text carries minLength, lists carry limit bounds and
//! opaque cursors.

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
            "orient",
            "One-call situational awareness for the served frontier: stats, verification \
             posture, ranked open targets, recent events, and gap-flagged findings. Pass \
             `problem` to also get the full task briefing for that problem (statement, gate \
             status, allowed output types, failed-route memory, attempt ledger, obligations, \
             staleness). Call this first in a session; for a single known finding use \
             `finding` instead. Example: {\"problem\": \"617\", \"limit\": 10}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "problem": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Problem number like \"617\", a vf_ finding id, or a statement substring. Omit for whole-frontier orientation only."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Cap for open targets, gaps, and the recent-event tail (default 12)."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Open targets and rankings are advice, never authority; claiming a target goes through `work` with action=claim.",
                "Campaign seeds require the server to know the frontier directory; hosted/merged serves list only review and verify lanes.",
            ],
        ),
        tool(
            "finding",
            "Fetch one finding by vf_ id: assertion, evidence, conditions, links, confidence, \
             and provenance. Add `include` entries to merge the finding's chronological event \
             history, its direct dependents, or its full graph neighborhood into the same \
             response. Use `search` when you do not know the id, and `graph` for multi-hop \
             traversal. Example: {\"id\": \"vf_3f9a\", \"include\": [\"history\", \"dependents\"]}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["id"],
                "properties": {
                    "id": {
                        "type": "string",
                        "minLength": 3,
                        "pattern": "^vf_",
                        "description": "The vf_ finding id (a unique prefix is accepted)."
                    },
                    "include": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["history", "dependents", "neighborhood"]},
                        "description": "Extra payloads to merge: history (event log for this finding), dependents (direct inbound links), neighborhood (rests-on / dependents / related / contradictions in one view)."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Neighborhood and dependent relations are declared links, not adjudicated truth.",
                "History event order reflects timestamps as recorded.",
            ],
        ),
        tool(
            "search",
            "Search the frontier by text over findings, sources, and evidence atoms. Returns \
             structured matches plus `next_cursor` when more remain — pass it back unchanged \
             to continue (it is an opaque cursor into the stable result order). Use `finding` \
             to fetch a known id, and `orient` for whole-frontier awareness. Example: \
             {\"query\": \"Sidon\", \"type\": \"finding\", \"limit\": 24}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Case-insensitive substring matched against assertions, conditions, entity names, source titles/DOIs, and evidence text."
                    },
                    "type": {
                        "type": "string",
                        "enum": ["finding", "source", "evidence", "any"],
                        "description": "Restrict the object kind searched (default any)."
                    },
                    "entity": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Additionally require this substring among a finding's entity names."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Maximum matches per page (default 24)."
                    },
                    "cursor": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Opaque continuation cursor from a previous response's next_cursor."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec!["Matches are substring hits over declared content, not a relevance ranking."],
        ),
        tool(
            "graph",
            "Walk the typed claim graph. mode=traverse explores out from `root` layered by hop \
             distance plus the finding's evidence chain (omit root for a whole-graph summary); \
             mode=impact computes the dependency blast radius and retraction cascade for \
             `root`; mode=contradictions lists raw contradiction links and first-class \
             contradiction objects together, each row tagged `first_class`. For one node's \
             immediate neighborhood use `finding` with include=[\"neighborhood\"]. Example: \
             {\"root\": \"vf_3f9a\", \"mode\": \"impact\", \"direction\": \"down\"}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "root": {
                        "type": "string",
                        "minLength": 3,
                        "pattern": "^vf_",
                        "description": "The vf_ finding to start from. Required for mode=impact; omit in mode=traverse for a whole-frontier summary."
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["up", "down", "both"],
                        "description": "Impact direction: up = what root rests on, down = what rests on root, both (default)."
                    },
                    "edge_kinds": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["supports", "contradicts", "depends_on", "derived_from", "replicates", "specializes"]},
                        "description": "Edge-kind filter. Applied to impact traversal and to whole-graph edge listings; traverse mode follows all declared kinds and notes when the filter is not applied."
                    },
                    "max_hops": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 6,
                        "description": "Traversal depth for mode=traverse (default 2)."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["traverse", "impact", "contradictions"],
                        "description": "What to compute (default traverse)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "description": "Cap on returned nodes/edges/rows per section."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Edges are candidate relations over declared links, not adjudicated truth.",
                "Impact is structural: being in the blast radius is not a claim a result is wrong.",
                "Candidate contradictions are auto-detected signals pending expert review.",
            ],
        ),
        tool(
            "verify",
            "Run the frozen verifiers against a frontier checkout on this machine's \
             filesystem. mode=strict holds the frontier to the strict bar (content-address \
             validation, strict reducer replay, signature signals — the same bundle the hub's \
             git ingestor enforces); mode=witness re-verifies every stored \
             witnesses/*.witness.json from scratch with the frozen exact verifiers. Read-only \
             but path-bound, so it is not served on hosted endpoints. Example: \
             {\"frontier_path\": \"examples/sidon-sets\", \"mode\": \"witness\"}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["frontier_path", "mode"],
                "properties": {
                    "frontier_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Path to the frontier repo (for witness mode, a witness file or directory also works)."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["strict", "witness"],
                        "description": "strict = validation + reducer replay + signature signals; witness = re-verify stored witnesses."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec!["Read-only: replays and verifies, writes nothing."],
        ),
        tool(
            "propose",
            "Draft a signed proposal against a finding; it lands pending_review, and only a \
             key-custody human accept changes state. `kind` selects the shape: review \
             (requires status), note (requires text; optional provenance), apply_note (a note \
             that auto-applies, only for actors registered with tier=auto-notes), \
             revise_confidence (requires new_score in [0,1]), retract. Requires a registered \
             actor_id and an Ed25519 signature over the canonical proposal preimage; use \
             `decide` (maintainer lane) to finalize. Example: {\"kind\": \"note\", \"target\": \
             \"vf_3f9a\", \"actor_id\": \"agent:x\", \"text\": \"…\", \"reason\": \"…\", \
             \"signature\": \"<hex>\"}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "target", "actor_id", "reason", "signature"],
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["review", "note", "revise_confidence", "retract", "apply_note"],
                        "description": "Proposal shape. review→finding.review, note/apply_note→finding.note, revise_confidence→finding.confidence_revise, retract→finding.retract."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 3,
                        "pattern": "^vf_",
                        "description": "The vf_ finding the proposal targets."
                    },
                    "actor_id": {
                        "type": "string",
                        "minLength": 3,
                        "pattern": "^[A-Za-z][A-Za-z0-9_.-]*:[A-Za-z0-9_.:-]+$",
                        "description": "Registered actor id (e.g. agent:swarm-1, reviewer:will-blair). Must exist in frontier.actors."
                    },
                    "reason": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Why this proposal exists; recorded on the proposal."
                    },
                    "signature": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Hex Ed25519 signature by actor_id over the canonical proposal preimage."
                    },
                    "created_at": {
                        "type": "string",
                        "minLength": 1,
                        "description": "RFC-3339 timestamp the signature was computed over (defaults to now; must match the signed preimage)."
                    },
                    "status": {
                        "type": "string",
                        "enum": ["accepted", "approved", "contested", "needs_revision", "rejected"],
                        "description": "Review verdict. Required when kind=review."
                    },
                    "text": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Note body. Required when kind=note or kind=apply_note."
                    },
                    "new_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Revised confidence. Required when kind=revise_confidence."
                    },
                    "provenance": {
                        "type": "object",
                        "description": "Optional structured provenance for notes; at least one of doi/pmid/title when present.",
                        "properties": {
                            "doi": {"type": "string", "description": "DOI of the grounding source."},
                            "pmid": {"type": "string", "description": "PubMed id of the grounding source."},
                            "title": {"type": "string", "description": "Title of the grounding source."},
                            "span": {"type": "string", "description": "The exact span the note rests on."}
                        }
                    }
                }
            }),
            PermissionLevel::Write,
            true,
            vec![
                "actor_id must be registered in frontier.actors (`vela actor add`) before writes verify.",
                "Proposals stay pending_review until a key-custody human accepts; apply_note additionally requires actor tier=auto-notes, and notes never change finding state.",
            ],
        ),
        tool(
            "decide",
            "Accept or reject a pending proposal as the named reviewer — the key-custody human \
             lane; agent sessions are refused by profile. The signature is over {action, \
             proposal_id, reviewer_id, reason, timestamp} canonicalized, and the reviewer must \
             be a registered actor. Use `propose` to create submissions instead of finalizing \
             them. Example: {\"proposal_id\": \"vpr_ab12cd34\", \"action\": \"accept\", \
             \"reviewer_id\": \"reviewer:will-blair\", \"reason\": \"verified\", \
             \"signature\": \"<hex>\"}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["proposal_id", "action", "reason", "reviewer_id", "signature"],
                "properties": {
                    "proposal_id": {
                        "type": "string",
                        "minLength": 5,
                        "pattern": "^vpr_",
                        "description": "The pending vpr_ proposal to decide."
                    },
                    "action": {
                        "type": "string",
                        "enum": ["accept", "reject"],
                        "description": "accept applies the proposal as a canonical event; reject records the decision without emitting one."
                    },
                    "reason": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Why; recorded with the decision."
                    },
                    "reviewer_id": {
                        "type": "string",
                        "minLength": 3,
                        "pattern": "^[A-Za-z][A-Za-z0-9_.-]*:[A-Za-z0-9_.:-]+$",
                        "description": "Registered reviewer actor id whose key signed the decision."
                    },
                    "signature": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Hex Ed25519 signature by reviewer_id over the canonical decision preimage."
                    },
                    "timestamp": {
                        "type": "string",
                        "minLength": 1,
                        "description": "RFC-3339 timestamp in the signed preimage (defaults to now; must match what was signed)."
                    }
                }
            }),
            PermissionLevel::Write,
            true,
            vec![
                "Committing a proposal into accepted state is a key-custody human act; an AI never signs an accept.",
                "Accepting an already-applied proposal returns its existing event_id; no duplicate event is emitted.",
            ],
        ),
        tool(
            "work",
            "The agent work loop against a local frontier checkout. action=claim leases an \
             open obligation so other agents route around it, signed with the agent's \
             auto-minted session key; action=record lands a vrc_ activity record as a pending \
             proposal; action=pack signs a vaa_ agent attestation plus a vsd_ scientific diff \
             pack bundling proposals. Coordination and drafting only — nothing here finalizes \
             state (that is `decide`). Example: {\"frontier_path\": \".\", \"action\": \
             \"claim\", \"obligation_id\": \"vf_3f9a\", \"agent_actor\": \"agent:swarm-1\"}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["frontier_path", "action"],
                "properties": {
                    "frontier_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Path to the frontier repo on this machine."
                    },
                    "action": {
                        "type": "string",
                        "enum": ["claim", "record", "pack"],
                        "description": "claim = lease an obligation; record = land a vrc_ record as a pending proposal; pack = sign an attestation + diff pack."
                    },
                    "obligation_id": {
                        "type": "string",
                        "minLength": 1,
                        "description": "claim: the vf_ finding to lease, or a namespaced external target like erdos:443."
                    },
                    "agent_actor": {
                        "type": "string",
                        "minLength": 4,
                        "pattern": "^(agent:|ci:)",
                        "description": "claim/pack: the agent identity doing the work (agent:<name> or ci:<name>)."
                    },
                    "ttl_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "claim: lease TTL (default 86400)."
                    },
                    "record_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "record: path to the vrc_ activity-record JSON emitted by `vela record`."
                    },
                    "summary": {
                        "type": "string",
                        "minLength": 1,
                        "description": "pack: one-line summary of the submission."
                    },
                    "aggregate_kind": {
                        "type": "string",
                        "minLength": 1,
                        "description": "pack: the aggregate kind of the bundled proposals."
                    },
                    "model_name": {
                        "type": "string",
                        "minLength": 1,
                        "description": "pack: model name for the attestation envelope."
                    },
                    "model_version": {
                        "type": "string",
                        "minLength": 1,
                        "description": "pack: model version for the attestation envelope."
                    },
                    "proposals": {
                        "type": "array",
                        "minItems": 1,
                        "description": "pack: the proposals to bundle.",
                        "items": {
                            "type": "object",
                            "required": ["kind", "payload"],
                            "properties": {
                                "kind": {"type": "string", "minLength": 1, "description": "Proposal kind."},
                                "payload": {"description": "Proposal payload."}
                            }
                        }
                    },
                    "prompt": {
                        "type": "string",
                        "description": "pack: hashed server-side; never stored verbatim."
                    },
                    "started_at": {
                        "type": "string",
                        "description": "pack: RFC-3339 run start (defaults to now)."
                    },
                    "finished_at": {
                        "type": "string",
                        "description": "pack: RFC-3339 run end (defaults to now)."
                    },
                    "total_tokens": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "pack: tokens consumed by the run."
                    },
                    "tool_calls": {
                        "type": "array",
                        "description": "pack: tool-call ledger; inputs/outputs are hashed, not stored.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool_name": {"type": "string", "description": "Tool invoked."},
                                "input": {"description": "Input (hashed server-side)."},
                                "output": {"description": "Output (hashed server-side)."},
                                "duration_ms": {"type": "integer", "minimum": 0, "description": "Call duration."}
                            }
                        }
                    },
                    "parent_attestation": {
                        "type": "string",
                        "description": "pack: parent vaa_ id for chained runs."
                    },
                    "parent_pack": {
                        "type": "string",
                        "description": "pack: parent vsd_ id for chained packs."
                    }
                }
            }),
            PermissionLevel::Write,
            true,
            vec![
                "Signs under the agent's own auto-minted session key (never a human's); VELA_AGENT_KEY_HEX overrides when an explicit key is wanted.",
                "A lease is coordination, never authority; records and packs stay reviewer-pending until a human key decides.",
            ],
        ),
        tool(
            "objects",
            "Read the content-addressed agent objects on a frontier checkout's .vela/ tree: \
             diff packs (vsd_), attestations (vaa_), evaluations (ver_), verdict conflicts \
             (vdc_), tool descriptors (vtd_). Pass `id` to fetch one object; omit it to list \
             with `limit` and opaque `cursor` pagination — `target` filters evaluations by \
             descriptor id and conflicts by resolution mode, `only_pending` filters packs. \
             Path-bound, so not served on hosted endpoints. Example: {\"frontier_path\": \
             \".\", \"type\": \"pack\", \"only_pending\": true}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["frontier_path", "type"],
                "properties": {
                    "frontier_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Path to the frontier repo on this machine."
                    },
                    "type": {
                        "type": "string",
                        "enum": ["pack", "attestation", "evaluation", "conflict", "tool_descriptor"],
                        "description": "Which object family to read."
                    },
                    "id": {
                        "type": "string",
                        "minLength": 5,
                        "description": "Fetch one object by its typed id (vsd_/vaa_/ver_/vdc_/vtd_). Omit to list."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 1,
                        "description": "List filter: for evaluations, a vtd_ descriptor id; for conflicts, a resolution mode (majority, owner_override, escalation)."
                    },
                    "only_pending": {
                        "type": "boolean",
                        "description": "List filter for packs: only those awaiting a reviewer verdict."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Maximum objects per page (default 50)."
                    },
                    "cursor": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Opaque continuation cursor from a previous response's next_cursor."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "Objects are read verbatim from the frontier's .vela/ tree; listing order is by id.",
            ],
        ),
        tool(
            "external",
            "Query an external service. service=pubmed runs a rough prior-art count for \
             `query` against NCBI esearch; service=nanopub exports `finding_id` as a \
             nanopublication (TriG/RDF) for the FAIR / semantic-web ecosystem. Results are \
             signals or interchange artifacts, never canonical state. Example: {\"service\": \
             \"pubmed\", \"query\": \"Sidon set bounds\"}.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["service"],
                "properties": {
                    "service": {
                        "type": "string",
                        "enum": ["pubmed", "nanopub"],
                        "description": "Which external surface to hit."
                    },
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "description": "pubmed: the prior-art query."
                    },
                    "finding_id": {
                        "type": "string",
                        "minLength": 3,
                        "pattern": "^vf_",
                        "description": "nanopub: the vf_ finding to export."
                    }
                }
            }),
            PermissionLevel::ReadOnly,
            false,
            vec![
                "PubMed counts are rough prior-art signals, not proof of novelty.",
                "Nanopublication export is a derived interchange artifact; the canonical finding remains the vf_ object.",
            ],
        ),
    ]
}

pub fn get_tool(name: &str) -> Option<ToolDefinition> {
    all_tools().into_iter().find(|tool| tool.name == name)
}

pub fn tool_caveats(name: &str) -> Vec<String> {
    get_tool(name).map(|tool| tool.caveats).unwrap_or_default()
}

/// Tools that COMMIT a pending proposal into accepted state. Reserved for the
/// maintainer profile regardless of their (coarser) `permission_level`. Keep
/// in sync with the substrate accept gate: these are the truth-bearing
/// finalize actions an agent must never reach through a draft session.
const FINALIZING_TOOLS: &[&str] = &["decide"];

/// MCP exposure profile (memo §9.1). A served frontier scopes which tools an
/// agent can see and call. `MCP exposes tools; Vela governs state` — even the
/// maintainer profile only drafts proposals; accepted public state still
/// requires a key-custody human accept off the MCP surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpProfile {
    /// Inspect state, graph, provenance, tasks, schemas. The default.
    ReadOnly,
    /// Read + non-finalizing writes: runs, observations, draft findings,
    /// draft submissions (`propose` and `work`).
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
    /// only non-mutating reads; draft admits the drafting writes but NOT
    /// the finalizing tools (`decide`, which commits accepted state) nor the
    /// `Dangerous` tier; maintainer admits all.
    ///
    /// Finalizing is a profile policy, not a property of `permission_level`:
    /// `decide` is a plain `Write`, but committing a pending proposal into
    /// accepted state is a maintainer act. The draft tier creates
    /// submissions; it does not finalize them.
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

    /// The whole surface, by contract: exactly these ten names.
    const THE_TEN: [&str; 10] = [
        "orient", "finding", "search", "graph", "verify", "propose", "decide", "work", "objects",
        "external",
    ];

    #[test]
    fn the_surface_is_exactly_ten_tools() {
        let names: Vec<String> = all_tools().into_iter().map(|t| t.name).collect();
        assert_eq!(names, THE_TEN.to_vec(), "the ten-tool contract");
    }

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
        // read-only = the seven inspection tools, and no mutating tool.
        let ro_names: Vec<&str> = ro.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            ro_names,
            vec![
                "orient", "finding", "search", "graph", "verify", "objects", "external"
            ],
            "read-only is exactly the inspection surface"
        );
        assert!(
            ro.iter().all(|t| !t.mutating),
            "read-only must expose no mutating tool"
        );
        // draft adds the drafting writes, never the finalizing tier.
        let draft_names: Vec<&str> = draft.iter().map(|t| t.name.as_str()).collect();
        assert!(
            draft_names.contains(&"propose") && draft_names.contains(&"work"),
            "draft exposes the drafting writes"
        );
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
    fn every_schema_is_strict() {
        for tool in all_tools() {
            let schema = &tool.parameters;
            assert_eq!(
                schema["additionalProperties"],
                Value::Bool(false),
                "{}: schemas are closed",
                tool.name
            );
            let props = schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{}: object schema with properties", tool.name));
            for (pname, p) in props {
                assert!(
                    p.get("description").and_then(Value::as_str).is_some(),
                    "{}.{pname}: every param carries a description",
                    tool.name
                );
                if let Some(limits) = p.get("type").and_then(Value::as_str)
                    && limits == "integer"
                    && pname == "limit"
                {
                    assert!(
                        p.get("minimum").is_some() && p.get("maximum").is_some(),
                        "{}.{pname}: limit params carry minimum/maximum",
                        tool.name
                    );
                }
            }
            assert!(
                !tool.description.contains("v0."),
                "{}: descriptions carry no version tags",
                tool.name
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
