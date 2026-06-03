//! # vela-scientist — the agent layer
//!
//! Sits on top of `vela-protocol`. Reads a researcher's working
//! directory and emits `StateProposal`s tagged with an `AgentRun`
//! for reviewer-facing provenance. Never signs canonical state.
//!
//! v0.22 ships **Literature Scout** only: PDF folder → `finding.add`
//! proposals. Other agents (Notes Compiler, Code Analyst,
//! Contradiction Finder, Experiment Planner, Reviewer Agent) land
//! one at a time in v0.23+.

pub mod agent;
pub mod code_analyst;
pub mod datasets;
pub mod experiments;
pub mod extract;
pub mod llm_cli;
pub mod notebook;
pub mod notes;
pub mod reviewer;
pub mod scout;
pub mod tensions;

/// Stable agent name + actor id for Literature Scout. Pairs with
/// `StateProposal::actor.id == AGENT_ACTOR_ID_LITERATURE_SCOUT` so
/// the Workbench can group its proposals.
pub const AGENT_LITERATURE_SCOUT: &str = "literature-scout";
pub const AGENT_ACTOR_ID_LITERATURE_SCOUT: &str = "agent:literature-scout";

/// Generate a fresh run id for an agent invocation. Format:
/// `vrun_<16 hex chars>` derived from the agent name + a UTC
/// timestamp. Not content-addressed (two identical inputs at
/// different wall-clock instants produce different ids); the run
/// id's job is to group proposals from the same invocation in the
/// reviewer UI, not to act as a substrate primitive.
pub fn new_run_id(agent: &str) -> String {
    use sha2::{Digest, Sha256};
    let now = chrono::Utc::now().to_rfc3339();
    let mut h = Sha256::new();
    h.update(agent.as_bytes());
    h.update(b"\0");
    h.update(now.as_bytes());
    format!("vrun_{}", &hex::encode(h.finalize())[..16])
}
