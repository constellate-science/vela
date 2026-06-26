//! Vela edge layer: significance, curation, ingestion, search, operations.
//! Depends on vela-protocol (the waist); never the reverse.

pub mod agent_attestation;
pub mod artifact_audit;
pub mod conformance;
pub mod deliverable_grade;
pub mod doctor;
pub mod export;
pub mod frontier_health;
pub mod frontier_release;
pub mod governance;
pub mod incremental_ingest;
pub mod index_db_schema;
pub mod lean_anchors;
pub mod lint;
pub mod normalize;
pub mod packet;
pub mod permission;
pub mod proof_packet;
pub mod provenance_compute;
pub mod queue;
pub mod research_trace;
pub mod reviewer_identity;
pub mod signals;
pub mod state_integrity;
pub mod tool_registry;
pub mod validate;
pub mod vela_agent_mcp;
