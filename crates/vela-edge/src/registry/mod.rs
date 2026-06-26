//! Tool registry, index schema, release, ingest, queue.
//! Re-exported flat (`vela_edge::*`) at the crate root; file organization only.

pub mod frontier_release;
pub mod incremental_ingest;
pub mod index_db_schema;
pub mod queue;
pub mod tool_registry;
