//! Library entry point for the `vela-hub` crate. The hub is primarily a
//! binary (`src/main.rs`), but a thin lib surface lets sibling binaries
//! such as `vela-hub-backfill-event-first` reuse the shared DB
//! abstraction without duplicating SQL.
//!
//! Doctrine: keep this surface minimal. If callers start needing more
//! than `HubDb` and its schema setup, that's a sign the hub should be
//! split into a service crate + a thin binary crate, not that the lib
//! should grow.

pub mod db;
pub mod storage;
