//! The HTTP/MCP server + the command engine + clap command defs.
//! Re-exported flat (`crate::cli_*`) at the crate root; file organization only.

pub mod cli_commands;
pub mod cli_engine;
pub mod serve;
