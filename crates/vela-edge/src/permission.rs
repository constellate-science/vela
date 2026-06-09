//! Permission metadata for the public frontier tool registry.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionLevel {
    ReadOnly,
    Write,
    Dangerous,
}

impl std::fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read-only"),
            Self::Write => write!(f, "write"),
            Self::Dangerous => write!(f, "dangerous"),
        }
    }
}
