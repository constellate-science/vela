//! v0.199: Tool Descriptor (`vtd_*`).
//!
//! Declares "this frontier consumes outputs from this tool" as a
//! first-class Carina primitive. ToolUniverse-compatible. Doesn't
//! require runtime tool integration; makes the dependency explicit
//! and auditable so a v0.194 trajectory step with `kind: Tool` can
//! resolve to a concrete tool's identity, version, calling
//! convention, and input/output schemas.
//!
//! Substrate-honest framing: a descriptor is purely declarative. It
//! does not vouch for the tool's correctness; it pins what the
//! frontier claims the tool is. A reviewer cross-checks the
//! descriptor against the provider's published specs.
//!
//! Composes with v0.200 (`ver_*` Evaluation Record can target a
//! `vtd_*` to record "this tool benched at score Y on benchmark Z")
//! and the v0.194 Trajectory Tool step.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const TOOL_DESCRIPTOR_SCHEMA: &str = "vela.tool_descriptor.v0.1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    HttpJson,
    PythonCallable,
    CliSubprocess,
    McpServer,
}

impl CallingConvention {
    pub fn canonical(&self) -> &'static str {
        match self {
            CallingConvention::HttpJson => "http_json",
            CallingConvention::PythonCallable => "python_callable",
            CallingConvention::CliSubprocess => "cli_subprocess",
            CallingConvention::McpServer => "mcp_server",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolDescriptor {
    pub schema: String,
    pub descriptor_id: String,
    pub tool_name: String,
    pub tool_version: String,
    pub provider: String,
    pub calling_convention: CallingConvention,
    pub input_schema: Value,
    pub output_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cited_in_findings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DescriptorDraft {
    pub tool_name: String,
    pub tool_version: String,
    pub provider: String,
    pub calling_convention: CallingConvention,
    pub input_schema: Value,
    pub output_schema: Value,
    pub evidence_url: Option<String>,
    pub cited_in_findings: Vec<String>,
}

impl ToolDescriptor {
    pub fn build(draft: DescriptorDraft) -> Result<Self, String> {
        validate_draft(&draft)?;
        let mut d = Self {
            schema: TOOL_DESCRIPTOR_SCHEMA.to_string(),
            descriptor_id: String::new(),
            tool_name: draft.tool_name,
            tool_version: draft.tool_version,
            provider: draft.provider,
            calling_convention: draft.calling_convention,
            input_schema: draft.input_schema,
            output_schema: draft.output_schema,
            evidence_url: draft.evidence_url,
            cited_in_findings: draft.cited_in_findings,
        };
        d.descriptor_id = d.derive_id();
        Ok(d)
    }

    /// Canonical bytes over which descriptor_id is derived. Order is
    /// fixed; any change to this layout is a breaking schema bump.
    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.tool_name.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.tool_version.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.provider.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.calling_convention.canonical().as_bytes());
        out.push(b'|');
        // Canonical JSON for the schemas: sorted keys + compact
        // separators. serde_json's to_string by default sorts when the
        // input is a plain Value::Object only if we use BTreeMap;
        // canonicalize explicitly here to keep id stability.
        out.extend_from_slice(canonical_json(&self.input_schema).as_bytes());
        out.push(b'|');
        out.extend_from_slice(canonical_json(&self.output_schema).as_bytes());
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        format!("vtd_{}", &hex::encode(hasher.finalize())[..16])
    }

    pub fn verify(&self) -> Result<(), String> {
        let rederived = self.derive_id();
        if rederived != self.descriptor_id {
            return Err(format!(
                "descriptor_id mismatch: declared {}, rebuilt {}",
                self.descriptor_id, rederived
            ));
        }
        Ok(())
    }
}

fn canonical_json(v: &Value) -> String {
    // Recursive canonicalization: arrays preserve order; object keys
    // sorted lexicographically; whitespace collapsed.
    fn walk(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), walk(&map[k]));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(walk).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&walk(v)).unwrap_or_default()
}

fn validate_draft(d: &DescriptorDraft) -> Result<(), String> {
    if d.tool_name.is_empty() {
        return Err("tool_name cannot be empty".to_string());
    }
    if d.tool_version.is_empty() {
        return Err("tool_version cannot be empty".to_string());
    }
    if d.provider.is_empty() {
        return Err("provider cannot be empty".to_string());
    }
    if !d.input_schema.is_object() {
        return Err("input_schema must be a JSON object".to_string());
    }
    if !d.output_schema.is_object() {
        return Err("output_schema must be a JSON object".to_string());
    }
    for vf in &d.cited_in_findings {
        if !vf.starts_with("vf_") {
            return Err(format!(
                "cited_in_findings entries must start with `vf_`, got `{vf}`"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_draft() -> DescriptorDraft {
        DescriptorDraft {
            tool_name: "protein_fold".to_string(),
            tool_version: "2024.10".to_string(),
            provider: "tooluniverse:protein-fold:2024.10".to_string(),
            calling_convention: CallingConvention::HttpJson,
            input_schema: json!({"type": "object", "properties": {"sequence": {"type": "string"}}}),
            output_schema: json!({"type": "object", "properties": {"pdb": {"type": "string"}}}),
            evidence_url: None,
            cited_in_findings: vec![],
        }
    }

    #[test]
    fn builds_with_deterministic_id() {
        let d1 = ToolDescriptor::build(ok_draft()).unwrap();
        let d2 = ToolDescriptor::build(ok_draft()).unwrap();
        assert_eq!(d1.descriptor_id, d2.descriptor_id);
        assert!(d1.descriptor_id.starts_with("vtd_"));
        assert_eq!(d1.descriptor_id.len(), 4 + 16);
    }

    #[test]
    fn different_version_produces_different_id() {
        let d1 = ToolDescriptor::build(ok_draft()).unwrap();
        let mut draft2 = ok_draft();
        draft2.tool_version = "2024.11".to_string();
        let d2 = ToolDescriptor::build(draft2).unwrap();
        assert_ne!(d1.descriptor_id, d2.descriptor_id);
    }

    #[test]
    fn different_input_schema_produces_different_id() {
        let d1 = ToolDescriptor::build(ok_draft()).unwrap();
        let mut draft2 = ok_draft();
        draft2.input_schema =
            json!({"type": "object", "properties": {"sequence_2": {"type": "string"}}});
        let d2 = ToolDescriptor::build(draft2).unwrap();
        assert_ne!(d1.descriptor_id, d2.descriptor_id);
    }

    #[test]
    fn json_key_order_does_not_affect_id() {
        // Build two descriptors whose input_schema has the same set
        // of keys but in different insertion order — the canonical
        // JSON normalizer should sort them and produce the same id.
        let d1 = ToolDescriptor::build(ok_draft()).unwrap();
        let mut draft2 = ok_draft();
        // Different key order in a sub-object.
        draft2.input_schema = json!({
            "properties": {"sequence": {"type": "string"}},
            "type": "object"
        });
        let d2 = ToolDescriptor::build(draft2).unwrap();
        assert_eq!(d1.descriptor_id, d2.descriptor_id);
    }

    #[test]
    fn empty_tool_name_rejected() {
        let mut d = ok_draft();
        d.tool_name = String::new();
        assert!(ToolDescriptor::build(d).is_err());
    }

    #[test]
    fn non_vf_finding_citation_rejected() {
        let mut d = ok_draft();
        d.cited_in_findings = vec!["vsd_not_a_vf".to_string()];
        assert!(ToolDescriptor::build(d).is_err());
    }

    #[test]
    fn tampered_body_fails_verify() {
        let mut d = ToolDescriptor::build(ok_draft()).unwrap();
        d.tool_version = "different".to_string();
        assert!(d.verify().is_err());
    }

    #[test]
    fn round_trips_through_json() {
        let d = ToolDescriptor::build(ok_draft()).unwrap();
        let s = serde_json::to_string(&d).unwrap();
        let back: ToolDescriptor = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
        back.verify().unwrap();
    }
}
