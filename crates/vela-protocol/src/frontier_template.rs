//! Frontier templates for first external adoption.
//!
//! Templates only scaffold local review structure. They do not create
//! evidence, accepted findings, or scientific authority.

use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const ADOPTION_FRONTIER_TEMPLATE: &str = "adoption-frontier";

pub fn apply(path: &Path, name: &str, template: &str) -> Result<Vec<String>, String> {
    match template {
        ADOPTION_FRONTIER_TEMPLATE => apply_adoption_frontier(path, name),
        _ => Ok(default_next_commands(path)),
    }
}

fn apply_adoption_frontier(path: &Path, name: &str) -> Result<Vec<String>, String> {
    write_root_docs(path, name)?;
    write_adoption_directories(path)?;
    write_policy_docs(path)?;
    patch_manifest(path)?;
    Ok(adoption_next_commands(path))
}

fn write_root_docs(path: &Path, name: &str) -> Result<(), String> {
    let readme = format!(
        "# {name}\n\nThis frontier is a local adoption workspace. It starts with source identity, task records, and review packets. Policy guides review. It is not evidence.\n\n## First task\n\n```bash\nvela doctor .\nvela source-inbox add . --title \"Example source\" --locator doi:10.0000/example --source-type paper --json\nvela source-inbox list . --json\nvela task create . --type source_ingestion --objective \"Review whether the example source changes the frontier.\" --input doi:10.0000/example --risk-class source_repair --acceptance \"source identity is verified\" --status eligible --json\nvela task list . --json\n```\n\n## Review boundary\n\nSource-inbox records and tasks are local work. They do not change accepted frontier state until a reviewed event is emitted.\n"
    );
    fs::write(path.join("README.md"), readme)
        .map_err(|e| format!("Failed to write README.md: {e}"))?;

    let frontier = format!(
        "# FRONTIER\n\nName: {name}\n\n## Bounded question\n\nWrite the scientific question this frontier reviews.\n\n## Review rule\n\nEvery accepted state change needs source grounding, a typed reviewer id, and a reason. Agent output remains source material until reviewed.\n"
    );
    fs::write(path.join("FRONTIER.md"), frontier)
        .map_err(|e| format!("Failed to write FRONTIER.md: {e}"))?;

    let scope = format!(
        "# Scope\n\nFrontier: {name}\n\n## Includes\n\n- Public source identity records.\n- Local tasks that decide what needs review.\n- Review packets and proof packets generated from local state.\n\n## Excludes\n\n- Treatment advice.\n- Unreviewed claims presented as evidence.\n- Agent output accepted without review.\n\nPolicy guides review. It is not evidence.\n"
    );
    fs::write(path.join("SCOPE.md"), scope).map_err(|e| format!("Failed to write SCOPE.md: {e}"))
}

fn write_adoption_directories(path: &Path) -> Result<(), String> {
    let dirs = BTreeMap::from([
        (
            ".vela/policy",
            "Frontier-owned policy files. Policy guides review. It is not evidence.",
        ),
        (
            ".vela/source-inbox",
            "Source identity records before evidence review.",
        ),
        (".vela/tasks", "Local scientific work units."),
        (
            ".vela/workspaces",
            "Isolated task workspaces for artifacts and logs.",
        ),
        (
            ".vela/diff_packs",
            "Scientific Diff Pack drafts before review.",
        ),
        (
            ".vela/review_packets",
            "Generated review packets for human inspection.",
        ),
        (
            ".vela/attestations",
            "Reviewer attestations and scoped decisions.",
        ),
        ("review", "Human review notes and packet exports."),
        ("proof", "Proof packets, hashes, and freshness records."),
        ("exports", "Share packages and generated read-only exports."),
    ]);

    for (dir, description) in dirs {
        let section = path.join(dir);
        fs::create_dir_all(&section).map_err(|e| format!("Failed to create {dir}/: {e}"))?;
        let readme = section.join("README.md");
        if !readme.exists() {
            let title = dir.rsplit('/').next().unwrap_or(dir);
            fs::write(readme, format!("# {title}\n\n{description}\n"))
                .map_err(|e| format!("Failed to write {dir}/README.md: {e}"))?;
        }
    }
    Ok(())
}

fn write_policy_docs(path: &Path) -> Result<(), String> {
    let policy_dir = path.join(".vela").join("policy");
    fs::create_dir_all(&policy_dir).map_err(|e| format!("Failed to create policy dir: {e}"))?;
    let policies = [
        (
            "evidence_policy.md",
            "---\ntitle: Evidence policy\n---\n# Evidence policy\n\nEvidence must be source-grounded before it can support a finding bundle. Source-inbox metadata supports source identity only. It is not scientific support by itself.\n\nReviewers should record population, model system, endpoint, locator, and caveats before accepting a claim-level change.\n",
        ),
        (
            "review_policy.md",
            "---\ntitle: Review policy\nrequired_roles:\n  low_risk:\n    - local_reviewer\n  source_repair:\n    - source_reviewer\n  confidence_change:\n    - domain_reviewer\n    - method_reviewer\n  clinical_translation:\n    - domain_reviewer\n    - safety_reviewer\n---\n# Review policy\n\nAccepted state changes require a typed reviewer id and a reason. Higher-impact changes require the roles listed in front matter. Review decisions should cite source, evidence, task, or Diff Pack ids when available.\n",
        ),
        (
            "confidence_policy.md",
            "---\ntitle: Confidence policy\nrequires_source_or_evidence_ref: true\n---\n# Confidence policy\n\nConfidence changes require a source or evidence reference, a direction, and a bounded reason. The policy does not compute truth. It records the review requirements for changing confidence.\n",
        ),
        (
            "agent_policy.md",
            "---\ntitle: Agent policy\nagents_may:\n  - create_source_inbox_record\n  - create_task\n  - propose_diff_pack\n  - build_review_packet\n---\n# Agent policy\n\nAgents may create source records, tasks, Diff Pack drafts, and review packets. Agents may not accept findings, change confidence, or publish clinical translation without review.\n",
        ),
    ];

    for (filename, body) in policies {
        fs::write(policy_dir.join(filename), body)
            .map_err(|e| format!("Failed to write .vela/policy/{filename}: {e}"))?;
    }
    Ok(())
}

fn patch_manifest(path: &Path) -> Result<(), String> {
    let manifest_path = path.join("frontier.yaml");
    let raw = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read frontier.yaml: {e}"))?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&raw).map_err(|e| format!("Failed to parse frontier.yaml: {e}"))?;

    set_yaml_path(
        &mut value,
        &["policies", "evidence"],
        ".vela/policy/evidence_policy.md",
    );
    set_yaml_path(
        &mut value,
        &["policies", "review"],
        ".vela/policy/review_policy.md",
    );
    set_yaml_path(
        &mut value,
        &["policies", "confidence"],
        ".vela/policy/confidence_policy.md",
    );
    set_yaml_path(
        &mut value,
        &["policies", "agent"],
        ".vela/policy/agent_policy.md",
    );
    set_yaml_path(&mut value, &["policies", "proof"], "proof/policy.yaml");

    if let Some(map) = value.as_mapping_mut() {
        map.insert(
            serde_yaml::Value::String("templates".to_string()),
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(
                ADOPTION_FRONTIER_TEMPLATE.to_string(),
            )]),
        );
    }

    let yaml = serde_yaml::to_string(&value)
        .map_err(|e| format!("Failed to serialize frontier.yaml: {e}"))?;
    fs::write(manifest_path, yaml).map_err(|e| format!("Failed to write frontier.yaml: {e}"))
}

fn set_yaml_path(value: &mut serde_yaml::Value, path: &[&str], leaf: &str) {
    if path.is_empty() {
        *value = serde_yaml::Value::String(leaf.to_string());
        return;
    }
    let mut cur = value;
    for key in &path[..path.len() - 1] {
        if !cur.is_mapping() {
            *cur = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        let map = cur.as_mapping_mut().expect("mapping initialized");
        cur = map
            .entry(serde_yaml::Value::String((*key).to_string()))
            .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    }
    if !cur.is_mapping() {
        *cur = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    cur.as_mapping_mut().expect("mapping initialized").insert(
        serde_yaml::Value::String(path[path.len() - 1].to_string()),
        serde_yaml::Value::String(leaf.to_string()),
    );
}

pub fn adoption_next_commands(path: &Path) -> Vec<String> {
    let target = path.display().to_string();
    vec![
        format!("vela doctor {target}"),
        format!(
            "vela source-inbox add {target} --title \"Example source\" --locator doi:10.0000/example --source-type paper --json"
        ),
        format!("vela source-inbox list {target} --json"),
        format!(
            "vela task create {target} --type source_ingestion --objective \"Review whether the example source changes the frontier.\" --input doi:10.0000/example --risk-class source_repair --acceptance \"source identity is verified\" --status eligible --json"
        ),
        format!("vela task list {target} --json"),
    ]
}

pub fn default_next_commands(path: &Path) -> Vec<String> {
    let target = path.display().to_string();
    vec![
        format!("vela doctor {target}"),
        format!("vela check {target} --strict --json"),
        format!("vela proof {target} --out proof/latest"),
        format!("vela stats {target}"),
        format!("vela workbench {target} --port 3741"),
    ]
}

pub fn init_payload_fields(template: &str, path: &Path) -> serde_json::Value {
    json!({
        "template": template,
        "next_commands": if template == ADOPTION_FRONTIER_TEMPLATE {
            adoption_next_commands(path)
        } else {
            default_next_commands(path)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontier_repo::{self, InitOptions};
    use tempfile::TempDir;

    #[test]
    fn adoption_template_writes_policy_and_manifest() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Template frontier",
                template: ADOPTION_FRONTIER_TEMPLATE,
                initialize_git: false,
            },
        )
        .unwrap();

        assert!(tmp.path().join("FRONTIER.md").is_file());
        assert!(tmp.path().join(".vela/policy/evidence_policy.md").is_file());
        assert!(tmp.path().join(".vela/diff_packs/README.md").is_file());
        let manifest = fs::read_to_string(tmp.path().join("frontier.yaml")).unwrap();
        assert!(manifest.contains("adoption-frontier"));
        assert!(manifest.contains(".vela/policy/review_policy.md"));
    }

    #[test]
    fn adoption_next_commands_are_copyable() {
        let commands = adoption_next_commands(Path::new("my-frontier"));
        assert_eq!(commands.len(), 5);
        assert!(commands[0].contains("vela doctor"));
        assert!(commands[3].contains("vela task create"));
    }
}
