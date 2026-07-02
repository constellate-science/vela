//! Owner-epoch governance-chain verification (`vela hub verify-chain`)
//! and its on-disk chain path. Moved verbatim from `cli/mod.rs`.

use super::*;

/// v0.146: derive the on-disk owner-epoch chain transcript path
/// for a given frontier. Sits at
/// `<frontier-dir>/.vela/governance/chain.json` regardless of
/// whether the input is a frontier file or a frontier directory.
pub(crate) fn governance_chain_path(frontier: &Path) -> PathBuf {
    let dir = if frontier.is_dir() {
        frontier.to_path_buf()
    } else if let Some(parent) = frontier.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    dir.join(".vela").join("governance").join("chain.json")
}

/// v0.146: verify the owner-epoch chain transcript for a frontier.
pub(crate) fn cmd_verify_chain(frontier: PathBuf, artifacts: PathBuf, json: bool) {
    use vela_edge::governance::{
        ChainStatus, GovernancePolicy, OwnerEpochChain, OwnerRotateAttestationBundle,
        OwnerRotateProposal, verify_chain,
    };

    let chain_path = governance_chain_path(&frontier);
    if !chain_path.exists() {
        // Legacy entry (pre-v0.144): no chain file.
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "command": "registry.verify-chain",
                    "frontier": frontier.display().to_string(),
                    "chain_status": "legacy",
                    "reason": format!("no chain file at {}", chain_path.display()),
                }))
                .expect("serialize legacy")
            );
        } else {
            println!(
                "{} chain status: legacy ({} not present)",
                style::ok("verify-chain"),
                chain_path.display()
            );
        }
        return;
    }

    let chain_raw = std::fs::read_to_string(&chain_path)
        .unwrap_or_else(|e| fail_return(&format!("read chain: {e}")));
    let chain: OwnerEpochChain = serde_json::from_str(&chain_raw)
        .unwrap_or_else(|e| fail_return(&format!("parse chain: {e}")));

    // Load artifacts up front so the closure-borrow stays simple.
    let mut policies: std::collections::HashMap<String, GovernancePolicy> =
        std::collections::HashMap::new();
    let mut proposals: std::collections::HashMap<String, OwnerRotateProposal> =
        std::collections::HashMap::new();
    let mut bundles: std::collections::HashMap<String, OwnerRotateAttestationBundle> =
        std::collections::HashMap::new();

    for transition in &chain.transitions {
        let policy_path = artifacts.join(format!("{}.json", transition.policy_id));
        let proposal_path = artifacts.join(format!("{}.json", transition.proposal_id));
        let bundle_path = artifacts.join(format!("{}.json", transition.bundle_id));

        if !policies.contains_key(&transition.policy_id) {
            let raw = std::fs::read_to_string(&policy_path).unwrap_or_else(|e| {
                fail_return(&format!("read policy {}: {e}", policy_path.display()))
            });
            let p: GovernancePolicy = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse policy: {e}")));
            policies.insert(transition.policy_id.clone(), p);
        }
        if !proposals.contains_key(&transition.proposal_id) {
            let raw = std::fs::read_to_string(&proposal_path).unwrap_or_else(|e| {
                fail_return(&format!("read proposal {}: {e}", proposal_path.display()))
            });
            let p: OwnerRotateProposal = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse proposal: {e}")));
            proposals.insert(transition.proposal_id.clone(), p);
        }
        if !bundles.contains_key(&transition.bundle_id) {
            let raw = std::fs::read_to_string(&bundle_path).unwrap_or_else(|e| {
                fail_return(&format!("read bundle {}: {e}", bundle_path.display()))
            });
            let b: OwnerRotateAttestationBundle = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse bundle: {e}")));
            bundles.insert(transition.bundle_id.clone(), b);
        }
    }

    let frontier_data = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let revocation = FrontierRevocation {
        map: frontier_data
            .actors
            .iter()
            .filter_map(|a| a.revoked_at.as_ref().map(|r| (a.id.clone(), r.clone())))
            .collect(),
    };
    let now = chrono::Utc::now().to_rfc3339();

    let status = verify_chain(&chain, &policies, &proposals, &bundles, &revocation, &now);

    let status_str = match status {
        ChainStatus::Bootstrap => "bootstrap",
        ChainStatus::Verified => "verified",
        ChainStatus::Legacy => "legacy",
        ChainStatus::Broken => "broken",
    };

    if json {
        let payload = json!({
            "ok": !matches!(status, ChainStatus::Broken),
            "command": "registry.verify-chain",
            "frontier": frontier.display().to_string(),
            "chain_status": status_str,
            "transition_count": chain.transitions.len(),
            "current_epoch": chain.transitions.last().map_or(0, |t| t.owner_epoch),
        });
        print_json(&payload);
    } else {
        println!(
            "{} chain status: {} ({} transition(s))",
            style::ok("verify-chain"),
            status_str,
            chain.transitions.len()
        );
        if let Some(t) = chain.transitions.last() {
            println!(
                "  current epoch: {}  policy: {}  bundle: {}",
                t.owner_epoch, t.policy_id, t.bundle_id
            );
        }
    }

    if matches!(status, ChainStatus::Broken) {
        std::process::exit(1);
    }
}

/// Revocation lookup backed by the frontier's actor records.
pub(crate) struct FrontierRevocation {
    pub(crate) map: std::collections::HashMap<String, String>,
}

impl vela_edge::governance::ActorRevocationLookup for FrontierRevocation {
    fn revoked_at(&self, actor_id: &str) -> Option<&str> {
        self.map.get(actor_id).map(String::as_str)
    }
}
