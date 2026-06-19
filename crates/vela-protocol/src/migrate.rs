//! One-shot re-genesis migration for the v0.700 empirical-field strip.
//!
//! The skip-guarded `FindingBundle` (see `bundle.rs`) serialises math findings
//! with no empirical keys, which changes `finding_hash` and therefore breaks the
//! `after_hash` pin on every already-accepted, SIGNED finding event. This module
//! re-mints that signed history: it rewrites each proposal's finding payload
//! through the clean struct, replays the event log re-deriving every finding /
//! evidence-atom state event's `before_hash`/`after_hash` from the clean body,
//! re-derives the content-addressed `event.id`, and re-signs with the original
//! actor's key.
//!
//! KEY CUSTODY: this code never reads a key from disk. The caller supplies an
//! `actor_id -> SigningKey` map (the human's reviewer key included), so the
//! signatures are produced under the operator's own custody, never by inference.
//! `vf_` finding ids are unaffected (`content_address` does not read any stripped
//! field); only `vev_` event ids move.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::bundle::FindingBundle;
use crate::events::{self, NULL_HASH, StateEvent};
use crate::proposals::StateProposal;
use crate::reducer;
use crate::sign;

/// Result of a re-genesis pass over one frontier.
pub struct Regenesis {
    /// Re-minted, re-signed events (new `vev_` ids, clean `after_hash` chain).
    pub events: Vec<StateEvent>,
    /// Proposals with their finding payloads rewritten through the clean struct.
    pub proposals: Vec<StateProposal>,
    /// Final materialized findings (clean serialization).
    pub findings: Vec<FindingBundle>,
    /// How many state events were re-minted (side-table events pass through).
    pub reminted: usize,
}

/// Hydrate genesis findings from the (already-rewritten-clean) proposal store
/// WITHOUT the `after_hash` pin check — the whole point of the migration is that
/// the old pin no longer matches the clean body. Mirrors `reducer::seed_genesis`
/// minus the verification branch.
fn seed_genesis_relaxed(
    events_sorted: &[StateEvent],
    proposals: &[StateProposal],
) -> Result<Vec<FindingBundle>, String> {
    let by_id: HashMap<&str, &StateProposal> =
        proposals.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut genesis: Vec<FindingBundle> = Vec::new();
    for ev in events_sorted {
        let payload_key = match ev.kind.as_str() {
            "finding.asserted" => "finding",
            "finding.superseded" => "new_finding",
            _ => continue,
        };
        if ev.payload.get("finding").is_some() && payload_key == "finding" {
            // Inline (v0.3 genesis) form — the reducer arm applies it on replay.
            continue;
        }
        let Some(pid) = ev.payload.get("proposal_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(proposal) = by_id.get(pid) else {
            return Err(format!(
                "{}: references proposal {pid}, not in the proposal store",
                ev.id
            ));
        };
        let Some(body) = proposal.payload.get(payload_key) else {
            return Err(format!(
                "{}: proposal {pid} has no payload.{payload_key}",
                ev.id
            ));
        };
        let finding: FindingBundle = serde_json::from_value(body.clone())
            .map_err(|e| format!("{}: proposal {pid} payload.{payload_key}: {e}", ev.id))?;
        if genesis.iter().any(|g| g.id == finding.id) {
            continue;
        }
        genesis.push(finding);
    }
    Ok(genesis)
}

/// Re-genesis a frontier's signed event log after the empirical-field strip.
///
/// `actor_keys` maps every signing actor id in the log to its key. A missing key
/// is a hard error (never silently drop a signature). Returns the re-minted
/// events, the clean proposals, and the final findings.
pub fn regenesis_strip_empirical(
    mut proposals: Vec<StateProposal>,
    events: Vec<StateEvent>,
    actor_keys: &HashMap<String, SigningKey>,
) -> Result<Regenesis, String> {
    // 1. Rewrite each proposal's finding payload through the clean struct so the
    //    stored body and the hydrated body both lose the empirical keys.
    for p in &mut proposals {
        for key in ["finding", "new_finding"] {
            if let Some(body) = p.payload.get(key).cloned() {
                if body.is_null() {
                    continue;
                }
                let f: FindingBundle = serde_json::from_value(body)
                    .map_err(|e| format!("proposal {}: payload.{key} deserialize: {e}", p.id))?;
                p.payload[key] = serde_json::to_value(&f)
                    .map_err(|e| format!("proposal {}: payload.{key} re-serialize: {e}", p.id))?;
            }
        }
    }

    // 2. Relaxed genesis seed from the clean proposals.
    let sorted = reducer::sorted_for_replay(&events);
    let genesis = seed_genesis_relaxed(&sorted, &proposals)?;

    // 3. Build a scaffold Project (genesis findings, empty event log) by replaying
    //    an empty log, then run our own re-minting replay over the real events.
    let mut state = reducer::replay_from_genesis(
        genesis,
        Vec::new(),
        "regenesis",
        "regenesis scaffold",
        "1970-01-01T00:00:00Z",
        "vela-migrate",
    )?;
    // Make the proposal store available to any arm that hydrates from it.
    state.proposals = proposals.clone();

    let mut prev_after: HashMap<String, String> = HashMap::new();
    let mut out_events: Vec<StateEvent> = Vec::with_capacity(sorted.len());
    let mut reminted = 0usize;
    // old event id -> new event id, for re-pointing proposal back-references.
    let mut id_remap: HashMap<String, String> = HashMap::new();

    for ev in sorted {
        let side_table = ev.before_hash == NULL_HASH && ev.after_hash == NULL_HASH;
        // Apply to advance materialized state (idempotent for already-seeded asserts).
        reducer::apply_event(&mut state, &ev)?;

        if side_table {
            // Activity against a finding without a state transition: its id and
            // signature do not depend on any finding body, so it is unchanged.
            out_events.push(ev.clone());
            state.events.push(ev);
            continue;
        }

        let tkey = format!("{}:{}", ev.target.r#type, ev.target.id);
        let before = prev_after
            .get(&tkey)
            .cloned()
            .unwrap_or_else(|| NULL_HASH.to_string());
        let after = match ev.target.r#type.as_str() {
            "finding" => events::finding_hash_by_id(&state, &ev.target.id),
            "evidence_atom" => events::evidence_atom_hash_by_id(&state, &ev.target.id),
            other => {
                return Err(format!(
                    "{}: re-mint of non-null-hash event with unexpected target type `{other}`",
                    ev.id
                ));
            }
        };

        let was_signed = ev.signature.is_some();
        let mut re = ev.clone();
        re.before_hash = before;
        re.after_hash = after.clone();
        re.id = events::event_id(&re);
        // Preserve the original signed/unsigned status: re-sign only events that
        // carried a signature (so an unsigned annotation is re-minted but stays
        // unsigned, never gaining a human attestation it never had).
        if was_signed {
            let key = actor_keys
                .get(&re.actor.id)
                .ok_or_else(|| format!("no signing key supplied for actor `{}`", re.actor.id))?;
            re.signature = Some(sign::sign_event(&re, key)?);
        }

        if re.id != ev.id {
            id_remap.insert(ev.id.clone(), re.id.clone());
        }
        prev_after.insert(tkey, after);
        reminted += 1;
        out_events.push(re.clone());
        state.events.push(re);
    }

    // Re-point each proposal's `applied_event_id` (the finding.asserted event
    // that accepted it) through the remap, so the status projection still finds
    // the decision event after its id moved.
    for p in &mut proposals {
        if let Some(old) = p.applied_event_id.clone()
            && let Some(new) = id_remap.get(&old)
        {
            p.applied_event_id = Some(new.clone());
        }
    }

    Ok(Regenesis {
        events: out_events,
        proposals,
        findings: state.findings.clone(),
        reminted,
    })
}
