//! Ancestor-closure primitive for federated event sets.
//!
//! Implements the substrate-level support for `docs/THEORY.md`
//! §5.2 (causally down-closed event sets) and §5.3 (merge
//! semantics):
//!
//! > An event set `E` is **causally down-closed** if
//! > `e in E => parents(e) is a subset of E`.
//! > Only down-closed event sets are valid replay inputs.
//! >
//! > For valid down-closed event sets `E_1 join E_2 = E_1 union E_2`.
//! > For incomplete received sets, merge is undefined until ancestor
//! > closure is restored.
//!
//! ## What this module ships
//!
//! Pure algebra over `(event_id, parents)` pairs:
//!
//! - [`is_causally_closed`]: predicate check.
//! - [`missing_ancestors`]: list ids referenced as parents but
//!   absent from the set.
//! - [`causal_closure`]: compute the transitive closure of parents
//!   over a known event pool.
//! - [`AncestorAction`]: enum naming the policy decisions
//!   federation must make when a received event set is incomplete.
//!
//! ## What this module does NOT do
//!
//! It does not perform network fetches, federation policy
//! application, or merge-conflict adjudication. Those live in the
//! federation module / hub server. This module is the algebra
//! they build on.
//!
//! For genericity over event types, the API takes
//! `(id, parents)` slices rather than coupling to
//! [`crate::events::StateEvent`]. Callers can extract those pairs
//! from any concrete event type.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The policy decision a federation hub must make when it receives
/// an event set whose ancestor closure is incomplete.
///
/// Per `docs/THEORY.md` §5.2: "If a hub receives an event without
/// ancestors, merge is undefined until missing ancestors are
/// fetched or an explicit fork policy is invoked."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AncestorAction {
    /// All ancestors are present; replay can proceed immediately.
    Proceed,
    /// Ancestors are missing; fetch them from the named source
    /// before replay. The list is the ids that must be obtained.
    Fetch {
        /// Ids referenced as parents but not present in the set.
        missing: Vec<String>,
    },
    /// Ancestors are missing and a federation policy chooses to
    /// fork rather than fetch. The fork branches off from the
    /// available events and treats the missing ancestors as out of
    /// scope. Recorded as a governance event in the log.
    Fork {
        /// Ids that triggered the fork decision.
        triggering_missing: Vec<String>,
        /// Reviewer-supplied reason for choosing fork over fetch.
        reason: String,
    },
}

impl AncestorAction {
    /// Whether this action permits replay to proceed without
    /// further work.
    #[must_use]
    pub fn proceeds(&self) -> bool {
        matches!(self, Self::Proceed)
    }
}

/// Whether the event set is causally down-closed: every parent
/// referenced by any event in the set is also present in the set.
pub fn is_causally_closed<I, S>(events: I) -> bool
where
    I: IntoIterator<Item = (S, Vec<S>)>,
    S: AsRef<str>,
{
    let pairs: Vec<(String, Vec<String>)> = events
        .into_iter()
        .map(|(id, parents)| {
            (
                id.as_ref().to_string(),
                parents.iter().map(|p| p.as_ref().to_string()).collect(),
            )
        })
        .collect();
    let known: BTreeSet<&str> = pairs.iter().map(|(id, _)| id.as_str()).collect();
    for (_, parents) in &pairs {
        for p in parents {
            if !known.contains(p.as_str()) {
                return false;
            }
        }
    }
    true
}

/// Find every parent id referenced by the event set but absent
/// from it. Returned ids are deduplicated and sorted lexically.
///
/// An empty result means the set is causally down-closed and merge
/// is well-defined.
pub fn missing_ancestors<I, S>(events: I) -> Vec<String>
where
    I: IntoIterator<Item = (S, Vec<S>)>,
    S: AsRef<str>,
{
    let pairs: Vec<(String, Vec<String>)> = events
        .into_iter()
        .map(|(id, parents)| {
            (
                id.as_ref().to_string(),
                parents.iter().map(|p| p.as_ref().to_string()).collect(),
            )
        })
        .collect();
    let known: BTreeSet<String> = pairs.iter().map(|(id, _)| id.clone()).collect();
    let mut missing: BTreeSet<String> = BTreeSet::new();
    for (_, parents) in &pairs {
        for p in parents {
            if !known.contains(p) {
                missing.insert(p.clone());
            }
        }
    }
    missing.into_iter().collect()
}

/// Compute the causal closure of `received` over the broader
/// `available` pool. The result is the union of `received` plus
/// every ancestor reachable through `available`.
///
/// If any required ancestor is not in `available`, it is returned
/// in `missing` instead of the closure.
///
/// Returns:
/// - `Ok(closure)` if every ancestor is reachable in `available`.
/// - `Err(missing)` if some ancestors are unreachable.
pub fn causal_closure<I1, I2, S>(received: I1, available: I2) -> Result<Vec<String>, Vec<String>>
where
    I1: IntoIterator<Item = (S, Vec<S>)>,
    I2: IntoIterator<Item = (S, Vec<S>)>,
    S: AsRef<str>,
{
    // Build a parents map over the available pool.
    let pool: BTreeMap<String, Vec<String>> = available
        .into_iter()
        .map(|(id, parents)| {
            (
                id.as_ref().to_string(),
                parents.iter().map(|p| p.as_ref().to_string()).collect(),
            )
        })
        .collect();

    let received_ids: Vec<String> = received
        .into_iter()
        .map(|(id, _)| id.as_ref().to_string())
        .collect();

    let mut closure: BTreeSet<String> = BTreeSet::new();
    let mut missing: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = received_ids.clone();

    while let Some(id) = queue.pop() {
        if closure.contains(&id) {
            continue;
        }
        match pool.get(&id) {
            Some(parents) => {
                closure.insert(id.clone());
                for p in parents {
                    if !closure.contains(p) {
                        queue.push(p.clone());
                    }
                }
            }
            None => {
                // Either this is a received event whose body is not
                // in the pool, or it's a referenced ancestor that
                // is unreachable. Track as missing.
                missing.insert(id.clone());
            }
        }
    }

    if missing.is_empty() {
        Ok(closure.into_iter().collect())
    } else {
        Err(missing.into_iter().collect())
    }
}

/// Decide what action federation should take given the event set
/// it has and the policy.
///
/// In v0.84 this function only computes the algebra: it tells you
/// whether ancestors are missing and which ones. The actual fetch
/// or fork dispatch is a hub-side decision and lives in the
/// federation runtime.
pub fn classify_ancestor_action<I, S>(events: I) -> AncestorAction
where
    I: IntoIterator<Item = (S, Vec<S>)>,
    S: AsRef<str>,
{
    let missing = missing_ancestors(events);
    if missing.is_empty() {
        AncestorAction::Proceed
    } else {
        AncestorAction::Fetch { missing }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, parents: &[&str]) -> (String, Vec<String>) {
        (
            id.to_string(),
            parents.iter().map(|s| (*s).to_string()).collect(),
        )
    }

    fn evs(events: &[(String, Vec<String>)]) -> Vec<(String, Vec<String>)> {
        events.to_vec()
    }

    #[test]
    fn empty_set_is_closed() {
        let events: Vec<(String, Vec<String>)> = vec![];
        assert!(is_causally_closed(evs(&events)));
        assert!(missing_ancestors(evs(&events)).is_empty());
        assert_eq!(
            classify_ancestor_action(evs(&events)),
            AncestorAction::Proceed
        );
    }

    #[test]
    fn root_event_with_no_parents_is_closed() {
        let events = vec![ev("e1", &[])];
        assert!(is_causally_closed(evs(&events)));
        assert!(missing_ancestors(evs(&events)).is_empty());
    }

    #[test]
    fn linear_chain_is_closed() {
        let events = vec![ev("e1", &[]), ev("e2", &["e1"]), ev("e3", &["e2"])];
        assert!(is_causally_closed(evs(&events)));
        assert!(missing_ancestors(evs(&events)).is_empty());
    }

    #[test]
    fn missing_root_is_detected() {
        // e2 references e1 as parent but e1 is not in the set.
        let events = vec![ev("e2", &["e1"]), ev("e3", &["e2"])];
        assert!(!is_causally_closed(evs(&events)));
        assert_eq!(missing_ancestors(evs(&events)), vec!["e1"]);
    }

    #[test]
    fn multiple_missing_ancestors_are_deduplicated_and_sorted() {
        let events = vec![
            ev("e3", &["e1", "e2"]),
            ev("e4", &["e2", "e1"]),
            ev("e5", &["e3"]),
        ];
        // e1 and e2 are referenced but missing; expect them sorted.
        assert_eq!(missing_ancestors(evs(&events)), vec!["e1", "e2"]);
    }

    #[test]
    fn classify_returns_fetch_when_missing() {
        let events = vec![ev("e2", &["e1"])];
        let action = classify_ancestor_action(evs(&events));
        match action {
            AncestorAction::Fetch { missing } => assert_eq!(missing, vec!["e1"]),
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn classify_returns_proceed_when_closed() {
        let events = vec![ev("e1", &[]), ev("e2", &["e1"])];
        assert_eq!(
            classify_ancestor_action(evs(&events)),
            AncestorAction::Proceed
        );
    }

    #[test]
    fn diamond_is_closed_when_complete() {
        // e1 -> e2 -> e4
        // e1 -> e3 -> e4
        let events = vec![
            ev("e1", &[]),
            ev("e2", &["e1"]),
            ev("e3", &["e1"]),
            ev("e4", &["e2", "e3"]),
        ];
        assert!(is_causally_closed(evs(&events)));
    }

    #[test]
    fn causal_closure_walks_back_through_pool() {
        // available pool: e1 -> e2 -> e3 -> e4
        let pool = vec![
            ev("e1", &[]),
            ev("e2", &["e1"]),
            ev("e3", &["e2"]),
            ev("e4", &["e3"]),
        ];
        // received: just e3. Closure should include e1, e2, e3.
        let received = vec![ev("e3", &["e2"])];
        let closure = causal_closure(received, pool.clone()).unwrap();
        assert_eq!(closure, vec!["e1", "e2", "e3"]);
    }

    #[test]
    fn causal_closure_reports_unreachable_missing() {
        // pool: e2 -> e3, but e1 is not in the pool.
        let pool = vec![ev("e2", &["e1"]), ev("e3", &["e2"])];
        let received = vec![ev("e3", &["e2"])];
        let result = causal_closure(received, pool);
        match result {
            Err(missing) => assert_eq!(missing, vec!["e1"]),
            Ok(_) => panic!("expected unreachable missing"),
        }
    }

    #[test]
    fn ancestor_action_fork_carries_reason() {
        let action = AncestorAction::Fork {
            triggering_missing: vec!["e1".to_string()],
            reason: "peer hub partitioned; proceed with local view".to_string(),
        };
        match &action {
            AncestorAction::Fork {
                triggering_missing,
                reason,
            } => {
                assert_eq!(triggering_missing, &vec!["e1"]);
                assert!(reason.starts_with("peer hub"));
            }
            other => panic!("expected Fork, got {other:?}"),
        }
        assert!(!action.proceeds());
    }

    #[test]
    fn ancestor_action_serde_round_trip() {
        let actions = vec![
            AncestorAction::Proceed,
            AncestorAction::Fetch {
                missing: vec!["e1".to_string()],
            },
            AncestorAction::Fork {
                triggering_missing: vec!["e2".to_string()],
                reason: "fork policy invoked".to_string(),
            },
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let back: AncestorAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    #[test]
    fn closure_handles_already_received_events() {
        // received and pool overlap; closure should include received events too.
        let pool = vec![ev("e1", &[]), ev("e2", &["e1"])];
        let received = vec![ev("e1", &[]), ev("e2", &["e1"])];
        let closure = causal_closure(received, pool).unwrap();
        assert_eq!(closure, vec!["e1", "e2"]);
    }
}
