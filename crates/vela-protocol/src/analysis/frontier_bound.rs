//! Typed frontier bounds — the "current best / value-to-beat" of an open
//! problem as a FIRST-CLASS object rather than prose buried in
//! `assertion_text`.
//!
//! Today the Erdős atlas adapter (`atlas_adapters::read_erdos_deep`) folds each
//! problem's `current_best` record into the free-text assertion. No consumer
//! (foundry targets, attack ranking) can read it as a value-to-beat. This module
//! gives the bound a typed shape that mirrors the Sidon producer's
//! `frontiers/sidon-sets/bounds.json` (schema `vela.frontier-bounds.v1`):
//! a per-problem record with the bound prose, an optional parsed numeric value,
//! a direction (lower/upper), and an `accepted` flag that is `false` until a
//! human attests it.
//!
//! The Erdős `current_best` field is prose (a sentence from the problem page),
//! so `source_text` is authoritative and `value`/`direction` are a best-effort
//! parse — never fabricated. A bound whose prose does not yield a clean
//! `>=`/`<=`/numeric form keeps `value: None` and `direction: Unknown`, and the
//! consumer falls back to the prose. This is the honest typed surface: the value
//! is present only when it is mechanically extractable, the prose always is.

use serde::{Deserialize, Serialize};

/// The schema tag written into a bounds sidecar, mirroring the Sidon producer's
/// `frontiers/sidon-sets/bounds.json`.
pub const FRONTIER_BOUNDS_SCHEMA: &str = "vela.frontier-bounds.v1";

/// Which side of the open quantity the bound constrains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BoundDirection {
    /// A lower bound (e.g. a construction: "best known >= 7").
    Lower,
    /// An upper bound (e.g. an impossibility: "<= 12").
    Upper,
    /// The prose did not yield a direction; `source_text` is authoritative.
    #[default]
    Unknown,
}

impl BoundDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            BoundDirection::Lower => "lower",
            BoundDirection::Upper => "upper",
            BoundDirection::Unknown => "unknown",
        }
    }
}

/// One typed bound for an open problem — the value-to-beat a foundry / attack
/// ranking reads. Mirrors a Sidon `bounds[]` row in shape (a `problem`
/// reference, a typed `value`/`direction`, and an `accepted` flag), but keeps
/// the authoritative `source_text` prose because the Erdős corpus states its
/// records in words.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrontierBound {
    /// Problem reference, e.g. `"erdos/12"` (namespace/id).
    pub problem: String,
    /// Best-effort parsed numeric value, when the prose yields one cleanly.
    /// `None` keeps the bound honest — the value was not mechanically extractable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// Which side the bound constrains (lower/upper/unknown).
    pub direction: BoundDirection,
    /// The authoritative prose the bound was read from (the problem's
    /// `current_best` field). Always present.
    pub source_text: String,
    /// `false` until a human key-custody holder attests the bound. An adapter
    /// only ever emits unattested (`false`) bounds.
    pub accepted: bool,
}

impl FrontierBound {
    /// Build a typed bound from a problem reference and the prose `current_best`
    /// record. The numeric value + direction are a best-effort parse of the
    /// prose; never fabricated (absent when not cleanly extractable). The bound
    /// is unattested (`accepted: false`) — an adapter cannot accept its own work.
    pub fn from_prose(problem: impl Into<String>, source_text: impl Into<String>) -> Self {
        let source_text = source_text.into();
        let (value, direction) = parse_bound_prose(&source_text);
        FrontierBound {
            problem: problem.into(),
            value,
            direction,
            source_text,
            accepted: false,
        }
    }
}

/// The bounds sidecar document — a typed mirror of a Sidon `bounds.json`,
/// holding the per-problem typed bounds for a frontier/source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrontierBoundsDoc {
    /// Always `vela.frontier-bounds.v1`.
    pub schema: String,
    /// The source/frontier these bounds were derived from (a tag, not a path).
    pub source: String,
    /// Free-form note describing provenance + the unattested-by-default rule.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// The typed bounds, deterministically ordered by `problem`.
    pub bounds: Vec<FrontierBound>,
}

impl FrontierBoundsDoc {
    pub fn new(
        source: impl Into<String>,
        note: impl Into<String>,
        mut bounds: Vec<FrontierBound>,
    ) -> Self {
        bounds.sort_by(|a, b| a.problem.cmp(&b.problem));
        FrontierBoundsDoc {
            schema: FRONTIER_BOUNDS_SCHEMA.to_string(),
            source: source.into(),
            note: note.into(),
            bounds,
        }
    }
}

/// Best-effort parse of a `current_best` prose record into (value, direction).
///
/// Honest by construction: returns `(Some(v), Lower|Upper)` only when the prose
/// carries an explicit comparator (`>=`, `>`, `<=`, `<`, or LaTeX `\geq`/`\leq`/
/// `\gg`/`\ll`) immediately governing a number; otherwise `(None, Unknown)`.
/// Never guesses a direction from a bare number. The caller keeps `source_text`
/// as the authoritative prose regardless.
pub fn parse_bound_prose(text: &str) -> (Option<f64>, BoundDirection) {
    // Normalize the common LaTeX comparators to ascii so one scanner handles both.
    let norm = text
        .replace("\\geqslant", ">=")
        .replace("\\leqslant", "<=")
        .replace("\\geq", ">=")
        .replace("\\leq", "<=")
        .replace("\\ge", ">=")
        .replace("\\le", "<=")
        .replace("\\gg", ">=")
        .replace("\\ll", "<=");
    let bytes = norm.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (dir, skip) = match bytes[i] {
            b'>' => {
                let s = if bytes.get(i + 1) == Some(&b'=') {
                    2
                } else {
                    1
                };
                (BoundDirection::Lower, s)
            }
            b'<' => {
                let s = if bytes.get(i + 1) == Some(&b'=') {
                    2
                } else {
                    1
                };
                (BoundDirection::Upper, s)
            }
            _ => {
                i += 1;
                continue;
            }
        };
        // Scan forward past whitespace / LaTeX cruft to the first number.
        let mut j = i + skip;
        while j < bytes.len() && !bytes[j].is_ascii_digit() {
            // Stop if we hit a letter that isn't LaTeX glue — the comparator
            // governs a symbol, not a number (e.g. ">= N"); keep direction but
            // no value.
            if bytes[j].is_ascii_alphabetic() {
                break;
            }
            j += 1;
        }
        if j < bytes.len() && bytes[j].is_ascii_digit() {
            let start = j;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            if let Ok(v) = norm[start..j].parse::<f64>() {
                return (Some(v), dir);
            }
        }
        // Comparator present but no clean number: record the direction, no value.
        return (None, dir);
    }
    (None, BoundDirection::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lower_bound_with_geq() {
        let (v, d) = parse_bound_prose("best known >= 7");
        assert_eq!(v, Some(7.0));
        assert_eq!(d, BoundDirection::Lower);
    }

    #[test]
    fn parses_latex_geq() {
        let (v, d) = parse_bound_prose("the best known bound is $\\geq 24$");
        assert_eq!(v, Some(24.0));
        assert_eq!(d, BoundDirection::Lower);
    }

    #[test]
    fn parses_upper_bound() {
        let (v, d) = parse_bound_prose("establishing an upper bound of <= 12");
        assert_eq!(v, Some(12.0));
        assert_eq!(d, BoundDirection::Upper);
    }

    #[test]
    fn prose_without_comparator_is_unknown() {
        let (v, d) = parse_bound_prose("Sawhney has provided the following proof.");
        assert_eq!(v, None);
        assert_eq!(d, BoundDirection::Unknown);
    }

    #[test]
    fn comparator_over_symbol_keeps_direction_no_value() {
        let (v, d) = parse_bound_prose("constructed such that |A| >= N");
        assert_eq!(v, None);
        assert_eq!(d, BoundDirection::Lower);
    }

    #[test]
    fn from_prose_is_unattested_and_keeps_source_text() {
        let b = FrontierBound::from_prose("erdos/12", "best known >= 7");
        assert!(!b.accepted);
        assert_eq!(b.problem, "erdos/12");
        assert_eq!(b.source_text, "best known >= 7");
        assert_eq!(b.value, Some(7.0));
        assert_eq!(b.direction, BoundDirection::Lower);
    }

    #[test]
    fn doc_round_trips_and_sorts_by_problem() {
        let doc = FrontierBoundsDoc::new(
            "erdos-problems",
            "test",
            vec![
                FrontierBound::from_prose("erdos/20", "upper bound <= 5"),
                FrontierBound::from_prose("erdos/3", "best known >= 9"),
            ],
        );
        // sorted by problem (lexicographic): erdos/20 < erdos/3
        assert_eq!(doc.bounds[0].problem, "erdos/20");
        assert_eq!(doc.bounds[1].problem, "erdos/3");
        let s = serde_json::to_string(&doc).unwrap();
        let back: FrontierBoundsDoc = serde_json::from_str(&s).unwrap();
        assert_eq!(doc, back);
        assert_eq!(back.schema, FRONTIER_BOUNDS_SCHEMA);
    }
}
