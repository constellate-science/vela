//! Deliverable-grade taxonomy and the solve-language gate.
//!
//! The substrate proves the *log* trustworthy (signatures, content
//! addresses, append-only replay). It does not, by itself, stop a
//! proposer from attaching grandiose prose to a modest result — a
//! "verified reduction" dressed up as "first to solve #N". That gap
//! is a credibility leak: the strongest-sounding claim in the record
//! may be the least earned.
//!
//! This module closes it with two pieces, ported from the Erdős
//! campaign's `canopus_trust.py` (the dogfooding that surfaced the
//! need):
//!
//! 1. [`DeliverableGrade`] — a closed taxonomy of what a deliverable
//!    actually *is*, from `unconditional_solve` down to `honest_null`
//!    and `retracted`. A grade is a claim about kind, not strength
//!    (strength is [`vela_protocol::confidence`]; evidence polarity is
//!    [`vela_protocol::status_provenance`]; this is the third, orthogonal
//!    axis: *what was delivered*).
//!
//! 2. [`grade_gate`] — blocks "solve language" in a claim's text
//!    unless the grade is itself a solve. You may not write "resolves
//!    #647" on an `improved_published_bound`. This is a lint, not a
//!    cryptographic check: it catches the honest overstatement and
//!    the hype-cycle headline before they enter the record, the same
//!    way the OpenAI "GPT-5 solved 10 Erdős problems" claim (later
//!    walked back by Bloom) would have been caught at the gate.
//!
//! Verifier evidence (the harder gate) is [`vela_protocol::verifier_attachment`].

use serde::{Deserialize, Serialize};

/// What a deliverable is. A closed taxonomy: a proposer must pick one,
/// and the string is content-stable so it can be content-addressed and
/// replayed identically across implementations.
///
/// Ordered from strongest kind of result to weakest, then the two
/// terminal states. The ordering is documentary only — the gate reads
/// membership in [`DeliverableGrade::is_solve`], never the order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverableGrade {
    /// A complete, unconditional resolution of the stated problem.
    UnconditionalSolve,
    /// A resolution that holds under a stated, named hypothesis
    /// (e.g. assuming GRH). A solve, but flagged conditional.
    ConditionalSolve,
    /// A strict improvement on a bound already in the literature.
    ImprovedPublishedBound,
    /// A verified reduction of one problem to another.
    VerifiedReduction,
    /// A map of where an obstruction lives — why a class of approach
    /// cannot work — without resolving the problem.
    ObstructionMap,
    /// A proof of part of the statement, or under extra assumptions
    /// not strong enough to count as a conditional solve.
    PartialProof,
    /// New work that extends a prior result without subsuming it.
    ExtendsPriorWork,
    /// A new term/value for an integer sequence (e.g. an OEIS entry).
    NewOeisTerm,
    /// A self-contained formal fragment (a Lean lemma) that is real
    /// but does not on its own resolve the target.
    LeanFragment,
    /// A negative result reported honestly: the search found nothing,
    /// the construction did not improve the bound. Banked because the
    /// null is itself information.
    HonestNull,
    /// Withdrawn. A deliverable that was retracted after the fact.
    Retracted,
}

impl DeliverableGrade {
    /// The two grades that license solve-language. Everything else is
    /// progress, not a solve, and may not claim otherwise.
    #[must_use]
    pub fn is_solve(self) -> bool {
        matches!(self, Self::UnconditionalSolve | Self::ConditionalSolve)
    }

    /// Canonical lowercase string (matches the serde wire form and the
    /// `canopus_trust.py` `GRADES` tuple).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnconditionalSolve => "unconditional_solve",
            Self::ConditionalSolve => "conditional_solve",
            Self::ImprovedPublishedBound => "improved_published_bound",
            Self::VerifiedReduction => "verified_reduction",
            Self::ObstructionMap => "obstruction_map",
            Self::PartialProof => "partial_proof",
            Self::ExtendsPriorWork => "extends_prior_work",
            Self::NewOeisTerm => "new_oeis_term",
            Self::LeanFragment => "lean_fragment",
            Self::HonestNull => "honest_null",
            Self::Retracted => "retracted",
        }
    }

    /// Parse a stored grade string. Unknown strings return `None`
    /// rather than guessing — an unrecognized grade is a gate failure,
    /// not a default.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "unconditional_solve" => Self::UnconditionalSolve,
            "conditional_solve" => Self::ConditionalSolve,
            "improved_published_bound" => Self::ImprovedPublishedBound,
            "verified_reduction" => Self::VerifiedReduction,
            "obstruction_map" => Self::ObstructionMap,
            "partial_proof" => Self::PartialProof,
            "extends_prior_work" => Self::ExtendsPriorWork,
            "new_oeis_term" => Self::NewOeisTerm,
            "lean_fragment" => Self::LeanFragment,
            "honest_null" => Self::HonestNull,
            "retracted" => Self::Retracted,
            _ => return None,
        })
    }

    /// Every grade, for enumeration and conformance.
    pub const ALL: [DeliverableGrade; 11] = [
        Self::UnconditionalSolve,
        Self::ConditionalSolve,
        Self::ImprovedPublishedBound,
        Self::VerifiedReduction,
        Self::ObstructionMap,
        Self::PartialProof,
        Self::ExtendsPriorWork,
        Self::NewOeisTerm,
        Self::LeanFragment,
        Self::HonestNull,
        Self::Retracted,
    ];
}

impl std::fmt::Display for DeliverableGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Phrases that assert a problem has been solved. A claim may only use
/// one of these if its grade [`DeliverableGrade::is_solve`]. Matched
/// case-insensitively as substrings, so "this resolves #647" trips on
/// `"resolves #"`.
pub const SOLVE_LANGUAGE: &[&str] = &[
    "solve",
    "solved",
    "solves",
    "guaranteed solve",
    "proven open",
    "closes the problem",
    "resolves #",
    "first to solve",
];

/// The result of the grade gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GradeGate {
    /// The grade is set, known, and consistent with the claim text.
    Ok(DeliverableGrade),
    /// No grade was supplied. A grade is required — an ungraded
    /// deliverable cannot be reasoned about by kind.
    Missing,
    /// The grade string was not in the taxonomy.
    Unknown(String),
    /// The claim uses solve-language but the grade is not a solve.
    /// Carries the offending phrase and the non-solve grade.
    SolveLanguageMismatch {
        phrase: &'static str,
        grade: DeliverableGrade,
    },
}

impl GradeGate {
    /// Whether the gate passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, GradeGate::Ok(_))
    }

    /// Human-readable reason a non-`Ok` gate failed (empty for `Ok`).
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            GradeGate::Ok(_) => String::new(),
            GradeGate::Missing => "no deliverable_grade set (required)".to_string(),
            GradeGate::Unknown(g) => format!("unknown deliverable_grade `{g}`"),
            GradeGate::SolveLanguageMismatch { phrase, grade } => format!(
                "grade `{grade}` is not a solve, but the claim uses solve-language `{phrase}`"
            ),
        }
    }
}

/// Whether `phrase` occurs in `lower` (already lowercased) as
/// solve-language. A single alphabetic word (`solve`, `solved`,
/// `solves`) must match on word boundaries so it does not fire inside
/// `resolves` or `dissolves`; multi-word and `#`-bearing phrases
/// (`resolves #`, `first to solve`) match as substrings, which is what
/// makes them specific. This is stricter and more precise than the
/// loose substring match in `canopus_trust.py`.
fn phrase_present(lower: &str, phrase: &str) -> bool {
    let is_single_word = phrase.bytes().all(|b| b.is_ascii_alphabetic());
    if !is_single_word {
        return lower.contains(phrase);
    }
    lower
        .split(|c: char| !c.is_ascii_alphabetic())
        .any(|w| w == phrase)
}

/// L5 anti-inflation: require a grade, and block solve-language unless
/// the grade is an actual solve.
///
/// `grade` is the raw stored string (so callers can pass an unvalidated
/// value straight from a payload and learn precisely why it failed).
/// Mirrors `canopus_trust.py::grade_gate`, with word-boundary matching
/// for the single-word triggers.
#[must_use]
pub fn grade_gate(claim: &str, grade: Option<&str>) -> GradeGate {
    let Some(grade) = grade else {
        return GradeGate::Missing;
    };
    let Some(grade) = DeliverableGrade::parse(grade) else {
        return GradeGate::Unknown(grade.to_string());
    };
    if !grade.is_solve() {
        let lower = claim.to_lowercase();
        // Check the specific multi-word / `#` phrases before the bare
        // single words, so a claim like "resolves #647" is attributed
        // to `resolves #`, not to the `solve` hidden inside `resolves`.
        let mut triggers: Vec<&&str> = SOLVE_LANGUAGE.iter().collect();
        triggers.sort_by_key(|p| p.bytes().all(|b| b.is_ascii_alphabetic()));
        for phrase in triggers {
            if phrase_present(&lower, phrase) {
                return GradeGate::SolveLanguageMismatch { phrase, grade };
            }
        }
    }
    GradeGate::Ok(grade)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_grade_fails() {
        assert!(matches!(
            grade_gate("a Sidon set of size 33", None),
            GradeGate::Missing
        ));
    }

    #[test]
    fn unknown_grade_fails() {
        assert!(matches!(
            grade_gate("anything", Some("totally_solved_it")),
            GradeGate::Unknown(_)
        ));
    }

    #[test]
    fn solve_language_on_non_solve_grade_is_blocked() {
        // The exact failure class the gate exists for: a bound
        // improvement that calls itself a resolution.
        let gate = grade_gate(
            "This resolves #647 with an improved bound.",
            Some("improved_published_bound"),
        );
        assert!(!gate.passed());
        match gate {
            GradeGate::SolveLanguageMismatch { phrase, grade } => {
                assert_eq!(phrase, "resolves #");
                assert_eq!(grade, DeliverableGrade::ImprovedPublishedBound);
            }
            other => panic!("expected SolveLanguageMismatch, got {other:?}"),
        }
    }

    #[test]
    fn solve_language_allowed_on_solve_grade() {
        let gate = grade_gate(
            "We solve the problem unconditionally.",
            Some("unconditional_solve"),
        );
        assert!(gate.passed());
        assert_eq!(gate, GradeGate::Ok(DeliverableGrade::UnconditionalSolve));
    }

    #[test]
    fn non_solve_grade_without_solve_language_passes() {
        let gate = grade_gate(
            "Extends the construction to n = 24 with a new term.",
            Some("new_oeis_term"),
        );
        assert!(gate.passed());
    }

    #[test]
    fn bare_solve_does_not_fire_inside_other_words() {
        // "dissolves" / "resolves" must not trip the bare `solve`
        // trigger; only the specific `resolves #` phrase should, and
        // only when present.
        let ok = grade_gate(
            "The compound dissolves in water at the measured rate.",
            Some("extends_prior_work"),
        );
        assert!(
            ok.passed(),
            "bare 'solve' should not match inside 'dissolves'"
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        let gate = grade_gate("FIRST TO SOLVE this open problem", Some("partial_proof"));
        assert!(matches!(gate, GradeGate::SolveLanguageMismatch { .. }));
    }

    #[test]
    fn parse_round_trips_every_grade() {
        for g in DeliverableGrade::ALL {
            assert_eq!(DeliverableGrade::parse(g.as_str()), Some(g));
        }
    }

    #[test]
    fn serde_uses_snake_case() {
        let json = serde_json::to_string(&DeliverableGrade::HonestNull).unwrap();
        assert_eq!(json, "\"honest_null\"");
        let back: DeliverableGrade = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DeliverableGrade::HonestNull);
    }

    #[test]
    fn only_two_grades_are_solves() {
        let solves: Vec<_> = DeliverableGrade::ALL
            .into_iter()
            .filter(|g| g.is_solve())
            .collect();
        assert_eq!(
            solves,
            vec![
                DeliverableGrade::UnconditionalSolve,
                DeliverableGrade::ConditionalSolve
            ]
        );
    }
}
