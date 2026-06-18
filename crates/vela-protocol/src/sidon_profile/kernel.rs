//! Finite, positive, ranked Scientific State Kernel — reference semantics.
//!
//! A port of `research/sidon-producer-profile/reference/kernel.py`. Lineage is
//! a bag in `N[X]` (a monomial is a sorted multiset of atoms; coefficients are
//! natural numbers). Minimal assumption environments are derived through `env`
//! (distinct-atom support, then superset pruning). Historical append is kept
//! strictly separate from active-view restriction.
//!
//! Every root (`presentation_root`, `circuit_root`, `lineage_root`,
//! `active_view_root`) is a [`content_id`] over a canonical structure, so two
//! implementations that build the same logical value derive the same root.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::canonical::content_id;

/// A monomial: a sorted bag of atoms (duplicates retained).
pub type Monomial = Vec<String>;
/// A polynomial in `N[X]`: a finite map from monomial to natural coefficient.
pub type Polynomial = BTreeMap<Monomial, i64>;

pub fn poly_zero() -> Polynomial {
    Polynomial::new()
}

pub fn poly_one() -> Polynomial {
    let mut p = Polynomial::new();
    p.insert(Vec::new(), 1);
    p
}

pub fn poly_atom(atom: &str) -> Polynomial {
    let mut p = Polynomial::new();
    p.insert(vec![atom.to_string()], 1);
    p
}

pub fn poly_add(left: &Polynomial, right: &Polynomial) -> Polynomial {
    let mut out = left.clone();
    for (mono, coeff) in right {
        let e = out.entry(mono.clone()).or_insert(0);
        *e += *coeff;
        if *e == 0 {
            out.remove(mono);
        }
    }
    out
}

pub fn poly_mul(left: &Polynomial, right: &Polynomial) -> Polynomial {
    if left.is_empty() || right.is_empty() {
        return Polynomial::new();
    }
    let mut out = Polynomial::new();
    for (lm, lc) in left {
        for (rm, rc) in right {
            let mut mono: Monomial = lm.iter().chain(rm.iter()).cloned().collect();
            mono.sort();
            *out.entry(mono).or_insert(0) += lc * rc;
        }
    }
    out
}

pub fn poly_product<I: IntoIterator<Item = Polynomial>>(polys: I) -> Polynomial {
    let mut out = poly_one();
    for p in polys {
        out = poly_mul(&out, &p);
    }
    out
}

/// `poly_to_json` in the reference: monomials sorted by `(len, atoms, coeff)`,
/// each `{ "atoms": [...], "coefficient": c }`.
pub fn poly_to_json(poly: &Polynomial) -> Value {
    let mut items: Vec<(&Monomial, &i64)> = poly.iter().collect();
    items.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.cmp(b.0))
            .then_with(|| a.1.cmp(b.1))
    });
    Value::Array(
        items
            .into_iter()
            .map(|(mono, coeff)| json!({ "atoms": mono, "coefficient": coeff }))
            .collect(),
    )
}

/// A ranked clause: `head <- body` under a sorted bag of `atoms`, attributed to
/// an accepted event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub clause_id: String,
    pub head: String,
    pub head_rank: i64,
    pub body: Vec<String>,
    pub atoms: Vec<String>,
    pub accepted_event_id: String,
}

impl Clause {
    /// Construct a clause, sorting `body` and `atoms` and deriving the
    /// content-addressed `clause_id`.
    pub fn make(
        head: &str,
        head_rank: i64,
        body: Vec<String>,
        atoms: Vec<String>,
        accepted_event_id: &str,
    ) -> Result<Self, String> {
        let mut body = body;
        body.sort();
        let mut atoms = atoms;
        atoms.sort();
        let core = json!({
            "head": head,
            "head_rank": head_rank,
            "body": body,
            "atoms": atoms,
            "accepted_event_id": accepted_event_id,
        });
        Ok(Clause {
            clause_id: content_id("vlc_", &core)?,
            head: head.to_string(),
            head_rank,
            body,
            atoms,
            accepted_event_id: accepted_event_id.to_string(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "clause_id": self.clause_id,
            "head": self.head,
            "head_rank": self.head_rank,
            "body": self.body,
            "atoms": self.atoms,
            "accepted_event_id": self.accepted_event_id,
        })
    }
}

/// A profile presentation: ranked cells, ranked clauses, the accepted-event
/// list, and per-cell metadata.
#[derive(Debug, Clone)]
pub struct Presentation {
    pub cell_ranks: BTreeMap<String, i64>,
    pub clauses: Vec<Clause>,
    pub accepted_events: Vec<String>,
    pub cell_metadata: BTreeMap<String, Value>,
}

impl Presentation {
    pub fn validate(&self) -> Result<(), String> {
        let unique: BTreeSet<&String> = self.accepted_events.iter().collect();
        if unique.len() != self.accepted_events.len() {
            return Err("duplicate accepted event".to_string());
        }
        let mut seen: BTreeSet<&String> = BTreeSet::new();
        for clause in &self.clauses {
            if !seen.insert(&clause.clause_id) {
                return Err("duplicate clause".to_string());
            }
            if self.cell_ranks.get(&clause.head) != Some(&clause.head_rank) {
                return Err("clause head rank disagrees with cell rank".to_string());
            }
            for body_cell in &clause.body {
                match self.cell_ranks.get(body_cell) {
                    None => return Err(format!("unknown body cell: {body_cell}")),
                    Some(r) if *r >= clause.head_rank => {
                        return Err("presentation is not strictly ranked".to_string());
                    }
                    Some(_) => {}
                }
            }
            if !self.accepted_events.contains(&clause.accepted_event_id) {
                return Err("clause references unaccepted event".to_string());
            }
        }
        Ok(())
    }

    /// Clauses ordered by `(head_rank, head, clause_id)`, each as JSON. This
    /// ordered list is what the circuit and presentation roots commit to.
    pub fn canonical_clauses(&self) -> Vec<Value> {
        let mut ordered: Vec<&Clause> = self.clauses.iter().collect();
        ordered.sort_by(|a, b| {
            a.head_rank
                .cmp(&b.head_rank)
                .then_with(|| a.head.cmp(&b.head))
                .then_with(|| a.clause_id.cmp(&b.clause_id))
        });
        ordered.iter().map(|c| c.to_json()).collect()
    }

    pub fn presentation_root(&self) -> Result<String, String> {
        self.validate()?;
        content_id(
            "vpr_",
            &json!({
                "accepted_events": self.accepted_events,
                "cell_ranks": self.cell_ranks,
                "cell_metadata": self.cell_metadata,
                "clauses": self.canonical_clauses(),
            }),
        )
    }

    pub fn circuit_root(&self) -> Result<String, String> {
        self.validate()?;
        content_id("vcr_", &Value::Array(self.canonical_clauses()))
    }

    pub fn from_json(value: &Value) -> Result<Self, String> {
        let obj = value.as_object().ok_or("presentation is not an object")?;
        let mut cell_ranks = BTreeMap::new();
        for (k, v) in obj
            .get("cell_ranks")
            .and_then(Value::as_object)
            .ok_or("missing cell_ranks")?
        {
            cell_ranks.insert(k.clone(), v.as_i64().ok_or("cell rank not an integer")?);
        }
        let mut clauses = Vec::new();
        for row in obj
            .get("clauses")
            .and_then(Value::as_array)
            .ok_or("missing clauses")?
        {
            clauses.push(Clause {
                clause_id: row["clause_id"].as_str().ok_or("clause_id")?.to_string(),
                head: row["head"].as_str().ok_or("head")?.to_string(),
                head_rank: row["head_rank"].as_i64().ok_or("head_rank")?,
                body: str_vec(&row["body"])?,
                atoms: str_vec(&row["atoms"])?,
                accepted_event_id: row["accepted_event_id"]
                    .as_str()
                    .ok_or("accepted_event_id")?
                    .to_string(),
            });
        }
        let accepted_events = str_vec(
            obj.get("accepted_events")
                .ok_or("missing accepted_events")?,
        )?;
        let cell_metadata = obj
            .get("cell_metadata")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let p = Presentation {
            cell_ranks,
            clauses,
            accepted_events,
            cell_metadata,
        };
        p.validate()?;
        Ok(p)
    }
}

fn str_vec(value: &Value) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or("expected array of strings")?
        .iter()
        .map(|v| v.as_str().map(str::to_string).ok_or("non-string in array".to_string()))
        .collect()
}

/// Compile the composed lineage `Gamma_P : H -> N[X]`. Clauses are folded in
/// `(head_rank, head, clause_id)` order; a clause contributes
/// `{atoms} * product(Gamma[body cell])` to its head.
pub fn compile_gamma(presentation: &Presentation) -> Result<BTreeMap<String, Polynomial>, String> {
    presentation.validate()?;
    let mut gamma: BTreeMap<String, Polynomial> = presentation
        .cell_ranks
        .keys()
        .map(|c| (c.clone(), poly_zero()))
        .collect();

    let mut ordered: Vec<&Clause> = presentation.clauses.iter().collect();
    ordered.sort_by(|a, b| {
        a.head_rank
            .cmp(&b.head_rank)
            .then_with(|| a.head.cmp(&b.head))
            .then_with(|| a.clause_id.cmp(&b.clause_id))
    });
    for clause in ordered {
        let mut atom_poly = Polynomial::new();
        atom_poly.insert(clause.atoms.clone(), 1);
        let body_poly = poly_product(clause.body.iter().map(|c| gamma[c].clone()));
        let term = poly_mul(&atom_poly, &body_poly);
        let head_poly = poly_add(&gamma[&clause.head], &term);
        gamma.insert(clause.head.clone(), head_poly);
    }
    Ok(gamma)
}

pub fn lineage_root(gamma: &BTreeMap<String, Polynomial>) -> Result<String, String> {
    let normalized: serde_json::Map<String, Value> = gamma
        .iter()
        .map(|(cell, poly)| (cell.clone(), poly_to_json(poly)))
        .collect();
    content_id("vlr_", &Value::Object(normalized))
}

/// Minimal assumption environments for a polynomial: the distinct-atom support
/// of each monomial, with supersets pruned. Sorted by `(len, atoms)`.
pub fn minimal_environments(poly: &Polynomial) -> Vec<Vec<String>> {
    let mut set: BTreeSet<Vec<String>> = BTreeSet::new();
    for mono in poly.keys() {
        let distinct: BTreeSet<String> = mono.iter().cloned().collect();
        set.insert(distinct.into_iter().collect());
    }
    let mut envs: Vec<Vec<String>> = set.into_iter().collect();
    envs.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    let mut minimal: Vec<Vec<String>> = Vec::new();
    for env in envs {
        let eset: BTreeSet<&String> = env.iter().collect();
        if minimal
            .iter()
            .any(|existing| existing.iter().all(|a| eset.contains(a)))
        {
            continue;
        }
        minimal.push(env);
    }
    minimal
}

pub fn active_environments(poly: &Polynomial, disabled: &BTreeSet<String>) -> Vec<Vec<String>> {
    minimal_environments(poly)
        .into_iter()
        .filter(|env| env.iter().all(|a| !disabled.contains(a)))
        .collect()
}

pub fn supported(poly: &Polynomial, disabled: &BTreeSet<String>) -> bool {
    !active_environments(poly, disabled).is_empty()
}

pub fn active_view_root(disabled: &BTreeSet<String>, policy_id: &str) -> Result<String, String> {
    let sorted: Vec<&String> = disabled.iter().collect();
    content_id(
        "vav_",
        &json!({ "policy_id": policy_id, "disabled_atoms": sorted }),
    )
}

/// A set of `atoms` hits a set of environments when every environment shares at
/// least one atom with it (and there is at least one environment to hit).
pub fn is_hitting_set(environments: &[Vec<String>], atoms: &[String]) -> bool {
    let attack: BTreeSet<&String> = atoms.iter().collect();
    !environments.is_empty()
        && environments
            .iter()
            .all(|env| env.iter().any(|a| attack.contains(a)))
}

pub fn evaluator_digest(evaluator_id: &str, semantics: &str) -> Result<String, String> {
    content_id(
        "veval_",
        &json!({ "id": evaluator_id, "semantics": semantics }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_retains_bag_multiplicity() {
        let a = poly_atom("x");
        let prod = poly_mul(&a, &a);
        // x * x -> the monomial [x, x] with coefficient 1
        assert_eq!(prod.get(&vec!["x".to_string(), "x".to_string()]), Some(&1));
    }

    #[test]
    fn env_dedups_within_a_monomial() {
        // [x, x] has distinct-atom support {x}.
        let mut poly = Polynomial::new();
        poly.insert(vec!["x".to_string(), "x".to_string()], 1);
        assert_eq!(minimal_environments(&poly), vec![vec!["x".to_string()]]);
    }

    #[test]
    fn minimal_prunes_supersets() {
        let mut poly = Polynomial::new();
        poly.insert(vec!["a".to_string()], 1);
        poly.insert(vec!["a".to_string(), "b".to_string()], 1);
        // {a} subsumes {a,b}
        assert_eq!(minimal_environments(&poly), vec![vec!["a".to_string()]]);
    }

    #[test]
    fn hitting_set_needs_every_environment() {
        let envs = vec![vec!["a".to_string()], vec!["b".to_string()]];
        assert!(is_hitting_set(&envs, &["a".to_string(), "b".to_string()]));
        assert!(!is_hitting_set(&envs, &["a".to_string()]));
        assert!(!is_hitting_set(&[], &["a".to_string()]));
    }
}
