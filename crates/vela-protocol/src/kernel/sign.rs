//! Cryptographic signing for finding bundles — the trust infrastructure layer.
//!
//! Every finding event can be signed with Ed25519 and verified independently.
//! Signatures cover the canonical JSON of the finding (deterministic, sorted keys).

use std::path::Path;

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::bundle::FindingBundle;
use crate::project::Project;
use crate::repo;

/// A signed envelope wrapping a finding's cryptographic signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub finding_id: String,
    /// Hex-encoded Ed25519 signature (128 hex chars = 64 bytes).
    pub signature: String,
    /// Hex-encoded public key of the signer (64 hex chars = 32 bytes).
    pub public_key: String,
    /// ISO 8601 timestamp of when the signature was produced.
    pub signed_at: String,
    /// Algorithm identifier (always "ed25519").
    pub algorithm: String,
}

/// Phase M (v0.4): registered actor identity. Maps a stable `actor.id`
/// to an Ed25519 public key, established at a specific timestamp.
///
/// Once an actor is registered in a frontier, any canonical event
/// whose `actor.id` matches must carry a verifiable signature under
/// `--strict`. Frontiers without registered actors retain the legacy
/// "placeholder reviewer" rejection from v0.3 only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRecord {
    /// Stable, namespaced identifier (e.g. "reviewer:will-blair").
    pub id: String,
    /// Hex-encoded Ed25519 public key (64 hex chars = 32 bytes).
    pub public_key: String,
    /// Algorithm identifier (always "ed25519").
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// ISO 8601 timestamp of when the actor was registered.
    pub created_at: String,
    /// Phase α (v0.6): trust tier permitting one-call auto-apply for a
    /// restricted set of low-risk proposal kinds. The only tier defined
    /// in v0.6 is `"auto-notes"`, which permits `propose_and_apply_note`.
    /// Tier is never honored for state-changing kinds (review, retract,
    /// confidence_revise, caveated). Pre-v0.6 actors load with `None`
    /// and behave exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// v0.43: Optional ORCID identifier for cross-system identity.
    /// Format: `0000-0000-0000-000X` (16 digits in 4 groups, final
    /// character optionally `X` per ISO 7064). When set, the actor's
    /// identity can be cross-referenced through the public ORCID
    /// directory at `https://orcid.org/<orcid>`. The substrate stores
    /// the pointer; it does not verify the ORCID exists online (that
    /// is L4 work). Pre-v0.43 actors load with `None` and behave
    /// exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orcid: Option<String>,
    /// v0.51: Read-side access clearance. `None` (default) means
    /// public-only access. `Some(Restricted)` permits reading
    /// `Public` and `Restricted` tiered objects; `Some(Classified)`
    /// permits all. Distinct from the v0.6 `tier` field above (which
    /// gates write-side auto-apply). The two are intentionally
    /// independent: an actor can have `tier: auto-notes` for fast
    /// note application without any read clearance, or
    /// `access_clearance: Classified` without any auto-apply
    /// privilege. Pre-v0.51 actors load with `None` and behave
    /// exactly as before — the field is purely additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_clearance: Option<crate::access_tier::AccessTier>,
    /// v0.127: revocation timestamp. When set, the actor's key is
    /// considered compromised or retired as of that moment.
    /// Signatures on events with `timestamp < revoked_at` remain
    /// valid (the key was trusted when the event was signed); new
    /// signatures on events with `timestamp >= revoked_at` are
    /// rejected by `verify_event_signature`. Pre-v0.127 actors load
    /// with `None` and verify exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// v0.127: free-form reason for revocation (e.g. "key
    /// compromised 2026-05-10", "rotated to reviewer:will-blair-v2").
    /// Display-only; the substrate does not parse this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
}

impl ActorRecord {
    /// v0.127: true iff the actor's key is revoked relative to an
    /// event timestamp. An event signed before `revoked_at` remains
    /// valid (the substrate does not retroactively invalidate
    /// historical signatures); an event signed at-or-after the
    /// revocation is rejected. Lexicographic RFC 3339 comparison
    /// matches chronological order.
    pub fn is_revoked_at(&self, event_timestamp: &str) -> bool {
        match self.revoked_at.as_deref() {
            None => false,
            Some(rev_at) => event_timestamp >= rev_at,
        }
    }
}

/// v0.43: Validate an ORCID identifier's structural shape. ORCID IDs
/// are 16 digits in 4 groups of 4 separated by hyphens, with the
/// final character optionally being `X` (the ISO 7064 check digit).
/// Accepts bare form `0000-0001-2345-6789`, the URL form
/// `https://orcid.org/0000-...`, or the prefixed form `orcid:0000-...`
/// and returns the bare form.
pub fn validate_orcid(s: &str) -> Result<String, String> {
    let trimmed = s.trim();
    let bare = trimmed
        .strip_prefix("https://orcid.org/")
        .or_else(|| trimmed.strip_prefix("http://orcid.org/"))
        .or_else(|| trimmed.strip_prefix("orcid:"))
        .unwrap_or(trimmed);
    if bare.len() != 19 {
        return Err(format!(
            "ORCID must be 19 chars (0000-0000-0000-000X), got {}",
            bare.len()
        ));
    }
    let mut groups = bare.split('-');
    for i in 0..4 {
        let g = groups
            .next()
            .ok_or_else(|| format!("ORCID missing group {} of 4", i + 1))?;
        if g.len() != 4 {
            return Err(format!(
                "ORCID group {} must be 4 chars, got {}",
                i + 1,
                g.len()
            ));
        }
        for (j, c) in g.chars().enumerate() {
            let allow_x = i == 3 && j == 3;
            if !c.is_ascii_digit() && !(allow_x && c == 'X') {
                return Err(format!(
                    "ORCID character '{c}' at group {} pos {} not a digit (or X check digit)",
                    i + 1,
                    j + 1
                ));
            }
        }
    }
    if groups.next().is_some() {
        return Err("ORCID has too many hyphenated groups".to_string());
    }
    Ok(bare.to_string())
}

fn default_algorithm() -> String {
    "ed25519".to_string()
}

/// Phase α (v0.6): authorization predicate for one-call auto-apply.
///
/// Returns `true` iff the actor's tier explicitly permits auto-applying
/// the given event kind without prior human review. Doctrine: tier
/// permits review-context kinds only (annotations); never state-changing
/// kinds (review verdicts, retractions, confidence revisions). Adding
/// state-changing auto-apply requires a broader tier model with
/// explicit doctrine review.
///
/// Currently recognized:
///   - `tier="auto-notes"` + `kind="finding.note"` → `true`
///   - everything else → `false`
#[must_use]
pub fn actor_can_auto_apply(actor: &ActorRecord, kind: &str) -> bool {
    matches!(
        (actor.tier.as_deref(), kind),
        (Some("auto-notes"), "finding.note")
    )
}

/// Result of verifying all signatures in a frontier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub total_findings: usize,
    pub signed: usize,
    pub unsigned: usize,
    pub valid: usize,
    pub invalid: usize,
    pub signers: Vec<String>,
    /// v0.37: number of findings carrying `flags.signature_threshold = Some(k)`.
    #[serde(default)]
    pub findings_with_threshold: usize,
    /// v0.37: number of findings whose threshold is currently met (k
    /// distinct unique-key valid signatures present).
    #[serde(default)]
    pub jointly_accepted: usize,
}

// ── Key generation ───────────────────────────────────────────────────

/// Generate an Ed25519 keypair. Writes the private key to `output_dir/private.key`
/// and the public key to `output_dir/public.key`. Both are hex-encoded.
pub fn generate_keypair(output_dir: &Path) -> Result<String, String> {
    use rand::rngs::OsRng;

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {e}"))?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());

    let private_path = output_dir.join("private.key");
    let public_path = output_dir.join("public.key");

    std::fs::write(&private_path, &private_hex)
        .map_err(|e| format!("Failed to write private key: {e}"))?;
    std::fs::write(&public_path, &public_hex)
        .map_err(|e| format!("Failed to write public key: {e}"))?;

    Ok(public_hex)
}

// ── Canonical JSON ───────────────────────────────────────────────────

/// Produce deterministic canonical JSON for a finding bundle.
/// Sorted keys + compact form via the single `canonical.rs` RFC-8785
/// primitive (the same one that mints the finding id).
///
/// `flags.jointly_accepted` is excluded from the signing preimage. The flag
/// is a derived cache that the substrate flips when the v0.37 multi-sig
/// threshold is met; including it in the canonical bytes meant every
/// signature that *triggered* the flip became invalid the moment the
/// flip mutated the bytes. Stripping the field here keeps signatures
/// stable across flag changes while leaving the on-disk projection of
/// `jointly_accepted` intact for tooling. `signature_threshold` stays
/// in the preimage so an attacker cannot lower the threshold without
/// invalidating signatures.
pub fn canonical_json(finding: &FindingBundle) -> Result<String, String> {
    let mut value =
        serde_json::to_value(finding).map_err(|e| format!("Failed to serialize finding: {e}"))?;
    if let Some(flags) = value.get_mut("flags").and_then(|v| v.as_object_mut()) {
        flags.remove("jointly_accepted");
    }
    // v0.712: route through the ONE canonicalizer (`canonical.rs`, RFC-8785,
    // conformance-pinned, rejects non-finite floats) instead of a private
    // sort+serialize. Two divergent canonical forms — the id committed via
    // canonical.rs, the signature here — were a latent drift surface: a
    // future number-formatting change to one would silently invalidate the
    // other. `canonical_signing_bytes_match_canonical_primitive` pins them.
    crate::canonical::to_canonical_string(&value)
}

// ── Signing and verification ─────────────────────────────────────────

/// Parse a hex-encoded Ed25519 signing key (64 hex chars = the 32-byte seed).
/// The inline form of [`load_signing_key_from_path`], for callers that hold the
/// key as a string rather than a file — e.g. a deployment secret delivered as
/// an environment variable (Fly/Heroku/K8s), where there is no key file to
/// point a path at.
pub fn signing_key_from_hex(hex_str: &str) -> Result<SigningKey, String> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex in private key: {e}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Private key must be exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Load a signing key from a hex-encoded file.
fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let hex_str =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read private key: {e}"))?;
    signing_key_from_hex(&hex_str)
}

/// v0.49.3: public key-loading and primitive-signing helpers so the
/// hub (and any other downstream binary) can sign small JSON payloads
/// — e.g., the `/.well-known/vela` manifest — without needing direct
/// access to the ed25519_dalek dep or to the SigningKey type.

/// Load a hex-encoded Ed25519 signing key from disk.
///
/// Same on-disk format `vela sign generate-keypair` writes.
pub fn load_signing_key_from_path(path: &Path) -> Result<SigningKey, String> {
    load_signing_key(path)
}

/// Sign arbitrary bytes with the given key. Returns the 64-byte
/// signature.
pub fn sign_bytes(signing_key: &SigningKey, bytes: &[u8]) -> [u8; 64] {
    signing_key.sign(bytes).to_bytes()
}

/// Hex-encoded Ed25519 public key (64 chars) for the given signing key.
pub fn pubkey_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

/// Load a verifying key from a hex-encoded file.
fn load_verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    let hex_str =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read public key: {e}"))?;
    parse_verifying_key(hex_str.trim())
}

/// Parse a verifying key from a hex string.
fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex in public key: {e}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid public key: {e}"))
}

/// Sign a single finding bundle, producing a SignedEnvelope.
pub fn sign_finding(
    finding: &FindingBundle,
    signing_key: &SigningKey,
) -> Result<SignedEnvelope, String> {
    let canonical = canonical_json(finding)?;
    let signature = signing_key.sign(canonical.as_bytes());
    let public_key = signing_key.verifying_key();

    Ok(SignedEnvelope {
        finding_id: finding.id.clone(),
        signature: hex::encode(signature.to_bytes()),
        public_key: hex::encode(public_key.to_bytes()),
        signed_at: Utc::now().to_rfc3339(),
        algorithm: "ed25519".to_string(),
    })
}

/// Verify a signed envelope against a finding bundle.
pub fn verify_finding(finding: &FindingBundle, envelope: &SignedEnvelope) -> Result<bool, String> {
    if finding.id != envelope.finding_id {
        return Ok(false);
    }

    let verifying_key = parse_verifying_key(&envelope.public_key)?;
    let sig_bytes =
        hex::decode(&envelope.signature).map_err(|e| format!("Invalid signature hex: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Signature must be 64 bytes")?,
    );

    let canonical = canonical_json(finding)?;
    Ok(verifying_key
        .verify(canonical.as_bytes(), &signature)
        .is_ok())
}

/// Verify a finding against a specific public key (hex-encoded).
pub fn verify_finding_with_pubkey(
    finding: &FindingBundle,
    envelope: &SignedEnvelope,
    expected_pubkey: &str,
) -> Result<bool, String> {
    if envelope.public_key != expected_pubkey {
        return Ok(false);
    }
    verify_finding(finding, envelope)
}

// ── Event signing (Phase M, v0.4) ────────────────────────────────────

/// Compute the canonical signing bytes for a `StateEvent`. The `signature`
/// field is excluded from the preimage (you can't sign over your own
/// signature). The same canonical-JSON rule that derives `vev_…` is reused.
///
/// A second implementation must produce byte-identical signing bytes
/// for the same event content; the verification rule depends on it.
pub fn event_signing_bytes(event: &crate::events::StateEvent) -> Result<Vec<u8>, String> {
    use serde_json::json;
    let preimage = json!({
        "schema": event.schema,
        "id": event.id,
        "kind": event.kind,
        "target": event.target,
        "actor": event.actor,
        "timestamp": event.timestamp,
        "reason": event.reason,
        "before_hash": event.before_hash,
        "after_hash": event.after_hash,
        "payload": event.payload,
        "caveats": event.caveats,
    });
    crate::canonical::to_canonical_bytes(&preimage)
}

/// Sign a canonical event with an Ed25519 private key, returning a
/// hex-encoded signature suitable for `event.signature`.
pub fn sign_event(
    event: &crate::events::StateEvent,
    signing_key: &SigningKey,
) -> Result<String, String> {
    let bytes = event_signing_bytes(event)?;
    let signature = signing_key.sign(&bytes);
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify that `event.signature` is a valid Ed25519 signature over the
/// canonical signing bytes of `event`, produced by the holder of the
/// private key matching `expected_pubkey_hex`.
pub fn verify_event_signature(
    event: &crate::events::StateEvent,
    expected_pubkey_hex: &str,
) -> Result<bool, String> {
    let signature_hex = event
        .signature
        .as_deref()
        .ok_or_else(|| format!("event {} has no signature field", event.id))?;
    let verifying_key = parse_verifying_key(expected_pubkey_hex)?;
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Signature must be 64 bytes")?,
    );
    let bytes = event_signing_bytes(event)?;
    Ok(verifying_key.verify(&bytes, &signature).is_ok())
}

// ── Proposal signing (Phase Q-w, v0.5) ───────────────────────────────

/// Compute the canonical signing bytes for a `StateProposal`. The
/// `signature` (held externally on the wire) is excluded from the
/// preimage. Same canonical-JSON discipline as `event_signing_bytes`.
///
/// The proposal `id` is included, which deterministically pins the
/// content (since `vpr_…` is content-addressed under Phase P).
pub fn proposal_signing_bytes(
    proposal: &crate::proposals::StateProposal,
) -> Result<Vec<u8>, String> {
    use serde_json::json;
    let preimage = json!({
        "schema": proposal.schema,
        "id": proposal.id,
        "kind": proposal.kind,
        "target": proposal.target,
        "actor": proposal.actor,
        "created_at": proposal.created_at,
        "reason": proposal.reason,
        "payload": proposal.payload,
        "source_refs": proposal.source_refs,
        "caveats": proposal.caveats,
    });
    crate::canonical::to_canonical_bytes(&preimage)
}

/// Sign a proposal with an Ed25519 private key, returning a hex-encoded
/// signature suitable for transport on a write API.
pub fn sign_proposal(
    proposal: &crate::proposals::StateProposal,
    signing_key: &SigningKey,
) -> Result<String, String> {
    let bytes = proposal_signing_bytes(proposal)?;
    Ok(hex::encode(signing_key.sign(&bytes).to_bytes()))
}

/// Verify a hex-encoded Ed25519 signature against the canonical signing
/// bytes of `proposal`, using `expected_pubkey_hex` as the verifying key.
pub fn verify_proposal_signature(
    proposal: &crate::proposals::StateProposal,
    signature_hex: &str,
    expected_pubkey_hex: &str,
) -> Result<bool, String> {
    let verifying_key = parse_verifying_key(expected_pubkey_hex)?;
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Signature must be 64 bytes")?,
    );
    let bytes = proposal_signing_bytes(proposal)?;
    Ok(verifying_key.verify(&bytes, &signature).is_ok())
}

/// Generic signature verifier for action-on-canonical-bytes: verify
/// `signature_hex` is a valid Ed25519 signature over `signing_bytes`,
/// produced by the holder of `expected_pubkey_hex`. Used by write
/// actions that don't sign over a full proposal/event struct (e.g.,
/// accept/reject decisions).
pub fn verify_action_signature(
    signing_bytes: &[u8],
    signature_hex: &str,
    expected_pubkey_hex: &str,
) -> Result<bool, String> {
    let verifying_key = parse_verifying_key(expected_pubkey_hex)?;
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Signature must be 64 bytes")?,
    );
    Ok(verifying_key.verify(signing_bytes, &signature).is_ok())
}

// ── Project-level operations ────────────────────────────────────────

/// Sign all findings in a frontier that are not yet signed BY THIS KEY.
/// Returns the number of newly signed findings.
///
/// v0.37: dedupe is now `(finding_id, public_key)`, not `finding_id`
/// alone. Prior versions stopped at the first signature on a finding;
/// that prevented multi-actor co-signing. Different actors with
/// different keys can now each contribute a `SignedEnvelope` to the
/// same finding. Re-running `vela sign apply` with the same key is
/// still idempotent.
pub fn sign_frontier(frontier_path: &Path, private_key_path: &Path) -> Result<usize, String> {
    let mut frontier: Project = repo::load_from_path(frontier_path)?;

    let signing_key = load_signing_key(private_key_path)?;
    let our_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let mut signed_count = 0usize;

    // Already signed by THIS key and still valid for current bytes.
    // If a finding changed after an earlier signature, drop the stale
    // same-key envelope so this run can refresh it. Other actors'
    // signatures stay.
    let finding_by_id = frontier
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<std::collections::HashMap<_, _>>();
    let mut already_signed_by_us = std::collections::HashSet::new();
    let mut stale_signed_by_us = std::collections::HashSet::new();
    for envelope in &frontier.signatures {
        if envelope.public_key != our_pubkey_hex {
            continue;
        }
        let valid = finding_by_id
            .get(envelope.finding_id.as_str())
            .and_then(|finding| verify_finding(finding, envelope).ok())
            .unwrap_or(false);
        if valid {
            already_signed_by_us.insert(envelope.finding_id.clone());
        } else {
            stale_signed_by_us.insert(envelope.finding_id.clone());
        }
    }
    if !stale_signed_by_us.is_empty() {
        frontier.signatures.retain(|envelope| {
            envelope.public_key != our_pubkey_hex
                || !stale_signed_by_us.contains(&envelope.finding_id)
        });
        already_signed_by_us.retain(|finding_id| !stale_signed_by_us.contains(finding_id));
    }

    for finding in &frontier.findings {
        if already_signed_by_us.contains(&finding.id) {
            continue;
        }
        let envelope = sign_finding(finding, &signing_key)?;
        frontier.signatures.push(envelope);
        signed_count += 1;
    }

    let actor_ids_for_key: std::collections::HashSet<String> = frontier
        .actors
        .iter()
        .filter(|actor| actor.public_key == our_pubkey_hex)
        .map(|actor| actor.id.clone())
        .collect();
    if !actor_ids_for_key.is_empty() {
        for event in &mut frontier.events {
            if event.signature.is_some()
                || event.actor.r#type != "human"
                || !actor_ids_for_key.contains(&event.actor.id)
            {
                continue;
            }
            event.signature = Some(sign_event(event, &signing_key)?);
            signed_count += 1;
        }
    }

    // v0.37: refresh `jointly_accepted` flags after multi-sig writes.
    refresh_jointly_accepted(&mut frontier);

    repo::save_to_path(frontier_path, &frontier)?;

    Ok(signed_count)
}

// ── Multi-sig helpers (v0.37) ────────────────────────────────────────

/// Hex-encoded public keys of every actor whose `SignedEnvelope`
/// targeting `finding_id` cryptographically verifies against the
/// finding's canonical bytes. Duplicate signatures from the same key
/// are counted once. Returns an empty Vec if the finding doesn't exist.
#[must_use]
pub fn signers_for(project: &Project, finding_id: &str) -> Vec<String> {
    let Some(finding) = project.findings.iter().find(|f| f.id == finding_id) else {
        return Vec::new();
    };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for env in &project.signatures {
        if env.finding_id != finding_id {
            continue;
        }
        if seen.contains(&env.public_key) {
            continue;
        }
        if let Ok(true) = verify_finding(finding, env) {
            seen.insert(env.public_key.clone());
        }
    }
    seen.into_iter().collect()
}

/// Number of unique valid signers on `finding_id`.
#[must_use]
pub fn valid_signature_count(project: &Project, finding_id: &str) -> usize {
    signers_for(project, finding_id).len()
}

/// True iff `flags.signature_threshold` is `Some(k)` and `k` distinct
/// valid signatures are present. `None` threshold means single-sig
/// semantics — never reports threshold-met.
#[must_use]
pub fn threshold_met(project: &Project, finding_id: &str) -> bool {
    let Some(finding) = project.findings.iter().find(|f| f.id == finding_id) else {
        return false;
    };
    let Some(threshold) = finding.flags.signature_threshold else {
        return false;
    };
    valid_signature_count(project, finding_id) >= threshold as usize
}

/// Walk every finding and (re)set `flags.jointly_accepted` to match
/// the current state of `signature_threshold` and the multi-sig
/// envelope set. Idempotent. Called from `sign_frontier` and the
/// verify path so the flag never drifts from the underlying truth.
pub fn refresh_jointly_accepted(project: &mut Project) {
    // First snapshot the truth without holding a mutable borrow on findings.
    let truth: std::collections::HashMap<String, bool> = project
        .findings
        .iter()
        .map(|f| (f.id.clone(), threshold_met(project, &f.id)))
        .collect();
    for f in &mut project.findings {
        f.flags.jointly_accepted = truth.get(&f.id).copied().unwrap_or(false);
    }
}

/// Verify all signatures in a frontier. Optionally filter by a specific public key.
pub fn verify_frontier(
    frontier_path: &Path,
    pubkey_path: Option<&Path>,
) -> Result<VerifyReport, String> {
    let frontier: Project = repo::load_from_path(frontier_path)?;

    verify_frontier_data(&frontier, pubkey_path)
}

/// Verify all signatures in an in-memory frontier.
pub fn verify_frontier_data(
    frontier: &Project,
    pubkey_path: Option<&Path>,
) -> Result<VerifyReport, String> {
    let expected_pubkey = match pubkey_path {
        Some(path) => {
            let key = load_verifying_key(path)?;
            Some(hex::encode(key.to_bytes()))
        }
        None => None,
    };

    // Index findings by ID for fast lookup.
    let finding_map: std::collections::HashMap<&str, &FindingBundle> = frontier
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect();

    // v0.104: count every signature individually, not one envelope per
    // finding. Pre-v0.104 the verify path built a sig_map keyed by
    // finding_id which collapsed multi-sig envelopes to whichever one
    // happened to land last in the HashMap, so multi-sig frontiers
    // under-reported `valid` and never showed two distinct signers
    // even when both cryptographically validated.
    let mut valid = 0usize;
    let mut invalid = 0usize;
    let mut signers: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut findings_with_signature: std::collections::HashSet<&str> =
        std::collections::HashSet::new();

    for envelope in &frontier.signatures {
        if let Some(ref expected) = expected_pubkey
            && &envelope.public_key != expected
        {
            invalid += 1;
            findings_with_signature.insert(envelope.finding_id.as_str());
            continue;
        }
        let Some(finding) = finding_map.get(envelope.finding_id.as_str()) else {
            invalid += 1;
            continue;
        };
        findings_with_signature.insert(envelope.finding_id.as_str());
        match verify_finding(finding, envelope) {
            Ok(true) => {
                valid += 1;
                signers.insert(envelope.public_key.clone());
            }
            _ => {
                invalid += 1;
            }
        }
    }

    let unsigned = frontier
        .findings
        .iter()
        .filter(|f| !findings_with_signature.contains(f.id.as_str()))
        .count();

    // v0.37: count threshold flags + verified joint-accept state.
    let mut findings_with_threshold = 0usize;
    let mut jointly_accepted = 0usize;
    for f in &frontier.findings {
        if f.flags.signature_threshold.is_some() {
            findings_with_threshold += 1;
            if threshold_met(frontier, &f.id) {
                jointly_accepted += 1;
            }
        }
    }

    Ok(VerifyReport {
        total_findings: frontier.findings.len(),
        signed: valid + invalid,
        unsigned,
        valid,
        invalid,
        signers: signers.into_iter().collect(),
        findings_with_threshold,
        jointly_accepted,
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;

    #[test]
    fn canonical_signing_bytes_match_legacy_sort() {
        // The unified canonical_json (now routed through canonical.rs) must be
        // BYTE-IDENTICAL to the legacy private sort+serialize, so every stored
        // finding signature keeps verifying. Pins the unification: if a future
        // canonical.rs change ever diverged from the old form, this fails
        // loudly instead of silently invalidating signatures/ids.
        fn legacy_sort(v: &serde_json::Value) -> serde_json::Value {
            use std::collections::BTreeMap;
            match v {
                serde_json::Value::Object(map) => {
                    let sorted: BTreeMap<String, serde_json::Value> = map
                        .iter()
                        .map(|(k, v)| (k.clone(), legacy_sort(v)))
                        .collect();
                    serde_json::to_value(sorted).unwrap()
                }
                serde_json::Value::Array(arr) => {
                    serde_json::Value::Array(arr.iter().map(legacy_sort).collect())
                }
                other => other.clone(),
            }
        }
        let f = sample_finding();
        let mut value = serde_json::to_value(&f).unwrap();
        if let Some(flags) = value.get_mut("flags").and_then(|v| v.as_object_mut()) {
            flags.remove("jointly_accepted");
        }
        let legacy = serde_json::to_string(&legacy_sort(&value)).unwrap();
        assert_eq!(
            canonical_json(&f).unwrap(),
            legacy,
            "unified canonicalizer must match the legacy form byte-for-byte"
        );
    }

    fn sample_finding() -> FindingBundle {
        FindingBundle::new(
            Assertion {
                text: "NLRP3 activates IL-1B".into(),
                assertion_type: "mechanism".into(),
                entities: vec![Entity {
                    name: "NLRP3".into(),
                    entity_type: "protein".into(),
                    identifiers: serde_json::Map::new(),
                    canonical_id: None,
                    candidates: vec![],
                    aliases: vec![],
                    resolution_provenance: None,
                    resolution_confidence: 1.0,
                    resolution_method: None,
                    species_context: None,
                    needs_review: false,
                }],
                relation: Some("activates".into()),
                direction: Some("positive".into()),
                causal_claim: None,
                causal_evidence_grade: None,
            },
            Evidence {
                evidence_type: "experimental".into(),
                model_system: "mouse".into(),
                method: "Western blot".into(),
                replicated: true,
                replication_count: Some(3),
                evidence_spans: vec![],
            },
            Conditions {
                text: "In vitro, mouse microglia".into(),
                duration: None,
            },
            Confidence::raw(0.85, "Experimental with replication", 0.9),
            Provenance {
                source_type: "published_paper".into(),
                doi: Some("10.1234/test".into()),
                url: None,
                title: "Test Paper".into(),
                authors: vec![Author {
                    name: "Smith J".into(),
                    orcid: None,
                }],
                year: Some(2024),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
            },
            Flags {
                gap: false,
                negative_space: false,
                contested: false,
                retracted: false,
                declining: false,
                gravity_well: false,
                review_state: None,
                superseded: false,
                signature_threshold: None,
                jointly_accepted: false,
            },
        )
    }

    fn test_keypair() -> SigningKey {
        use rand::rngs::OsRng;
        SigningKey::generate(&mut OsRng)
    }

    /// The deposit-endpoint signing contract: a deposit client (e.g. a producer
    /// posting to the hub's append endpoint)
    /// signs `to_vec(json!({action, vfr_id, parent_event_log_hash, batch}))`
    /// with the owner key; the hub rebuilds that preimage from the parsed wire
    /// body and checks it with `verify_action_signature`. This asserts the two
    /// sides agree — including the JSON round-trip the batch takes over the
    /// wire — so a correctly-signed client request is accepted, and a tampered
    /// one is not.
    #[test]
    fn append_deposit_signature_roundtrips_client_to_server() {
        use ed25519_dalek::Signer;
        use serde_json::json;

        let key = test_keypair();
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());

        // Client side: build the batch value, then the preimage, then sign.
        let batch = json!([
            {"object_kind": "event_only", "event": {"id": "vev_1", "kind": "finding.asserted"}}
        ]);
        let preimage = json!({
            "action": "append",
            "vfr_id": "vfr_demo",
            "parent_event_log_hash": "sha256:abc",
            "batch": batch,
        });
        let client_bytes = serde_json::to_vec(&preimage).unwrap();
        let sig_hex = hex::encode(key.sign(&client_bytes).to_bytes());

        // Server side: the batch arrives as parsed JSON; rebuild the preimage
        // from it (the round-trip the wire imposes) and verify.
        let parsed_batch: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&batch).unwrap()).unwrap();
        let server_preimage = json!({
            "action": "append",
            "vfr_id": "vfr_demo",
            "parent_event_log_hash": "sha256:abc",
            "batch": parsed_batch,
        });
        let server_bytes = serde_json::to_vec(&server_preimage).unwrap();

        assert_eq!(
            client_bytes, server_bytes,
            "preimage bytes must match across the wire"
        );
        assert!(
            verify_action_signature(&server_bytes, &sig_hex, &pubkey_hex).unwrap(),
            "the client's signature must verify on the server side"
        );
        // A tampered parent hash must NOT verify.
        let tampered = json!({
            "action": "append", "vfr_id": "vfr_demo",
            "parent_event_log_hash": "sha256:DIFFERENT", "batch": parsed_batch,
        });
        assert!(
            !verify_action_signature(
                &serde_json::to_vec(&tampered).unwrap(),
                &sig_hex,
                &pubkey_hex
            )
            .unwrap(),
            "a tampered preimage must be rejected"
        );
    }

    #[test]
    fn keygen_produces_valid_files() {
        let dir = std::env::temp_dir().join("vela_test_keygen");
        let _ = std::fs::remove_dir_all(&dir);

        let pubkey = generate_keypair(&dir).unwrap();
        assert_eq!(pubkey.len(), 64); // 32 bytes hex-encoded

        let private_hex = std::fs::read_to_string(dir.join("private.key")).unwrap();
        let public_hex = std::fs::read_to_string(dir.join("public.key")).unwrap();
        assert_eq!(private_hex.len(), 64);
        assert_eq!(public_hex, pubkey);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let finding = sample_finding();
        let key = test_keypair();

        let envelope = sign_finding(&finding, &key).unwrap();
        assert_eq!(envelope.finding_id, finding.id);
        assert_eq!(envelope.algorithm, "ed25519");
        assert_eq!(envelope.signature.len(), 128); // 64 bytes hex-encoded

        let valid = verify_finding(&finding, &envelope).unwrap();
        assert!(valid, "Signature should verify against original finding");
    }

    #[test]
    fn tampered_finding_fails_verification() {
        let finding = sample_finding();
        let key = test_keypair();
        let envelope = sign_finding(&finding, &key).unwrap();

        // Tamper with the finding
        let mut tampered = finding.clone();
        tampered.assertion.text = "Tampered assertion text".into();

        let valid = verify_finding(&tampered, &envelope).unwrap();
        assert!(!valid, "Tampered finding should fail verification");
    }

    #[test]
    fn sign_frontier_replaces_stale_same_key_signature() {
        let dir = tempfile::tempdir().unwrap();
        let frontier_path = dir.path().join("frontier.json");
        let private_key_path = dir.path().join("private.key");
        let key = test_keypair();
        std::fs::write(&private_key_path, hex::encode(key.to_bytes())).unwrap();

        let mut finding = sample_finding();
        let stale_envelope = sign_finding(&finding, &key).unwrap();
        finding.assertion.text = "NLRP3 activates IL-1B under revised scope".into();
        let mut frontier = empty_project(vec![finding], vec![stale_envelope]);
        crate::repo::save_to_path(&frontier_path, &frontier).unwrap();

        let signed = sign_frontier(&frontier_path, &private_key_path).unwrap();
        assert_eq!(signed, 1);

        frontier = crate::repo::load_from_path(&frontier_path).unwrap();
        let report = verify_frontier_data(&frontier, None).unwrap();
        assert_eq!(report.valid, 1);
        assert_eq!(report.invalid, 0);
        assert_eq!(frontier.signatures.len(), 1);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let finding = sample_finding();
        let key1 = test_keypair();
        let key2 = test_keypair();

        let envelope = sign_finding(&finding, &key1).unwrap();
        let pubkey2_hex = hex::encode(key2.verifying_key().to_bytes());

        let valid = verify_finding_with_pubkey(&finding, &envelope, &pubkey2_hex).unwrap();
        assert!(!valid, "Wrong public key should fail verification");
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let finding = sample_finding();
        let json1 = canonical_json(&finding).unwrap();
        let json2 = canonical_json(&finding).unwrap();
        assert_eq!(json1, json2, "Canonical JSON must be deterministic");
    }

    #[test]
    fn registered_actor_signed_event_roundtrip() {
        // Phase M: a registered actor's event must sign-and-verify
        // against its registered pubkey via `event_signing_bytes`. This
        // is the load-bearing claim for the v0.4 strict-mode gate.
        use crate::events::{
            EVENT_SCHEMA, NULL_HASH, StateActor, StateEvent, StateTarget, compute_event_id,
        };

        let key = test_keypair();
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());

        let mut event = StateEvent {
            schema: EVENT_SCHEMA.to_string(),
            id: String::new(),
            kind: "finding.reviewed".into(),
            target: StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            actor: StateActor {
                id: "reviewer:registered".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: "2026-04-25T00:00:00Z".to_string(),
            reason: "phase-m round-trip test".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: "sha256:abc".to_string(),
            payload: serde_json::json!({"status": "accepted", "proposal_id": "vpr_test"}),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        event.id = compute_event_id(&event);
        event.signature = Some(sign_event(&event, &key).unwrap());

        // Verifies against the registered pubkey.
        assert!(verify_event_signature(&event, &pubkey_hex).unwrap());

        // Tampering with the reason invalidates the signature.
        let mut tampered = event.clone();
        tampered.reason = "different reason".to_string();
        assert!(!verify_event_signature(&tampered, &pubkey_hex).unwrap());
    }

    #[test]
    fn provenance_co_author_confers_no_signing_authority() {
        // The co-authorship block names a non-human assistant (agent:claude)
        // inside the SIGNED payload. The structural guarantee: the signature is
        // verified only against actor.id's key, never against any provenance
        // name. An AI named as a co-author can therefore never stand in as the
        // signer, so no model is ever in the trust path even when it is recorded
        // as having drafted the work.
        use crate::events::{
            EVENT_SCHEMA, NULL_HASH, StateActor, StateEvent, StateTarget, compute_event_id,
        };
        use crate::provenance::{CoAuthor, Provenance};

        let human_key = test_keypair();
        let human_pubkey = hex::encode(human_key.verifying_key().to_bytes());
        let agent_key = test_keypair();
        let agent_pubkey = hex::encode(agent_key.verifying_key().to_bytes());

        let mut payload = serde_json::json!({"status": "accepted", "proposal_id": "vpr_test"});
        crate::provenance::attach_to_payload(
            &mut payload,
            &Provenance {
                co_authors: vec![CoAuthor {
                    id: "agent:claude".to_string(),
                    class: "agent".to_string(),
                    role: "drafted".to_string(),
                    generated_by: "claude-code (model: claude-opus-4-8)".to_string(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(payload["provenance"]["co_authors"][0]["id"], "agent:claude");

        let mut event = StateEvent {
            schema: EVENT_SCHEMA.to_string(),
            id: String::new(),
            kind: "review.accepted".into(),
            target: StateTarget {
                r#type: "proposal".to_string(),
                id: "vpr_test".to_string(),
            },
            actor: StateActor {
                id: "reviewer:will-blair".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: "2026-06-30T00:00:00Z".to_string(),
            reason: "co-authored accept".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: "sha256:abc".to_string(),
            payload,
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        event.id = compute_event_id(&event);
        event.signature = Some(sign_event(&event, &human_key).unwrap());

        // The accountable human's key verifies the co-authored event.
        assert!(verify_event_signature(&event, &human_pubkey).unwrap());
        // The co-author's own key does NOT verify it: being named in provenance
        // grants zero signing authority.
        assert!(!verify_event_signature(&event, &agent_pubkey).unwrap());
        // The block is signed-over, so tampering with the co-author name breaks
        // the human's signature (the attribution is tamper-evident).
        let mut tampered = event.clone();
        tampered.payload["provenance"]["co_authors"][0]["id"] =
            serde_json::json!("agent:someone-else");
        assert!(!verify_event_signature(&tampered, &human_pubkey).unwrap());
    }

    #[test]
    fn verify_frontier_data_reports_correctly() {
        let f1 = sample_finding();
        let mut f2 = sample_finding();
        f2.id = "vf_other_id_12345".into();
        f2.assertion.text = "Different finding".into();

        let key = test_keypair();
        let env1 = sign_finding(&f1, &key).unwrap();
        // Leave f2 unsigned

        let frontier = Project {
            vela_version: "0.1.0".into(),
            schema: "test".into(),
            frontier_id: None,
            project: crate::project::ProjectMeta {
                name: "test".into(),
                description: "test".into(),
                compiled_at: "2024-01-01T00:00:00Z".into(),
                compiler: "vela/0.2.0".into(),
                papers_processed: 0,
                errors: 0,
                dependencies: Vec::new(),
            },
            stats: crate::project::ProjectStats {
                findings: 2,
                links: 0,
                replicated: 0,
                unreplicated: 2,
                avg_confidence: 0.85,
                gaps: 0,
                negative_space: 0,
                contested: 0,
                categories: std::collections::HashMap::new(),
                link_types: std::collections::HashMap::new(),
                human_reviewed: 0,
                agent_reviewed: 0,
                review_event_count: 0,
                confidence_update_count: 0,
                event_count: 0,
                source_count: 0,
                evidence_atom_count: 0,
                condition_record_count: 0,
                proposal_count: 0,
                confidence_distribution: crate::project::ConfidenceDistribution {
                    high_gt_80: 2,
                    medium_60_80: 0,
                    low_lt_60: 0,
                },
            },
            findings: vec![f1, f2],
            sources: vec![],
            evidence_atoms: vec![],
            condition_records: vec![],
            review_events: vec![],
            confidence_updates: vec![],
            events: vec![],
            proposals: vec![],
            proof_state: Default::default(),
            signatures: vec![env1],
            actors: vec![],
            artifacts: vec![],
            released_diff_packs: vec![],
            verdict_conflicts: vec![],
            contradictions: vec![],
            verifier_attachments: vec![],
            attempts: vec![],
            attempt_resolutions: vec![],
            transfers: vec![],
            endorsements: vec![],
            statement_attestations: Vec::new(),
            anchor_links: Vec::new(),
            attempt_claims: Vec::new(),
            statement_registrations: Vec::new(),
        };

        let report = verify_frontier_data(&frontier, None).unwrap();
        assert_eq!(report.total_findings, 2);
        assert_eq!(report.signed, 1);
        assert_eq!(report.unsigned, 1);
        assert_eq!(report.valid, 1);
        assert_eq!(report.invalid, 0);
        assert_eq!(report.signers.len(), 1);
    }

    // ── v0.37 Multi-sig tests ────────────────────────────────────────

    fn empty_project(findings: Vec<FindingBundle>, signatures: Vec<SignedEnvelope>) -> Project {
        Project {
            vela_version: "0.37.0".into(),
            schema: "test".into(),
            frontier_id: None,
            project: crate::project::ProjectMeta {
                name: "test".into(),
                description: "test".into(),
                compiled_at: "2026-04-27T00:00:00Z".into(),
                compiler: "vela/0.37.0".into(),
                papers_processed: 0,
                errors: 0,
                dependencies: Vec::new(),
            },
            stats: crate::project::ProjectStats::default(),
            findings,
            sources: vec![],
            evidence_atoms: vec![],
            condition_records: vec![],
            review_events: vec![],
            confidence_updates: vec![],
            events: vec![],
            proposals: vec![],
            proof_state: Default::default(),
            signatures,
            actors: vec![],
            artifacts: vec![],
            released_diff_packs: vec![],
            verdict_conflicts: vec![],
            contradictions: vec![],
            verifier_attachments: vec![],
            attempts: vec![],
            attempt_resolutions: vec![],
            transfers: vec![],
            endorsements: vec![],
            statement_attestations: Vec::new(),
            anchor_links: Vec::new(),
            attempt_claims: Vec::new(),
            statement_registrations: Vec::new(),
        }
    }

    #[test]
    fn signers_for_dedupes_by_pubkey() {
        let mut f = sample_finding();
        f.flags.signature_threshold = Some(2);
        let key1 = test_keypair();
        let key2 = test_keypair();
        let env1 = sign_finding(&f, &key1).unwrap();
        let env1_dup = sign_finding(&f, &key1).unwrap();
        let env2 = sign_finding(&f, &key2).unwrap();
        let project = empty_project(vec![f.clone()], vec![env1, env1_dup, env2]);
        let signers = signers_for(&project, &f.id);
        assert_eq!(signers.len(), 2, "duplicate pubkey must be counted once");
    }

    #[test]
    fn threshold_met_requires_k_unique_signers() {
        let mut f = sample_finding();
        f.flags.signature_threshold = Some(2);
        let key1 = test_keypair();
        let env1 = sign_finding(&f, &key1).unwrap();
        let project_one = empty_project(vec![f.clone()], vec![env1.clone()]);
        assert!(!threshold_met(&project_one, &f.id), "1 of 2 not met");

        let key2 = test_keypair();
        let env2 = sign_finding(&f, &key2).unwrap();
        let project_two = empty_project(vec![f.clone()], vec![env1, env2]);
        assert!(threshold_met(&project_two, &f.id), "2 of 2 met");
    }

    #[test]
    fn threshold_none_reports_not_met() {
        let f = sample_finding();
        // signature_threshold defaults to None.
        let key = test_keypair();
        let env = sign_finding(&f, &key).unwrap();
        let project = empty_project(vec![f.clone()], vec![env]);
        assert!(
            !threshold_met(&project, &f.id),
            "no policy → never met (single-sig regime)"
        );
    }

    #[test]
    fn refresh_jointly_accepted_sets_flag() {
        let mut f = sample_finding();
        f.flags.signature_threshold = Some(1);
        let key = test_keypair();
        let env = sign_finding(&f, &key).unwrap();
        let mut project = empty_project(vec![f.clone()], vec![env]);
        refresh_jointly_accepted(&mut project);
        assert!(project.findings[0].flags.jointly_accepted);
    }

    #[test]
    fn invalid_signature_does_not_count_toward_threshold() {
        let mut f = sample_finding();
        f.flags.signature_threshold = Some(2);
        let key1 = test_keypair();
        let key2 = test_keypair();
        let env1 = sign_finding(&f, &key1).unwrap();
        let mut env2_tampered = sign_finding(&f, &key2).unwrap();
        // Replace signature bytes with garbage; key still claims to be key2.
        env2_tampered.signature = "00".repeat(64);
        let project = empty_project(vec![f.clone()], vec![env1, env2_tampered]);
        assert_eq!(valid_signature_count(&project, &f.id), 1);
        assert!(!threshold_met(&project, &f.id));
    }

    #[test]
    fn verify_report_surfaces_threshold_counts() {
        let mut f = sample_finding();
        f.flags.signature_threshold = Some(1);
        let key = test_keypair();
        let env = sign_finding(&f, &key).unwrap();
        let project = empty_project(vec![f.clone()], vec![env]);
        let report = verify_frontier_data(&project, None).unwrap();
        assert_eq!(report.findings_with_threshold, 1);
        assert_eq!(report.jointly_accepted, 1);
    }

    // ── v0.43 ORCID validation ───────────────────────────────────────

    #[test]
    fn validate_orcid_accepts_canonical_form() {
        assert_eq!(
            validate_orcid("0000-0001-2345-6789").unwrap(),
            "0000-0001-2345-6789"
        );
    }

    #[test]
    fn validate_orcid_accepts_check_digit_x() {
        assert_eq!(
            validate_orcid("0000-0001-5109-393X").unwrap(),
            "0000-0001-5109-393X"
        );
    }

    #[test]
    fn validate_orcid_strips_url_prefix() {
        assert_eq!(
            validate_orcid("https://orcid.org/0000-0001-2345-6789").unwrap(),
            "0000-0001-2345-6789"
        );
    }

    #[test]
    fn validate_orcid_strips_orcid_prefix() {
        assert_eq!(
            validate_orcid("orcid:0000-0001-2345-6789").unwrap(),
            "0000-0001-2345-6789"
        );
    }

    #[test]
    fn validate_orcid_rejects_short() {
        assert!(validate_orcid("0000-0001").is_err());
    }

    #[test]
    fn validate_orcid_rejects_letters_in_non_check_position() {
        assert!(validate_orcid("0000-A001-2345-6789").is_err());
    }

    #[test]
    fn validate_orcid_rejects_x_in_first_three_groups() {
        assert!(validate_orcid("000X-0001-2345-6789").is_err());
    }

    #[test]
    fn validate_orcid_rejects_extra_groups() {
        assert!(validate_orcid("0000-0001-2345-6789-9999").is_err());
    }
}
