//! Ed25519 signing for the event log — the trust infrastructure layer.
//!
//! The signed EVENT log is the sole signing authority: a registered human
//! actor's events carry a verifiable signature, and `verify_event_signature`
//! checks them against the registered pubkey. The legacy per-finding signature
//! lane (the v0.37 multi-sig `SignedEnvelope` / threshold machinery) was retired
//! — `SignedEnvelope` and `Project.signatures` survive only so historical
//! frontiers that still carry envelopes deserialize and replay unchanged. They
//! are vestigial data (hash-neutral): nothing creates, verifies, or gates on
//! them.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::project::Project;
use crate::repo;

/// A signed envelope wrapping a finding's cryptographic signature.
///
/// Vestigial: retained so historical `Project.signatures` deserialize. The
/// finding-signature lane is retired; no code path produces or verifies these.
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

/// Parse a verifying key from a hex string.
fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex in public key: {e}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid public key: {e}"))
}

// ── Event signing (Phase M, v0.4) ────────────────────────────────────

/// Compute the canonical signing bytes for a `StateEvent`. The `signature`
/// field is excluded from the preimage (you can't sign over your own
/// signature). The same canonical-JSON rule that derives `vev_…` is reused.
///
/// A second implementation must produce byte-identical signing bytes
/// for the same event content; the verification rule depends on it.
pub fn event_signing_bytes(
    event: &crate::events::StateEvent,
    version: crate::signing_input::SigVersion,
) -> Result<Vec<u8>, String> {
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
    let body = crate::canonical::to_canonical_bytes(&preimage)?;
    Ok(crate::signing_input::signing_input(
        version,
        crate::signing_input::payload_type::EVENT,
        &body,
    ))
}

/// Sign a canonical event with an Ed25519 private key, returning a signature
/// suitable for `event.signature`. New signatures are v1 (DSSE/PAE), carried as
/// a `v1:` prefix on the signature string so historical bare-hex signatures read
/// as v0. The prefix is not part of the event id or the (content-only)
/// event_log_hash, so the flip is transparent to addressing.
pub fn sign_event(
    event: &crate::events::StateEvent,
    signing_key: &SigningKey,
) -> Result<String, String> {
    let bytes = event_signing_bytes(event, crate::signing_input::SigVersion::V1)?;
    let signature = signing_key.sign(&bytes);
    Ok(format!("v1:{}", hex::encode(signature.to_bytes())))
}

/// Verify that `event.signature` is a valid Ed25519 signature over the canonical
/// signing bytes of `event`, produced by the holder of `expected_pubkey_hex`.
/// The signing-input version is read from the signature's `v1:` prefix (a bare
/// hex signature is historical v0); the framing is then fixed, so flipping the
/// prefix changes the bytes and fails verification (fail-closed).
pub fn verify_event_signature(
    event: &crate::events::StateEvent,
    expected_pubkey_hex: &str,
) -> Result<bool, String> {
    use crate::signing_input::SigVersion;
    let raw = event
        .signature
        .as_deref()
        .ok_or_else(|| format!("event {} has no signature field", event.id))?;
    let (version, signature_hex) = match raw.strip_prefix("v1:") {
        Some(hex) => (SigVersion::V1, hex),
        None => (SigVersion::V0, raw),
    };
    let verifying_key = parse_verifying_key(expected_pubkey_hex)?;
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Signature must be 64 bytes")?,
    );
    let bytes = event_signing_bytes(event, version)?;
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
    let body = crate::canonical::to_canonical_bytes(&preimage)?;
    Ok(crate::signing_input::signing_input(
        crate::signing_input::SigVersion::V0,
        crate::signing_input::payload_type::PROPOSAL,
        &body,
    ))
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

/// Sign all unsigned EVENTS whose registered human actor matches the given key.
/// Returns the number of newly signed events.
///
/// The legacy per-finding signature lane (the v0.37 multi-sig `SignedEnvelope`
/// machinery) was retired: the signed event log is the sole signing authority for
/// new state. Existing finding envelopes remain as vestigial data and still
/// verify, but nothing creates new ones, and the joint-accept / threshold quorum
/// machinery is gone.
pub fn sign_registered_events(
    frontier_path: &Path,
    private_key_path: &Path,
) -> Result<usize, String> {
    let mut frontier: Project = repo::load_from_path(frontier_path)?;

    let signing_key = load_signing_key(private_key_path)?;
    let our_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let mut signed_count = 0usize;

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

    repo::save_to_path(frontier_path, &frontier)?;

    Ok(signed_count)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn v0_and_v1_event_signatures_both_verify() {
        // The migration seam (M8): a new signature is v1 (v1:-prefixed) and a
        // historical signature is v0 (bare hex). Both must verify so the flip
        // never strands a historical event, and a downgrade (claiming a v1
        // signature is v0) must fail closed.
        use crate::events::{
            EVENT_SCHEMA, NULL_HASH, StateActor, StateEvent, StateTarget, compute_event_id,
        };
        use crate::signing_input::SigVersion;

        let key = test_keypair();
        let pubkey = hex::encode(key.verifying_key().to_bytes());
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
            timestamp: "2026-06-30T00:00:00Z".to_string(),
            reason: "v0/v1 dual-verify".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: "sha256:abc".to_string(),
            payload: serde_json::json!({"status": "accepted", "proposal_id": "vpr_test"}),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        event.id = compute_event_id(&event);

        // New default: sign_event emits a v1: signature, and it verifies.
        event.signature = Some(sign_event(&event, &key).unwrap());
        assert!(event.signature.as_deref().unwrap().starts_with("v1:"));
        assert!(verify_event_signature(&event, &pubkey).unwrap());

        // Historical v0: a bare-hex signature over the v0 framing still verifies.
        let v0_bytes = event_signing_bytes(&event, SigVersion::V0).unwrap();
        let mut v0_event = event.clone();
        v0_event.signature = Some(hex::encode(key.sign(&v0_bytes).to_bytes()));
        assert!(verify_event_signature(&v0_event, &pubkey).unwrap());

        // Downgrade attempt: strip the v1: prefix so it claims v0. The framing
        // then differs from what was signed, so it must fail closed.
        let mut downgraded = event.clone();
        let bare = event
            .signature
            .as_deref()
            .unwrap()
            .strip_prefix("v1:")
            .unwrap()
            .to_string();
        downgraded.signature = Some(bare);
        assert!(!verify_event_signature(&downgraded, &pubkey).unwrap());
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
        use crate::provenance::{MachineContribution, Provenance};

        let human_key = test_keypair();
        let human_pubkey = hex::encode(human_key.verifying_key().to_bytes());
        let agent_key = test_keypair();
        let agent_pubkey = hex::encode(agent_key.verifying_key().to_bytes());

        let mut payload = serde_json::json!({"status": "accepted", "proposal_id": "vpr_test"});
        crate::provenance::attach_to_payload(
            &mut payload,
            &Provenance {
                machine_contributions: vec![MachineContribution {
                    id: "agent:claude".to_string(),
                    class: "agent".to_string(),
                    role: "drafted".to_string(),
                    tool: "claude-code".to_string(),
                    generated_by: "model: claude-opus-4-8".to_string(),
                    authority: "none".to_string(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            payload["provenance"]["machine_contributions"][0]["id"],
            "agent:claude"
        );

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
        tampered.payload["provenance"]["machine_contributions"][0]["id"] =
            serde_json::json!("agent:someone-else");
        assert!(!verify_event_signature(&tampered, &human_pubkey).unwrap());
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
