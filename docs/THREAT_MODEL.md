# Threat model

This document is the substrate's honest read on its own attack
surface. It exists because v0.107 is the first release where Vela
shipped as published software (prebuilt release binaries via
`install.sh`, signed frontiers on a public hub) rather
than a development-only artifact. Public software is a target.

[`SECURITY.md`](../SECURITY.md) covers the reporting policy. This
document covers what is actually defended, what is not, and what is
deferred.

## Scope

In scope:

- the published Rust crates (`vela-protocol`, `vela-cli`,
  `vela-atlas`, `vela-constellation`, `vela-scientist`)
- the published Python package (`vela-state`)
- the public hub at `hub.constellate.science`
- the public site at `app.constellate.science`
- the conformance contract at `conformance/`
- the canonical event signing and replay rules
- the Workbench HTTP API (`/api/*`) when run via `vela serve`
- the agent write target (`POST /api/proposals/from-carina`)

Out of scope (deferred to later cycles, named at the end):

- federation across multiple hubs with peer trust
- public/private state boundary enforcement at the protocol level
- science-factory orchestration and lab write-back
- agent reliability records and AI capability gating
- IRB-equivalent review board for risky proposals

## Threat actors

The model assumes three classes of adversary, in order of severity:

1. **Network attacker.** Can read and tamper with traffic between a
   user's machine and `hub.constellate.science` or
   `app.constellate.science`. Cannot run code on the user's machine.

2. **Compromised actor key.** Has access to a private Ed25519 key
   that is registered as an `ActorRecord` on a published frontier.
   Can produce signatures that pass verification.

3. **Compromised hub or supply-chain operator.** Has write access to
   the hub server, the `crates.io` `vela-cli` account, the PyPI
   `vela-state` account, or the GitHub repo. Can push poisoned
   artifacts that pass installation.

The substrate's defenses scale with severity. A network attacker is
fully defended. A compromised actor key is partially defended. A
compromised supply-chain operator is undefended at the protocol
layer; the substrate inherits the security of the platforms it
publishes through.

## Trust boundaries

```
crates.io / PyPI / GitHub  <-- trust anchor
       |
       v
Published binary (vela)  ----  Published Python module (vela_state)
       |
       v
User's machine (local frontier, local keys)
       |
       v
Hub (hub.constellate.science)  <-- trust anchor for published frontiers
       |
       v
Other readers (anyone)
```

Three named trust anchors. The substrate's signature and replay
machinery defends every boundary the published binary touches; it
does not defend the publishing platforms themselves.

## Attack surfaces

Numbered for reference. Status: **Defended**, **Partial**,
**Undefended**, or **Deferred**.

### A1. Tampering with a finding's bytes on disk · Defended

If anyone modifies `findings/<vf_id>.json`, the content-address
no longer matches the file's bytes. `vela check` catches this via
the `state_integrity` and `events` checks (`scripts/test-check.sh`
pins the behavior). Theorems 1 and 5 in `lean/Vela/CoreTheorems`
are the formal backing.

### A2. Tampering with a canonical event · Defended

Same content-addressing rule. `event_id` is a hash of the
canonical-bytes preimage minus the signature; tampering with any
field changes the id. `verify_replay` catches this.

### A3. Forging a signature on a finding · Defended

Ed25519 signatures over the canonical-bytes preimage. Verifier
recomputes canonical bytes against current finding state and
checks signature. `sign::canonical_json` strips `flags.jointly_accepted`
from the preimage (v0.104 fix); Theorem 6 backs this. The
signing key never leaves the user's machine; the public key is
registered as an `ActorRecord` and is content-addressed into
events.

### A4. Replaying a signature across findings · Defended

Each signature commits to the specific `finding_id`. The
`SignedEnvelope` carries `finding_id` and `public_key`; verify
rejects any signature whose `finding_id` doesn't match the
finding being verified.

### A5. Lowering the multi-sig threshold to bypass joint review · Defended

`flags.signature_threshold` IS in the canonical signing preimage
(v0.104 design; the dual property to A3). Lowering the threshold
changes the canonical bytes and invalidates every existing
signature on the finding. The Lean companion
`canonicalJson_threshold_locked` proves this.

### A6. Submitting a poisoned Carina packet via the agent write target · Partial

`POST /api/proposals/from-carina` validates the packet shape
(`ArtifactPacket::validate` rejects malformed schemas, missing
required fields, and unrecognized artifact kinds) before
touching disk. **Defended** against:

- malformed JSON
- wrong schema constant
- missing producer / topic / artifacts
- unknown artifact kinds outside the allowlist
- duplicate artifact ids within a packet

**Undefended** against:

- semantic prompt injection inside `assertion` text or `notes`
  fields (the substrate stores what an agent says; reviewers
  read it; a downstream LLM consuming `vela log` could be
  prompt-injected)
- adversarial `provenance` claims (the locator is stored
  verbatim; a reviewer must verify the source)
- citation poisoning (a fabricated DOI passes validation;
  Crossref lookup is best-effort, not enforced)

The substrate's stance: validation catches structural attacks;
semantic attacks are the reviewer's job. The
`scripts/test-from-carina.sh` gate pins the structural validation
contract.

**Citation-poisoning closure (v0.108.3):** `vela bridge-kit
verify-provenance <packet>` walks artifact locators and
candidate-claim source_refs, extracts recognized DOI / PMID
identifiers (raw, prefixed, or as URLs), and asks Crossref /
PubMed eutils whether each one resolves. Fabricated identifiers
return HTTP 404 from the upstream registry and are reported
as `unresolved`. The CLI exits 1 if any identifier fails to
resolve, so the verification can be wired into review gates or
CI without further glue. Network call; identifiers skip
gracefully when the upstream is unreachable.

This is a voluntary tool: the agent write target itself does
not call out to Crossref / PubMed on every POST (creating a
network dependency on the write path is a worse failure mode
than the citation-poisoning gap). Reviewers should run
`verify-provenance` against any packet they are about to
accept.

### A7. Compromised reviewer key · Mitigated at v0.127

If a single reviewer's private key is stolen, the attacker can
sign arbitrary findings under that reviewer's id. **Mitigations:**

- Multi-sig threshold (v0.37, fixed v0.104) lets a frontier
  require k distinct actor signatures before
  `jointly_accepted` flips. A single-key compromise is bounded
  to k=1 findings; k=2 frontiers require a second compromise.
- Every signed event is timestamped and content-addressed; a
  forensic audit can identify divergent signing windows.
- **v0.127:** explicit key-rotation primitive
  `vela actor rotate --id <retired> --new-id <new> --new-pubkey
  <hex> --reason <text>` retires an actor in place. The retired
  actor's record gains `revoked_at` (RFC3339 timestamp) and
  `revoked_reason`. Historical signatures (event timestamp <
  revoked_at) remain valid; new signatures from the retired key
  (event timestamp ≥ revoked_at) are rejected by the signals
  layer as `post_revocation_signature` blockers under
  `vela check --strict`. A reviewer who suspects a key compromise
  can rotate within seconds; the rotation event is itself a
  canonical record. Pinned by
  `scripts/test-actor-rotate.sh`.
- Multi-sig threshold soundness (Theorem 11, v0.125) pins the
  algebraic shape of the per-finding accumulation rule:
  distinct-signer counting is sound under monotonicity,
  distinctness, and registration-bound. An attacker with one
  key cannot inflate the count past 1 distinct registered
  signer.

**Open work:**

- No threshold-signature scheme (where k-of-n keys must
  combine on every signature, not just per-finding). Multi-sig
  here is per-finding accumulation, not per-signature
  threshold. The substrate accepts this design choice: the
  k=2+ frontier policy is what most reviewers will actually
  use, and per-signature threshold schemes add operational
  complexity without changing the bound.

### A8. Compromised owner key for a published frontier · Mitigated at v0.138, hardened at v0.145

A frontier registered on a hub carries an owner-signed git-remote
registration naming an `owner_pubkey`. If that key is compromised, the
attacker can:

- re-point the frontier's registered git remote at a repo they control

They still cannot fabricate accepted state: the ingest loop strictly
replays the committed event log, so a repo whose events are not signed
by the frontier's registered reviewer keys is refused, and a consumer's
`git clone` + `vela check --strict` never touches the hub at all.

**Mitigations:**

- The registration is content-addressed and owner-signed; the hub
  verifies the signature before re-pointing, and tampering with the
  stored registration changes its hash.
- Owner-key rotation happens in the frontier itself: `vela actor rotate`
  revokes the old actor record with a recorded reason and registers the
  new key under a versioned id, so the rotation timeline (`revoked_at` /
  `revoked_reason` on the retired record, `created_at` on the new
  record) is reconstructable from the frontier alone. (The retired
  hub-side `vela registry owner-rotate` verb did this against registry
  entries; the in-frontier primitive is the surviving path.)
- v0.145's multi-sig governance survives as the owner-epoch chain. A
  per-frontier `vela.registry_governance_policy.v0.1` (v0.144) declares
  a quorum of eligible attesters and a threshold; the rotation flow is
  propose -> attest -> apply, and `vela hub verify-chain` re-runs the
  quorum verification over the recorded chain transcript. The verifier
  checks:
  signatures valid against attester pubkeys, attester not
  revoked at `signed_at`, attester in `rotate_quorum.eligible_actors`,
  duplicate attester ids counted once, proposal not expired,
  proposal `previous_entry_hash` + `governance_policy_id` +
  `owner_epoch` pin the rotation to a specific chain position
  so attestations cannot be replayed. With governance bound, a
  fully-compromised current owner key alone is insufficient
  authority for non-bootstrap rotations: the threshold of
  distinct eligible attesters must approve.
- The heading's version stamps (v0.138 / v0.145) date when each
  primitive first shipped; the verbs above are the current surface.

**Out of scope (deferred to future cycle):**

- A fully-compromised owner who still controls the current
  signing key can rotate to an attacker-controlled key. The
  rotation primitive only authenticates the rotation by the
  fact that the new key now signs the registry entry; it does
  not introduce multi-party authorization. Defending against
  this case requires multi-sig governance over rotations, which
  is a distinct threat surface.
- The hub-side attestation history (storing every historical
  `owner_pubkey` under one `vfr_id` so consumers can audit the
  rotation chain without re-fetching every intermediate state)
  remains future work. The frontier's in-band actor records
  carry the rotation chain in the substrate-honest sense.

### A9. Compromised install channel · Undefended at protocol layer

The install channel today is GitHub releases: `install.sh` fetches a
prebuilt binary for the resolved release tag (or builds from source).
A compromised GitHub account or Actions pipeline could ship a
malicious asset; `curl | bash` inherits the security of GitHub's
account auth plus TLS. The substrate cannot prevent this.

Historical note: early releases (v0.102–v0.1xx) were also published
to crates.io and PyPI. Neither channel is maintained — no vela crates
exist on crates.io today, and the `vela-state` PyPI package is frozen
at a pre-consolidation version. Do not install from either; treat the
PyPI artifact as historical until it is re-published or formally
yanked (a maintainer-account decision).

**Mitigations available, not yet adopted:**

- Sigstore / SLSA provenance attestations on release assets
  would let consumers verify the publisher (release-provenance.yml
  is the start of this).
- Pinning an exact tag (`VELA_VERSION=v0.726.0 ./install.sh`)
  prevents silent rolls.
- Reviewing the diff between released versions would catch
  obvious malice; the GitHub release notes are the suggested
  audit trail.

### A10. Stale package-registry artifacts · Accepted (documented above)

The A9 historical note is the whole story: the dormant PyPI
`vela-state` package is the one artifact an attacker could
impersonate or a user could stumble into. Re-publish or yank is
tracked as maintainer work.

### A11. Compromised hub server · Partial (witness-check Defended at v0.129)

`hub.constellate.science` is a single hub today. If it is compromised:

- the index could omit entries (discovery lies).
- the index could serve a stale or wrong projection; but bytes
  come from the frontier's git repo, so a consumer running
  `git clone` + `vela check --strict` is unaffected — the hub
  no longer serves bytes a verifier depends on.

**Mitigations:**

- Pulled frontiers are signature-verified before
  acceptance. A hub cannot serve content whose signature
  doesn't match the registered owner pubkey.
- The hub's `/release.json` ships a `git_sha` that ties the
  deployed site to a specific commit;
  `scripts/check-live-release.sh` cross-checks this.
- **v0.129:** `vela hub witness-check <vfr_id> --hubs
  <a,b,c>` fetches the same registry entry from multiple
  hubs, canonicalizes each via the substrate's
  `to_canonical_bytes` helper, and asserts byte-identical
  agreement on the canonical sha256. Reports `unanimous`,
  `majority`, `split`, or `insufficient` consensus. The
  substrate-honest claim: if two trustworthy mirrors agree
  on the canonical bytes, a third hub's diverging copy is
  detectable. The substrate does not adjudicate which hub
  is correct in a split; that is the operator's call. Pinned
  by `scripts/test-registry-witness.sh`.
- Seeding a second hub is now trivial by construction: register
  the same git remotes on it and let its ingest loop re-derive the
  index (the retired `vela registry mirror` copied registry bytes
  instead). v0.129's witness-check closes the verification half by
  giving consumers a cross-hub agreement signal.

**Deferred:**

- Multi-hub federation with three or more hubs deployed in
  production (one hub today; the substrate primitives are
  ready for more).
- A separate transparency log (Merkle tree, RFC 6962 shape)
  anchoring every signed registry entry by hash.

### A12. Tampered conformance fixtures · Partial (integrity half Defended at v0.107.4)

The conformance fixtures at `conformance/fixtures/` are
checked into the repo. A compromised GitHub account could
modify them to weaken the cross-impl agreement check.

**Mitigations:**

- v0.107.4 ships `conformance/fixtures/fixtures.manifest.json`
  recording the SHA-256 and byte-length of every fixture.
  `conformance/verify.py` runs an integrity preflight before
  the cross-impl diff and refuses to proceed (exit 2) if any
  fixture's bytes drift from the recorded digest. A
  byte-modified fixture is detected immediately.
- The fixtures are auto-generated from the Rust test suite
  (`crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs::export_cross_impl_reducer_fixtures`);
  re-generating from the canonical generator detects
  tampering. The manifest is regenerated alongside.
- Every commit to the repo is signed via GitHub's commit
  signing when the contributor opts in.

**Not defended:**

- The manifest itself is not cryptographically signed. A
  compromised GitHub account that modifies BOTH a fixture
  and the manifest entry for it would pass the preflight.
  A future cycle adds a `fixtures.manifest.sig` under a
  maintainer Ed25519 key so the manifest is itself a
  trust-anchored object.

### A13. Resource exhaustion via large packets · Partial (body-cap Defended at v0.107.5)

The agent write target accepts JSON bodies and writes them to
a tempfile before processing. An attacker could submit a
gigabyte-sized packet to exhaust disk or memory.

**Mitigations:**

- v0.107.5 sets an explicit `DefaultBodyLimit::max(8 MiB)` on
  the entire `vela serve` axum router. Bodies above 8 MiB
  return HTTP 413 (Payload Too Large) before any handler
  runs. 8 MiB fits a real Carina packet with several
  artifacts; gigabyte payloads are refused at the layer
  boundary.
- The cap is pinned explicitly so a future axum default
  change does not silently expose the surface.
- The serve binary defaults to bind on localhost; remote
  exhaustion requires the user to expose the port.

**Not defended:**

- No explicit per-route rate limits.
- No per-actor or per-IP request budget.

A user running `vela serve` on a public network should put it
behind a reverse proxy that enforces rate limits on top of
the body-cap. The substrate does the body-cap; the rate-limit
half is still deferred.

### A14. Workbench client-side attacks · Mitigated at v0.128

The Workbench renders user-submitted finding text, evidence
spans, annotation prose, and entity names. A poisoned packet
could include `<script>` tags or other XSS payloads.

**Mitigations:**

- Astro renders by default with HTML escaping. Inline
  rendering of user-submitted text uses textContent, not
  innerHTML.
- **v0.128:** static Content-Security-Policy ships at the
  nginx edge for every response:
  `default-src 'self'; script-src 'self'; ...`. An injected
  inline `<script>` cannot execute even if user-text
  somehow reached `innerHTML` unsanitized — the CSP is the
  real defense, not the rendering discipline. The CSP also
  carries `frame-ancestors 'none'` (clickjacking),
  `base-uri 'self'` (base-tag injection), and a
  `connect-src` allowlist matching the four Bridge-kit
  upstreams plus the substrate hub.
- **v0.128:** the hardening trio (X-Frame-Options: DENY,
  X-Content-Type-Options: nosniff,
  Referrer-Policy: strict-origin-when-cross-origin) plus a
  Permissions-Policy locking down geolocation / mic /
  camera / payment.
- **v0.128:** `scripts/test-no-unsafe-html.sh` forbids the
  always-unsafe DOM primitives (`eval`, `new Function`,
  `document.write`, `document.writeln`,
  `dangerouslySetInnerHTML`). `innerHTML` uses are allowed
  but require the per-site convention of wrapping every
  user-text interpolation in `escapeHtml()` (audited in the
  v0.107 pass).
- **v0.128:** `scripts/test-site-csp-headers.sh` (network
  gate, skips offline) confirms the deployed site returns
  every header above.

**Open work (deferred to a future cycle if the substrate
adopts heavier interactivity):**

- A formal third-party XSS audit has not been run; the
  v0.128 hardening defends against injection at the CSP
  layer, but a full pen-test would surface remaining edge
  cases in custom rendering paths.
- Nonce-based CSP (per-response random nonce on every
  inline script) tightens the policy further if the site
  ever needs trusted inline scripts. The current
  `script-src 'self'` covers all known cases because Astro
  emits hydration scripts under `_astro/`.

### A15. Identity spoofing in `actors.json` · Defended

`vela actor add` validates that the public key is exactly 64
hex chars (`scripts/test-actor.sh` pins this). Duplicate
actor ids are rejected. ORCID identifiers, when supplied, are
validated against the ISO 7064 checksum (v0.43). Adding an
actor whose pubkey does not match a real Ed25519 keypair
makes signatures from that actor unverifiable.

### A17. Private signing keys committed to public git · Mitigated at v0.111.1

`vela id create` writes a freshly-generated Ed25519 keypair
to `<frontier>/keys/` by default. If a quickstart-scaffolded
frontier is committed to a public repo as a reference example
without first removing `keys/`, the private key reaches public
git history.

**Mitigations:**

- v0.111.1 added `keys/` and `*.key` patterns to repo-level
  `.gitignore`, so future quickstart-scaffolded frontiers
  committed as reference examples do not carry the keys
  directory.
- The v0.111.0 incident (`vsi_2026-05-10-erdos-key-leak`) is the
  reason this item exists: a reference frontier briefly carried a
  scaffolded keypair in public git history. The exposed key had
  performed zero signing operations, it was removed and treated as
  compromised (never to be re-registered), and git history was left
  unrewritten — the leak is itself part of the honest record.
- The reference frontiers under `examples/` and the project-layer
  frontiers under `projects/*` audit clean: no `keys/` directory in
  any of them.

**Not defended:**

- The `.gitignore` rule is repo-level. A user creating a fork
  with their own quickstart frontiers needs to either inherit
  the rule or add their own. Future cycles could ship the
  rule as part of `vela init`'s scaffolding so it lands in
  every fresh frontier repo, not just the canonical one.
- Pre-commit auditing for sensitive file shapes
  (`*.key`, `*.pem`, `*credential*`, `*private*`) is not
  enforced by the substrate. A future cycle should add a
  `vela check --strict` pass that flags suspicious paths
  before commit.

### A16. Causal/scientific incorrectness · Out of scope

The substrate validates structure: content addresses, signature
chains, replay determinism, schema compliance. It does not
validate the science. A frontier can be perfectly signed,
perfectly replayed, and perfectly conformant while making
totally wrong claims. The reviewer's job is the science; the
substrate's job is to make the reviewer's signed verdict
durable and auditable.

This is named explicitly because it is the most common
misunderstanding from non-expert users: "Vela makes claims
correct." It does not. Vela makes claims durable.

## Defenses by primitive

| Primitive | Code | Theorem | Gate |
|-----------|------|---------|------|
| Content addressing | `events.rs::event_id`, `bundle.rs::FindingBundle::content_address` | T1, T5 | `test-check` |
| Replay determinism | `reducer.rs::replay_from_genesis` | T1 | `test-readme-demo` |
| Provenance retraction | `provenance_poly.rs` | T2 | unit tests |
| Status soundness | `status_provenance.rs` | T3 | unit tests |
| Detector monotonicity | `discord_compute.rs` | T4 | `test-discord` |
| Hash-DAG integrity | `events.rs::event_id` | T5 | `test-check` |
| Multi-sig signature stability | `sign.rs::canonical_json` | T6 | `test-multisig-threshold` |
| Cross-impl agreement | `clients/python/vela_reducer.py` + Rust | (none, conformance) | `conformance/verify.py` |
| Schema validation | `events.rs::validate_event_payload` | (none) | `test-carina-validate` |
| Actor registration | `sign.rs::ActorRecord` | (none) | `test-actor` |
| Public-no-write | site has zero `/review/` POST routes | (none) | `check-public-no-write-routes.py` |

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Email the maintainer; do not open
public issues. Include reproduction steps and the affected component.

## What is deferred

These are real gaps named honestly. They are not defended
today and are tracked for future cycles:

- Sigstore / SLSA provenance on published crates and Python
  artifacts (closes A9, A10)
- Multi-hub federation with mirror verification (closes A11)
- Owner-key revocation protocol (closes part of A8)
- Threshold-signature scheme for per-signature k-of-n (closes
  part of A7)
- Per-route rate limits and body caps in `vela serve`
  (closes A13)
- Formal XSS audit on the Workbench (closes A14)
- Signed `fixtures.sig` for the conformance contract
  (closes A12)
- AGENTS.md for science (mentioned in the 10-year plan)
- Public/private state boundary enforcement at the protocol
  level (mentioned in the 10-year plan)
- Agent reliability records and AI capability gating
  (mentioned in the 10-year plan)
- IRB-equivalent review board for risky proposals
  (mentioned in the 10-year plan)

## Summary

The substrate is fully defended against tampering with
on-disk state, replay attacks, signature forgery, and
threshold bypass. It is partially defended against
compromised individual reviewer keys, agent prompt injection,
and resource exhaustion. It is undefended at the protocol
layer against compromised crates.io / PyPI / hub accounts;
those depend on platform security.

The most likely real-world failure mode is not a kernel
attack. It is a reviewer accepting a bad claim and signing it
into the substrate. The substrate makes the verdict durable
and auditable. Whether the verdict is right is the reviewer's
job.
