//! CLI command surface — the clap `Commands` enum and its `*Action`
//! subcommand enums, split out of `cli.rs` so the ~5k lines of command
//! definitions live apart from the handler functions and dispatch. Pure
//! data: the handlers and `run_command` dispatch stay in `cli.rs`.
//!
//! ## Flag-naming conventions (one name per concept, no aliases)
//! - **Acting identity** → `--reviewer` for the decision/judgment commands
//!   (the old `--actor`/`--by` aliases were retired in the dev-only
//!   cleanup). `--owner` stays distinct (registry owner-role operations);
//!   `--actor` stays the canonical for the lower-level verifier/author
//!   identities (lean verify-all, ingest) that are NOT the reviewer concept.
//!   The value defaults from the configured identity (`vela id`), so the
//!   flag is usually omitted entirely.
//! - **Signing key** → `--key`. Defaults from `vela id`.
//! - **Targets** → `--hub` (a registry/peer base URL the client talks to),
//!   `--to` (a publish/append destination), `--from` (a read source). One
//!   meaning each; do not overload.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Check frontier quality and proof readiness
    Check {
        /// Frontier JSON file, Vela repo, or proof packet
        source: Option<PathBuf>,
        /// Run schema validation
        #[arg(long)]
        schema: bool,
        /// Run frontier lint checks
        #[arg(long)]
        stats: bool,
        /// Run the Evidence-CI readiness check (source, evidence, condition,
        /// confidence, policy). Folds in the standalone `evidence-ci` verb.
        #[arg(long)]
        evidence: bool,
        /// Run conformance vectors
        #[arg(long)]
        conformance: bool,
        /// Conformance test directory
        #[arg(long, default_value = "conformance")]
        conformance_dir: PathBuf,
        /// Run all checks
        #[arg(long)]
        all: bool,
        /// Run only structural schema validation
        #[arg(long)]
        schema_only: bool,
        /// Treat warnings and blocking signals as failures
        #[arg(long)]
        strict: bool,
        /// Show fix suggestions
        #[arg(long)]
        fix: bool,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Diagnose first-user checkout, frontier, proof, and serve readiness.
    Doctor {
        /// Frontier JSON file or Vela repo. Defaults to the release frontier
        /// when run from the repository root.
        frontier: Option<PathBuf>,
        /// Local serve port to check.
        #[arg(long, default_value_t = 3741)]
        port: u16,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Normalize deterministic frontier state without changing claims
    Normalize {
        /// Frontier JSON file or Vela repo
        source: PathBuf,
        /// Output normalized frontier copy
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Write changes back to the input
        #[arg(long)]
        write: bool,
        /// Force dry-run
        #[arg(long)]
        dry_run: bool,
        /// Rewrite finding IDs to content addresses and update links
        #[arg(long)]
        rewrite_ids: bool,
        /// Write old-to-new ID map when rewriting IDs
        #[arg(long)]
        id_map: Option<PathBuf>,
        /// Phase N: regenerate finding.provenance fields (title, year,
        /// journal, authors, license, publisher, funders) from the
        /// canonical SourceRecord matched by DOI / PMID / title.
        #[arg(long)]
        resync_provenance: bool,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Export and validate a proof packet
    Proof {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Output proof packet directory
        #[arg(long, short = 'o', default_value = "proof-packet")]
        out: PathBuf,
        /// Proof packet template
        #[arg(long, default_value = "generic")]
        template: String,
        /// Record latest proof packet state back into the input frontier
        #[arg(long)]
        record_proof_state: bool,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Serve a read-only frontier over MCP stdio or HTTP
    Serve {
        /// Frontier JSON file or Vela repo
        #[arg(required_unless_present_any = ["frontiers", "setup"])]
        frontier: Option<PathBuf>,
        /// Directory of frontier files
        #[arg(long)]
        frontiers: Option<PathBuf>,
        /// LLM backend reserved for future optional tools
        #[arg(short, long)]
        backend: Option<String>,
        /// Run an HTTP server on this port instead of MCP stdio
        #[arg(long)]
        http: Option<u16>,
        /// Print MCP setup instructions
        #[arg(long)]
        setup: bool,
        /// Validate public tool contracts and exit
        #[arg(long)]
        check_tools: bool,
        /// Include first external frontier adoption guidance in --check-tools output
        #[arg(long)]
        adoption: bool,
        /// MCP exposure profile (memo §9.1): `read-only` (default), `draft`
        /// (adds the propose/draft write tools), or `maintainer` (all tools).
        /// Scopes which tools are listed AND executable. Agents should get
        /// read-only unless a human starts a scoped session.
        #[arg(long, default_value = "read-only")]
        profile: String,
        /// Output stable JSON for --check-tools
        #[arg(long)]
        json: bool,
    },
    /// v0.42: Show what's pending right now — the daily-driver
    /// equivalent of `git status`. One screen: counts, the inbox,
    /// the audit. Read in two seconds.
    Status {
        frontier: PathBuf,
        /// Output stable JSON for programmatic callers.
        #[arg(long)]
        json: bool,
    },
    /// v0.42: Recent canonical events in human-readable form. The
    /// `git log` analogue. Default newest-first; cap on count.
    Log {
        frontier: PathBuf,
        /// How many recent events to show.
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Filter to events matching this kind (substring match).
        #[arg(long)]
        kind: Option<String>,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// v0.42: Triage list of pending proposals. What you sit down to
    /// review. Reviewer-agent scores surface where present; flagged
    /// items rise to the top.
    Inbox {
        frontier: PathBuf,
        /// Show only proposals matching this kind (substring match).
        #[arg(long)]
        kind: Option<String>,
        /// Cap on entries shown.
        #[arg(long, default_value = "30")]
        limit: usize,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Recompute SHA-256 over every file in a proof packet, compare to
    /// the manifest, and validate the proof-trace chain. Use this when
    /// you've pulled a packet from someone else and want one command
    /// that says "yes, this is what they signed, byte for byte."
    Verify {
        /// Path to the proof packet directory (the one with manifest.json)
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// The verification gate: deliverable-grade and verifier-attachment
    /// checks. `vela verify` proves the *log* is what was signed; `vela
    /// gate` proves a *claim* earned its status — ≥2 independent matched
    /// verifier attachments and a surviving adversarial probe, never a
    /// self-reported "verified" string. See `vela_protocol::verifier_attachment`
    /// and `vela_edge::deliverable_grade`.
    Gate {
        #[command(subcommand)]
        action: GateAction,
    },
    /// Generate vendor agent-config adapters from the canonical `VELA.md`
    /// (one source of truth; the adapter files are disposable, regenerable
    /// leaves). `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/vela.mdc`,
    /// `.github/copilot-instructions.md`, and `.mcp.json` regenerate from
    /// VELA.md; the deletion test holds (delete them, sync, they return).
    Agents {
        #[command(subcommand)]
        action: AgentsAction,
    },
    /// Re-verify stored witnesses from scratch with the frozen exact
    /// verifiers (`vela-verify`). Trust is never self-reported: a stranger
    /// runs `vela reproduce <example>` and confirms every claimed
    /// construction re-checks (Sidon, Golomb, cap, B_h, covering,
    /// constant-weight, Costas, linear codes). Exits non-zero if any
    /// witness fails to re-verify.
    Reproduce {
        /// A witness JSON file, or a directory (reproduces every
        /// `*.witness.json` under it, or a `witnesses/` subdir).
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// The discovery engine: search for verifier-gated constructions, then
    /// verify them with the frozen `vela-verify` and (optionally) propose the
    /// result. Search *produces* candidates; the frozen verifier is the gate —
    /// nothing is reported that does not re-check. Deterministic: the same
    /// `--seed` reproduces the same find. AI proposes; a key-holder accepts.
    Campaign {
        #[command(subcommand)]
        action: CampaignAction,
    },
    /// The foundry: one unattended compounding turn (Phase 2). Produce a
    /// candidate with the frozen-verifier campaign, register its witness, and
    /// run it through the exact-lane de-human-gate — produce -> frozen-verify
    /// -> auto-admit -> machine_verified, with no human and no key. Dry-run by
    /// default (previews the gate); `--apply` records the admission.
    Foundry {
        #[command(subcommand)]
        action: FoundryAction,
    },
    /// Experiment-plane receipts (Inevitability Program Phase 0): assemble a
    /// content-addressed run-manifest over an experiment's turns, and project the
    /// discharge status of a typed cohort over accepted state. Non-authoritative;
    /// no event, no wire change.
    Experiment {
        #[command(subcommand)]
        action: ExperimentAction,
    },
    /// The ranked "what should I work on next" queue: the dark-matter boundary
    /// (one-premise-away first, then brittle single-points-of-failure, fragile,
    /// contested, stale-open) as a flat, ordered, actionable list.
    Attack {
        /// Frontier directory (e.g. examples/erdos-problems).
        frontier: PathBuf,
        /// Show at most this many targets.
        #[arg(long, default_value_t = 12)]
        top: usize,
        #[arg(long)]
        json: bool,
    },
    /// Explore a finding's neighbourhood: what it rests on and what rests on it,
    /// within `--hops` (the MCP frontier_explore as a CLI verb).
    Explore {
        /// Frontier directory.
        frontier: PathBuf,
        /// Finding id (vf_...) to explore around.
        finding: String,
        #[arg(long, default_value_t = 2)]
        hops: usize,
        #[arg(long)]
        json: bool,
    },
    /// Optional signing and signature verification
    Sign {
        #[command(subcommand)]
        action: SignAction,
    },
    /// Your Vela identity: set up a key once, then publish/accept/propose
    /// with no `--key`/`--actor`/`--hub` flags. `vela id create` is the
    /// one-time onboarding step.
    Id {
        #[command(subcommand)]
        action: IdAction,
    },
    /// Push a frontier's current state to the hub. The one verb to share
    /// your work: owner, key, and hub come from your `vela id` profile, so
    /// the common path is just `vela publish <frontier>`. A full,
    /// idempotent publish (it replaces the hub's view), so it always
    /// succeeds regardless of how the hub's log diverged.
    ///
    /// `vela push` is the git-style alias: clone -> reproduce -> propose ->
    /// push is the producer loop, with `clone` and `push` as its bookends.
    #[command(visible_alias = "push")]
    Publish {
        /// Path to the frontier (`.vela/` repo or frontier.json).
        frontier: PathBuf,
        /// Hub base URL. Optional: defaults to your configured identity's hub.
        #[arg(long)]
        to: Option<String>,
        /// Optional SPDX license identifier for the registry entry.
        #[arg(long)]
        license: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Clone a published frontier from a hub into a fresh working `.vela/`
    /// tree — the git-style pull. Reconstructs everything `vela reproduce`
    /// needs (events, objects, witnesses, proof, lock) and verifies it
    /// byte-for-byte against the publisher's signed hashes. Unlike
    /// `registry pull` (which writes a single snapshot/export file), the
    /// result is a working frontier you can reproduce, extend, and re-push.
    Clone {
        /// The frontier to clone: a `vfr_…` id, or a hub URL containing it
        /// (e.g. https://hub.constellate.science/entries/vfr_…).
        target: String,
        /// Destination directory (created if absent). Defaults to the vfr id.
        dest: Option<PathBuf>,
        /// Hub/registry to clone from. Defaults to your configured hub.
        #[arg(long)]
        from: Option<String>,
        /// Read artifact blobs from a local content-addressed mirror
        /// (`<dir>/<hash>` or `<dir>/sha256/<hash>`) instead of the hub blob
        /// tier. Used by the offline round-trip conformance pin.
        #[arg(long)]
        blobs_from: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// The workspace registry: which frontiers you have checked out and the
    /// hub remote each tracks (a git-style "list of working copies"). The
    /// conformance gate reads it instead of a hardcoded frontier list.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Manage the frontier's registered actor identities (Phase M, v0.4)
    Actor {
        #[command(subcommand)]
        action: ActorAction,
    },
    /// Manage frontier-level metadata: cross-frontier dependencies (v0.8).
    /// Use `vela frontier add-dep` to declare a remote frontier this
    /// frontier links into via `vf_…@vfr_…` references.
    Frontier {
        #[command(subcommand)]
        action: FrontierAction,
    },
    /// Walk the local serve draft queue:
    /// list, sign-and-apply, or clear queued review actions
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
    /// Publish, list, or pull frontiers through a registry
    /// (Phase S, v0.5: verifiable distribution)
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },
    /// Initialize a .vela frontier repo
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value = "unnamed")]
        name: String,
        #[arg(long, default_value = "default")]
        template: String,
        #[arg(long)]
        no_git: bool,
        #[arg(long)]
        json: bool,
    },
    /// Compare two frontiers, or preview one pending proposal
    /// against the current frontier.
    ///
    /// v0.74: when the first positional arg starts with `vpr_`,
    /// route to the existing `proposals preview` path so a single
    /// `vela diff <proposal_id>` shows the proposal-vs-frontier
    /// delta the README quotes. The two-arg form
    /// (`vela diff <frontier_a> <frontier_b>`) keeps its existing
    /// behavior.
    Diff {
        /// Frontier path A, a `vpr_*` proposal id for preview
        /// mode, or a `vfr_*` registry id (v0.140) resolved via
        /// the registry into a pulled snapshot before diffing.
        target: String,
        /// Frontier path B for two-frontier compare. Accepts a
        /// filesystem path or a `vfr_*` registry id (v0.140). Omit
        /// when `target` is a proposal id.
        frontier_b: Option<String>,
        /// Frontier root for proposal-preview mode. Defaults to
        /// `.` if the first positional is a proposal id and no
        /// `--frontier` flag is provided.
        #[arg(long)]
        frontier: Option<PathBuf>,
        /// Reviewer attribution for the proposal-preview mode.
        #[arg(long, default_value = "reviewer:preview")]
        reviewer: String,
        /// v0.140: registry locator to resolve `vfr_*` ids
        /// against. Accepts a hub URL (`https://...`) or a local
        /// registry path. Defaults to `~/.vela/registry/entries.json`.
        /// Only consulted when `target` or `frontier_b` starts
        /// with `vfr_`.
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quiet: bool,
    },
    /// Inspect or apply proposal-first frontier writes
    Proposals {
        #[command(subcommand)]
        action: ProposalAction,
    },
    /// v0.164: anchor Lean theorems to their content-addressed
    /// source bytes. Walks the substrate's theorem registry
    /// (T1-T19 by v0.166) and emits a `vla_*` anchor per
    /// theorem pinning (id, module path, decl, module sha256).
    /// Structural — does not run lake build.
    Lean {
        #[command(subcommand)]
        action: LeanAction,
    },
    /// Verify banked attempts (`vat_`): id re-derivation + Ed25519
    /// signature + claim_digest, exactly as the reducer does on deposit.
    Attempt {
        #[command(subcommand)]
        action: AttemptAction,
    },
    /// Verify cross-domain transfers (`vtr_`): id re-derivation + Ed25519
    /// signature, exactly as the reducer does on deposit. Admission (whether
    /// the link is sound) is a separate read-time derivation over project state.
    Transfer {
        #[command(subcommand)]
        action: TransferAction,
    },
    /// Manage finding bundles as the core frontier primitive
    Finding {
        #[command(subcommand)]
        command: FindingCommands,
    },
    /// Show state-transition history for one finding
    History {
        frontier: PathBuf,
        finding_id: String,
        #[arg(long)]
        json: bool,
        /// v0.55: time-travel replay — show only events at-or-before
        /// this RFC3339 timestamp, and report the confidence score
        /// the finding had at that moment (last revision <= cutoff).
        #[arg(long, value_name = "RFC3339_TIMESTAMP")]
        as_of: Option<String>,
    },
    // v0.74: top-level alias verbs. Each variant is a thin wrapper
    // routing to an existing canonical-event emission path. No new
    // substrate logic. The aliases exist so the daily flow reads
    // `init / ingest / propose / diff / accept / attest / log /
    // lineage / serve` rather than burying the verbs under
    // `proposals accept`, `sign apply`, `history`. See plan
    // v0.74.1.
    /// v0.74: ingest a single file or folder, dispatching by
    /// extension to the right backing path. Aliases:
    ///   `.pdf` or folder of pdfs -> `scout`
    ///   `.md` or folder of notes -> `compile-notes`
    ///   `.csv` / `.tsv`          -> `compile-data`
    ///   `.json` (Carina packet)  -> `artifact-to-state`
    ///   `doi:` / `pmid:` / `nct:` URI -> `source-fetch`
    ///   repo dir                 -> `compile-code`
    Ingest {
        /// File path or folder to ingest. Also accepts a stable
        /// identifier URI (`doi:<doi>`, `pmid:<id>`, `nct:<id>`).
        path: String,
        /// Frontier file or `.vela/` repo the proposals or sources
        /// land in.
        #[arg(long)]
        frontier: PathBuf,
        /// LLM backend override for agent-driven paths
        /// (scout/compile-*). Ignored for source-fetch and
        /// artifact-to-state.
        #[arg(short, long)]
        backend: Option<String>,
        /// Actor recording the ingest. Required for
        /// artifact-to-state; defaults to
        /// `agent:vela-ingest-bot` for agent paths.
        #[arg(long)]
        actor: Option<String>,
        /// Preview without writing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },

    /// v0.74: shortcut for the most common reviewer proposal, a
    /// `finding.review` verdict. Mirrors `vela review`. Other
    /// proposal kinds (note, caveat, revise, reject, retract)
    /// keep their existing top-level verbs and stay reachable via
    /// `vela help advanced`.
    Propose {
        frontier: PathBuf,
        finding_id: String,
        /// One of: accepted | needs_revision | contested | rejected.
        #[arg(long)]
        status: String,
        /// Decision note. Optional: defaults to "marked <status>".
        #[arg(long)]
        reason: Option<String>,
        /// Reviewer actor id. Optional: defaults to your configured identity.
        #[arg(long)]
        reviewer: Option<String>,
        /// Apply the proposal immediately under reviewer authority
        /// (writes a signed canonical event).
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },

    /// v0.74: alias for `proposals accept`. Apply a pending
    /// proposal under the configured reviewer id, emitting the
    /// signed canonical event.
    Accept {
        frontier: PathBuf,
        proposal_id: String,
        /// Reviewer actor id. Optional: defaults to your configured
        /// identity (`vela id create`).
        #[arg(long)]
        reviewer: Option<String>,
        /// Decision note recorded in the signed event. Optional: defaults to
        /// "accepted via review". Key custody, not the note, is the authority.
        #[arg(long)]
        reason: Option<String>,
        /// Path to the reviewer's Ed25519 private key (hex seed). Optional:
        /// defaults to your configured identity's key. Key custody, not the
        /// typed name, is the accept authority; the event is signed with it.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Engine strict mode: also block when the acceptance introduces
        /// new review warnings, not only release-blocking regressions.
        #[arg(long)]
        strict: bool,
        /// Override the Engine gate. The override is recorded in the
        /// proposal's decision reason so it stays auditable.
        #[arg(long)]
        force: bool,
        /// After applying the accept locally, also deliver the signed
        /// acceptance to the hub (the same human signature, under key custody).
        /// Best-effort: a hub failure never unwinds the local accept. Resolves
        /// the hub from your `vela id` profile unless `--to` overrides it.
        #[arg(long)]
        push: bool,
        /// Hub URL to deliver the accept to (implies `--push`).
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Land a result in one step (the producer happy path, like `git push`):
    /// accept a pending proposal under your configured identity, with zero hex.
    /// `target` is either a `vpr_` proposal id (accepted directly) or a `vf_`
    /// finding id (its pending `finding.add` proposal is found and accepted).
    /// Key custody — running this IS the human accept; an agent must not.
    Land {
        frontier: PathBuf,
        /// A `vpr_` proposal id or a `vf_` finding id to land.
        target: String,
        /// Decision note. Optional: defaults to "landed via review".
        #[arg(long)]
        reason: Option<String>,
        /// Reviewer actor id. Optional: defaults to your configured identity.
        #[arg(long)]
        reviewer: Option<String>,
        /// Reviewer key path. Optional: defaults to your configured identity's key.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },

    /// Bind a verifier attachment to a finding (propose → accept in one step).
    /// Reads a `vela.verifier_attachment.v0.1` JSON object (whose `target` is the
    /// finding's `vf_…` id) and lands it via the canonical `verifier.attach`
    /// proposal→accept path. The finding's trust-gate status is derived on read.
    #[command(hide = true)]
    Attach {
        frontier: PathBuf,
        /// The finding (`vf_…`) the attachment binds to.
        #[arg(long)]
        target: String,
        /// Path to a JSON file holding the VerifierAttachment object.
        #[arg(long)]
        attachment_file: PathBuf,
        /// Reviewer authority applying the attachment (e.g. `reviewer:opus`).
        /// Optional: defaults to your `vela id`.
        #[arg(long)]
        reviewer: Option<String>,
        #[arg(long, default_value = "bind verifier attachment")]
        reason: String,
        #[arg(long)]
        json: bool,
    },

    /// Emit shell completions for bash, zsh, or fish.
    Completions {
        /// bash | zsh | fish
        shell: String,
    },

    /// Lease an open obligation so other producers route around it.
    /// Signed event; one live lease per obligation; expiry = claimed_at
    /// + ttl, computed at read time.
    Claim {
        frontier: PathBuf,
        /// The obligation finding (`vf_…`) being claimed.
        obligation: String,
        #[arg(long, default_value_t = 86400)]
        ttl: u64,
        /// Claiming actor (agent:… or reviewer:…). Optional: defaults to
        /// your configured identity (`vela id`).
        #[arg(long = "reviewer")]
        by: Option<String>,
        /// Path to the claimant's Ed25519 private key. Optional: defaults to
        /// your configured identity's key.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },

    /// Accept a batch of proposals in one load → apply-all → save pass.
    ///
    /// The scale-capable accept path: the single `accept` reloads, re-runs
    /// Evidence CI, and re-serializes the whole frontier per proposal —
    /// O(N²) for N accepts. This loads once, runs CI once before and once
    /// after, applies every selected proposal in memory, gates on the
    /// *aggregate* delta, and saves once. The batch is all-or-nothing at
    /// the Engine gate (use `--force` to override), and `--dry-run`
    /// previews the verdict with zero on-disk effect.
    ///
    /// This is the reviewer's batch path: `vela accept-batch <frontier>
    /// --all-pending` accepts every pending proposal in one signed pass and
    /// reconciles derived views, instead of a per-proposal loop.
    AcceptBatch {
        frontier: PathBuf,
        /// Accept every `pending_review` proposal in the frontier.
        #[arg(long)]
        all_pending: bool,
        /// Explicit proposal id to accept (repeatable). Combined with
        /// `--all-pending` if both are given.
        #[arg(long = "id")]
        ids: Vec<String>,
        /// Restrict the selection to proposals of this kind (repeatable),
        /// e.g. `--kind finding.add`. Applies to `--all-pending`.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        /// Cap the number accepted (0 = no cap). Useful for staged rollout.
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// Reviewer actor id. Optional: defaults to your configured identity
        /// (`vela id create`).
        #[arg(long)]
        reviewer: Option<String>,
        #[arg(long)]
        reason: String,
        /// Engine strict mode: also block on new review warnings.
        #[arg(long)]
        strict: bool,
        /// Override the Engine gate for the whole batch (audited per
        /// proposal).
        #[arg(long)]
        force: bool,
        /// Preview only: run the gate and report, persist nothing.
        #[arg(long)]
        dry_run: bool,
        /// Skip the post-accept `frontier materialize` reconcile (derived
        /// views are left to a later materialize/gate run).
        #[arg(long)]
        no_reconcile: bool,
        #[arg(long)]
        json: bool,
    },

    /// v0.74: alias for `sign apply`. Sign every unsigned finding
    /// in the frontier under the supplied private key.
    ///
    /// v0.80: extended with `--event <vev_id>` for per-event
    /// attestation. When `--event` is supplied, instead of signing
    /// findings frontier-wide, the substrate emits an
    /// `attestation.recorded` canonical event pointing at the
    /// target event id. Useful for layered attestation
    /// (e.g. a second reviewer countersigning a finding.reviewed
    /// event, or a Lean run attesting a Stupp-protocol claim by
    /// pointing at its accept event).
    Attest {
        /// Frontier path. Required.
        frontier: PathBuf,
        /// Role-scoped target id (`vev_*`, `vsd_*`, `vrp_*`, or `vpf_*`).
        /// When present, writes a local scientific attestation record.
        target_id: Option<String>,
        /// Role-scoped attestation scope. Repeatable.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Local reviewer id, for example `reviewer:will-blair`.
        #[arg(long)]
        reviewer: Option<String>,
        /// Reviewer role for this attestation, such as `domain_reviewer`.
        #[arg(long)]
        role: Option<String>,
        /// Bounded reason for the attestation.
        #[arg(long)]
        reason: Option<String>,
        /// Optional ORCID for the reviewer.
        #[arg(long)]
        orcid: Option<String>,
        /// Optional ROR affiliation.
        #[arg(long)]
        ror: Option<String>,
        /// Per-event mode: target event id (`vev_*`).
        /// When omitted, runs the v0.74 frontier-wide
        /// `sign apply` path.
        #[arg(long)]
        event: Option<String>,
        /// Reviewer attester id (`reviewer:<name>` or
        /// `agent:<name>`). Required for per-event mode.
        #[arg(long)]
        attester: Option<String>,
        /// Scope note explaining what this attestation covers.
        /// Required for per-event mode.
        #[arg(long)]
        scope_note: Option<String>,
        /// Optional Carina Proof primitive id (`vpf_*`) the
        /// attestation is backed by.
        #[arg(long)]
        proof_id: Option<String>,
        /// Optional Ed25519 signature over the target event's
        /// canonical preimage. Future-cycle work to verify; today
        /// the substrate stores the signature and trusts the
        /// emitter's keypair.
        #[arg(long)]
        signature: Option<String>,
        /// v0.74 frontier-wide path: private key for `sign apply`.
        /// Ignored in per-event mode.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum IdAction {
    /// One-time setup: generate a key, store it, and remember your actor id
    /// and default hub. After this, `vela publish` / `vela accept` /
    /// `vela propose` need no `--key`/`--actor`/`--hub` flags.
    Create {
        /// Your handle, e.g. `alice`. Becomes `reviewer:alice` (or
        /// `agent:alice` with --agent). Defaults to `$USER`.
        #[arg(long)]
        handle: Option<String>,
        /// Register as an agent identity (`agent:<handle>`) instead of a
        /// human reviewer.
        #[arg(long)]
        agent: bool,
        /// Default hub base URL for publish/propose/verify.
        #[arg(long)]
        hub: Option<String>,
        /// Overwrite an existing identity.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show the current identity (actor id, public key, key path, hub).
    /// Aliased as `vela whoami`.
    #[command(alias = "whoami")]
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Adopt an existing private key as your identity (e.g. one a
    /// teammate generated, or a key you already use elsewhere).
    Import {
        /// Path to the existing Ed25519 private key (hex seed).
        #[arg(long)]
        key: PathBuf,
        /// Your handle, e.g. `alice`. Defaults to `$USER`.
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        agent: bool,
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SignAction {
    /// Generate an Ed25519 keypair
    GenerateKeypair {
        #[arg(long, default_value = ".vela/keys")]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Sign unsigned findings in a frontier
    Apply {
        frontier: PathBuf,
        /// Path to the Ed25519 private key.
        #[arg(long = "key")]
        private_key: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify frontier signatures
    Verify {
        frontier: PathBuf,
        #[arg(long)]
        public_key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// v0.37: Attach a multi-signature threshold to a finding. Once
    /// `k` distinct registered actors have each signed the finding, it
    /// is marked `jointly_accepted`. Setting `--to 1` is equivalent to
    /// the default single-sig regime.
    ThresholdSet {
        frontier: PathBuf,
        /// Target finding id (`vf_<hash>`).
        finding_id: String,
        /// Number of unique valid signatures required (>= 1).
        #[arg(long)]
        to: u32,
        #[arg(long)]
        json: bool,
    },
}

/// `vela experiment` — experiment-plane receipts (Inevitability Program Phase 0).
#[derive(Subcommand)]
pub(crate) enum ExperimentAction {
    /// Assemble a content-addressed run-manifest over an experiment's `vac_`
    /// activity turns (ordered, immutable, complete) so a run can be replayed and
    /// no turn can be silently dropped.
    Manifest {
        /// Frontier directory whose `activity/` holds the run's `vac_` envelopes.
        frontier: PathBuf,
        /// Experiment id; filters turns tagged `experiment:<id>`. Use `*` for all.
        #[arg(long, default_value = "*")]
        experiment: String,
        /// Optional path to write the manifest JSON.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Project the discharge status of a typed cohort (open / discharged /
    /// blocked) over the frontier's accepted findings — mechanical, not asserted.
    Status {
        /// Cohort JSON: an array of obligations, or `{ "obligations": [...] }`.
        cohort: PathBuf,
        /// Frontier directory whose accepted findings discharge obligations.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Author a content-addressed (`vxo_`) cohort obligation from its fields.
    Obligation {
        /// Cohort id this obligation belongs to.
        #[arg(long)]
        cohort: String,
        /// The `vf_` finding id whose acceptance discharges this obligation.
        #[arg(long)]
        target: String,
        /// The exact statement (pins `statement_digest`).
        #[arg(long)]
        statement: String,
        /// Prior accepted judgment ids this obligation depends on (repeatable).
        #[arg(long = "dep")]
        deps: Vec<String>,
        /// How discharge is checked: `lean_kernel` | `vela_verify` | other.
        #[arg(long, default_value = "lean_kernel")]
        discharge_kind: String,
        #[arg(long)]
        json: bool,
    },
}

/// `vela foundry` — one unattended compounding turn over the de-human-gate.
#[derive(Subcommand)]
pub(crate) enum FoundryAction {
    /// Run one turn: produce a candidate (campaign), register its witness, and
    /// run the exact-lane auto-admit. Dry-run by default; `--apply` records the
    /// `policy.auto_admitted` admission when the gate says YES.
    Run {
        /// Frontier directory (e.g. `examples/sidon-sets`).
        frontier: PathBuf,
        /// Witness kind: `sidon`, `golomb`, `cap`, `bh`, …
        #[arg(long)]
        kind: String,
        /// The ambient size parameter `n`.
        #[arg(long)]
        n: usize,
        /// For `bh` witnesses, the order `h`.
        #[arg(long, default_value_t = 2)]
        h: usize,
        /// Secondary order parameter `k` (e.g. `diff_triangle` within-row order J
        /// for a HorizonMath DTS(n,k) target, or `covering`'s block size). Passed
        /// to the campaign only when non-zero.
        #[arg(long, default_value_t = 0)]
        k: usize,
        /// Search restarts.
        #[arg(long, default_value_t = 200)]
        restarts: u64,
        /// Search seed.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Portfolio size: scan this many consecutive seeds (a diverse-search
        /// portfolio), keep the best-scoring, and propose only that one.
        #[arg(long, default_value_t = 1)]
        seeds: u64,
        /// Gate the turn on the continuous ablation: fail (exit 1) if inherited
        /// frontier state does NOT make this kind compound (treatment <= control).
        #[arg(long)]
        run_ablation: bool,
        /// Record the admission (else dry-run preview the whole turn).
        #[arg(long)]
        apply: bool,
        /// Re-run even if this exact (kind, n, seed, restarts) cell is already in
        /// the attempt ledger. By default the foundry skips a banked cell
        /// (failed-route reuse: don't re-search what a prior turn already did).
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// The foundry's work-list: the attackable target portfolio with its
    /// value-to-beat, read from a substrate-native catalog (the HorizonMath
    /// verifier-attackable subset by default) and cross-referenced against the
    /// live per-family records (e.g. `frontiers/sidon-sets/bounds.json`) so the
    /// gap between the current accepted best and the value-to-beat is legible.
    /// This is what `foundry run` selects from; replaces the web/script JSON
    /// (cohort.json, erdos-wedge.json) as the foundry's portfolio source.
    Targets {
        /// Target catalog (a `HorizonMathCatalog`-shaped JSON with a `problems`
        /// array of `{id, verifier_kind, params, incumbent, status}`).
        #[arg(long, default_value = "frontiers/horizonmath/catalog.json")]
        catalog: PathBuf,
        /// Directory holding live per-family records files (the accepted-best
        /// model, `bounds.json` template). Read to show the current accepted
        /// best against each value-to-beat.
        #[arg(long, default_value = "frontiers")]
        records: PathBuf,
        /// Only show targets a `vela campaign` kind can attack (an engine kind).
        #[arg(long)]
        attackable_only: bool,
        /// Optional typed Erdős bounds sidecar (`examples/erdos-problems/bounds.json`,
        /// the `vela.frontier-bounds.v1` doc emitted by the erdos-deep adapter).
        /// When present, each problem's typed current-best bound is surfaced as a
        /// `value_to_beat` row in the portfolio, so the foundry / attack ranking
        /// sees the Erdős value-to-beat alongside the catalog's incumbents.
        #[arg(long)]
        erdos_bounds: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// The continuous-ablation heartbeat (the plan's hard gate): does inherited
    /// frontier state make the next solver go farther per unit compute? At a
    /// FIXED budget, treatment concentrates it on the boundary (skip-known-work,
    /// enabled by inheriting the frontier's solved targets); control spreads the
    /// same budget across the range it must rediscover. Reports treatment vs
    /// control boundary-success over N seeds; exits 1 if inheritance does not
    /// beat control (so a foundry run can gate on it).
    Ablate {
        /// Frontier directory (its solved targets are the inherited state).
        frontier: PathBuf,
        /// Witness kind to ablate (`sidon`, `golomb`, …).
        #[arg(long)]
        kind: String,
        /// Optional per-family records catalog (`records/<family>.json` or
        /// `bounds.json`): the inherited-state count is read from its accepted,
        /// reproduce-backed bounds instead of the frontier's accepted findings.
        /// Lets the compounding measurement run on a family WITHOUT a key-custody
        /// accept ceremony (the records are already frozen-verified).
        #[arg(long)]
        records: Option<PathBuf>,
        /// The boundary target `n` (the frontier edge being attacked).
        #[arg(long)]
        n: usize,
        /// For `bh`: order `h`.
        #[arg(long, default_value_t = 2)]
        h: usize,
        /// The fixed total search budget (restarts) each arm gets.
        #[arg(long, default_value_t = 200)]
        budget: u64,
        /// Number of seeds to average over.
        #[arg(long, default_value_t = 5)]
        seeds: u64,
        #[arg(long)]
        json: bool,
    },
    /// The prover-in-the-loop work-list: open Lean obligations in a
    /// formal-conjectures corpus, ranked by tractability. Known proved lemmas
    /// compose into proofs of open theorems; this surfaces the tractable
    /// formalization-gap targets (sorry-carrying / `@[category research open]`
    /// decls) the prove loop attacks. Read-only.
    LeanTargets {
        /// The formal-conjectures (or other Lean) corpus root, e.g.
        /// `/Users/.../formal-conjectures`.
        #[arg(long)]
        lean_dir: PathBuf,
        /// Restrict to a sub-path under the corpus (default: the Erdős problems).
        #[arg(long, default_value = "FormalConjectures/ErdosProblems")]
        subdir: String,
        /// Show every open decl, including the headline research-open problems
        /// that are not expected to be subagent-closable (off by default).
        #[arg(long)]
        all: bool,
        /// Cap the number of targets emitted.
        #[arg(long, default_value_t = 40)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// The non-AI verifier half of the prove loop: given a Lean proof already
    /// written into the corpus (the AI producer's output), build it, classify
    /// the target decl's axioms (`#print axioms`, fail-closed on `sorryAx`),
    /// anchor + mint a signed `vlv_`, and — when a frontier is given — draft a
    /// PENDING `verifier.attach`. STOPS there: the truth-bearing accept is a
    /// human key-custody decision (the Lean lane never auto-admits). The Lean
    /// kernel is the trust; the proof's producer is never in the trust path.
    LeanRun {
        /// The Lean corpus root (e.g. the formal-conjectures clone). Its
        /// `lean-toolchain` / `lake-manifest.json` pin the `vlv_`'s provenance.
        #[arg(long)]
        lean_dir: PathBuf,
        /// Module path relative to `--lean-dir`, e.g.
        /// `FormalConjectures/ErdosProblems/828.lean`.
        #[arg(long)]
        module: String,
        /// Fully-qualified decl name for `#print axioms`, e.g.
        /// `Erdos828.erdos_828`.
        #[arg(long)]
        decl: String,
        /// Optional Vela frontier to draft the `verifier.attach` into.
        #[arg(long)]
        frontier: Option<PathBuf>,
        /// The open finding this proof closes (required with `--frontier`).
        #[arg(long)]
        finding: Option<String>,
        /// Reviewer/actor (an `agent:` actor drafts PENDING; a human applies).
        #[arg(long, default_value = "agent:vela-foundry-lean")]
        reviewer: String,
        /// Verifier identity stamped on the `vlv_` (a machine key, not a human).
        #[arg(long, default_value = "agent:vela-foundry-lean")]
        actor: String,
        /// Signing key for the `vlv_` (the verifier's machine key). Resolved
        /// from managed identity when omitted.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Where to write the `vla_`/`vlv_` artifacts (default: alongside the
        /// frontier under `lean/`, else the current dir).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// The decisive lemma-inheritance measurement (the memo's "Compounding B"):
    /// do accepted Lean lemmas widen the closable boundary? Treatment counts the
    /// open targets that are one-premise-away WITH the inherited lemmas present;
    /// control demotes those lemmas to Open. Δ>0 means inherited verified state
    /// makes the next proof reachable — the formal analogue of skip-known-work.
    LeanAblate {
        /// Frontier directory with Lean findings + inter-problem premise edges.
        frontier: PathBuf,
        /// Explicit inherited-lemma finding ids (comma-separated). Default: every
        /// finding whose assertion_type marks a Lean formalization.
        #[arg(long)]
        lemmas: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Project the typed current-best bounds (value-to-beat) from the erdos-deep
    /// source into a `vela.frontier-bounds.v1` sidecar. ADDITIVE — it reads the
    /// staged source the erdos adapter already ingests and writes a NEW
    /// `bounds.json`; it never touches accepted findings or the frontier
    /// canonical root, so `vela reproduce` is unaffected. Every bound is
    /// unattested (`accepted: false`). Deterministic. `foundry targets
    /// --erdos-bounds <out>` then reads it back as value-to-beat rows.
    ErdosBounds {
        /// The staged erdos-deep source (the `read_erdos_deep` adapter input).
        #[arg(
            long,
            default_value = "examples/erdos-problems/sources/erdos-deep.v1.json"
        )]
        input: PathBuf,
        /// Where to write the typed bounds sidecar.
        #[arg(long, default_value = "examples/erdos-problems/bounds.json")]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

/// `vela campaign` — the discovery engine over verifier-gated constructions.
#[derive(Subcommand)]
pub(crate) enum CampaignAction {
    /// Run the engine and report the best verified construction found. Writes
    /// nothing. `--kind` is a verifier kind: gf2_sidon, union_free,
    /// rook_directions, cap, constant_weight (with `--d`/`--w`), covering (with
    /// `--k`/`--t`), sidon, bh (with `--h`), golomb, costas, diff_triangle
    /// (with `--k` as the within-row order J; HorizonMath DTS(I,J) targets).
    Search {
        /// Verifier kind to search.
        kind: String,
        /// Target parameter n (set size domain / order / ground set, kind-dependent).
        #[arg(long)]
        n: usize,
        /// For `bh`: the order h (h=2 is Sidon). Ignored by other kinds.
        #[arg(long, default_value_t = 2)]
        h: usize,
        /// For `constant_weight`: minimum Hamming distance d.
        #[arg(long, default_value_t = 0)]
        d: usize,
        /// For `constant_weight`: codeword weight w.
        #[arg(long, default_value_t = 0)]
        w: usize,
        /// For `covering`: block size k.
        #[arg(long, default_value_t = 0)]
        k: usize,
        /// For `covering`: cover every t-subset.
        #[arg(long, default_value_t = 0)]
        t: usize,
        /// Number of randomized restarts (the work budget).
        #[arg(long, default_value_t = 200)]
        restarts: u64,
        /// RNG seed; the same seed reproduces the same search.
        #[arg(long, default_value_t = 24221)]
        seed: u64,
        #[arg(long)]
        json: bool,
    },
    /// Search, write the verified witness (so `vela reproduce` covers it), and
    /// optionally land a *pending* `finding.add` proposal (no key — a
    /// key-holder accepts).
    Run {
        /// Verifier kind to search (see `search`).
        kind: String,
        #[arg(long)]
        n: usize,
        #[arg(long, default_value_t = 2)]
        h: usize,
        #[arg(long, default_value_t = 0)]
        d: usize,
        #[arg(long, default_value_t = 0)]
        w: usize,
        #[arg(long, default_value_t = 0)]
        k: usize,
        #[arg(long, default_value_t = 0)]
        t: usize,
        #[arg(long, default_value_t = 200)]
        restarts: u64,
        #[arg(long, default_value_t = 24221)]
        seed: u64,
        /// Witness output path. Defaults to
        /// `<frontier>/witnesses/<kind>-n<N>.witness.json`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Frontier directory (required for `--propose`, or to derive `--out`).
        #[arg(long)]
        frontier: Option<PathBuf>,
        /// Also land a pending `finding.add` proposal for the verified bound.
        #[arg(long)]
        propose: bool,
        /// Reviewer/author identity for the proposal.
        #[arg(long, default_value = "reviewer:will-blair")]
        reviewer: String,
        #[arg(long)]
        json: bool,
    },
}

/// `vela agents` — keep vendor agent-config files generated from `VELA.md`.
#[derive(Subcommand)]
pub(crate) enum AgentsAction {
    /// Regenerate the adapter files from VELA.md (idempotent; writes only
    /// what changed).
    Sync {
        /// Worktree root holding VELA.md (default: current directory).
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Check that the adapters are in sync with VELA.md. Exit 1 on drift or
    /// a missing adapter (use in CI).
    Doctor {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show which adapters would change on the next `sync`.
    Diff {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

/// `vela gate` — the verification gate over a claim.
#[derive(Subcommand)]
pub(crate) enum GateAction {
    /// L5 anti-inflation: require a deliverable grade and block
    /// solve-language unless the grade is an actual solve. Exit 1 on a
    /// gate failure (e.g. an `improved_published_bound` whose claim text
    /// says "resolves #647").
    Grade {
        /// The claim text to lint.
        #[arg(long)]
        claim: String,
        /// The deliverable grade (e.g. `improved_published_bound`,
        /// `unconditional_solve`, `new_oeis_term`). Omit to see the
        /// "grade required" failure.
        #[arg(long)]
        grade: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Derive the verification gate status (G1 independence + G2
    /// claim-match + G3 surviving probe + G4 well-formed) for a claim
    /// from a JSON array of verifier attachments. There is no setter:
    /// the status is computed, never stored. Exit 1 unless the gate
    /// derives `verified`.
    Check {
        /// The exact claim text the attachments must be bound to.
        #[arg(long)]
        claim: String,
        /// Path to a JSON array of `VerifierAttachment` objects.
        #[arg(long)]
        attachments: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print the deliverable-grade taxonomy and verifier-method /
    /// probe-kind vocabularies (the closed sets the gate accepts).
    Vocab {
        #[arg(long)]
        json: bool,
    },
    /// Backfill frozen-verifier attachments. For each witness artifact in the
    /// frontier, re-run the matching frozen verifier (vela-verify) and, on
    /// pass, land a signed `verifier.attach` recording the check
    /// (ComputationalSearch / vela-verify / Sound). Makes the frozen verifier
    /// legible per finding; the gate still needs >=2 independent attachments to
    /// derive `verified`, so this records the check, it does not flip the gate.
    Backfill {
        /// Frontier directory (e.g. `examples/sidon-sets`).
        frontier: PathBuf,
        /// Reviewer authority landing the attachments (e.g.
        /// `reviewer:will-blair`). Optional: defaults to your configured
        /// identity (`vela id`). A signing key is required to apply.
        #[arg(long)]
        reviewer: Option<String>,
        /// Report the plan without writing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Preview the exact-lane auto-admission decision for a finding (Phase 1A,
    /// the de-human-gate). READ-ONLY: it runs the full un-forgeable trust path
    /// over real data — a fresh `vela-verify` re-check of the finding's witness
    /// (reproduce-binding), the frozen `claim_witness_faithful` claim<->witness
    /// binding, and the proposal-level guards + attachment corroboration
    /// predicate — and prints whether the finding WOULD auto-admit to
    /// `machine_verified`, with every guard's verdict. It never writes; the
    /// `policy.auto_admitted` emit is held off pending the acceptance checklist
    /// (see docs/VERIFICATION.md).
    AutoAdmit {
        /// Frontier directory (e.g. `examples/sidon-sets`).
        frontier: PathBuf,
        /// The finding id (`vf_…`) to preview.
        #[arg(long)]
        finding: String,
        /// Record the unsigned `policy.auto_admitted` audit event when (and
        /// only when) the finding WOULD auto-admit. Idempotent: re-running is a
        /// no-op. Never signs, never lands the finding in canonical state. Omit
        /// for a read-only preview.
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ActorAction {
    /// Register an Ed25519 public key for a stable actor identity
    Add {
        frontier: PathBuf,
        /// Stable actor id (e.g. "reviewer:will-blair"). Optional: defaults to
        /// your configured identity (`vela id`).
        id: Option<String>,
        /// Hex-encoded Ed25519 public key (64 hex chars). Optional: defaults to
        /// your configured identity's public key — you should never type it.
        #[arg(long)]
        pubkey: Option<String>,
        /// Optional trust tier (Phase α, v0.6). Currently recognized:
        /// "auto-notes" — permits one-call propose_and_apply_note.
        /// Unknown tier strings load fine but never grant auto-apply.
        #[arg(long)]
        tier: Option<String>,
        /// v0.43: Optional ORCID identifier for cross-system identity.
        /// Format `0000-0000-0000-000X`. Accepts bare form, URL form
        /// (`https://orcid.org/0000-...`), or `orcid:` prefix.
        #[arg(long)]
        orcid: Option<String>,
        /// v0.51: Optional read-side access clearance.
        /// `public` (default), `restricted`, or `classified`. Higher
        /// clearance permits reading lower-tier objects through
        /// `vela serve`'s actor-aware MCP/HTTP read paths.
        #[arg(long)]
        clearance: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List registered actors in a frontier
    List {
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// v0.127: Rotate an actor's signing key. Registers a new actor
    /// record under a versioned id, marks the prior actor as revoked
    /// at the current timestamp, and pins a free-form reason. Closes
    /// THREAT_MODEL.md A7 (compromised reviewer key) by giving
    /// reviewers a primitive for retiring a key without inventing
    /// per-frontier ceremony. Historical signatures under the
    /// retired key remain valid (the substrate does not retroactively
    /// invalidate canonical history); new signatures with the retired
    /// key are flagged as `post_revocation_signature` errors by the
    /// signals layer.
    Rotate {
        frontier: PathBuf,
        /// Existing actor id to retire (e.g. `reviewer:will-blair`).
        /// Must be currently registered and not already revoked.
        #[arg(long)]
        id: String,
        /// New actor id to register (e.g.
        /// `reviewer:will-blair-v2-2026-05-10`). Must not collide
        /// with an existing actor id. Convention: append `-v<N>` or
        /// `-v<N>-<date>` to the prior id.
        #[arg(long = "new-id")]
        new_id: String,
        /// New Ed25519 public key (64 hex chars).
        #[arg(long = "new-pubkey")]
        new_pubkey: String,
        /// Free-form reason recorded against the retired actor's
        /// `revoked_reason` field.
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum LeanAction {
    /// Anchor every theorem in the substrate registry. Writes
    /// one `vla_*` anchor JSON per theorem under <output>/.
    AnchorAll {
        /// Path to the `lean/` directory (defaults to repo root).
        #[arg(long)]
        lean_dir: Option<PathBuf>,
        /// Output directory for anchor JSON files. Defaults to
        /// `./theorems/`.
        #[arg(long, default_value = "./theorems")]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Anchor a single theorem by its id (1..=6 in Arc 6 wave 1).
    Anchor {
        /// Theorem id (e.g. 1 for T1).
        id: u32,
        #[arg(long)]
        lean_dir: Option<PathBuf>,
        /// Output path for the anchor record (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// List the substrate's registered theorems.
    List {
        #[arg(long)]
        json: bool,
    },
    /// v0.170: generate a fresh Ed25519 verifier keypair. Writes
    /// the 32-byte private key (hex) to `--key-out` and the
    /// public-key spec JSON to `--pub-out`.
    Keygen {
        #[arg(long)]
        key_out: PathBuf,
        #[arg(long)]
        pub_out: PathBuf,
        /// Free-form identity to embed in the public-key spec
        /// (e.g. "github-action:constellate-science/vela:verify-lean-bundle").
        #[arg(long)]
        actor: String,
    },
    /// v0.170: sign verification records for every anchor in
    /// `--anchors-dir`. Reads `--build-log` and computes its
    /// sha256 as the verifier_output_hash; the lake build that
    /// produced that log must have completed cleanly.
    VerifyAll {
        /// Directory containing T<N>.anchor.json files (default:
        /// `./theorems`).
        #[arg(long, default_value = "./theorems")]
        anchors_dir: PathBuf,
        /// Output directory for T<N>.vlv.json verification records
        /// (default: same as anchors_dir).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Path to a lake build log file. Its sha256 becomes the
        /// verifier_output_hash; the file content is opaque to
        /// the substrate.
        #[arg(long)]
        build_log: PathBuf,
        /// Path to the Ed25519 private key. Optional: defaults to your
        /// configured identity's key (`vela id`).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Free-form verifier identity (e.g. github-action URL).
        #[arg(long)]
        actor: String,
        /// Lean toolchain pin (e.g. `leanprover/lean4:v4.29.1`).
        /// Defaults to the contents of `lean/lean-toolchain` if
        /// present.
        #[arg(long)]
        lean_toolchain: Option<String>,
        /// Mathlib revision (e.g. `v4.29.1`). Defaults to the
        /// `mathlib4.git` pin in `lean/lakefile.lean`.
        #[arg(long)]
        mathlib_revision: Option<String>,
        /// Path to the per-decl axiom report emitted by `Vela/AxiomAudit.lean`
        /// (lines `AXIOMS <decl> | axiom1, axiom2`). When present, each
        /// theorem's axioms are classified against the TCB policy and the
        /// record status is set accordingly. When absent, records are minted
        /// axiom-unknown (legacy behavior).
        #[arg(long)]
        axioms_report: Option<PathBuf>,
        /// Path to the external kernel re-check log (lean4checker/Lean4Lean).
        /// Presence of the marker `KERNEL_RECHECK_FAILED` marks the re-check
        /// failed; an empty/clean log marks it passed; omitting the flag
        /// marks it not-run.
        #[arg(long)]
        kernel_recheck_log: Option<PathBuf>,
        /// External kernel checker name recorded in the TCB policy
        /// (e.g. `lean4checker`). Defaults to `none`.
        #[arg(long, default_value = "none")]
        kernel_checker: String,
        /// External kernel checker version pin (e.g. `lean4checker@v4.29.1`).
        #[arg(long, default_value = "")]
        kernel_checker_version: String,
        /// Comma-separated allowlist of axioms. Defaults to the three
        /// standard classical axioms.
        #[arg(long)]
        allowed_axioms: Option<String>,
        /// Comma-separated forbidden axioms. Defaults to the standard
        /// compiler-trust / `sorry` set.
        #[arg(long)]
        forbidden_axioms: Option<String>,
        /// Output path for the `vtcb_` policy JSON (default:
        /// `<out_dir>/policy.vtcb.json`).
        #[arg(long)]
        out_tcb: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// v0.170: verify a single `vlv_*` record: signature against
    /// declared pubkey + id derivation + anchor cross-check.
    VerifyCheck {
        record: PathBuf,
        /// Path to the matching T<N>.anchor.json. Confirms the
        /// record's anchor_id + module_sha256 still match.
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Optional path to the `vtcb_` policy JSON. When present,
        /// re-classifies the record's axioms and asserts the stored
        /// `axiom_verdict` and `tcb_id` match.
        #[arg(long)]
        tcb: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum AttemptAction {
    /// Verify a banked attempt file: a single `Attempt` JSON, or a
    /// CanopusAttemptLedger (`{"records": [...]}`, v1 or v2). Each record's
    /// `vat_` id must re-derive, its claim_digest must match, and its Ed25519
    /// signature must verify under the declared pubkey. Unsigned records (no
    /// signature) are reported, not failed.
    Verify {
        /// Path to an Attempt JSON or a ledger with a `records` array.
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List the banked attempts (`vat_`) in a frontier's event log — the
    /// durable inherited memory (every run's outcome, including failures). The
    /// next portfolio reads this to avoid repeating searched routes. Filter by
    /// `--problem`, `--kind`, or `--status`.
    List {
        /// Frontier directory or repo.
        frontier: PathBuf,
        #[arg(long)]
        problem: Option<u32>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TransferAction {
    /// Verify a cross-domain transfer file: a single `Transfer` JSON, or a
    /// `{"records": [...]}` ledger. Each record's `vtr_` id must re-derive and
    /// its Ed25519 signature must verify under the declared pubkey. Unsigned
    /// records are reported, not failed. (This is the structural check; the
    /// T1–T5 admission gate runs in the reducer / `derive_transfer_status`.)
    Verify {
        /// Path to a Transfer JSON or a ledger with a `records` array.
        file: PathBuf,
        /// Re-derive the T1–T5 ADMISSION verdict over real state (the read-time
        /// `derive_transfer_status`), not just the structural signature check.
        /// Resolves A's gate from `--frontier`'s accepted attachments, the
        /// theorem `vlv_` from `--vlv`, and the domain tags.
        #[arg(long)]
        admit: bool,
        /// Source frontier A — its accepted verifier attachments (matching the
        /// transfer's source_claim_digest) resolve A's gate outcome (T1).
        #[arg(long)]
        frontier: Option<PathBuf>,
        /// The transfer theorem's `vlv_` verification file (the LeanHomomorphism
        /// T2 witness). Mint it with `vela foundry lean-run` over the theorem.
        #[arg(long)]
        vlv: Option<PathBuf>,
        /// A's actual domain for the T3 type-match (defaults to the
        /// homomorphism's declared source_type).
        #[arg(long)]
        source_domain: Option<String>,
        /// B's premise domain for the T3 type-match (defaults to the
        /// homomorphism's declared target_type).
        #[arg(long)]
        target_domain: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Mint a signed `vtr_` from a draft JSON (the Transfer body minus
    /// id/signature/signer): source_claim, source_claim_digest, target_claim,
    /// target_premise_digest, homomorphism{...}. Signs with the Ed25519 key
    /// (raw 32-byte hex seed) and writes the content-addressed record.
    Mint {
        /// Path to the draft JSON.
        draft: PathBuf,
        /// Path to the Ed25519 signing key. Optional: defaults to your
        /// configured identity's key (`vela id`).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Where to write the signed `vtr_` record.
        #[arg(long)]
        out: PathBuf,
    },
    /// Index the cross-domain transfers (`vtr_`) into the transfer registry: a
    /// derived, lane-organized view (certified / target-checked / exploratory)
    /// grouped by domain pair, with each link's proof roots and structural check.
    /// Reads `examples/transfers/*.vtr.json` (or `--dir`); a projection, never a
    /// re-verification or an admission decision.
    Registry {
        /// Directory of `*.vtr.json` transfer records (default examples/transfers).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Emit the registry as JSON (for the web export) instead of a summary.
        #[arg(long)]
        json: bool,
        /// Write the JSON registry to a file as well.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FrontierAction {
    /// Scaffold a fresh, publishable `frontier.json` stub. The result
    /// passes `vela check --strict` immediately and is ready to accept
    /// findings via `vela finding add` and a publish via `vela registry
    /// publish`. Use this instead of `vela init` when you intend to
    /// publish to a hub — `init` creates a `.vela/` repo, which is not
    /// directly publishable in v0.
    New {
        /// Path to write the new frontier file (e.g. `./frontier.json`).
        path: PathBuf,
        /// Human-readable frontier name.
        #[arg(long)]
        name: String,
        /// Optional one-paragraph description of the bounded question.
        #[arg(long, default_value = "")]
        description: String,
        /// Overwrite if the file already exists.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Replay a split frontier repository into frontier.json and vela.lock.
    Materialize {
        /// Frontier repository directory.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Declare a cross-frontier dependency. Subsequent links of the
    /// form `vf_<id>@vfr_<id>` resolve through this entry; strict
    /// validation refuses cross-frontier targets without one.
    AddDep {
        /// Path to the frontier file
        frontier: PathBuf,
        /// The remote frontier's content-addressed id (`vfr_…`)
        vfr_id: String,
        /// Where to fetch the remote frontier file from. Typically
        /// an `https://…` URL pointing at raw JSON.
        #[arg(long)]
        locator: String,
        /// SHA-256 of the remote's canonical snapshot. Strict pull
        /// verifies the fetched dependency's snapshot matches this.
        #[arg(long)]
        snapshot: String,
        /// Optional human-readable name for the dependency.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List the frontier's declared dependencies.
    ListDeps {
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// v0.32: emit a structured diff of findings added, updated, and
    /// contradicted in a time window. The canonical replacement for the
    /// `scripts/weekly-diff.sh` Python fallback shipped in v0.31.
    ///
    /// Default window is the current ISO week (Monday 00:00 UTC →
    /// next Monday 00:00 UTC). Use `--since <RFC3339>` for an arbitrary
    /// start, or `--week YYYY-Www` for a specific ISO week.
    ///
    /// Output is JSON if `--json` is set; otherwise a human summary.
    /// The diff is read-only over the canonical state — it does not
    /// modify the frontier and does not require a signing key.
    Diff {
        /// Path to the frontier (project dir, `.vela/` repo, or `.json` file).
        frontier: PathBuf,
        /// Compute diff since this RFC 3339 timestamp.
        /// Mutually exclusive with `--week`.
        #[arg(long)]
        since: Option<String>,
        /// Compute diff for a specific ISO week (e.g. `2026-W18`).
        /// If absent and no `--since`, defaults to the current ISO week.
        #[arg(long)]
        week: Option<String>,
        /// Emit JSON to stdout.
        #[arg(long)]
        json: bool,
    },
    /// v0.158: tag the current frontier state as a versioned
    /// release. Writes a content-addressed `vfrr_*` record to
    /// `<frontier-dir>/.vela/releases/<vfrr_*>.json`. Releases
    /// are immutable; the substrate-side equivalent of a paper
    /// edition or software version tag.
    Release {
        /// Frontier path.
        frontier: PathBuf,
        /// Human-readable release name (e.g. `v1.0`, `2026-Q2`,
        /// `pre-print`). Required, non-empty.
        #[arg(long)]
        name: String,
        /// Optional release notes (changelog, scope, attribution).
        #[arg(long)]
        notes: Option<String>,
        /// Optional previous release id to chain. When omitted,
        /// the substrate looks up the latest release in
        /// `<frontier-dir>/.vela/releases/` and chains there.
        #[arg(long)]
        previous: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// v0.158: list every release recorded for a frontier.
    Releases {
        /// Frontier path.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Audit readiness across strict check, proof, Evidence CI,
    /// health, stats, and review-work queues.
    Audit {
        /// Frontier repo directory or frontier JSON file.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum QueueAction {
    /// List queued draft actions (no signing)
    List {
        #[arg(long)]
        queue_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Sign each queued draft with the actor's Ed25519 key and apply
    /// it locally. Removes signed entries from the queue on success.
    Sign {
        /// Stable actor id matching a registered entry in the frontier.
        /// Optional: defaults to your configured identity (`vela id`).
        #[arg(long)]
        actor: Option<String>,
        /// Path to the actor's Ed25519 private key. Optional: defaults to
        /// your configured identity's key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Override the queue file location
        #[arg(long)]
        queue_file: Option<PathBuf>,
        /// Skip per-action confirmation prompts and sign every queued
        /// draft. Required in non-interactive contexts.
        #[arg(long)]
        yes_to_all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Drop all queued draft actions
    Clear {
        #[arg(long)]
        queue_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum WorkspaceAction {
    /// List the frontiers in the workspace registry (and their hub remotes).
    List {
        /// Read a specific workspace file instead of the default
        /// (`$VELA_WORKSPACE`, else `~/.vela/workspace.json`).
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Record a checked-out frontier and the hub it tracks. Upserts by path
    /// (re-adding the same path updates it in place). Resolves the `vfr_…`
    /// id from the frontier on disk.
    Add {
        /// Path to the frontier (`.vela/` repo or frontier.json).
        frontier: PathBuf,
        /// The hub this frontier pushes to / pulls from.
        #[arg(long)]
        remote: Option<String>,
        /// Human-friendly name (defaults to the frontier's project name).
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Drop a frontier from the workspace registry (by path).
    Remove {
        /// Path key to remove (as recorded by `add`).
        frontier: String,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum RegistryAction {
    /// Deprecate a published frontier on a hub: an owner-signed,
    /// append-only lifecycle event. The entry vanishes from /entries and
    /// /search but stays auditable at /entries/{vfr}/status — never a
    /// silent deletion. Only the owner key that published the entry can
    /// deprecate it (the re-publish continuity rule).
    Deprecate {
        /// The frontier to deprecate (vfr_…)
        vfr_id: String,
        /// Hub base URL (e.g. https://hub.constellate.science)
        #[arg(long)]
        to: String,
        /// Path to the owner's Ed25519 private key. Optional: defaults to
        /// your configured identity's key (`vela id`).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Why this frontier is retired (recorded in the signed receipt)
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Rotate a published frontier's owner key on a hub. Signed by the
    /// CURRENT effective owner; the named successor key becomes the one
    /// every owner check accepts (re-publish, deprecate, next rotation).
    RotateOwner {
        /// The frontier (vfr_…)
        vfr_id: String,
        /// Hub base URL
        #[arg(long)]
        to: String,
        /// Path to the CURRENT owner's Ed25519 private key. Optional:
        /// defaults to your configured identity's key (`vela id`).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Path to the successor PUBLIC key (hex), or the 64-char hex itself
        #[arg(long)]
        new_owner: String,
        /// Why the key is rotating (recorded in the signed receipt)
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Manage a frontier's maintainer set on a hub (signed add/remove;
    /// authority = effective owner or a current maintainer).
    Maintainer {
        /// add | remove | list
        action: String,
        vfr_id: String,
        #[arg(long)]
        to: String,
        /// The maintainer's PUBLIC key (hex or path) for add/remove.
        #[arg(long)]
        maintainer: Option<String>,
        /// Path to the AUTHORIZING private key (owner or maintainer).
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, default_value = "maintainer-set update")]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// List all entries in a local registry
    List {
        /// Path or file:// URL of the registry; defaults to ~/.vela/registry/entries.json
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Publish a frontier's current snapshot+event_log hashes to a registry
    Publish {
        /// Path to the frontier file
        frontier: PathBuf,
        /// Stable owner actor id (must be registered in the frontier).
        /// Optional: defaults to your configured identity.
        #[arg(long)]
        owner: Option<String>,
        /// Path to the owner's Ed25519 private key. Optional: defaults to
        /// your configured identity's key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Network locator under which the frontier is reachable
        /// (file:// path or HTTP URL the publisher serves). Optional
        /// since v0.55: when publishing to an HTTP hub, the hub's own
        /// `/entries/<vfr>/snapshot` URL is auto-filled if omitted, and
        /// the substrate is uploaded inline so locator divergence is
        /// no longer a failure mode.
        #[arg(long)]
        locator: Option<String>,
        /// Registry to publish to (path/URL); default ~/.vela/registry/entries.json
        #[arg(long)]
        to: Option<String>,
        /// v0.154: optional SPDX license identifier
        /// (e.g. `CC-BY-4.0`, `CC0-1.0`, `MIT`, `Apache-2.0`). The
        /// license rides on the registry entry so consumers can
        /// audit reuse rights without re-fetching the frontier.
        #[arg(long)]
        license: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Hub-native proposal — the frictionless second-signer on-ramp.
    ///
    /// A contributor with only a keypair and the hub URL submits a
    /// signed `StateProposal` to a frontier's OPEN submission endpoint
    /// (`POST /entries/{vfr}/proposals`). No local `.vela/` workspace,
    /// no pre-registration: any valid Ed25519 self-signature is accepted
    /// and enqueued to `pending_review` (actor.id is provenance, not
    /// authority). This is the sibling of `registry append` (owner
    /// deposits events directly) for everyone who is NOT the owner.
    ///
    /// The proposal id is content-addressed and the signature is taken
    /// over the exact canonical preimage the hub re-derives, so a beat
    /// here is the genuine "someone other than the maintainer wrote a
    /// signed transition into the registry" event.
    Propose {
        /// Frontier address (`vfr_…`) to propose into.
        vfr_id: String,
        /// Hub base URL. Optional: defaults to your configured identity's hub.
        #[arg(long)]
        to: Option<String>,
        /// Path to the proposer's Ed25519 private key. Optional: defaults to
        /// your configured identity's key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Proposer actor id. Optional: defaults to your configured identity.
        #[arg(long)]
        actor: Option<String>,
        /// Actor type: `human` or `agent`.
        #[arg(long, default_value = "human")]
        actor_type: String,
        /// Proposal kind (e.g. `finding.add`, `finding.review`).
        #[arg(long, default_value = "finding.add")]
        kind: String,
        /// Human-readable reason for the proposal.
        #[arg(long)]
        reason: String,
        /// Path to a JSON file holding the proposal payload (a finding
        /// bundle or other change body). Use `-` to read from stdin.
        #[arg(long)]
        payload: PathBuf,
        /// Source reference (repeatable), e.g. a DOI or URL.
        #[arg(long = "source-ref")]
        source_refs: Vec<String>,
        /// Caveat to attach (repeatable).
        #[arg(long = "caveat")]
        caveats: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// v0.129: fetch the same registry entry from multiple hubs and
    /// assert byte-identical agreement. Closes part of
    /// THREAT_MODEL.md A11 (compromised hub) by giving operators a
    /// substrate-side cross-hub divergence detector. The
    /// substrate-honest claim: if two or more trustworthy mirrors
    /// agree on the entry's canonical bytes, a third hub's diverging
    /// copy is identifiable.
    WitnessCheck {
        /// Frontier address (`vfr_…`) to fetch from every hub.
        vfr_id: String,
        /// Comma-separated list of hub URLs to query. Requires
        /// at least two; three or more makes the consensus
        /// substrate-honest (a majority can outvote a single
        /// divergent hub).
        #[arg(long, value_delimiter = ',')]
        hubs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// v0.153: registry-wide verification. Reads a local
    /// registry, walks every entry, runs entry-signature
    /// verification per row, and surfaces a pass/fail summary.
    /// Used by operators + dashboards to attest the registry is
    /// internally consistent.
    VerifyAll {
        /// Local registry path. Defaults to
        /// `~/.vela/registry/entries.json`.
        #[arg(long)]
        from: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// v0.146: verify a frontier's owner-epoch chain transcript.
    /// Walks each transition, loads the corresponding policy,
    /// proposal, and attestation bundle, and re-runs the v0.145
    /// quorum verification. Surfaces `bootstrap` (chain empty),
    /// `verified` (every transition checks out), `legacy` (no
    /// chain file present; the entry pre-dates v0.144), or
    /// `broken` (at least one transition fails verification).
    VerifyChain {
        /// Frontier path. The chain is read from
        /// `<frontier-dir>/.vela/governance/chain.json`.
        frontier: PathBuf,
        /// Directory holding the `vgp_*.json`, `vop_*.json`,
        /// `vab_*.json` artifacts referenced by the chain. Files
        /// must be named `<id>.json` (e.g. `vop_abc123.json`).
        #[arg(long)]
        artifacts: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// v0.138: A8 graduation primitive. Rotate the owner key of a
    /// published frontier. Revokes the current owner actor record
    /// (sets `revoked_at` / `revoked_reason`), registers (or
    /// promotes) the new owner actor record, and re-publishes the
    /// frontier under the new owner key. Consumers who re-pull
    /// after rotation receive the new entry signed under the new
    /// `owner_pubkey`; the in-frontier actor record retains the
    /// rotation timeline so the audit chain is reconstructable
    /// from the frontier itself.
    OwnerRotate {
        /// Path to the frontier file
        frontier: PathBuf,
        /// Current owner actor id (must be registered and not revoked).
        #[arg(long)]
        current_owner: String,
        /// New owner actor id (auto-registered if not already present).
        #[arg(long)]
        new_owner: String,
        /// Path to the new owner's Ed25519 private key (hex-encoded).
        #[arg(long)]
        new_key: PathBuf,
        /// Required reason (non-empty); recorded on the retired
        /// owner's `revoked_reason` for the audit chain.
        #[arg(long)]
        reason: String,
        /// Network locator under which the rotated frontier is
        /// reachable. Same shape as `registry publish`: optional
        /// when `--to` is an HTTP hub (auto-filled), required for
        /// local registries.
        #[arg(long)]
        locator: Option<String>,
        /// Registry to publish the rotated entry to. Same shape as
        /// `registry publish --to`.
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Pull and verify a frontier from a registry by `vfr_id`
    Pull {
        /// Frontier address (`vfr_…`)
        vfr_id: String,
        /// Registry to pull from
        #[arg(long)]
        from: Option<String>,
        /// Output file path the pulled frontier lands at.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Independently verify a hub's RFC 6962 transparency log: fetch the
    /// signed tree head (STH), check its Ed25519 signature against an
    /// externally-pinned pubkey, recompute the Merkle root from the event
    /// content-address preimages, and (with --event) check that event's
    /// inclusion proof. Proves the hub cannot forge or silently drop accepted
    /// state. The Rust sibling of clients/python/vela_verify_log.py.
    VerifyLog {
        /// The frontier (vfr_…) whose log to verify.
        vfr_id: String,
        /// Hub base URL (e.g. https://hub.constellate.science). `--to` is an accepted
        /// alias (harmonized with `registry propose --to`).
        #[arg(long, visible_alias = "to")]
        hub: String,
        /// Optional event id (vev_…) to also prove inclusion of.
        #[arg(long)]
        event: Option<String>,
        /// Expected Ed25519 pubkey (hex), pinned out-of-band. Strongly
        /// recommended; without it the STH's self-advertised key is trusted
        /// (a corruption check only, not authenticity).
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum LinkAction {
    /// Append a typed link from one finding to another. The target
    /// may be a local `vf_<hex>` or a cross-frontier `vf_<hex>@vfr_<hex>`
    /// (v0.8). Cross-frontier targets require a matching declared dep —
    /// run `vela frontier add-dep` first or strict validation will refuse.
    Add {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Source finding id (`vf_<hex>`)
        #[arg(long)]
        from: String,
        /// Target. Either `vf_<hex>` (local) or `vf_<hex>@vfr_<hex>` (cross).
        #[arg(long)]
        to: String,
        /// Link type. One of: supports, contradicts, extends, depends, replicates, supersedes, synthesized_from
        #[arg(long, default_value = "supports")]
        r#type: String,
        /// Optional human-readable note
        #[arg(long, default_value = "")]
        note: String,
        /// Who inferred the link. One of: compiler, reviewer, author
        #[arg(long, default_value = "reviewer")]
        inferred_by: String,
        /// v0.16: skip the cross-frontier target-status check. By
        /// default, when adding a cross-frontier link, the substrate
        /// fetches the dep's frontier from its declared locator and
        /// warns if the target finding has `flags.superseded = true`
        /// (you'd be linking to an outdated wording). The link is
        /// still recorded — this is a best-effort review hint, not a
        /// hard refusal. Set this flag to skip the network fetch
        /// (useful in CI or when offline).
        #[arg(long)]
        no_check_target: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum FindingCommands {
    /// Add a manual finding bundle with an assertion field
    Add {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Assertion text inside the finding bundle
        #[arg(long)]
        assertion: String,
        /// Assertion type. One of: mechanism, observational, computational, theoretical, negative, measurement, exclusion, tension, open_question, hypothesis, candidate_finding
        #[arg(long, default_value = "mechanism")]
        r#type: String,
        /// Source label for the finding
        #[arg(long, default_value = "manual finding")]
        source: String,
        /// Source type. One of: published_paper, preprint, model_output, expert_assertion, database_record, data_release, researcher_notes
        #[arg(long, default_value = "expert_assertion")]
        source_type: String,
        /// Author/reviewer identifier
        #[arg(long)]
        author: String,
        /// Initial confidence score from 0.0 to 1.0
        #[arg(long, default_value = "0.3")]
        confidence: f64,
        /// Evidence type. One of: experimental, observational, computational, theoretical, extracted_from_notes
        #[arg(long, default_value = "theoretical")]
        evidence_type: String,
        /// Evidence span text or JSON. Repeat to attach multiple source spans
        #[arg(long)]
        evidence_span: Vec<String>,
        /// Mark this finding as a candidate gap
        #[arg(long)]
        gap: bool,
        /// Mark this finding as negative-space evidence
        #[arg(long)]
        negative_space: bool,
        /// v0.11: DOI of the source artifact (e.g. "10.1038/s41586-024-...")
        #[arg(long)]
        doi: Option<String>,
        /// v0.11: Publication year
        #[arg(long)]
        year: Option<i32>,
        /// v0.11: Generic source URL when none of the structured identifiers fit
        #[arg(long)]
        url: Option<String>,
        /// v0.11: Source-paper authors as semicolon-separated list (distinct from --author which is the curating Vela actor)
        #[arg(long)]
        source_authors: Option<String>,
        /// v0.11: Conditions/scope text. Replaces the placeholder otherwise written. Should describe scope boundaries (species, dosing, age range, model, etc.)
        #[arg(long)]
        conditions_text: Option<String>,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
        /// Immediately accept and apply the proposal locally
        #[arg(long)]
        apply: bool,
        /// v0.339: path to a replication_attestation JSON (e.g. emitted by
        /// the mechinterp harness for a verified circuit claim). When set,
        /// it rides in the finding.add payload as a sibling of `finding`;
        /// with `--author agent:replicator --apply` the accept gate
        /// auto-accepts the finding iff the attestation passes.
        #[arg(long)]
        replication_attestation: Option<PathBuf>,
    },
    /// v0.327: Read-only projection of one finding: assertion,
    /// evidence atoms, conditions, confidence with basis and
    /// actor-classified reviewed-state, typed links, and provenance.
    /// Deep inspection without raw-JSON spelunking.
    Show {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Finding id (`vf_<hex>`)
        finding_id: String,
        /// Emit stable JSON instead of the human view
        #[arg(long)]
        json: bool,
    },
    /// v0.14: Supersede an existing finding with a new content-addressed
    /// claim. The new finding gets its own `vf_…` id; an auto-injected
    /// `supersedes` link points back at the old id; the old finding is
    /// flagged `superseded`. Both remain queryable. Real corrections
    /// (Phase 4 follow-up data, retraction, refined wording) belong here
    /// rather than as caveats stacked on top of an immutable claim.
    Supersede {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// `vf_…` id of the finding to supersede
        old_id: String,
        /// New assertion text (drives the new finding's content address)
        #[arg(long)]
        assertion: String,
        /// New assertion type
        #[arg(long, default_value = "mechanism")]
        r#type: String,
        /// Source label
        #[arg(long, default_value = "manual finding")]
        source: String,
        /// Source type
        #[arg(long, default_value = "expert_assertion")]
        source_type: String,
        /// Curating Vela actor id
        #[arg(long)]
        author: String,
        /// Reason for the supersede (becomes the proposal/event reason)
        #[arg(long)]
        reason: String,
        /// New confidence score 0.0..=1.0
        #[arg(long, default_value = "0.5")]
        confidence: f64,
        /// New evidence type
        #[arg(long, default_value = "experimental")]
        evidence_type: String,
        /// DOI of the source artifact
        #[arg(long)]
        doi: Option<String>,
        /// Publication year
        #[arg(long)]
        year: Option<i32>,
        /// Generic source URL
        #[arg(long)]
        url: Option<String>,
        /// Source-paper authors (semicolon-separated)
        #[arg(long)]
        source_authors: Option<String>,
        /// Conditions/scope text
        #[arg(long)]
        conditions_text: Option<String>,
        json: bool,
        /// Immediately accept and apply the proposal locally
        #[arg(long)]
        apply: bool,
    },
    /// Attach a lightweight note to a finding.
    Note {
        frontier: PathBuf,
        finding_id: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        author: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Attach an explicit caveat to a finding.
    Caveat {
        frontier: PathBuf,
        finding_id: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        author: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Revise a finding's confidence interpretation.
    Revise {
        frontier: PathBuf,
        finding_id: String,
        #[arg(long)]
        confidence: f64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Mark a finding rejected without deleting it.
    Reject {
        frontier: PathBuf,
        finding_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Retract a finding.
    Retract {
        source: PathBuf,
        finding_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Add typed links between findings.
    Link {
        #[command(subcommand)]
        action: LinkAction,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProposalAction {
    /// List proposals in a frontier
    List {
        frontier: PathBuf,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show one proposal
    Show {
        frontier: PathBuf,
        proposal_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Preview applying one proposal without mutating the frontier
    Preview {
        frontier: PathBuf,
        proposal_id: String,
        #[arg(long, default_value = "reviewer:preview")]
        reviewer: String,
        #[arg(long)]
        json: bool,
    },
    /// Import proposal files into a frontier
    Import {
        frontier: PathBuf,
        source: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate standalone proposal files or directories
    Validate {
        source: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Export proposal records from a frontier
    Export {
        frontier: PathBuf,
        output: PathBuf,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Accept and apply one proposal
    Accept {
        frontier: PathBuf,
        proposal_id: String,
        /// Reviewer actor id. Optional: defaults to your configured identity.
        #[arg(long)]
        reviewer: Option<String>,
        #[arg(long)]
        reason: String,
        /// Path to the reviewer's Ed25519 private key. Optional: defaults to
        /// your configured identity's key.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Reject one proposal
    Reject {
        frontier: PathBuf,
        proposal_id: String,
        /// Reviewer actor id. Optional: defaults to your configured identity.
        #[arg(long)]
        reviewer: Option<String>,
        #[arg(long)]
        reason: String,
        /// Path to the reviewer's Ed25519 private key. Optional: defaults to
        /// your configured identity's key. A reject is a signed, append-only
        /// event, so key custody is its authority just as for accept.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Reconstruct signed-review history for decisions made before
    /// `review.*` events existed. Synthesizes an unsigned legacy event for
    /// every already-rejected / needs-revision proposal that lacks one, so
    /// `verify_proposal_decision_parity` holds. Idempotent.
    BackfillReviews {
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
}
