//! CLI command surface — the clap `Commands` enum and its `*Action`
//! subcommand enums, split out of `cli.rs` so the ~5k lines of command
//! definitions live apart from the handler functions and dispatch. Pure
//! data: the handlers and `run_command` dispatch stay in `cli.rs`.

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
        /// Run conformance vectors
        #[arg(long)]
        conformance: bool,
        /// Conformance test directory
        #[arg(long, default_value = "tests/conformance")]
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
    /// Check structural integrity of accepted frontier state
    Integrity {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
        /// CI gate: treat warnings (unreviewed AI-authored findings,
        /// unattributed sources, stale proof) as failures and exit non-zero.
        #[arg(long)]
        strict: bool,
    },
    /// v0.262: run Evidence CI as a review-readiness gate.
    EvidenceCi {
        /// Frontier JSON file or Vela repo.
        frontier: PathBuf,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Diagnose first-user checkout, frontier, proof, and Workbench readiness.
    Doctor {
        /// Frontier JSON file or Vela repo. Defaults to the release frontier
        /// when run from the repository root.
        frontier: Option<PathBuf>,
        /// Local Workbench port to check.
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
        /// Optional benchmark suite to include
        #[arg(long)]
        gold: Option<PathBuf>,
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
        /// Output stable JSON for --check-tools
        #[arg(long)]
        json: bool,
    },
    /// v0.42: Show what's pending right now — the daily-driver
    /// equivalent of `git status`. One screen: counts, the inbox,
    /// the audit, the federation health. Read in two seconds.
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
    /// v0.42: Conversational substrate access. Type a natural-language
    /// question; the substrate routes it to a structured query and
    /// renders the answer. No agent in the loop — kernel queries only.
    /// Codex-flavored REPL that doesn't pretend to be an agent.
    Ask {
        frontier: PathBuf,
        /// The question. If omitted, drops into a REPL.
        #[arg(trailing_var_arg = true)]
        question: Vec<String>,
        /// Output stable JSON when the answer has structure.
        #[arg(long)]
        json: bool,
    },
    /// Show frontier statistics
    Stats {
        /// Frontier JSON file, Vela repo, or packet
        frontier: PathBuf,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Search findings
    Search {
        /// Search query
        query: String,
        /// Frontier JSON file, Vela repo, or packet
        #[arg(long)]
        source: Option<PathBuf>,
        /// Filter by entity
        #[arg(long)]
        entity: Option<String>,
        /// Filter by assertion type
        #[arg(long)]
        r#type: Option<String>,
        /// Search every frontier in a directory
        #[arg(long)]
        all: Option<PathBuf>,
        /// Maximum results
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
    },
    /// List candidate contradictions and tensions
    Tensions {
        source: PathBuf,
        #[arg(long)]
        both_high: bool,
        #[arg(long)]
        cross_domain: bool,
        #[arg(long, default_value = "20")]
        top: usize,
        #[arg(long)]
        json: bool,
    },
    /// Export frontier artifacts
    Export {
        frontier: PathBuf,
        #[arg(short, long, default_value = "csv")]
        format: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Recompute SHA-256 over every file in a proof packet, compare to
    /// the manifest, and validate the proof-trace chain. Friendlier
    /// alias for `vela packet validate <path>` — same code path, same
    /// guarantee. Use this when you've pulled a packet from someone
    /// else and want one command that says "yes, this is what they
    /// signed, byte for byte."
    Verify {
        /// Path to the proof packet directory (the one with manifest.json)
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Run protocol conformance vectors
    Conformance {
        #[arg(default_value = "tests/conformance")]
        dir: PathBuf,
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
    /// Show version information
    Version,
    /// Optional signing and signature verification
    Sign {
        #[command(subcommand)]
        action: SignAction,
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
    /// Walk the local Workbench draft queue (Phase R, v0.5):
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
    /// v0.103: scaffold a fresh frontier end-to-end in one command.
    /// Composes init + sign generate-keypair + actor add + finding add
    /// + a print-ready next-steps banner. Designed for the
    /// fresh-from-`cargo install` user who wants to feel the substrate
    /// in 30 seconds without memorizing the demo sequence.
    /// v0.131: scaffold an AI-agent identity kit. Generates an
    /// Ed25519 keypair, writes an `actor.json` with the canonical
    /// `actor:<slug>-<date>` id and `actor.type: "agent"`, plus a
    /// minimal `agent.yaml` config file documenting which
    /// frameworks the agent supports. The output is portable: a
    /// human reviewer can register the agent into any frontier
    /// with `vela actor add <frontier> <agent_id> --pubkey
    /// <hex>`, after which the agent can draft proposals that
    /// flow through the reviewer-gated truth-claim discipline.
    /// See docs/AI_ATTRIBUTION.md for the full doctrine and
    /// docs/AGENT_QUICKSTART.md for the workflow.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    Quickstart {
        /// Frontier directory to create. Defaults to ./demo
        #[arg(default_value = "demo")]
        path: PathBuf,
        /// Frontier display name. Defaults to "Quickstart frontier".
        #[arg(long, default_value = "Quickstart frontier")]
        name: String,
        /// Reviewer / actor id under which the first finding lands.
        /// Defaults to `reviewer:you`. Override with e.g.
        /// `--reviewer reviewer:will-blair`.
        #[arg(long, default_value = "reviewer:you")]
        reviewer: String,
        /// First-finding assertion text. Defaults to a generic placeholder.
        /// Override with `--assertion "your real claim"`.
        #[arg(long)]
        assertion: Option<String>,
        /// Where to drop the generated keypair. Defaults to
        /// `<path>/keys/`.
        #[arg(long)]
        keys_out: Option<PathBuf>,
        /// Output stable JSON instead of the human-readable banner.
        #[arg(long)]
        json: bool,
    },
    /// v0.109: regenerate or verify the frontier's `vela.lock`
    /// pinning every cross-frontier dependency by snapshot hash.
    /// The lockfile is the substrate's "I used this exact
    /// scientific state" artifact. Default mode regenerates the
    /// lock from current state; `--check` verifies on-disk state
    /// matches the recorded lock and exits non-zero on drift.
    Lock {
        /// Frontier path (the .vela/ repo root)
        path: PathBuf,
        /// Verify the existing lock against current on-disk
        /// state instead of regenerating.
        #[arg(long)]
        check: bool,
        /// Emit JSON to stdout instead of the human banner.
        #[arg(long)]
        json: bool,
    },
    /// v0.110: generate a static HTML site documenting the
    /// frontier. Self-contained: no JS framework, no external
    /// dependencies, browseable from disk in any browser.
    /// Cargo's docs.rs analog for scientific state. Renders
    /// index, findings table, events table, and per-finding
    /// detail pages.
    Doc {
        /// Frontier path (the .vela/ repo root)
        path: PathBuf,
        /// Output directory. Defaults to `<path>/doc/`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Emit a JSON report to stdout instead of the human
        /// banner. The HTML files are written either way.
        #[arg(long)]
        json: bool,
    },
    /// Import frontier JSON into a .vela repo
    Import {
        frontier: PathBuf,
        #[arg(long)]
        into: Option<PathBuf>,
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
    /// Retro-impact: how much downstream verified state rests on a record,
    /// via the declared dependency graph (`depends_on` + transfer discharges).
    /// A deterministic oracle over verified state, never a popularity score.
    RetroImpact {
        /// The record id (`vat_`/`vf_`/`vfr_`/`vtr_`) to measure.
        record: String,
        /// Path to the frontier (project root or frontier.json file).
        #[arg(long)]
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Local frontier tasks. Tasks organize scientific work before any
    /// accepted event changes frontier truth state.
    Task {
        #[command(subcommand)]
        action: TaskAction,
    },
    /// v0.167: declare a federated-hub spec primitive (`vhs_*`).
    /// Pure data; content-addressed over (hub_id, base_url,
    /// operator_pubkey_hex, substrate_version, declared_at).
    /// No network calls.
    Hub {
        #[command(subcommand)]
        action: HubSpecCli,
    },
    /// v0.163: render a frontier as a Markdown preprint
    /// (abstract, contributors with CRediT roles, findings as
    /// evidence sections, BibTeX citation block). Pure derived
    /// view from the canonical substrate state.
    Preprint {
        /// Frontier path.
        frontier: PathBuf,
        /// Optional release timestamp to pin in the footer.
        /// Defaults to now (UTC).
        #[arg(long)]
        released_at: Option<String>,
        /// Output path (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Import a Carina artifact packet as reviewable frontier proposals
    ArtifactToState {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Artifact packet JSON
        packet: PathBuf,
        /// Actor importing the packet
        #[arg(long)]
        actor: String,
        /// Apply artifact proposals immediately while leaving truth changes pending
        #[arg(long)]
        apply_artifacts: bool,
        #[arg(long)]
        json: bool,
    },
    /// Manage finding bundles as the core frontier primitive
    Finding {
        #[command(subcommand)]
        command: FindingCommands,
    },
    /// Add typed links between findings — including cross-frontier
    /// references of the form `vf_<id>@vfr_<id>` (v0.8). Until v0.9
    /// link state lived only in JSON; `vela link add` is the CLI on-ramp.
    Link {
        #[command(subcommand)]
        action: LinkAction,
    },
    /// v0.19: resolve unresolved entities against a bundled common-entity
    /// table (UniProt for proteins, MeSH for diseases, ChEBI/DrugBank for
    /// compounds, etc.). Lowers `needs_review` for matched entities and
    /// populates `canonical_id`. Idempotent unless `--force` is passed.
    Entity {
        #[command(subcommand)]
        action: EntityAction,
    },
    /// Create or apply one proposal-backed finding review
    Review {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Finding ID to review
        finding_id: String,
        /// accepted, contested, needs_revision, or rejected
        #[arg(long)]
        status: Option<String>,
        /// Reason for the review
        #[arg(long)]
        reason: Option<String>,
        /// Reviewer identifier
        #[arg(long)]
        reviewer: String,
        /// Immediately accept and apply the proposal locally
        #[arg(long)]
        apply: bool,
        /// Output stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a lightweight note to a finding
    Note {
        frontier: PathBuf,
        finding_id: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        author: String,
        /// Immediately accept and apply the proposal locally
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Add an explicit caveat to a finding
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
    /// Revise an interpretation field while preserving history
    Revise {
        frontier: PathBuf,
        finding_id: String,
        /// New confidence score from 0.0 to 1.0
        #[arg(long)]
        confidence: f64,
        /// Reason for the revision
        #[arg(long)]
        reason: String,
        /// Reviewer identifier
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Mark a finding as rejected without deleting it
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
    /// Import review/state events from a packet or JSON file into a frontier
    ImportEvents {
        source: PathBuf,
        #[arg(long)]
        into: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Retract a finding
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
    /// v0.117: Register a machine-checked Proof primitive (`vpf_*`)
    /// against an existing finding. The proof script is hashed with
    /// sha256 to produce a content-addressed locator; the artifact
    /// rides as a `kind: source_file` artifact carrying
    /// `metadata.carina_kind: proof_script` plus tool + tool-version
    /// (matching the v0.75.6 sidon-sets pattern). Routes to
    /// `state::add_artifact`; the artifact event is signed under the
    /// reviewer's actor id. Closes the v0.75.6 Carina Proof primitive
    /// loop end-to-end: every proof script lives in the frontier's
    /// canonical event log with a content-addressed locator the
    /// substrate's verifier can pin against.
    ProofAdd {
        frontier: PathBuf,
        /// Finding the proof targets (`vf_*`).
        #[arg(long = "target-finding")]
        target_finding: String,
        /// Proof-assistant identifier. One of: lean4 (default), coq,
        /// isabelle, agda, metamath, rocq, other.
        #[arg(long, default_value = "lean4")]
        tool: String,
        /// Tool version pin (e.g. `4.29.1` for Lean 4).
        #[arg(long = "tool-version", default_value = "4.29.1")]
        tool_version: String,
        /// Path to the proof script on disk.
        #[arg(long = "script-path")]
        script_path: PathBuf,
        /// Human-readable label for the proof artifact.
        #[arg(long, default_value = "Proof script")]
        name: String,
        /// Reviewer actor id (e.g. `reviewer:will-blair`).
        #[arg(long)]
        reviewer: String,
        /// Reason for registering the proof artifact.
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// v0.151: attest that an external verifier ran a Carina
    /// Proof artifact and produced a specific output hash. Writes
    /// a signed `vpv_*` record next to the proof; consumers
    /// verify the attestation via `proof-verify-attestation`.
    /// The verifier itself (Lean kernel, Coq, etc.) runs
    /// outside the substrate; this command records the
    /// verifier's signed output and pubkey.
    ProofAttestVerification {
        /// Proof artifact id (`vpf_*`) the verification covers.
        #[arg(long)]
        proof_id: String,
        /// Verifier tool: lean4|coq|isabelle|agda|metamath|rocq|other.
        #[arg(long, default_value = "lean4")]
        tool: String,
        #[arg(long = "tool-version", default_value = "4.29.1")]
        tool_version: String,
        /// Content-addressed locator (sha256:HEX) of the proof
        /// script the verifier ran.
        #[arg(long)]
        script_locator: String,
        /// Optional sha256 over the Lake manifest (or equivalent).
        #[arg(long = "lake-manifest-hash")]
        lake_manifest_hash: Option<String>,
        /// sha256:HEX over the verifier's standard output.
        #[arg(long = "verifier-output-hash")]
        verifier_output_hash: String,
        /// `verified` | `failed` | `toolchain_mismatch`.
        #[arg(long, default_value = "verified")]
        status: String,
        /// Verifier actor identifier (GitHub Action url, Vela
        /// actor id, institutional steward id).
        #[arg(long = "verifier-actor")]
        verifier_actor: String,
        /// Verifier's Ed25519 signing key.
        #[arg(long)]
        key: PathBuf,
        /// Output path for the verification record JSON.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// v0.151: verify a `vpv_*` proof-verification record:
    /// re-derive the id, verify the Ed25519 signature against
    /// `verifier_pubkey`. Exits non-zero on any mismatch.
    ProofVerifyAttestation {
        /// Path to the `vpv_*` verification record JSON.
        record: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show read-only review-work queues for a frontier.
    ReviewWork {
        frontier: PathBuf,
        /// Emit JSON to stdout.
        #[arg(long)]
        json: bool,
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
        #[arg(long)]
        reason: String,
        #[arg(long)]
        reviewer: String,
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
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        reason: String,
        /// Path to the reviewer's Ed25519 private key (hex seed). REQUIRED
        /// when the reviewer is registered with a public key: key custody,
        /// not the typed name, is the accept authority, and the accept
        /// event is signed with this key.
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
        #[arg(long)]
        json: bool,
    },

    /// Bind a verifier attachment to a finding (propose → accept in one step).
    /// Reads a `vela.verifier_attachment.v0.1` JSON object (whose `target` is the
    /// finding's `vf_…` id) and lands it via the canonical `verifier.attach`
    /// proposal→accept path. The finding's trust-gate status is derived on read.
    Attach {
        frontier: PathBuf,
        /// The finding (`vf_…`) the attachment binds to.
        #[arg(long)]
        target: String,
        /// Path to a JSON file holding the VerifierAttachment object.
        #[arg(long)]
        attachment_file: PathBuf,
        /// Reviewer authority applying the attachment (e.g. `reviewer:opus`).
        #[arg(long)]
        reviewer: String,
        #[arg(long, default_value = "bind verifier attachment")]
        reason: String,
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
        #[arg(long)]
        reviewer: String,
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

    /// v0.75: validate Carina-shaped JSON against the bundled
    /// schemas, list bundled primitives, or print one schema.
    Carina {
        #[command(subcommand)]
        action: CarinaAction,
    },
}

/// v0.75: actions on the Carina spec deliverable. Each one talks
/// to the schemas embedded under
/// `crates/vela-protocol/embedded/carina-schemas/`.
#[derive(Subcommand)]
pub(crate) enum CarinaAction {
    /// Validate a JSON file against the matching Carina schema.
    /// Detects the primitive automatically from the input's
    /// `schema: "carina.<name>.v0.X"` field, or accepts an
    /// explicit `--primitive <name>`.
    Validate {
        /// Path to a JSON file containing one Carina primitive,
        /// or a `primitives.v0.X.json`-style aggregate object
        /// with a `primitives` map.
        path: PathBuf,
        /// Override auto-detection: validate as a specific
        /// primitive (`finding`, `evidence`, `proof`, ...).
        #[arg(long)]
        primitive: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List the 14 bundled Carina primitives.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Print one bundled Carina schema to stdout.
    Schema { primitive: String },
}

#[derive(Subcommand)]
pub(crate) enum PacketAction {
    /// Inspect a proof packet manifest
    Inspect {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate a proof packet
    Validate {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TraceAction {
    /// Validate a bounded research trace source artifact
    Validate {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Draft pending review proposals from a trace
    Propose {
        path: PathBuf,
        #[arg(long)]
        frontier: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum CorrectionReturnAction {
    /// Validate a correction return object
    Validate {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Draft pending review proposals from a correction return
    Propose {
        path: PathBuf,
        #[arg(long)]
        frontier: PathBuf,
        #[arg(long)]
        out: PathBuf,
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
        #[arg(long)]
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
}

#[derive(Subcommand)]
pub(crate) enum ActorAction {
    /// Register an Ed25519 public key for a stable actor identity
    Add {
        frontier: PathBuf,
        /// Stable actor id (e.g. "reviewer:will-blair")
        id: String,
        /// Hex-encoded Ed25519 public key (64 hex chars)
        #[arg(long)]
        pubkey: String,
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

/// v0.131: AI-agent scaffolding subcommands. The agent layer is
/// purely substrate-side: an agent gets an Ed25519 keypair and an
/// `agent:<slug>-<date>` actor id; the agent then drafts proposals
/// against frontiers it has been registered in. The substrate
/// makes the agent-draft / human-verdict distinction load-bearing
/// (see docs/AI_ATTRIBUTION.md).
#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Scaffold an agent identity kit at `agents/<slug>/`. Creates
    /// `agent.yaml` (config), `actor.json` (the substrate-side
    /// actor record for `actor add`), `keys/` (Ed25519 keypair).
    Init {
        /// Short agent name (slug). The canonical actor id becomes
        /// `agent:<slug>-<rfc3339-date>`.
        name: String,
        /// Framework hint stored in `agent.yaml`. One of:
        /// `claude-code`, `claude-api`, `langchain`, `openai`,
        /// `agent4science`, `scienceclaw`, `custom`.
        #[arg(long, default_value = "custom")]
        framework: String,
        /// Output directory. Defaults to `agents/<slug>/`.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// List every scaffolded agent under `agents/`.
    List {
        /// Agents root directory. Defaults to `./agents/`.
        #[arg(long, default_value = "agents")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum CausalAction {
    /// v0.40: Audit every finding's (causal_claim, causal_evidence_grade)
    /// for identifiability. Reports underidentified, conditional,
    /// and underdetermined findings with rationale + remediation.
    Audit {
        frontier: PathBuf,
        /// Restrict the report to entries needing reviewer attention
        /// (Underidentified or Conditional). Useful for triage.
        #[arg(long)]
        problems_only: bool,
        #[arg(long)]
        json: bool,
    },
    /// v0.44 (Pearl level 2): Identify the causal effect of a source
    /// finding on a target finding by searching for a back-door
    /// adjustment set in the frontier's directed link graph. Reports
    /// either the adjustment set Z that identifies P(target | do(source))
    /// from observational data alone, or surfaces the open back-door
    /// paths that prevent identification.
    ///
    /// The link graph used: `depends` and `supports` edges. Every
    /// finding's parents are the findings it relies on as evidence;
    /// every finding's children are the findings that build on it.
    /// `contradicts` and other link types are excluded from the
    /// causal DAG.
    Effect {
        frontier: PathBuf,
        /// Source finding id (`vf_<hash>`).
        source: String,
        /// Target finding id, given via `--on`.
        #[arg(long)]
        on: String,
        #[arg(long)]
        json: bool,
    },
    /// v0.44: Print the causal-graph topology over the frontier.
    /// Lists each node's parents and children for inspection.
    Graph {
        frontier: PathBuf,
        /// Limit output to a single node's neighborhood.
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// v0.45 (Pearl level 3): answer a counterfactual query of the form
    /// "if we had observed `intervene_on` at `value`, what would
    /// `target`'s confidence have been?" Twin-network propagation
    /// requires every edge on the source→target paths to declare a
    /// `mechanism`; edges without one block propagation honestly with
    /// a `mechanism_unspecified` verdict.
    Counterfactual {
        frontier: PathBuf,
        /// The finding to intervene on (`vf_<hash>`).
        intervene_on: String,
        /// The confidence value to set on the intervened finding (in [0,1]).
        #[arg(long)]
        set_to: f64,
        /// The target finding whose counterfactual confidence we want (`vf_<hash>`).
        #[arg(long)]
        target: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum BridgesAction {
    /// Derive bridges between two frontiers and persist the resulting
    /// `vbr_<id>` records under the *first* frontier's `.vela/bridges/`
    /// directory. Idempotent on (entity, sorted-frontier-pair).
    Derive {
        /// First frontier (Vela repo or frontier JSON file).
        /// Bridges are persisted under this frontier.
        frontier_a: PathBuf,
        /// Human label for the first frontier in bridge records.
        #[arg(long, default_value = "a")]
        label_a: String,
        /// Second frontier (Vela repo or frontier JSON file).
        frontier_b: PathBuf,
        /// Human label for the second frontier in bridge records.
        #[arg(long, default_value = "b")]
        label_b: String,
        #[arg(long)]
        json: bool,
    },
    /// List bridges persisted under a frontier's `.vela/bridges/` dir.
    List {
        /// Frontier (must be a Vela repo with a `.vela/` directory).
        frontier: PathBuf,
        /// Filter by status: derived, confirmed, refuted.
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show a single bridge by `vbr_<id>`.
    Show {
        frontier: PathBuf,
        bridge_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Promote a bridge from `derived` to `confirmed`. Persists in
    /// place; the content-address `vbr_<id>` is unchanged. v0.67:
    /// emits a `bridge.reviewed` canonical event under the configured
    /// reviewer id so federation sync can propagate the verdict.
    Confirm {
        frontier: PathBuf,
        bridge_id: String,
        /// Reviewer identity attaching the verdict. Defaults to
        /// $VELA_REVIEWER_ID or `reviewer:will-blair`.
        #[arg(long)]
        reviewer: Option<String>,
        /// Optional verdict note.
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Mark a bridge `refuted`. Persists in place. v0.67: emits a
    /// `bridge.reviewed` canonical event with `status: refuted`.
    Refute {
        frontier: PathBuf,
        bridge_id: String,
        #[arg(long)]
        reviewer: Option<String>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum FederationAction {
    /// v0.39: Register a peer hub in this frontier. Adding a peer
    /// declares awareness — it does not trust their state. Sync /
    /// merge runtime ships in v0.39.1+.
    PeerAdd {
        frontier: PathBuf,
        /// Stable peer id (e.g. `hub:vela-mirror-eu`).
        id: String,
        /// HTTPS URL where the peer publishes signed manifests.
        #[arg(long)]
        url: String,
        /// Hex-encoded Ed25519 public key (64 hex chars).
        #[arg(long)]
        pubkey: String,
        /// Optional human-readable note (e.g. "EU mirror, run by lab Z").
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long)]
        json: bool,
    },
    /// List federation peers registered in a frontier.
    PeerList {
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Remove a peer from the registry. Does not retroactively
    /// invalidate events that referenced the peer; just stops further
    /// sync attempts.
    PeerRemove {
        frontier: PathBuf,
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// v0.39.1 / v0.41.0: Sync our frontier against a peer's
    /// published view. Three modes:
    ///   1. `--via-hub --vfr-id <id>`: route through the peer hub's
    ///      `/entries/<vfr_id>` endpoint, verify the registry entry
    ///      signature, follow the locator. The "real federation"
    ///      path. Surfaces broken-locator and unverified-entry
    ///      conflicts when the peer is reachable but stale.
    ///   2. `--url <override>`: fetch directly from a manifest URL,
    ///      bypassing the hub's registry. Useful for static-mirror
    ///      peers (raw GitHub) or for testing.
    ///   3. (default): tries `<peer.url>/manifest/<frontier_id>.json`.
    /// Diffs the resulting Project against ours, appends one
    /// `frontier.synced_with_peer` event + one
    /// `frontier.conflict_detected` event per disagreement.
    /// Read-only with respect to findings; conflict resolution
    /// happens through subsequent reviewer-signed proposals.
    Sync {
        frontier: PathBuf,
        /// Peer id (must already be in the registry).
        peer_id: String,
        /// Direct manifest URL override.
        #[arg(long)]
        url: Option<String>,
        /// Route through the peer hub's `/entries/<vfr-id>` endpoint
        /// (verify entry signature, follow locator). Requires
        /// `--vfr-id`.
        #[arg(long)]
        via_hub: bool,
        /// vfr_id to fetch when using `--via-hub`. Defaults to our
        /// local frontier_id when omitted.
        #[arg(long)]
        vfr_id: Option<String>,
        /// v0.64: opt-in flag to allow `--via-hub --vfr-id <peer_vfr>`
        /// where `<peer_vfr>` differs from the local frontier's id.
        /// Without this flag, cross-vfr sync is refused because every
        /// peer-side finding gets recorded as a "missing_locally"
        /// conflict, flooding the inbox with substrate-honest but
        /// operationally noisy events.
        #[arg(long)]
        allow_cross_vfr: bool,
        /// Run the diff but don't append events.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// v0.70: Push a single locally-resolved
    /// `frontier.conflict_resolved` event back to the originating
    /// peer hub. Reads the event from the local frontier, signs the
    /// canonical bytes with the supplied private key (or the actor's
    /// key under `~/.config/vela/keys/`), and POSTs to the peer's
    /// `/entries/<vfr_id>/events` endpoint with paired
    /// `X-Vela-Signer-Pubkey` and `X-Vela-Signature` headers.
    /// One event at a time; the hub validates signature, actor
    /// pubkey, pairing against an existing
    /// `frontier.conflict_detected`, and idempotency on the
    /// resolution. Subsequent `vela federation sync` calls against
    /// that hub return the resolution to anyone else who pulls.
    PushResolution {
        frontier: PathBuf,
        /// The id of the original `frontier.conflict_detected`
        /// event whose paired `frontier.conflict_resolved` event
        /// should be pushed.
        conflict_event_id: String,
        /// Peer id (must already be in the registry).
        #[arg(long = "to")]
        to: String,
        /// Path to the actor's Ed25519 private key file (hex). If
        /// omitted, looks up `~/.config/vela/keys/<actor_id>.key`,
        /// then `~/.config/vela/keys/private.key`.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Override the vfr_id sent to the peer (defaults to the
        /// local frontier_id).
        #[arg(long)]
        vfr_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReviewThreadCli {
    /// Create a fresh review thread on a target (`vpr_*`,
    /// `vf_*`, or `vsd_*` Scientific Diff Pack). Writes the
    /// empty thread JSON to `--out`.
    Create {
        /// `vpr_*`, `vf_*`, or `vsd_*` target id.
        target: String,
        #[arg(long)]
        frontier_id: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Append a signed message to an existing thread. The
    /// signing key is read from disk in raw 32-byte hex form.
    Post {
        /// Existing thread JSON file (will be rewritten in
        /// place to include the new message).
        thread: PathBuf,
        #[arg(long)]
        author_actor_id: String,
        /// Path to a 32-byte hex-encoded Ed25519 signing key.
        #[arg(long)]
        key: PathBuf,
        /// Message body (free-form text).
        #[arg(long)]
        message: String,
        /// Optional parent `vrm_*` id (for threaded replies).
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Verify every message in a thread: signature against
    /// declared pubkey + id matches preimage.
    Verify {
        thread: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum HubSpecCli {
    /// Build a `vhs_*` spec record and write it to `--out`.
    Declare {
        #[arg(long)]
        hub_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        operator_pubkey_hex: String,
        #[arg(long)]
        substrate_version: String,
        #[arg(long)]
        contact: Option<String>,
        #[arg(long)]
        latest_checkpoint: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Validate an existing `vhs_*` spec file: re-derive the id
    /// and check it matches the record.
    Validate {
        spec: PathBuf,
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
        /// (e.g. "github-action:vela-science/vela:verify-lean-bundle").
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
        /// Path to a 32-byte hex-encoded Ed25519 private key.
        #[arg(long)]
        key: PathBuf,
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
        /// Path to the Ed25519 signing key (64 hex chars).
        #[arg(long)]
        key: PathBuf,
        /// Where to write the signed `vtr_` record.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum DiffPackAction {
    /// Bundle N existing proposals into a Scientific Diff Pack.
    /// The pack is signed (if --key is supplied), content-addressed,
    /// and written to --out. The pack id can then be cited from a
    /// reviewer surface or a federated event.
    Create {
        /// Path to the frontier (project root or frontier.json file).
        frontier: PathBuf,
        /// Ordered list of vpr_* ids the pack bundles. Order matters
        /// (it's part of the canonical preimage).
        #[arg(long, value_delimiter = ',', required = true)]
        proposals: Vec<String>,
        /// Reviewer-readable summary (<=280 chars).
        #[arg(long)]
        summary: String,
        /// Plain-language category (e.g. finding.cluster_revision,
        /// evidence.refresh, correction.batch, agent.proposal_set).
        #[arg(long)]
        aggregate_kind: String,
        /// Optional v0.195 agent attestation envelope id.
        #[arg(long)]
        agent_run: Option<String>,
        /// Optional parent pack this one amends.
        #[arg(long)]
        parent_pack: Option<String>,
        /// Optional path to a 32-byte hex-encoded Ed25519 signing
        /// key. When present, the pack is signed under it.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Output path for the pack JSON.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Pretty-print the contents of a `vsd_*` pack file.
    Show {
        pack: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a pack in a frontier repo as a reviewable state-change unit.
    Inspect {
        /// Path to the frontier repo (with a `.vela/` directory).
        frontier: PathBuf,
        /// The `vsd_*` pack id to inspect.
        pack_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify a pack: pack_id matches re-derivation; signature
    /// verifies under declared pubkey if present.
    Verify {
        pack: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate a pack in a frontier repo. With --evidence-ci, run
    /// review-readiness checks over the pack and its member proposals.
    Validate {
        /// Path to the frontier repo (with a `.vela/` directory).
        frontier: PathBuf,
        /// The `vsd_*` pack id to validate.
        pack_id: String,
        #[arg(long)]
        evidence_ci: bool,
        #[arg(long)]
        json: bool,
    },
    /// v0.205: walk `.vela/pending_verdicts/` on the given
    /// frontier and promote each pending verdict to a canonical
    /// `diff_pack.reviewed` event. Atomic per-verdict: accept
    /// applies every canonical member or rolls back.
    PromoteVerdicts {
        /// Path to the frontier repo (with a `.vela/` directory).
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// v0.221: scan `.vela/diff_packs/` and emit a canonical
    /// `diff_pack.released` event for every pack that does not
    /// already have one. Idempotent — re-running is a no-op once
    /// every pack has a release event. Closes the v0.213 reducer
    /// arm for frontiers built by pre-v0.221 scaffolding scripts
    /// that wrote packs to disk without emitting release events.
    BackfillRelease {
        /// Path to the frontier repo (with a `.vela/` directory).
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// v0.216: witness-check a Scientific Diff Pack across N hubs.
    /// GETs `<hub>/diff-packs/<pack_id>` from each hub in --hubs
    /// and compares the signed body byte-for-byte. Reports verified
    /// / split / missing. Theorem 30 pins the soundness: verified
    /// responses imply N-way agreement on the pack body.
    WitnessCheck {
        /// The `vsd_*` pack id to witness-check.
        pack_id: String,
        /// Comma-separated list of hub base URLs.
        #[arg(long, value_delimiter = ',', required = true)]
        hubs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PolicyAction {
    /// Check frontier-owned policy files and print the canonical policy view.
    Check {
        /// Frontier repo directory or frontier file.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TaskAction {
    /// Create a local frontier task under `.vela/tasks/`.
    Create {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Task type, such as source_ingestion or contradiction_resolution.
        #[arg(long = "type")]
        task_type: String,
        /// Bounded objective for the work unit.
        #[arg(long)]
        objective: String,
        /// Source, finding, proposal, or artifact input id. Repeatable.
        #[arg(long = "input")]
        inputs: Vec<String>,
        /// Review risk class used by local policy.
        #[arg(long, default_value = "low_risk")]
        risk_class: String,
        /// Blocking task id or condition. Repeatable.
        #[arg(long = "blocker")]
        blockers: Vec<String>,
        /// Acceptance criterion. Repeatable.
        #[arg(long = "acceptance")]
        acceptance_criteria: Vec<String>,
        /// Initial task state.
        #[arg(long, default_value = "backlog")]
        status: String,
        #[arg(long)]
        json: bool,
    },
    /// List local frontier tasks.
    List {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Filter by task status.
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show one local frontier task.
    Show {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Claim a task for local review or execution.
    Claim {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        /// Typed reviewer or operator id, for example `reviewer:you`.
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        json: bool,
    },
    /// Run a task's reproduction entrypoint (run.sh) in its isolated workspace
    /// and import the captured result as pending proposals (reviewer-gated).
    Execute {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        /// Actor recording the run.
        #[arg(long, default_value = "agent:repro-executor")]
        actor: String,
        #[arg(long)]
        json: bool,
    },
    /// Close a task with a terminal status.
    Close {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        /// Terminal status: accepted, rejected, superseded, or archived.
        #[arg(long)]
        status: String,
        /// Reason for the terminal decision.
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Move a task to a non-terminal operational state.
    SetStatus {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        /// New task status.
        #[arg(long)]
        status: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TaskWorkspaceAction {
    /// Create `.vela/workspaces/<task-id>/` and preserve the task artifacts.
    Init {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show workspace layout, source copies, and snapshot hash.
    Status {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReviewPacketAction {
    /// Build a review packet from a task workspace and linked Diff Pack.
    Build {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vtask_*` task id.
        task_id: String,
        /// Output Markdown path. JSON is also written into the task workspace.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReviewSessionAction {
    /// Start a local reviewer session.
    Start {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Typed reviewer id, for example `reviewer:external`.
        #[arg(long)]
        reviewer: String,
        /// Review scope, such as `diff_pack:vsd_...`.
        #[arg(long)]
        scope: String,
        /// Optional transcript path connected to this session.
        #[arg(long)]
        transcript: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Add a note to an open reviewer session.
    Note {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vrs_*` review session id.
        session_id: String,
        /// Object id under review, such as `vsd_*`, `vtask_*`, or `vf_*`.
        #[arg(long)]
        object: String,
        /// Reviewer note.
        #[arg(long)]
        note: String,
        #[arg(long)]
        json: bool,
    },
    /// Close a reviewer session with a bounded decision.
    Close {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vrs_*` review session id.
        session_id: String,
        /// accepted, rejected, needs_revision, or closed.
        #[arg(long)]
        decision: String,
        /// Bounded close reason.
        #[arg(long)]
        reason: String,
        /// Optional follow-up task ids.
        #[arg(long = "follow-up-task")]
        follow_up_tasks: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List local reviewer sessions.
    List {
        /// Frontier repo directory.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show one local reviewer session.
    Show {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vrs_*` review session id.
        session_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SourceInboxAction {
    /// Add a source-material record under `.vela/source-inbox/`.
    Add {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Optional stable source id from the frontier source registry.
        #[arg(long)]
        source_id: Option<String>,
        /// Human-readable source title.
        #[arg(long)]
        title: String,
        /// DOI, PMID, URL, registry id, path, or other locator.
        #[arg(long)]
        locator: String,
        /// Source type, such as paper, registry_record, dataset, or note.
        #[arg(long, default_value = "source_material")]
        source_type: String,
        /// Initial source-inbox state.
        #[arg(long, default_value = "discovered")]
        state: String,
        /// Review risk class used by local policy.
        #[arg(long, default_value = "source_repair")]
        risk_class: String,
        /// Optional content hash for fetched bytes or normalized metadata.
        #[arg(long)]
        content_hash: Option<String>,
        /// Source-inbox note. Repeatable.
        #[arg(long = "note")]
        notes: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List local source-inbox records.
    List {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Filter by state, or use task-linked / stale.
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Mark one source-inbox record verified by a typed reviewer.
    Verify {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vsrcin_*` source-inbox id.
        record_id: String,
        /// Typed reviewer id, for example `reviewer:you`.
        #[arg(long)]
        reviewer: String,
        /// Verification reason.
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Create a local frontier task from one source-inbox record.
    CreateTask {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vsrcin_*` source-inbox id.
        record_id: String,
        /// Optional task objective. Defaults to a source-review objective.
        #[arg(long)]
        objective: Option<String>,
        /// Initial task state.
        #[arg(long, default_value = "eligible")]
        status: String,
        #[arg(long)]
        json: bool,
    },
    /// Import a text, CSV, BibTeX, or RIS source list into source-inbox work.
    Import {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Source list file.
        #[arg(long = "from")]
        from: PathBuf,
        /// Input format: text, csv, bibtex, or ris. Defaults from extension.
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum AdoptionAction {
    /// Build a first-review transcript for the current frontier state.
    Transcript {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Write Markdown transcript to this path.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Append one local adoption friction record.
    Log {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Adoption step, such as source-inbox, proof, or share.
        #[arg(long)]
        step: String,
        /// Friction category. Derived from --step when omitted.
        #[arg(long)]
        category: Option<String>,
        /// One of confusing, missing_doc, command_failed, slow_step, trust_blocker, useful_object.
        #[arg(long)]
        kind: String,
        /// Short reviewer note.
        #[arg(long)]
        note: String,
        #[arg(long)]
        json: bool,
    },
    /// Reclassify one local adoption friction record.
    LogClassify {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vaf_*` friction record id.
        record_id: String,
        /// Category such as source-intake, proof, share, or docs.
        #[arg(long)]
        category: String,
        #[arg(long)]
        json: bool,
    },
    /// Link one local adoption friction record to an existing task.
    LogLinkTask {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vaf_*` friction record id.
        record_id: String,
        /// `vtask_*` task id.
        task_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Create a local follow-up task for one friction record.
    LogFollowUpTask {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vaf_*` friction record id.
        record_id: String,
        /// Optional task objective. Defaults to the friction note.
        #[arg(long)]
        objective: Option<String>,
        /// Initial task status.
        #[arg(long, default_value = "eligible")]
        status: String,
        #[arg(long)]
        json: bool,
    },
    /// Close one local adoption friction record.
    LogClose {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vaf_*` friction record id.
        record_id: String,
        /// Closure reason.
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// List local adoption friction records.
    LogList {
        /// Frontier repo directory.
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ShareAction {
    /// Build a read-only frontier package for external review.
    Build {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Output directory for the share package.
        #[arg(long)]
        out: PathBuf,
        /// Include local adoption friction records in the package.
        #[arg(long)]
        include_friction_log: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a share package manifest and proof-packet presence.
    Inspect {
        /// Share package directory.
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Render a share package into static HTML pages.
    Render {
        /// Share package directory.
        package: PathBuf,
        /// Output directory for the static pages.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ControllerAction {
    /// Run one local frontier controller and reconcile issues into tasks.
    Run {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Controller kind: stale-evidence, source-freshness, contradiction-debt,
        /// proof-freshness, or missing-attestation.
        #[arg(long)]
        kind: String,
        /// Preview the proposed task records without writing them.
        #[arg(long)]
        dry_run: bool,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum IncidentAction {
    /// Open a local frontier incident and create affected review tasks.
    Open {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Incident type: source_retracted, source_corrected, extraction_error,
        /// trial_registry_mismatch, high_impact_contradiction, or translation_risk.
        #[arg(long)]
        kind: String,
        /// Severity label, such as high, medium, low, or critical.
        #[arg(long, default_value = "medium")]
        severity: String,
        /// Short incident title.
        #[arg(long)]
        title: String,
        /// Reason this incident is being opened.
        #[arg(long)]
        reason: String,
        /// Typed reviewer or operator id, for example reviewer:you.
        #[arg(long)]
        reviewer: String,
        /// Optional source id, source-inbox id, DOI, PMID, or locator.
        #[arg(long)]
        source_id: Option<String>,
        /// Optional finding id directly affected by the incident.
        #[arg(long)]
        finding_id: Option<String>,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List local frontier incidents.
    List {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// Filter by status: open or closed.
        #[arg(long)]
        status: Option<String>,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Close a local frontier incident after review.
    Close {
        /// Frontier repo directory.
        frontier: PathBuf,
        /// `vinc_*` incident id.
        incident_id: String,
        /// Typed reviewer or operator id, for example reviewer:you.
        #[arg(long)]
        reviewer: String,
        /// Close reason.
        #[arg(long)]
        reason: String,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ToolCliAction {
    /// Register a tool descriptor (`vtd_*`). The descriptor is
    /// content-addressed over (tool_name, tool_version, provider,
    /// calling_convention, input_schema, output_schema) and written
    /// to --out. Input/output schemas are JSON files on disk.
    Register {
        #[arg(long)]
        tool_name: String,
        #[arg(long)]
        tool_version: String,
        /// Free-form provider identifier
        /// (e.g. tooluniverse:protein-fold:2024.10).
        #[arg(long)]
        provider: String,
        /// One of: http_json, python_callable, cli_subprocess,
        /// mcp_server.
        #[arg(long)]
        calling_convention: String,
        /// Path to a JSON file containing the tool's input schema.
        #[arg(long)]
        input_schema: PathBuf,
        /// Path to a JSON file containing the tool's output schema.
        #[arg(long)]
        output_schema: PathBuf,
        /// Optional URL evidencing the tool (paper, doc, release).
        #[arg(long)]
        evidence_url: Option<String>,
        /// Optional comma-separated list of vf_* finding ids that
        /// cite outputs from this tool.
        #[arg(long, value_delimiter = ',')]
        cited_in_findings: Vec<String>,
        /// Output path for the descriptor JSON.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Pretty-print the contents of a `vtd_*` descriptor file.
    Show {
        descriptor: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a descriptor: descriptor_id matches re-derivation.
    Verify {
        descriptor: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum EvalCliAction {
    /// Record an evaluation outcome against a substrate object.
    /// The record is content-addressed over its body and optionally
    /// signed under --key.
    Record {
        /// One of: vsd, vtr, vf, vpf, vtd, vaa.
        #[arg(long)]
        target_kind: String,
        /// Id of the targeted object (must match target_kind prefix).
        #[arg(long)]
        target_id: String,
        /// One of: replication, benchmark, validation, peer_review.
        #[arg(long)]
        evaluation_kind: String,
        /// One of: succeeded, failed, partial, inconclusive.
        #[arg(long)]
        outcome: String,
        /// Stable actor id (e.g. lab:replication_site_42).
        #[arg(long)]
        evaluator: String,
        /// Comma-separated evidence references (any kernel-object ids).
        #[arg(long, value_delimiter = ',')]
        evidence_refs: Vec<String>,
        /// Optional benchmark id (e.g. astabench:protein-fold:v1).
        #[arg(long)]
        benchmark_id: Option<String>,
        /// Optional numeric score.
        #[arg(long)]
        score: Option<f64>,
        /// Optional free-text notes.
        #[arg(long)]
        notes: Option<String>,
        /// Optional path to a 32-byte hex Ed25519 signing key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Output path for the record JSON.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Pretty-print the contents of a `ver_*` record file.
    Show {
        record: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a record: record_id matches re-derivation; signature
    /// verifies under declared pubkey if present.
    Verify {
        record: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConflictCliAction {
    /// Scan `.vela/pending_verdicts/` for contradicting verdicts
    /// on overlapping Diff Pack members. Returns a list of
    /// candidate-conflict records — pairs of vpv_* ids that
    /// disagree on at least one shared vpr_*.
    Detect {
        /// Path to the frontier repo (with a `.vela/` directory).
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List every resolved `vdc_*` on the frontier.
    List {
        frontier: PathBuf,
        #[arg(long)]
        json: bool,
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
pub(crate) enum RepoAction {
    /// Show materialization, proof, proposal, and hash status.
    Status {
        /// Frontier repository directory.
        frontier: PathBuf,
        /// Output stable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check folder shape, manifest paths, stale proof, and root clutter.
    Doctor {
        /// Frontier repository directory.
        frontier: PathBuf,
        /// Output stable JSON.
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
        /// Stable actor id matching a registered entry in the frontier
        #[arg(long)]
        actor: String,
        /// Path to the actor's Ed25519 private key (hex-encoded)
        #[arg(long)]
        key: PathBuf,
        /// Override the queue file location
        #[arg(long)]
        queue_file: Option<PathBuf>,
        /// Skip per-action confirmation prompts and sign every queued
        /// draft. Required in non-interactive contexts. The `--all`
        /// alias is accepted for muscle-memory convenience (the v0.28
        /// sim-user docs and an early friction report both wrote it
        /// that way; cheaper to accept the alias than to retrain).
        #[arg(long, alias = "all")]
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
pub(crate) enum RegistryAction {
    /// Deprecate a published frontier on a hub: an owner-signed,
    /// append-only lifecycle event. The entry vanishes from /entries and
    /// /search but stays auditable at /entries/{vfr}/status — never a
    /// silent deletion. Only the owner key that published the entry can
    /// deprecate it (the re-publish continuity rule).
    Deprecate {
        /// The frontier to deprecate (vfr_…)
        vfr_id: String,
        /// Hub base URL (e.g. https://vela-hub.fly.dev)
        #[arg(long)]
        to: String,
        /// Path to the owner's Ed25519 private key (hex seed)
        #[arg(long)]
        key: PathBuf,
        /// Why this frontier is retired (recorded in the signed receipt)
        #[arg(long)]
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
        /// Stable owner actor id (must be registered in the frontier)
        #[arg(long)]
        owner: String,
        /// Path to the owner's Ed25519 private key (hex-encoded)
        #[arg(long)]
        key: PathBuf,
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
    /// Incrementally deposit a frontier's new events to a hub via the
    /// owner-authenticated append endpoint (`POST /entries/{vfr}/append`),
    /// instead of re-publishing the whole snapshot. Computes the delta vs the
    /// hub's current event-log tail, signs the batch under the owner key, and
    /// posts only the new records. Owner-deposit path: it does not run the
    /// Evidence-CI accept gate (a reviewer accept still does).
    Append {
        /// Path to the local frontier (`.vela/` repo or frontier.json).
        frontier: PathBuf,
        /// Hub base URL (e.g. https://vela-hub.fly.dev).
        #[arg(long)]
        to: String,
        /// Path to the owner's Ed25519 private key (hex-encoded).
        #[arg(long)]
        key: PathBuf,
        /// Cap the number of new records pushed this run (0 = all).
        #[arg(long, default_value_t = 0)]
        limit: usize,
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
        /// Hub base URL.
        #[arg(long, default_value = "https://vela-hub.fly.dev")]
        to: String,
        /// Path to the proposer's Ed25519 private key (hex-encoded).
        #[arg(long)]
        key: PathBuf,
        /// Proposer actor id (e.g. `reviewer:alice` or `agent:my-bot`).
        #[arg(long)]
        actor: String,
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
        /// Output path for the pulled frontier. With --transitive, this
        /// is the directory dependencies are also written into; without
        /// it, this is the file path the primary lands at.
        #[arg(long)]
        out: PathBuf,
        /// v0.8: also pull every cross-frontier dependency the primary
        /// declares, recursively, verifying each pinned snapshot.
        #[arg(long)]
        transitive: bool,
        /// v0.8: maximum recursion depth when --transitive is set.
        /// Primary is depth 0; its direct deps are depth 1.
        #[arg(long, default_value = "4")]
        depth: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GovernanceAction {
    /// Construct a new governance policy from CLI flags and write it
    /// to `--out`. The policy id (`vgp_*`) is derived from the
    /// canonical bytes of the policy body.
    Init {
        /// Frontier path the policy will govern.
        frontier: PathBuf,
        /// Threshold for the standard rotate quorum.
        #[arg(long)]
        threshold: u32,
        /// Comma-separated list of eligible actor ids.
        #[arg(long, value_delimiter = ',')]
        eligible: Vec<String>,
        /// Whether this is a bootstrap policy (owner_epoch = 0,
        /// bootstrap_epoch = 0). When set, `current_owner_counts`
        /// is permitted to be `true`; this is the only way a
        /// freshly published frontier can authorize its first
        /// rotation.
        #[arg(long)]
        bootstrap: bool,
        /// Owner epoch this policy applies to. Defaults to 0 when
        /// `--bootstrap` is set, otherwise required to be >= 1.
        #[arg(long)]
        owner_epoch: Option<u64>,
        /// Whether the current owner counts toward the rotate
        /// quorum. Only permitted (and only sensible) for bootstrap
        /// policies; the v0.144 validator rejects otherwise.
        #[arg(long)]
        current_owner_counts: bool,
        /// Attestation TTL in hours (default 168).
        #[arg(long, default_value = "168")]
        attestation_ttl_hours: u32,
        /// Output path for the policy JSON. When omitted, the
        /// policy is printed to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Read a policy JSON file and pretty-print its core fields.
    Show {
        /// Path to a policy JSON file.
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate a policy JSON file against the v0.144 rules and
    /// re-derive its content address. Exits non-zero on violation.
    Validate {
        /// Path to a policy JSON file.
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum HubFederationAction {
    /// Fetch + verify the latest checkpoint from each source and
    /// compute cross-source consensus on `(registry_root,
    /// sequence)`.
    ///
    /// Sources are `--source <id>=<url>` pairs. The `<id>` is a
    /// free-form label (typically the hub id); the `<url>` is
    /// either `https://...` pointing at the checkpoint JSON or
    /// `file://...` pointing at a local file. At least two
    /// sources are required.
    Status {
        #[arg(long = "source", value_delimiter = ',')]
        sources: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum CheckpointAction {
    /// Build and sign a new registry checkpoint.
    Create {
        /// Local registry file path (e.g. `~/.vela/registry/entries.json`).
        #[arg(long)]
        from: PathBuf,
        /// Hub operator identifier (free-form).
        #[arg(long)]
        hub_id: String,
        /// Sequence number. Use 0 for the first checkpoint.
        #[arg(long)]
        sequence: u64,
        /// Optional `vrc_*` id of the predecessor checkpoint.
        #[arg(long)]
        previous: Option<String>,
        /// Hub operator's Ed25519 private key.
        #[arg(long)]
        key: PathBuf,
        /// Output path.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a checkpoint against a registry: re-derive id,
    /// re-compute root, verify signature.
    Verify {
        /// Checkpoint JSON file.
        checkpoint: PathBuf,
        /// Registry file the checkpoint claims to summarize.
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum OwnerRotateGovernedAction {
    /// Construct a `vop_*` proposal for a specific rotation and
    /// write it to `--out`. The proposal binds frontier id, old
    /// owner id+pubkey, new owner id+pubkey, target owner epoch,
    /// previous registry entry hash, governance policy id,
    /// reason, expiry, and nonce. Governance attesters sign the
    /// canonical preimage of this object.
    Propose {
        frontier: PathBuf,
        #[arg(long)]
        old_owner: String,
        #[arg(long)]
        new_owner: String,
        /// Path to the new owner's public key (used to derive the
        /// pubkey hex; the corresponding private key is supplied
        /// at `apply` time).
        #[arg(long)]
        new_pubkey_hex: String,
        #[arg(long)]
        target_epoch: u64,
        #[arg(long)]
        previous_entry_hash: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "168")]
        ttl_hours: u32,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Sign a proposal's preimage with the attester's key. Writes
    /// or extends an attestation bundle at `--bundle`. Idempotent
    /// on `(attester_id, proposal_id)` pairs: re-signing replaces
    /// the previous entry under the same id.
    Attest {
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        attester_id: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify the bundle satisfies the policy's rotate_quorum
    /// (signatures valid, attesters eligible + unrevoked, distinct
    /// signers >= threshold, proposal not expired), then execute
    /// the v0.138 owner-rotate mutation under the new owner key.
    Apply {
        frontier: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        /// New owner's private key. Must derive to the pubkey
        /// declared in the proposal's `new_owner_pubkey`.
        #[arg(long)]
        new_key: PathBuf,
        #[arg(long)]
        locator: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GapsAction {
    /// Rank candidate gap review leads
    Rank {
        frontier: PathBuf,
        #[arg(long, default_value = "10")]
        top: usize,
        #[arg(long)]
        domain: Option<String>,
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
pub(crate) enum EntityAction {
    /// List the bundled lookup table.
    List {
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
        /// Assertion type. One of: mechanism, therapeutic, diagnostic, epidemiological, observational, review, methodological, computational, theoretical, negative
        #[arg(long, default_value = "mechanism")]
        r#type: String,
        /// Source label for the finding
        #[arg(long, default_value = "manual finding")]
        source: String,
        /// Source type. One of: published_paper, preprint, clinical_trial, lab_notebook, model_output, expert_assertion, database_record
        #[arg(long, default_value = "expert_assertion")]
        source_type: String,
        /// Author/reviewer identifier
        #[arg(long)]
        author: String,
        /// Initial confidence score from 0.0 to 1.0
        #[arg(long, default_value = "0.3")]
        confidence: f64,
        /// Evidence type. One of: experimental, observational, computational, theoretical, meta_analysis, systematic_review, case_report
        #[arg(long, default_value = "theoretical")]
        evidence_type: String,
        /// Entities as comma-separated name:type pairs. Entity types: gene, protein, compound, disease, cell_type, organism, pathway, assay, anatomical_structure, particle, instrument, dataset, quantity, other
        #[arg(long, default_value = "")]
        entities: String,
        /// Mark manually supplied entities as curator-reviewed
        #[arg(long)]
        entities_reviewed: bool,
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
        /// v0.11: PubMed ID
        #[arg(long)]
        pmid: Option<String>,
        /// v0.11: Publication year
        #[arg(long)]
        year: Option<i32>,
        /// v0.11: Journal name
        #[arg(long)]
        journal: Option<String>,
        /// v0.11: Generic source URL when none of the structured identifiers fit
        #[arg(long)]
        url: Option<String>,
        /// v0.11: Source-paper authors as semicolon-separated list (distinct from --author which is the curating Vela actor)
        #[arg(long)]
        source_authors: Option<String>,
        /// v0.11: Conditions/scope text. Replaces the placeholder otherwise written. Should describe scope boundaries (species, dosing, age range, model, etc.)
        #[arg(long)]
        conditions_text: Option<String>,
        /// v0.11: Verified species as semicolon-separated list (e.g. "Mus musculus;Homo sapiens")
        #[arg(long)]
        species: Option<String>,
        /// v0.11: Mark the finding as in vivo
        #[arg(long)]
        in_vivo: bool,
        /// v0.11: Mark the finding as in vitro
        #[arg(long)]
        in_vitro: bool,
        /// v0.11: Mark the finding as having human data
        #[arg(long)]
        human_data: bool,
        /// v0.11: Mark the finding as a clinical trial
        #[arg(long)]
        clinical_trial: bool,
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
        /// New entities (`name:type` pairs, comma-separated)
        #[arg(long, default_value = "")]
        entities: String,
        /// DOI of the source artifact
        #[arg(long)]
        doi: Option<String>,
        /// PubMed ID
        #[arg(long)]
        pmid: Option<String>,
        /// Publication year
        #[arg(long)]
        year: Option<i32>,
        /// Journal name
        #[arg(long)]
        journal: Option<String>,
        /// Generic source URL
        #[arg(long)]
        url: Option<String>,
        /// Source-paper authors (semicolon-separated)
        #[arg(long)]
        source_authors: Option<String>,
        /// Conditions/scope text
        #[arg(long)]
        conditions_text: Option<String>,
        /// Verified species (semicolon-separated)
        #[arg(long)]
        species: Option<String>,
        #[arg(long)]
        in_vivo: bool,
        #[arg(long)]
        in_vitro: bool,
        #[arg(long)]
        human_data: bool,
        #[arg(long)]
        clinical_trial: bool,
        #[arg(long)]
        json: bool,
        /// Immediately accept and apply the proposal locally
        #[arg(long)]
        apply: bool,
    },
    /// v0.38: Set or revise the Pearlian causal type and study-design
    /// grade for a finding. Appends an `assertion.reinterpreted_causal`
    /// event capturing the prior reading, the new reading, and the
    /// reviewer who re-graded. Pre-v0.38 findings carry no causal
    /// metadata; the first call materializes both fields.
    CausalSet {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// `vf_<id>` of the finding to re-grade.
        finding_id: String,
        /// Causal claim kind: correlation | mediation | intervention.
        #[arg(long)]
        claim: String,
        /// Optional study-design grade: rct | quasi_experimental |
        /// observational | theoretical.
        #[arg(long)]
        grade: Option<String>,
        /// Reviewer/curator id (must match a registered actor under
        /// `--strict`). Recorded on the appended event.
        #[arg(long)]
        actor: String,
        /// One-paragraph reason. Becomes the event's `reason` field
        /// and ships with the proposal.
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
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
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        reason: String,
        /// Path to the reviewer's Ed25519 private key (hex seed). REQUIRED
        /// when the reviewer is registered with a public key.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Reject one proposal
    Reject {
        frontier: PathBuf,
        proposal_id: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SourceAdapterAction {
    /// Run a source adapter over a frontier-owned ingest plan
    Run {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Adapter id. Currently: clinicaltrials-gov-v2 or regulatory-documents-v1
        adapter: String,
        /// Stable actor id recorded on generated proposals
        #[arg(long)]
        actor: String,
        /// Restrict to source ingest entry ids
        #[arg(long = "entry")]
        entries: Vec<String>,
        /// Restrict to P0, P1, or P2 entries
        #[arg(long)]
        priority: Option<String>,
        /// Include entries marked excluded
        #[arg(long)]
        include_excluded: bool,
        /// Continue when one source record fails
        #[arg(long)]
        allow_partial: bool,
        /// Report planned work without writing packets, proposals, or run files
        #[arg(long)]
        dry_run: bool,
        /// Read saved source fixtures from this directory
        #[arg(long)]
        input_dir: Option<PathBuf>,
        /// Apply artifact proposals while leaving truth changes pending
        #[arg(long)]
        apply_artifacts: bool,
        /// Also write fetched source records into the local source inbox.
        #[arg(long)]
        write_inbox: bool,
        /// Emit JSON to stdout
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum RuntimeAdapterAction {
    /// Normalize an external runtime export into reviewable frontier proposals
    Run {
        /// Frontier JSON file or Vela repo
        frontier: PathBuf,
        /// Adapter id. Currently: scienceclaw-artifact-v1 or agent-discourse-v1
        adapter: String,
        /// External runtime export JSON file or directory
        #[arg(long)]
        input: PathBuf,
        /// Stable actor id recorded on generated proposals
        #[arg(long)]
        actor: String,
        /// Report planned work without writing packets, proposals, or run files
        #[arg(long)]
        dry_run: bool,
        /// Apply artifact proposals while leaving truth changes pending
        #[arg(long)]
        apply_artifacts: bool,
        /// Also write runtime artifacts into the local source inbox.
        #[arg(long)]
        write_inbox: bool,
        /// Emit JSON to stdout
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum BridgeKitAction {
    /// Validate one packet JSON file or a directory of packet JSON files
    Validate {
        /// Packet JSON file or directory
        source: PathBuf,
        /// Emit JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// v0.108.3: Verify that DOIs and PMIDs claimed in a Carina
    /// packet's artifact locators and candidate-claim source_refs
    /// actually resolve through Crossref / PubMed eutils. Closes
    /// part of THREAT_MODEL.md A6 (citation poisoning: a fabricated
    /// DOI passes structural validation today). Network call;
    /// skips identifiers if the upstream is unreachable.
    VerifyProvenance {
        /// Packet JSON file
        packet: PathBuf,
        /// Emit JSON to stdout
        #[arg(long)]
        json: bool,
        /// v0.126: cross-source agreement pass. For each artifact /
        /// candidate-claim that resolves through more than one
        /// upstream source (Crossref + PubMed + S2 + ArXiv), compare
        /// the title and first-author last-name. Disagreement
        /// surfaces as a `disagreement` consensus signal. Closes
        /// more of THREAT_MODEL.md A6 (citation poisoning).
        #[arg(long = "cross-check")]
        cross_check: bool,
    },
}
