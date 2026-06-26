pub const DB_SCHEMA: &str = "vela.frontier_index_db.v0.1";
pub const REPORT_SCHEMA: &str = "vela.frontier_index_db_report.v0.1";
pub const RELEASE_SLICE: &str = "v0.652";
pub const CANONICAL_STATE: &str = "frontier files and accepted events";

pub const TABLES: &[&str] = &[
    "frontiers",
    "findings",
    "sources",
    "evidence_atoms",
    "links",
    "events",
    "proposals",
    "tasks",
    "proof_files",
    "proof_status",
    "score_returns",
    "return_material",
    "benchmark_rows",
    "benchmark_summaries",
    "answer_paths",
    "answer_path_findings",
    "answer_path_sources",
    "source_health",
    "evidence_atom_locators",
    "index_metadata",
];

pub const CREATE_STATEMENTS: &[&str] = &[
    "create table index_metadata (
        key text primary key,
        value text not null
    )",
    "create table frontiers (
        id text primary key,
        path text not null,
        title text,
        schema text,
        content_hash text,
        indexed_at text
    )",
    "create table findings (
        id text primary key,
        frontier_id text not null,
        assertion text,
        assertion_type text,
        confidence real,
        review_state text,
        source_count integer not null,
        link_count integer not null,
        raw_json text not null
    )",
    "create table sources (
        id text primary key,
        frontier_id text not null,
        title text,
        kind text,
        locator text,
        doi text,
        pmid text,
        content_hash text,
        status text,
        raw_json text not null
    )",
    "create table evidence_atoms (
        id text primary key,
        frontier_id text not null,
        finding_id text,
        source_id text,
        locator text,
        evidence_type text,
        raw_json text not null
    )",
    "create table links (
        id text primary key,
        frontier_id text not null,
        source_finding_id text not null,
        target_finding_id text,
        relation text,
        mechanism text,
        status text,
        raw_json text not null
    )",
    "create table events (
        id text primary key,
        frontier_id text not null,
        kind text,
        target_id text,
        reviewer text,
        timestamp text,
        raw_json text not null
    )",
    "create table proposals (
        id text primary key,
        frontier_id text not null,
        kind text,
        status text,
        target_id text,
        raw_json text not null
    )",
    "create table tasks (
        id text primary key,
        frontier_id text not null,
        status text,
        priority text,
        raw_json text not null
    )",
    "create table proof_files (
        path text primary key,
        frontier_id text not null,
        role text,
        sha256 text not null,
        size_bytes integer not null
    )",
    "create table proof_status (
        id text primary key,
        frontier_id text not null,
        proof_dir text not null,
        packet_format text,
        packet_version text,
        replay_ok text not null,
        replay_status text,
        replay_hash_match text not null,
        check_summary_records integer not null,
        source_table_rows integer not null,
        strict_clean text not null,
        manifest_sha256 text not null,
        raw_json text not null
    )",
    "create table score_returns (
        path text primary key,
        schema text,
        review_status text,
        local_only text,
        sha256 text not null,
        raw_json text not null
    )",
    "create table return_material (
        id text primary key,
        source_path text not null,
        schema text,
        status text,
        material_type text not null,
        local_only text not null,
        valid text not null,
        writes_frontier_state text not null,
        external_validation text not null,
        draft_event_count integer not null,
        sha256 text not null,
        raw_json text not null
    )",
    "create table benchmark_rows (
        id text primary key,
        source_path text not null,
        schema text,
        kind text,
        raw_json text not null
    )",
    "create table benchmark_summaries (
        id text primary key,
        source_path text not null,
        schema text,
        suite_id text,
        artifact_kind text not null,
        task_count integer,
        answer_count integer,
        visibility text,
        local_only text not null,
        score_total integer,
        score_max integer,
        sha256 text not null,
        raw_json text not null
    )",
    "create table answer_paths (
        answer_id text primary key,
        frontier_id text not null,
        question text,
        answer text,
        interpretation text,
        stable_sources integer not null,
        preserved_locator_only_sources integer not null,
        missing_locator_sources integer not null,
        source_count integer not null,
        evidence_atom_count integer not null,
        supporting_count integer not null,
        counterweight_count integer not null,
        raw_json text not null
    )",
    "create table answer_path_findings (
        id text primary key,
        frontier_id text not null,
        answer_id text not null,
        finding_id text not null,
        role text not null,
        assertion text,
        confidence real,
        reviewed text,
        raw_json text not null
    )",
    "create table answer_path_sources (
        id text primary key,
        frontier_id text not null,
        answer_id text not null,
        source_id text not null,
        locator_health text,
        evidence_atom_count integer not null,
        finding_count integer not null,
        raw_json text not null
    )",
    "create table source_health (
        id text primary key,
        frontier_id text not null,
        answer_id text not null,
        source_id text not null,
        locator_health text,
        stable_source text not null,
        evidence_atom_count integer not null,
        raw_json text not null
    )",
    "create table evidence_atom_locators (
        id text primary key,
        frontier_id text not null,
        answer_id text not null,
        evidence_atom_id text not null,
        finding_id text,
        source_id text,
        locator text,
        human_verified text,
        supports_or_challenges text,
        raw_json text not null
    )",
    "create index findings_assertion_idx on findings(assertion)",
    "create index evidence_atoms_finding_idx on evidence_atoms(finding_id)",
    "create index evidence_atoms_source_idx on evidence_atoms(source_id)",
    "create index links_source_idx on links(source_finding_id)",
    "create index links_target_idx on links(target_finding_id)",
    "create index events_target_idx on events(target_id)",
    "create index proposals_target_idx on proposals(target_id)",
    "create index proof_status_frontier_idx on proof_status(frontier_id)",
    "create index answer_path_findings_answer_idx on answer_path_findings(answer_id)",
    "create index answer_path_findings_finding_idx on answer_path_findings(finding_id)",
    "create index answer_path_sources_answer_idx on answer_path_sources(answer_id)",
    "create index answer_path_sources_source_idx on answer_path_sources(source_id)",
    "create index source_health_source_idx on source_health(source_id)",
    "create index evidence_atom_locators_answer_idx on evidence_atom_locators(answer_id)",
    "create index evidence_atom_locators_atom_idx on evidence_atom_locators(evidence_atom_id)",
    "create index return_material_type_idx on return_material(material_type)",
    "create index return_material_source_idx on return_material(source_path)",
    "create index benchmark_summaries_suite_idx on benchmark_summaries(suite_id)",
    "create index benchmark_summaries_kind_idx on benchmark_summaries(artifact_kind)",
];
