//! Source identity resolver for the local source inbox.
//!
//! Resolution supports source identity. It does not create evidence atoms and
//! does not update accepted frontier state.

use crate::source_inbox::{self, SourceInboxAddOptions, SourceInboxRecord, SourceInboxState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SOURCE_RESOLUTION_SCHEMA: &str = "vela.source_resolution.v0.1";
pub const SOURCE_CACHE_SCHEMA: &str = "vela.source_metadata_cache.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceResolveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmcid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nct: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<PathBuf>,
    pub fetch_metadata: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceResolveResult {
    pub ok: bool,
    pub schema: String,
    pub input_kind: String,
    pub normalized_locator: String,
    pub source_type: String,
    pub title: String,
    pub resolution_status: String,
    pub record: SourceInboxRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_path: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceImportReport {
    pub ok: bool,
    pub schema: String,
    pub frontier_path: String,
    pub input_path: String,
    pub format: String,
    pub created: usize,
    pub existing: usize,
    pub invalid: usize,
    pub needs_review: usize,
    #[serde(default)]
    pub created_record_ids: Vec<String>,
    #[serde(default)]
    pub existing_locators: Vec<String>,
    #[serde(default)]
    pub rejected_rows: Vec<RejectedImportRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedImportRow {
    pub row_number: usize,
    pub raw: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct NormalizedSource {
    input_kind: String,
    locator: String,
    source_type: String,
    title: String,
    content_hash: Option<String>,
    metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
struct ImportRow {
    row_number: usize,
    raw: String,
    title: Option<String>,
    locator: String,
    source_type: Option<String>,
    risk_class: Option<String>,
    notes: Vec<String>,
}

pub fn resolve_into_inbox(
    frontier_path: &Path,
    request: SourceResolveRequest,
) -> Result<SourceResolveResult, String> {
    let root = source_inbox::repo_root(frontier_path)?;
    let mut normalized = normalize_request(&request)?;
    let mut caveats =
        vec!["metadata supports source identity only; it is not scientific evidence".to_string()];
    let mut resolution_status = "unresolved_metadata".to_string();
    let mut cache_path = None;

    if request.fetch_metadata {
        let fetch_root = root.clone();
        let fetch_source = normalized.clone();
        let fetch_result = std::thread::spawn(move || fetch_metadata(&fetch_root, &fetch_source))
            .join()
            .map_err(|_| "metadata fetch worker panicked".to_string())?;
        match fetch_result {
            Ok(Some(fetched)) => {
                resolution_status = "fetched_metadata".to_string();
                if let Some(title) = fetched.title {
                    normalized.title = title;
                }
                normalized.metadata.extend(fetched.metadata);
                cache_path = Some(fetched.cache_path);
            }
            Ok(None) => {
                caveats.push("no live metadata adapter for this source kind".to_string());
            }
            Err(err) => {
                caveats.push(format!("metadata fetch failed: {err}"));
            }
        }
    }

    normalized.metadata.insert(
        "source_resolver_schema".to_string(),
        json!(SOURCE_RESOLUTION_SCHEMA),
    );
    normalized.metadata.insert(
        "input_kind".to_string(),
        json!(normalized.input_kind.clone()),
    );
    normalized.metadata.insert(
        "resolution_status".to_string(),
        json!(resolution_status.clone()),
    );
    normalized.metadata.insert(
        "metadata_caveat".to_string(),
        json!("source identity support only; not scientific support"),
    );

    let record = source_inbox::add_record(
        &root,
        SourceInboxAddOptions {
            source_id: None,
            title: normalized.title.clone(),
            locator: normalized.locator.clone(),
            source_type: normalized.source_type.clone(),
            state: SourceInboxState::Discovered,
            risk_class: "source_repair".to_string(),
            content_hash: normalized.content_hash.clone(),
            notes: vec!["Resolved into source inbox as source identity support.".to_string()],
            metadata: normalized.metadata.clone(),
        },
    )?;

    Ok(SourceResolveResult {
        ok: true,
        schema: SOURCE_RESOLUTION_SCHEMA.to_string(),
        input_kind: normalized.input_kind,
        normalized_locator: normalized.locator,
        source_type: normalized.source_type,
        title: normalized.title,
        resolution_status,
        record,
        cache_path,
        metadata: normalized.metadata,
        caveats,
    })
}

pub fn import_into_inbox(
    frontier_path: &Path,
    input_path: &Path,
    format: Option<&str>,
) -> Result<SourceImportReport, String> {
    let root = source_inbox::repo_root(frontier_path)?;
    let format = format
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| infer_import_format(input_path));
    let rows = if input_path.is_dir() {
        parse_directory_rows(input_path)?
    } else {
        let body = fs::read_to_string(input_path)
            .map_err(|e| format!("read source import {}: {e}", input_path.display()))?;
        parse_import_rows(&body, &format)?
    };
    let existing_records = source_inbox::list_records(&root)?;
    let mut seen_locators = existing_records
        .records
        .iter()
        .map(|record| record.locator.clone())
        .collect::<BTreeSet<_>>();
    let mut created_record_ids = Vec::new();
    let mut existing_locators = Vec::new();
    let mut rejected_rows = Vec::new();

    for row in rows {
        match import_one_row(&root, &row, &mut seen_locators) {
            Ok(ImportRowOutcome::Created(record_id)) => created_record_ids.push(record_id),
            Ok(ImportRowOutcome::Existing(locator)) => existing_locators.push(locator),
            Err(reason) => rejected_rows.push(RejectedImportRow {
                row_number: row.row_number,
                raw: row.raw,
                reason,
            }),
        }
    }

    let rejected_path = if rejected_rows.is_empty() {
        None
    } else {
        Some(write_rejected_rows(
            &root,
            input_path,
            &format,
            &rejected_rows,
        )?)
    };

    let created = created_record_ids.len();
    let existing = existing_locators.len();
    let invalid = rejected_rows.len();
    Ok(SourceImportReport {
        ok: invalid == 0,
        schema: "vela.source_inbox_import.v0.1".to_string(),
        frontier_path: root.display().to_string(),
        input_path: input_path.display().to_string(),
        format,
        created,
        existing,
        invalid,
        needs_review: created,
        created_record_ids,
        existing_locators,
        rejected_rows,
        rejected_path,
    })
}

enum ImportRowOutcome {
    Created(String),
    Existing(String),
}

fn import_one_row(
    root: &Path,
    row: &ImportRow,
    seen_locators: &mut BTreeSet<String>,
) -> Result<ImportRowOutcome, String> {
    let request = request_from_locator(&row.locator)?;
    let mut normalized = normalize_request(&request)?;
    if seen_locators.contains(&normalized.locator) {
        return Ok(ImportRowOutcome::Existing(normalized.locator));
    }
    if let Some(title) = row
        .title
        .as_ref()
        .and_then(|title| clean_import_text(title))
    {
        normalized.title = title;
    }
    if let Some(source_type) = row
        .source_type
        .as_ref()
        .and_then(|source_type| clean_import_text(source_type))
    {
        normalized.source_type = source_type;
    }
    let risk_class = row
        .risk_class
        .as_ref()
        .and_then(|risk| clean_import_text(risk))
        .unwrap_or_else(|| "source_repair".to_string());
    normalized.metadata.insert(
        "source_resolver_schema".to_string(),
        json!(SOURCE_RESOLUTION_SCHEMA),
    );
    normalized.metadata.insert(
        "input_kind".to_string(),
        json!(normalized.input_kind.clone()),
    );
    normalized.metadata.insert(
        "resolution_status".to_string(),
        json!("unresolved_metadata"),
    );
    normalized.metadata.insert(
        "metadata_caveat".to_string(),
        json!("source identity support only; not scientific support"),
    );
    normalized
        .metadata
        .insert("imported_from_batch".to_string(), json!(true));
    let mut notes = row
        .notes
        .iter()
        .filter_map(|note| clean_import_text(note))
        .collect::<Vec<_>>();
    notes.push("Imported source record. Review before treating as evidence.".to_string());
    let record = source_inbox::add_record(
        root,
        SourceInboxAddOptions {
            source_id: None,
            title: normalized.title.clone(),
            locator: normalized.locator.clone(),
            source_type: normalized.source_type.clone(),
            state: SourceInboxState::Discovered,
            risk_class,
            content_hash: normalized.content_hash.clone(),
            notes,
            metadata: normalized.metadata.clone(),
        },
    )?;
    seen_locators.insert(record.locator.clone());
    Ok(ImportRowOutcome::Created(record.id))
}

fn normalize_request(request: &SourceResolveRequest) -> Result<NormalizedSource, String> {
    let present = [
        request.doi.as_ref().map(|_| "doi"),
        request.pmid.as_ref().map(|_| "pmid"),
        request.pmcid.as_ref().map(|_| "pmcid"),
        request.nct.as_ref().map(|_| "nct"),
        request.url.as_ref().map(|_| "url"),
        request.local_path.as_ref().map(|_| "path"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if present.len() != 1 {
        return Err(
            "source-inbox resolve requires exactly one of --doi, --pmid, --pmcid, --nct, --url, or --path"
                .to_string(),
        );
    }
    if let Some(value) = &request.doi {
        return normalize_doi(value);
    }
    if let Some(value) = &request.pmid {
        return normalize_pmid(value);
    }
    if let Some(value) = &request.pmcid {
        return normalize_pmcid(value);
    }
    if let Some(value) = &request.nct {
        return normalize_nct(value);
    }
    if let Some(value) = &request.url {
        return normalize_url(value);
    }
    if let Some(value) = &request.local_path {
        return normalize_file(value);
    }
    unreachable!("present checked above")
}

fn normalize_doi(raw: &str) -> Result<NormalizedSource, String> {
    let doi = raw
        .trim()
        .trim_start_matches("doi:")
        .trim_start_matches("DOI:")
        .trim_start_matches("https://doi.org/")
        .trim_start_matches("http://doi.org/")
        .trim()
        .to_ascii_lowercase();
    if !(doi.starts_with("10.") && doi.contains('/')) {
        return Err(format!("invalid DOI `{raw}`"));
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("doi".to_string(), json!(doi.clone()));
    Ok(NormalizedSource {
        input_kind: "doi".to_string(),
        locator: format!("doi:{doi}"),
        source_type: "paper".to_string(),
        title: format!("DOI {doi}"),
        content_hash: None,
        metadata,
    })
}

fn normalize_pmid(raw: &str) -> Result<NormalizedSource, String> {
    let pmid = raw
        .trim()
        .trim_start_matches("pmid:")
        .trim_start_matches("PMID:")
        .trim();
    if pmid.is_empty() || !pmid.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid PMID `{raw}`"));
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("pmid".to_string(), json!(pmid));
    Ok(NormalizedSource {
        input_kind: "pmid".to_string(),
        locator: format!("pmid:{pmid}"),
        source_type: "paper".to_string(),
        title: format!("PMID {pmid}"),
        content_hash: None,
        metadata,
    })
}

fn normalize_pmcid(raw: &str) -> Result<NormalizedSource, String> {
    let normalized = raw
        .trim()
        .trim_start_matches("pmcid:")
        .trim_start_matches("PMCID:")
        .trim()
        .to_ascii_uppercase();
    let stripped = normalized.trim_start_matches("PMC").trim();
    if stripped.is_empty() || !stripped.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid PMCID `{raw}`"));
    }
    let pmcid = format!("PMC{stripped}");
    let mut metadata = BTreeMap::new();
    metadata.insert("pmcid".to_string(), json!(pmcid.clone()));
    Ok(NormalizedSource {
        input_kind: "pmcid".to_string(),
        locator: format!("pmcid:{pmcid}"),
        source_type: "paper".to_string(),
        title: format!("PMCID {pmcid}"),
        content_hash: None,
        metadata,
    })
}

fn normalize_nct(raw: &str) -> Result<NormalizedSource, String> {
    let stripped = raw
        .trim()
        .trim_start_matches("nct:")
        .trim_start_matches("NCT:")
        .trim()
        .to_ascii_uppercase();
    if stripped.len() != 11
        || !stripped.starts_with("NCT")
        || !stripped[3..].chars().all(|ch| ch.is_ascii_digit())
    {
        return Err(format!("invalid ClinicalTrials.gov NCT id `{raw}`"));
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("nct_id".to_string(), json!(stripped.clone()));
    Ok(NormalizedSource {
        input_kind: "nct".to_string(),
        locator: format!("nct:{stripped}"),
        source_type: "registry_record".to_string(),
        title: format!("ClinicalTrials.gov {stripped}"),
        content_hash: None,
        metadata,
    })
}

fn normalize_url(raw: &str) -> Result<NormalizedSource, String> {
    let url = raw.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("invalid URL `{raw}`"));
    }
    let github_repo = is_github_repo_url(url);
    let mut metadata = BTreeMap::new();
    metadata.insert("url".to_string(), json!(url));
    if github_repo {
        metadata.insert("github_repository".to_string(), json!(true));
    }
    Ok(NormalizedSource {
        input_kind: if github_repo { "github" } else { "url" }.to_string(),
        locator: url.to_string(),
        source_type: if github_repo {
            "code_repository"
        } else {
            "web_page"
        }
        .to_string(),
        title: if github_repo {
            format!("GitHub repository {url}")
        } else {
            format!("URL {url}")
        },
        content_hash: None,
        metadata,
    })
}

fn normalize_file(path: &Path) -> Result<NormalizedSource, String> {
    if !path.is_file() {
        return Err(format!(
            "local source path does not exist: {}",
            path.display()
        ));
    }
    let mut file =
        fs::File::open(path).map_err(|e| format!("open local source {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("read local source {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let hash = format!("sha256:{}", hex::encode(hasher.finalize()));
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut metadata = BTreeMap::new();
    metadata.insert("path".to_string(), json!(canonical.display().to_string()));
    Ok(NormalizedSource {
        input_kind: "path".to_string(),
        locator: format!("path:{}", canonical.display()),
        source_type: "local_file".to_string(),
        title: canonical
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| format!("Local file {name}"))
            .unwrap_or_else(|| format!("Local file {}", canonical.display())),
        content_hash: Some(hash),
        metadata,
    })
}

#[derive(Debug)]
struct FetchedMetadata {
    title: Option<String>,
    metadata: BTreeMap<String, Value>,
    cache_path: String,
}

fn fetch_metadata(
    root: &Path,
    normalized: &NormalizedSource,
) -> Result<Option<FetchedMetadata>, String> {
    let Some(url) = metadata_url(normalized) else {
        return Ok(None);
    };
    let client = reqwest::blocking::Client::builder()
        .user_agent("vela-source-resolver/0.1")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let body = client
        .get(&url)
        .send()
        .map_err(|e| format!("GET {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GET {url}: {e}"))?
        .text()
        .map_err(|e| format!("read {url}: {e}"))?;
    let parsed: Value =
        serde_json::from_str(&body).map_err(|e| format!("parse metadata JSON from {url}: {e}"))?;
    let hash = format!("sha256:{}", hex::encode(Sha256::digest(body.as_bytes())));
    let title = title_from_metadata(&normalized.input_kind, &parsed);
    let cache_path = write_cache(root, &url, &hash, &parsed)?;
    let mut metadata = BTreeMap::new();
    metadata.insert("metadata_url".to_string(), json!(url));
    metadata.insert("metadata_hash".to_string(), json!(hash));
    metadata.insert("fetched_metadata".to_string(), parsed);
    Ok(Some(FetchedMetadata {
        title,
        metadata,
        cache_path,
    }))
}

fn metadata_url(normalized: &NormalizedSource) -> Option<String> {
    match normalized.input_kind.as_str() {
        "doi" => normalized
            .metadata
            .get("doi")
            .and_then(Value::as_str)
            .map(|doi| format!("https://api.crossref.org/works/{}", urlencoding::encode(doi))),
        "pmid" => normalized.metadata.get("pmid").and_then(Value::as_str).map(|pmid| {
            format!("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi?db=pubmed&id={pmid}&retmode=json")
        }),
        "nct" => normalized.metadata.get("nct_id").and_then(Value::as_str).map(|nct| {
            format!("https://clinicaltrials.gov/api/v2/studies/{nct}")
        }),
        _ => None,
    }
}

fn title_from_metadata(kind: &str, value: &Value) -> Option<String> {
    match kind {
        "doi" => value
            .pointer("/message/title/0")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        "pmid" => value
            .pointer("/result")
            .and_then(Value::as_object)
            .and_then(|result| {
                result
                    .iter()
                    .find(|(key, _)| key.as_str() != "uids")
                    .and_then(|(_, entry)| entry.get("title"))
                    .and_then(Value::as_str)
            })
            .map(ToString::to_string),
        "nct" => value
            .pointer("/protocolSection/identificationModule/briefTitle")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        _ => None,
    }
}

fn write_cache(
    root: &Path,
    source_url: &str,
    hash: &str,
    metadata: &Value,
) -> Result<String, String> {
    let cache_dir = root.join(".vela").join("source-cache");
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("create source cache {}: {e}", cache_dir.display()))?;
    let id = hex::encode(Sha256::digest(source_url.as_bytes()));
    let path = cache_dir.join(format!("{}.json", &id[..16]));
    let payload = json!({
        "schema": SOURCE_CACHE_SCHEMA,
        "source_url": source_url,
        "fetched_at": chrono::Utc::now().to_rfc3339(),
        "metadata_hash": hash,
        "caveat": "metadata supports source identity only; it is not scientific evidence",
        "metadata": metadata,
    });
    let body = serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("serialize source cache: {e}"))?;
    fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write source cache {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

fn is_github_repo_url(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
    else {
        return false;
    };
    let segments = rest
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    segments.len() >= 2
}

fn infer_import_format(path: &Path) -> String {
    if path.is_dir() {
        return "directory".to_string();
    }
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "csv" => "csv".to_string(),
        "bib" | "bibtex" => "bibtex".to_string(),
        "ris" => "ris".to_string(),
        _ => "text".to_string(),
    }
}

fn parse_import_rows(body: &str, format: &str) -> Result<Vec<ImportRow>, String> {
    match format {
        "text" | "txt" => Ok(parse_text_rows(body)),
        "csv" => parse_csv_rows(body),
        "bib" | "bibtex" => Ok(parse_bibtex_rows(body)),
        "ris" => Ok(parse_ris_rows(body)),
        other => Err(format!(
            "source import format must be text, csv, bibtex, ris, or directory; got `{other}`"
        )),
    }
}

fn parse_directory_rows(path: &Path) -> Result<Vec<ImportRow>, String> {
    let mut entries = fs::read_dir(path)
        .map_err(|e| format!("read source directory {}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read source directory entry {}: {e}", path.display()))?;
    entries.sort_by_key(|entry| entry.path());
    let mut rows = Vec::new();
    for (idx, entry) in entries.into_iter().enumerate() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        rows.push(ImportRow {
            row_number: idx + 1,
            raw: path.display().to_string(),
            title: Some(format!("Local file {name}")),
            locator: format!("path:{}", path.display()),
            source_type: Some("local_file".to_string()),
            risk_class: None,
            notes: vec!["Imported from local source directory.".to_string()],
        });
    }
    Ok(rows)
}

fn parse_text_rows(body: &str) -> Vec<ImportRow> {
    body.lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let value = line.trim();
            if value.is_empty() || value.starts_with('#') {
                return None;
            }
            Some(ImportRow {
                row_number: idx + 1,
                raw: line.to_string(),
                title: None,
                locator: value.to_string(),
                source_type: None,
                risk_class: None,
                notes: Vec::new(),
            })
        })
        .collect()
}

fn parse_csv_rows(body: &str) -> Result<Vec<ImportRow>, String> {
    let mut lines = body.lines().enumerate();
    let Some((_, header)) = lines.next() else {
        return Ok(Vec::new());
    };
    let headers = parse_csv_line(header);
    let mut rows = Vec::new();
    for (idx, line) in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cells = parse_csv_line(line);
        let mut by_header = BTreeMap::new();
        for (header, cell) in headers.iter().zip(cells.iter()) {
            by_header.insert(header.trim().to_ascii_lowercase(), cell.trim().to_string());
        }
        let locator = by_header
            .get("locator")
            .cloned()
            .or_else(|| by_header.get("doi").map(|value| format!("doi:{value}")))
            .or_else(|| by_header.get("pmid").map(|value| format!("pmid:{value}")))
            .or_else(|| by_header.get("nct").map(|value| format!("nct:{value}")))
            .unwrap_or_default();
        rows.push(ImportRow {
            row_number: idx + 1,
            raw: line.to_string(),
            title: by_header.get("title").cloned(),
            locator,
            source_type: by_header.get("source_type").cloned(),
            risk_class: by_header.get("risk_class").cloned(),
            notes: by_header
                .get("notes")
                .and_then(|notes| clean_import_text(notes))
                .map(|note| vec![note])
                .unwrap_or_default(),
        });
    }
    Ok(rows)
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur.trim().to_string());
    out
}

fn parse_bibtex_rows(body: &str) -> Vec<ImportRow> {
    body.split('@')
        .enumerate()
        .filter_map(|(idx, entry)| {
            if !entry.contains('{') {
                return None;
            }
            let title = bib_value(entry, "title");
            let locator = bib_value(entry, "doi")
                .map(|doi| format!("doi:{doi}"))
                .or_else(|| bib_value(entry, "pmid").map(|pmid| format!("pmid:{pmid}")))
                .or_else(|| bib_value(entry, "url"));
            locator.map(|locator| ImportRow {
                row_number: idx + 1,
                raw: format!("@{}", entry.trim()),
                title,
                locator,
                source_type: Some("paper".to_string()),
                risk_class: None,
                notes: Vec::new(),
            })
        })
        .collect()
}

fn bib_value(entry: &str, field: &str) -> Option<String> {
    let field_lower = field.to_ascii_lowercase();
    for line in entry.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim().to_ascii_lowercase() != field_lower {
            continue;
        }
        let value = value
            .trim()
            .trim_end_matches(',')
            .trim()
            .trim_matches('{')
            .trim_matches('}')
            .trim_matches('"')
            .trim()
            .to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn parse_ris_rows(body: &str) -> Vec<ImportRow> {
    body.split("\nER  -")
        .enumerate()
        .filter_map(|(idx, entry)| {
            let mut title = None;
            let mut doi = None;
            let mut url = None;
            let mut pmid = None;
            for line in entry.lines() {
                let Some((tag, value)) = line.split_once("  -") else {
                    continue;
                };
                let value = value.trim();
                match tag.trim() {
                    "TI" | "T1" => title = Some(value.to_string()),
                    "DO" => doi = Some(value.to_string()),
                    "UR" | "L1" => url = Some(value.to_string()),
                    "AN" if value.to_ascii_uppercase().starts_with("PMID") => {
                        pmid = value.split(':').nth(1).map(|v| v.trim().to_string())
                    }
                    _ => {}
                }
            }
            let locator = doi
                .map(|doi| format!("doi:{doi}"))
                .or_else(|| pmid.map(|pmid| format!("pmid:{pmid}")))
                .or(url);
            locator.map(|locator| ImportRow {
                row_number: idx + 1,
                raw: entry.trim().to_string(),
                title,
                locator,
                source_type: Some("paper".to_string()),
                risk_class: None,
                notes: Vec::new(),
            })
        })
        .collect()
}

fn request_from_locator(locator: &str) -> Result<SourceResolveRequest, String> {
    let value = locator.trim();
    if value.is_empty() {
        return Err("missing locator".to_string());
    }
    let lower = value.to_ascii_lowercase();
    let empty = || SourceResolveRequest {
        doi: None,
        pmid: None,
        pmcid: None,
        nct: None,
        url: None,
        local_path: None,
        fetch_metadata: false,
    };
    if lower.starts_with("doi:")
        || lower.starts_with("https://doi.org/")
        || lower.starts_with("http://doi.org/")
        || (lower.starts_with("10.") && lower.contains('/'))
    {
        return Ok(SourceResolveRequest {
            doi: Some(value.to_string()),
            ..empty()
        });
    }
    if lower.starts_with("pmid:") || value.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(SourceResolveRequest {
            pmid: Some(value.to_string()),
            ..empty()
        });
    }
    if lower.starts_with("pmcid:") || lower.starts_with("pmc") {
        return Ok(SourceResolveRequest {
            pmcid: Some(value.to_string()),
            ..empty()
        });
    }
    if lower.starts_with("nct:") || lower.starts_with("nct") {
        return Ok(SourceResolveRequest {
            nct: Some(value.to_string()),
            ..empty()
        });
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(SourceResolveRequest {
            url: Some(value.to_string()),
            ..empty()
        });
    }
    let path = value.strip_prefix("path:").unwrap_or(value);
    Ok(SourceResolveRequest {
        local_path: Some(PathBuf::from(path)),
        ..empty()
    })
}

fn write_rejected_rows(
    root: &Path,
    input_path: &Path,
    format: &str,
    rows: &[RejectedImportRow],
) -> Result<String, String> {
    let path = source_inbox::rejected_imports_path(root);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open rejected imports {}: {e}", path.display()))?;
    for row in rows {
        let payload = json!({
            "schema": "vela.source_inbox_rejected_import.v0.1",
            "rejected_at": chrono::Utc::now().to_rfc3339(),
            "input_path": input_path.display().to_string(),
            "format": format,
            "row_number": row.row_number,
            "raw": row.raw,
            "reason": row.reason,
        });
        let line = serde_json::to_string(&payload)
            .map_err(|e| format!("serialize rejected import row: {e}"))?;
        writeln!(file, "{line}")
            .map_err(|e| format!("write rejected imports {}: {e}", path.display()))?;
    }
    Ok(path.display().to_string())
}

fn clean_import_text(value: &str) -> Option<String> {
    let trimmed = value.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vela_protocol::frontier_repo::{self, InitOptions};

    #[test]
    fn normalizes_source_identifiers() {
        assert_eq!(
            normalize_doi("https://doi.org/10.1056/NEJMoa2212948")
                .unwrap()
                .locator,
            "doi:10.1056/nejmoa2212948"
        );
        assert_eq!(
            normalize_pmid("PMID: 12345678").unwrap().locator,
            "pmid:12345678"
        );
        assert_eq!(normalize_pmcid("pmc1234").unwrap().locator, "pmcid:PMC1234");
        assert_eq!(
            normalize_nct("nct03887455").unwrap().locator,
            "nct:NCT03887455"
        );
        assert_eq!(
            normalize_url("https://github.com/openai/symphony")
                .unwrap()
                .source_type,
            "code_repository"
        );
    }

    #[test]
    fn resolver_adds_discovered_source_record() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Resolver frontier",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        let result = resolve_into_inbox(
            tmp.path(),
            SourceResolveRequest {
                doi: Some("10.1056/NEJMoa2212948".to_string()),
                pmid: None,
                pmcid: None,
                nct: None,
                url: None,
                local_path: None,
                fetch_metadata: false,
            },
        )
        .unwrap();
        assert!(result.ok);
        assert_eq!(result.resolution_status, "unresolved_metadata");
        assert_eq!(result.record.state, SourceInboxState::Discovered);
        assert_eq!(result.record.locator, "doi:10.1056/nejmoa2212948");
        assert!(result.record.metadata.contains_key("metadata_caveat"));
    }
}
