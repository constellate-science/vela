//! `cmd_source_fetch` and its handler logic, split out of cli.rs.

use crate::cli::fail_return;

use std::path::Path;

use reqwest::Client;
use serde_json::{Value, json};

/// v0.57: Fetch metadata + abstract for an external source.
/// Cache-first: if a cache hit exists and `--refresh` was not
/// passed, return the cached JSON. Otherwise call the right
/// upstream (Crossref / NCBI eutils / ClinicalTrials.gov v2).
pub(crate) async fn cmd_source_fetch(
    identifier: &str,
    cache_root: Option<&Path>,
    out_path: Option<&Path>,
    refresh: bool,
    _json_output: bool,
) {
    use sha2::{Digest, Sha256};

    let normalized = normalize_source_identifier(identifier);
    let cache_path = cache_root.map(|root| {
        let hash = format!("{:x}", Sha256::digest(normalized.as_bytes()));
        root.join("sources")
            .join("cache")
            .join(format!("{hash}.json"))
    });

    if !refresh
        && let Some(p) = cache_path.as_ref()
        && p.is_file()
    {
        let body = std::fs::read_to_string(p)
            .unwrap_or_else(|e| fail_return(&format!("read cache {}: {e}", p.display())));
        emit_source_fetch_result(&body, out_path);
        return;
    }

    let result = fetch_source_metadata(&normalized).await;
    let json = match result {
        Ok(value) => serde_json::to_string_pretty(&value)
            .unwrap_or_else(|e| fail_return(&format!("serialize fetched record: {e}"))),
        Err(e) => fail_return(&format!("source-fetch '{identifier}': {e}")),
    };

    if let Some(p) = cache_path.as_ref() {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| fail_return(&format!("mkdir {}: {e}", parent.display())));
        }
        std::fs::write(p, &json)
            .unwrap_or_else(|e| fail_return(&format!("write cache {}: {e}", p.display())));
    }
    emit_source_fetch_result(&json, out_path);
}

fn emit_source_fetch_result(body: &str, out_path: Option<&Path>) {
    if let Some(p) = out_path {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(p, body)
            .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", p.display())));
    } else {
        println!("{body}");
    }
}

fn normalize_source_identifier(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("doi:")
        || trimmed.starts_with("pmid:")
        || trimmed.starts_with("nct:")
        || trimmed.starts_with("pmc:")
    {
        return trimmed.to_string();
    }
    if trimmed.starts_with("10.") {
        return format!("doi:{trimmed}");
    }
    if trimmed.starts_with("NCT") || trimmed.starts_with("nct") {
        return format!(
            "nct:{}",
            trimmed
                .to_uppercase()
                .trim_start_matches("NCT")
                .to_string()
                .split_at(0)
                .0
        );
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return format!("pmid:{trimmed}");
    }
    trimmed.to_string()
}

async fn fetch_source_metadata(normalized: &str) -> Result<Value, String> {
    let client = Client::builder()
        .user_agent("vela/0.66.0 (vela-source-fetch; +https://vela-science.fly.dev)")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    if let Some(rest) = normalized.strip_prefix("doi:") {
        // v0.66: DOI primary path is Crossref. If Crossref returns
        // an empty abstract (common for NEJM, JAMA, gated journals),
        // fall through to a PubMed lookup via DOI -> PMID and merge
        // the abstract back into the Crossref record. Keeps Crossref
        // metadata (title, year, journal, authors) authoritative;
        // only fills the abstract gap.
        let mut record = fetch_via_crossref(&client, rest).await?;
        let crossref_abstract = record
            .get("abstract")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if crossref_abstract.is_empty()
            && let Some(pmid) = resolve_doi_to_pmid(&client, rest).await
            && let Ok(pubmed_record) = fetch_via_pubmed(&client, &pmid).await
        {
            let pubmed_abstract = pubmed_record
                .get("abstract")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !pubmed_abstract.is_empty()
                && let Some(obj) = record.as_object_mut()
            {
                obj.insert("abstract".to_string(), Value::String(pubmed_abstract));
                obj.insert(
                    "abstract_source".to_string(),
                    Value::String(format!("pubmed:{pmid}")),
                );
            }
        }
        return Ok(record);
    }
    if let Some(rest) = normalized.strip_prefix("pmid:") {
        return fetch_via_pubmed(&client, rest).await;
    }
    if let Some(rest) = normalized.strip_prefix("nct:") {
        return fetch_via_ctgov(&client, rest).await;
    }
    Err(format!(
        "unsupported source identifier '{normalized}'. Use doi:, pmid:, or nct: prefix."
    ))
}

/// v0.66: resolve a DOI to a PubMed PMID via eutils esearch. Returns
/// None if no PMID is found or the lookup fails. The abstract-fallback
/// path uses this to enrich Crossref records that have empty abstracts.
async fn resolve_doi_to_pmid(client: &Client, doi: &str) -> Option<String> {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term={}[doi]&retmode=json",
        urlencoding::encode(doi)
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: Value = resp.json().await.ok()?;
    let id_list = body.pointer("/esearchresult/idlist")?.as_array()?;
    if id_list.len() != 1 {
        // Refuse ambiguous matches; the substrate would rather have
        // an empty abstract than the wrong paper's text.
        return None;
    }
    id_list.first()?.as_str().map(|s| s.to_string())
}

async fn fetch_via_crossref(client: &Client, doi: &str) -> Result<Value, String> {
    let url = format!("https://api.crossref.org/works/{doi}");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("crossref get: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("crossref returned {}", resp.status()));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("crossref json: {e}"))?;
    let work = body.get("message").cloned().unwrap_or(Value::Null);
    let title = work
        .get("title")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let abstract_html = work
        .get("abstract")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let abstract_text = strip_jats_tags(&abstract_html);
    let year = work
        .get("issued")
        .and_then(|v| v.get("date-parts"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_i64());
    let journal = work
        .get("container-title")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let authors = work
        .get("author")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let given = a.get("given").and_then(|v| v.as_str()).unwrap_or("");
                    let family = a.get("family").and_then(|v| v.as_str()).unwrap_or("");
                    let combined = format!("{given} {family}").trim().to_string();
                    if combined.is_empty() {
                        None
                    } else {
                        Some(combined)
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "schema": "vela.source_fetch.v0.1",
        "identifier": format!("doi:{doi}"),
        "source": "crossref",
        "title": title,
        "abstract": abstract_text,
        "year": year,
        "journal": journal,
        "authors": authors,
        "retrieved_at": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn fetch_via_pubmed(client: &Client, pmid: &str) -> Result<Value, String> {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi?db=pubmed&id={pmid}&retmode=xml"
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("pubmed get: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("pubmed returned {}", resp.status()));
    }
    let xml = resp.text().await.map_err(|e| format!("pubmed text: {e}"))?;
    let title = extract_xml_text(&xml, "<ArticleTitle>", "</ArticleTitle>");
    let abstract_text = extract_xml_text(&xml, "<AbstractText>", "</AbstractText>");
    let year = extract_xml_text(&xml, "<Year>", "</Year>")
        .parse::<i64>()
        .ok();
    let journal = extract_xml_text(&xml, "<Title>", "</Title>");
    Ok(json!({
        "schema": "vela.source_fetch.v0.1",
        "identifier": format!("pmid:{pmid}"),
        "source": "pubmed",
        "title": title,
        "abstract": abstract_text,
        "year": year,
        "journal": journal,
        "authors": Vec::<String>::new(),
        "retrieved_at": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn fetch_via_ctgov(client: &Client, nct: &str) -> Result<Value, String> {
    let nct_clean = nct.trim();
    let nct_id = if nct_clean.starts_with("NCT") || nct_clean.starts_with("nct") {
        nct_clean.to_uppercase()
    } else {
        format!("NCT{nct_clean}")
    };
    let url = format!("https://clinicaltrials.gov/api/v2/studies/{nct_id}");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("ctgov get: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("ctgov returned {}", resp.status()));
    }
    let body: Value = resp.json().await.map_err(|e| format!("ctgov json: {e}"))?;
    let title = body
        .pointer("/protocolSection/identificationModule/briefTitle")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let abstract_text = body
        .pointer("/protocolSection/descriptionModule/briefSummary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let phase = body
        .pointer("/protocolSection/designModule/phases")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(json!({
        "schema": "vela.source_fetch.v0.1",
        "identifier": format!("nct:{nct_id}"),
        "source": "clinicaltrials.gov",
        "title": title,
        "abstract": abstract_text,
        "year": Value::Null,
        "journal": phase,
        "authors": Vec::<String>::new(),
        "retrieved_at": chrono::Utc::now().to_rfc3339(),
    }))
}

fn extract_xml_text(xml: &str, open: &str, close: &str) -> String {
    if let Some(start) = xml.find(open) {
        let after = &xml[start + open.len()..];
        if let Some(end) = after.find(close) {
            return after[..end].trim().to_string();
        }
    }
    String::new()
}

fn strip_jats_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}
