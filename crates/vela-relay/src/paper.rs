//! v0.142: paper-to-vela end-to-end. Resolves a paper identifier
//! (`doi:*`, `arxiv:*`, `pmid:*`, `s2:*`) through the corresponding
//! upstream registry, normalizes the response into a minimal
//! Carina-style proposal envelope, and emits the envelope as JSON.
//!
//! The substrate's full verifier logic — cross-source agreement,
//! provenance scoring, etc. — lives in `vela-protocol`'s
//! `bridge-kit verify-provenance` path. This binary's job is to be
//! the discoverable surface that turns a single identifier into a
//! `vpr_*` proposal envelope a reviewer can pipe into
//! `vela artifact-to-state` for substrate-side acceptance.
//!
//! The envelope shape is intentionally minimal: schema, vpr_id
//! (sha256 of canonical bytes), kind (`paper.ingested`), target
//! (`source:<identifier>`), and a `paper` payload carrying
//! title + authors + year + the identifier round-trip.

use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Result of paper-to-vela: a normalized proposal envelope and a
/// few inspectable fields the caller may print outside of `--json`.
pub struct PaperEnvelope {
    pub envelope: Value,
    pub title: Option<String>,
    pub year: Option<u32>,
    pub first_author: Option<String>,
    pub source: &'static str,
}

/// Build the envelope and compute its content-addressed id.
fn build_envelope(
    identifier: &str,
    source: &'static str,
    title: Option<String>,
    authors: Vec<String>,
    year: Option<u32>,
) -> PaperEnvelope {
    let first_author = authors.first().cloned();
    let payload = json!({
        "identifier": identifier,
        "source": source,
        "title": title,
        "authors": authors,
        "year": year,
    });
    let preimage_bytes = serde_json::to_vec(&json!({
        "kind": "paper.ingested",
        "target_id": format!("source:{identifier}"),
        "payload": payload,
    }))
    .expect("serialize preimage");
    let digest = Sha256::digest(&preimage_bytes);
    let vpr_id = format!("vpr_{}", &hex::encode(digest)[..16]);
    let envelope = json!({
        "schema": "vela.proposal.v0.1",
        "vpr_id": vpr_id,
        "kind": "paper.ingested",
        "target": {
            "type": "source",
            "id": format!("source:{identifier}"),
        },
        "actor": {
            "id": "agent:vela-relay",
            "type": "agent",
        },
        "created_at": Utc::now().to_rfc3339(),
        "reason": format!("vela-relay paper-to-vela: {identifier} resolved via {source}"),
        "payload": payload,
    });
    PaperEnvelope {
        envelope,
        title,
        year,
        first_author,
        source,
    }
}

/// Dispatch a `<prefix>:<id>` identifier to the right upstream.
pub async fn paper_to_vela(identifier: &str) -> Result<PaperEnvelope, String> {
    let trimmed = identifier.trim();
    let (prefix, rest) = trimmed.split_once(':').ok_or_else(|| {
        format!("identifier must start with `doi:`, `arxiv:`, `pmid:`, or `s2:`; got `{trimmed}`")
    })?;
    let client = reqwest::Client::builder()
        .user_agent(format!(
            "vela-relay/{} (+https://github.com/vela-science/vela)",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("build http client: {e}"))?;
    match prefix.to_ascii_lowercase().as_str() {
        "doi" => fetch_crossref(&client, rest, trimmed).await,
        "arxiv" => fetch_arxiv(&client, rest, trimmed).await,
        "pmid" => fetch_pubmed(&client, rest, trimmed).await,
        "s2" => fetch_s2(&client, rest, trimmed).await,
        other => Err(format!(
            "unsupported prefix `{other}`. Valid: doi, arxiv, pmid, s2"
        )),
    }
}

async fn fetch_crossref(
    client: &reqwest::Client,
    doi: &str,
    full_id: &str,
) -> Result<PaperEnvelope, String> {
    let url = format!("https://api.crossref.org/works/{}", urlencoded_segment(doi));
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Crossref request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Crossref returned status {}", resp.status()));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("Crossref body parse failed: {e}"))?;
    let work = body.get("message").unwrap_or(&body);
    let title = work
        .get("title")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .map(str::to_string);
    let authors: Vec<String> = work
        .get("author")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let given = a.get("given").and_then(Value::as_str).unwrap_or("");
                    let family = a.get("family").and_then(Value::as_str).unwrap_or("");
                    let name = format!("{given} {family}").trim().to_string();
                    if name.is_empty() { None } else { Some(name) }
                })
                .collect()
        })
        .unwrap_or_default();
    let year = work
        .get("issued")
        .and_then(|v| v.get("date-parts"))
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(Value::as_u64)
        .and_then(|y| u32::try_from(y).ok());
    Ok(build_envelope(full_id, "crossref", title, authors, year))
}

async fn fetch_arxiv(
    client: &reqwest::Client,
    arxiv_id: &str,
    full_id: &str,
) -> Result<PaperEnvelope, String> {
    let url = format!(
        "https://export.arxiv.org/api/query?id_list={}",
        urlencoded_segment(arxiv_id)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("ArXiv request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("ArXiv returned status {}", resp.status()));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| format!("ArXiv body read failed: {e}"))?;
    // Minimal Atom parser: extract <title> of the first entry,
    // <name> children of each <author>, and the year from <published>.
    let entry_start = body
        .find("<entry>")
        .ok_or_else(|| "ArXiv response missing <entry>; the id may not exist".to_string())?;
    let entry = &body[entry_start..];
    let title = extract_xml_tag(entry, "title").map(|s| s.trim().to_string());
    let mut authors = Vec::new();
    let mut rest = entry;
    while let Some(pos) = rest.find("<author>") {
        let after = &rest[pos + "<author>".len()..];
        let close = after
            .find("</author>")
            .ok_or_else(|| "ArXiv response malformed: <author> not closed".to_string())?;
        let chunk = &after[..close];
        if let Some(name) = extract_xml_tag(chunk, "name") {
            authors.push(name.trim().to_string());
        }
        rest = &after[close..];
    }
    let year = extract_xml_tag(entry, "published")
        .and_then(|s| s.get(..4).map(str::to_string))
        .and_then(|s| s.parse::<u32>().ok());
    Ok(build_envelope(full_id, "arxiv", title, authors, year))
}

async fn fetch_pubmed(
    client: &reqwest::Client,
    pmid: &str,
    full_id: &str,
) -> Result<PaperEnvelope, String> {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi?db=pubmed&id={}&retmode=json",
        urlencoded_segment(pmid)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("PubMed request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("PubMed returned status {}", resp.status()));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("PubMed body parse failed: {e}"))?;
    let result = body
        .get("result")
        .and_then(|r| r.get(pmid))
        .ok_or_else(|| format!("PubMed response missing result.{pmid}"))?;
    let title = result
        .get("title")
        .and_then(Value::as_str)
        .map(str::to_string);
    let authors: Vec<String> = result
        .get("authors")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let year = result
        .get("pubdate")
        .and_then(Value::as_str)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u32>().ok());
    Ok(build_envelope(full_id, "pubmed", title, authors, year))
}

async fn fetch_s2(
    client: &reqwest::Client,
    s2_id: &str,
    full_id: &str,
) -> Result<PaperEnvelope, String> {
    let url = format!(
        "https://api.semanticscholar.org/graph/v1/paper/{}?fields=title,authors,year",
        urlencoded_segment(s2_id)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Semantic Scholar request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "Semantic Scholar returned status {}",
            resp.status()
        ));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("Semantic Scholar body parse failed: {e}"))?;
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .map(str::to_string);
    let authors: Vec<String> = body
        .get("authors")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let year = body
        .get("year")
        .and_then(Value::as_u64)
        .and_then(|y| u32::try_from(y).ok());
    Ok(build_envelope(
        full_id,
        "semantic-scholar",
        title,
        authors,
        year,
    ))
}

/// Minimal URL-segment encoder: lets `/`, `.`, alphanumerics through;
/// percent-encodes everything else. Sufficient for DOI / arxiv / PMID
/// / s2 ids which are all `[A-Za-z0-9./-]`.
fn urlencoded_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b':') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Extract the text content of the first occurrence of `<tag>...</tag>`
/// in `xml`. Returns `None` if the tag is missing. Doesn't decode
/// XML entities — sufficient for the Atom fields we read.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?;
    let after = &xml[start + open.len()..];
    let end = after.find(&close)?;
    Some(after[..end].to_string())
}
