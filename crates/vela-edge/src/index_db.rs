use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{Connection, Row, SqliteConnection};

use crate::index_db_schema;

fn read_json(path: &Path) -> Result<Value, String> {
    let body = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn raw_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| format!("serialize json: {e}"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sha256_path(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

fn semantic_fingerprint(
    frontier_hash: &str,
    counts: &Value,
    integrity: &Value,
) -> Result<String, String> {
    let payload = json!({
        "schema": index_db_schema::DB_SCHEMA,
        "release_slice": index_db_schema::RELEASE_SLICE,
        "frontier_hash": frontier_hash,
        "counts": counts,
        "integrity": integrity,
        "authority": {
            "database_is_authority": false,
            "canonical_state": index_db_schema::CANONICAL_STATE,
        },
    });
    Ok(format!(
        "sha256:{}",
        sha256_bytes(raw_json(&payload)?.as_bytes())
    ))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn array_field<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn object_field<'a>(value: &'a Value, key: &str) -> Option<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object)
}

fn canonical_frontier_dir(input: &Path) -> PathBuf {
    if input.file_name().and_then(|s| s.to_str()) == Some("frontier.json") {
        input.parent().unwrap_or(input).to_path_buf()
    } else {
        input.to_path_buf()
    }
}

fn workspace_root() -> PathBuf {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("benchmarks").is_dir() {
            return dir;
        }
        if !dir.pop() {
            return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        }
    }
}

fn display_path(path: &Path) -> String {
    let root = workspace_root();
    path.strip_prefix(&root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn sqlite_url(path: &Path) -> String {
    format!("sqlite://{}", path.to_string_lossy())
}

async fn connect(path: &Path, create: bool) -> Result<SqliteConnection, String> {
    let options = SqliteConnectOptions::from_str(&sqlite_url(path))
        .map_err(|e| format!("sqlite path {}: {e}", path.display()))?
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal);
    SqliteConnection::connect_with(&options)
        .await
        .map_err(|e| format!("open sqlite {}: {e}", path.display()))
}

async fn table_count(conn: &mut SqliteConnection, table: &str) -> Result<i64, String> {
    let sql = format!("select count(*) as count from {table}");
    let row = sqlx::query(&sql)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("count {table}: {e}"))?;
    Ok(row.get::<i64, _>("count"))
}

fn index_paths(frontier_dir: &Path) -> (PathBuf, PathBuf) {
    let index_dir = frontier_dir.join(".vela").join("index");
    (
        index_dir.join("frontier-index.sqlite"),
        index_dir.join("frontier-index.report.v1.json"),
    )
}

pub async fn build(frontier: &Path) -> Result<Value, String> {
    let frontier_dir = canonical_frontier_dir(frontier);
    let frontier_path = frontier_dir.join("frontier.json");
    if !frontier_path.is_file() {
        return Err(format!(
            "missing frontier file: {}",
            frontier_path.display()
        ));
    }
    let frontier_json = read_json(&frontier_path)?;
    let frontier_id = string_field(&frontier_json, "frontier_id")
        .unwrap_or_else(|| {
            frontier_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("frontier")
        })
        .to_string();
    let (db_path, report_path) = index_paths(&frontier_dir);
    let index_dir = db_path
        .parent()
        .ok_or_else(|| format!("missing index dir for {}", db_path.display()))?;
    fs::create_dir_all(index_dir).map_err(|e| format!("create {}: {e}", index_dir.display()))?;
    let tmp_path = db_path.with_extension("sqlite.tmp");
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|e| format!("remove {}: {e}", tmp_path.display()))?;
    }

    let indexed_at = Utc::now().to_rfc3339();
    let frontier_hash = sha256_path(&frontier_path)?;
    let mut conn = connect(&tmp_path, true).await?;
    for statement in index_db_schema::CREATE_STATEMENTS {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .map_err(|e| format!("create frontier index schema: {e}"))?;
    }
    insert_metadata(&mut conn, &indexed_at).await?;
    insert_frontier(
        &mut conn,
        &frontier_id,
        &frontier_dir,
        &frontier_json,
        &indexed_at,
    )
    .await?;
    insert_findings(
        &mut conn,
        &frontier_id,
        array_field(&frontier_json, "findings"),
    )
    .await?;
    insert_sources(
        &mut conn,
        &frontier_id,
        array_field(&frontier_json, "sources"),
    )
    .await?;
    insert_evidence_atoms(
        &mut conn,
        &frontier_id,
        array_field(&frontier_json, "evidence_atoms"),
    )
    .await?;
    insert_links(
        &mut conn,
        &frontier_id,
        array_field(&frontier_json, "findings"),
    )
    .await?;
    insert_events(
        &mut conn,
        &frontier_id,
        array_field(&frontier_json, "events"),
    )
    .await?;
    insert_proposals(
        &mut conn,
        &frontier_id,
        array_field(&frontier_json, "proposals"),
    )
    .await?;
    insert_tasks(&mut conn, &frontier_id, &frontier_dir).await?;
    insert_proof_files(&mut conn, &frontier_id, &frontier_dir).await?;
    insert_proof_status(&mut conn, &frontier_id, &frontier_dir).await?;
    insert_score_returns(&mut conn).await?;
    insert_return_material(&mut conn).await?;
    insert_benchmark_rows(&mut conn).await?;
    insert_benchmark_summaries(&mut conn).await?;
    insert_answer_path_indexes(&mut conn, &frontier_id, &frontier_dir).await?;
    conn.close()
        .await
        .map_err(|e| format!("close sqlite {}: {e}", tmp_path.display()))?;
    fs::rename(&tmp_path, &db_path).map_err(|e| format!("replace {}: {e}", db_path.display()))?;

    let mut conn = connect(&db_path, false).await?;
    let counts = counts(&mut conn).await?;
    conn.close()
        .await
        .map_err(|e| format!("close sqlite {}: {e}", db_path.display()))?;
    let integrity = integrity(&frontier_json, &counts);
    let semantic_fingerprint = semantic_fingerprint(&frontier_hash, &counts, &integrity)?;
    let report = json!({
        "command": "index build",
        "schema": index_db_schema::REPORT_SCHEMA,
        "release_slice": index_db_schema::RELEASE_SLICE,
        "frontier": {
            "id": frontier_id,
            "path": display_path(&frontier_dir),
            "frontier_json": display_path(&frontier_path),
        },
        "database": {
            "path": display_path(&db_path),
            "sha256": sha256_path(&db_path)?,
        },
        "authority": {
            "database_is_authority": false,
            "canonical_state": index_db_schema::CANONICAL_STATE,
        },
        "determinism": {
            "semantic_fingerprint": semantic_fingerprint,
            "volatile_fields": [
                "indexed_at",
                "database.sha256"
            ],
        },
        "counts": counts,
        "integrity": integrity,
        "indexed_at": indexed_at,
    });
    fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).map_err(|e| format!("serialize report: {e}"))? + "\n",
    )
    .map_err(|e| format!("write {}: {e}", report_path.display()))?;
    Ok(report)
}

pub async fn status(frontier: &Path) -> Result<Value, String> {
    let frontier_dir = canonical_frontier_dir(frontier);
    let (db_path, report_path) = index_paths(&frontier_dir);
    if !db_path.is_file() {
        return Ok(json!({
            "command": "index status",
            "present": false,
            "frontier": display_path(&frontier_dir),
            "database": {"path": display_path(&db_path)},
            "authority": {
                "database_is_authority": false,
                "canonical_state": index_db_schema::CANONICAL_STATE,
            },
            "counts": {},
        }));
    }
    let mut conn = connect(&db_path, false).await?;
    let counts = counts(&mut conn).await?;
    let metadata = metadata(&mut conn).await?;
    conn.close()
        .await
        .map_err(|e| format!("close sqlite {}: {e}", db_path.display()))?;
    Ok(json!({
        "command": "index status",
        "present": true,
        "frontier": display_path(&frontier_dir),
        "database": {
            "path": display_path(&db_path),
            "sha256": sha256_path(&db_path)?,
        },
        "report": {
            "path": display_path(&report_path),
            "present": report_path.is_file(),
        },
        "authority": {
            "database_is_authority": metadata.get("database_is_authority").and_then(Value::as_str) == Some("true"),
            "canonical_state": index_db_schema::CANONICAL_STATE,
        },
        "counts": counts,
        "metadata": metadata,
    }))
}

pub async fn query(frontier: &Path, kind: &str, q: &str, limit: usize) -> Result<Value, String> {
    let frontier_dir = canonical_frontier_dir(frontier);
    let (db_path, _) = index_paths(&frontier_dir);
    if !db_path.is_file() {
        return Err(format!(
            "frontier index is missing. run `vela index build {}` first",
            display_path(&frontier_dir)
        ));
    }
    let mut conn = connect(&db_path, false).await?;
    let results = match kind {
        "finding" => query_findings(&mut conn, q, limit).await?,
        "source" => query_sources(&mut conn, q, limit).await?,
        "answer_path" => query_answer_paths(&mut conn, q, limit).await?,
        "source_trail" => query_source_trails(&mut conn, q, limit).await?,
        other => {
            return Err(format!(
                "unsupported index query kind `{other}`. expected finding, source, answer_path, or source_trail"
            ));
        }
    };
    conn.close()
        .await
        .map_err(|e| format!("close sqlite {}: {e}", db_path.display()))?;
    Ok(json!({
        "command": "index query",
        "kind": kind,
        "q": q,
        "limit": limit,
        "result_count": results.len(),
        "results": results,
        "authority": {
            "database_is_authority": false,
            "canonical_state": index_db_schema::CANONICAL_STATE,
        },
    }))
}

async fn insert_metadata(conn: &mut SqliteConnection, indexed_at: &str) -> Result<(), String> {
    let rows = [
        ("schema", index_db_schema::DB_SCHEMA),
        ("release_slice", index_db_schema::RELEASE_SLICE),
        ("database_is_authority", "false"),
        ("canonical_state", index_db_schema::CANONICAL_STATE),
        ("indexed_at", indexed_at),
    ];
    for (key, value) in rows {
        sqlx::query("insert into index_metadata(key, value) values (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("insert index metadata: {e}"))?;
    }
    Ok(())
}

async fn insert_frontier(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    frontier_dir: &Path,
    frontier: &Value,
    indexed_at: &str,
) -> Result<(), String> {
    let meta = object_field(frontier, "frontier");
    let title = meta
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .or_else(|| string_field(frontier, "name"));
    sqlx::query(
        "insert into frontiers(id, path, title, schema, content_hash, indexed_at)
        values (?, ?, ?, ?, ?, ?)",
    )
    .bind(frontier_id)
    .bind(display_path(frontier_dir))
    .bind(title)
    .bind(string_field(frontier, "schema"))
    .bind(sha256_path(&frontier_dir.join("frontier.json"))?)
    .bind(indexed_at)
    .execute(conn)
    .await
    .map_err(|e| format!("insert frontier: {e}"))?;
    Ok(())
}

async fn insert_findings(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    findings: &[Value],
) -> Result<(), String> {
    for finding in findings {
        let assertion = object_field(finding, "assertion");
        let confidence = object_field(finding, "confidence");
        let provenance = object_field(finding, "provenance");
        let review = provenance
            .and_then(|p| p.get("review"))
            .and_then(Value::as_object);
        let evidence = object_field(finding, "evidence");
        let reviewed = review
            .and_then(|r| r.get("reviewed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        sqlx::query(
            "insert into findings(
                id, frontier_id, assertion, assertion_type, confidence,
                review_state, source_count, link_count, raw_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(string_field(finding, "id"))
        .bind(frontier_id)
        .bind(
            assertion
                .and_then(|a| a.get("text"))
                .and_then(Value::as_str),
        )
        .bind(
            assertion
                .and_then(|a| a.get("type"))
                .and_then(Value::as_str),
        )
        .bind(
            confidence
                .and_then(|c| c.get("score"))
                .and_then(Value::as_f64),
        )
        .bind(if reviewed { "reviewed" } else { "unreviewed" })
        .bind(
            evidence
                .and_then(|e| e.get("evidence_spans"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0) as i64,
        )
        .bind(array_field(finding, "links").len() as i64)
        .bind(raw_json(finding)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert finding: {e}"))?;
    }
    Ok(())
}

async fn insert_sources(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    sources: &[Value],
) -> Result<(), String> {
    for source in sources {
        sqlx::query(
            "insert into sources(
                id, frontier_id, title, kind, locator, doi, pmid,
                content_hash, status, raw_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(string_field(source, "id"))
        .bind(frontier_id)
        .bind(string_field(source, "title"))
        .bind(string_field(source, "source_type").or_else(|| string_field(source, "kind")))
        .bind(string_field(source, "locator"))
        .bind(string_field(source, "doi"))
        .bind(string_field(source, "pmid"))
        .bind(string_field(source, "content_hash").or_else(|| string_field(source, "sha256")))
        .bind(string_field(source, "source_quality").or_else(|| string_field(source, "status")))
        .bind(raw_json(source)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert source: {e}"))?;
    }
    Ok(())
}

async fn insert_evidence_atoms(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    atoms: &[Value],
) -> Result<(), String> {
    for atom in atoms {
        sqlx::query(
            "insert into evidence_atoms(
                id, frontier_id, finding_id, source_id, locator, evidence_type, raw_json
            ) values (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(string_field(atom, "id"))
        .bind(frontier_id)
        .bind(string_field(atom, "finding_id"))
        .bind(string_field(atom, "source_id"))
        .bind(string_field(atom, "locator"))
        .bind(string_field(atom, "evidence_type"))
        .bind(raw_json(atom)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert evidence atom: {e}"))?;
    }
    Ok(())
}

async fn insert_links(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    findings: &[Value],
) -> Result<(), String> {
    for finding in findings {
        let source = string_field(finding, "id").unwrap_or("");
        for (index, link) in array_field(finding, "links").iter().enumerate() {
            let raw = json!({"source": source, "index": index, "link": link});
            let link_id = format!("vl_{}", &sha256_bytes(raw_json(&raw)?.as_bytes())[..16]);
            sqlx::query(
                "insert into links(
                    id, frontier_id, source_finding_id, target_finding_id,
                    relation, mechanism, status, raw_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(link_id)
            .bind(frontier_id)
            .bind(source)
            .bind(string_field(link, "target").or_else(|| string_field(link, "target_id")))
            .bind(string_field(link, "type").or_else(|| string_field(link, "relation")))
            .bind(string_field(link, "mechanism"))
            .bind(string_field(link, "status"))
            .bind(raw_json(&raw)?)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("insert link: {e}"))?;
        }
    }
    Ok(())
}

async fn insert_events(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    events: &[Value],
) -> Result<(), String> {
    for event in events {
        let target = object_field(event, "target");
        let actor = object_field(event, "actor");
        sqlx::query(
            "insert into events(
                id, frontier_id, kind, target_id, reviewer, timestamp, raw_json
            ) values (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(string_field(event, "id"))
        .bind(frontier_id)
        .bind(string_field(event, "kind"))
        .bind(
            target
                .and_then(|t| t.get("id"))
                .and_then(Value::as_str)
                .or_else(|| string_field(event, "target_id")),
        )
        .bind(
            actor
                .and_then(|a| a.get("id"))
                .and_then(Value::as_str)
                .or_else(|| string_field(event, "reviewer")),
        )
        .bind(string_field(event, "timestamp"))
        .bind(raw_json(event)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert event: {e}"))?;
    }
    Ok(())
}

async fn insert_proposals(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    proposals: &[Value],
) -> Result<(), String> {
    for proposal in proposals {
        let target = object_field(proposal, "target");
        sqlx::query(
            "insert into proposals(id, frontier_id, kind, status, target_id, raw_json)
            values (?, ?, ?, ?, ?, ?)",
        )
        .bind(string_field(proposal, "id"))
        .bind(frontier_id)
        .bind(string_field(proposal, "kind"))
        .bind(string_field(proposal, "status"))
        .bind(
            target
                .and_then(|t| t.get("id"))
                .and_then(Value::as_str)
                .or_else(|| string_field(proposal, "target_id")),
        )
        .bind(raw_json(proposal)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert proposal: {e}"))?;
    }
    Ok(())
}

async fn insert_tasks(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    frontier_dir: &Path,
) -> Result<(), String> {
    let task_dir = frontier_dir.join(".vela").join("tasks");
    if !task_dir.is_dir() {
        return Ok(());
    }
    for path in json_files(&task_dir) {
        let task = read_json(&path)?;
        let task_id = string_field(&task, "id")
            .map(str::to_string)
            .unwrap_or_else(|| format!("task_{}", &sha256_path(&path).unwrap_or_default()[..16]));
        sqlx::query(
            "insert into tasks(id, frontier_id, status, priority, raw_json) values (?, ?, ?, ?, ?)",
        )
        .bind(task_id)
        .bind(frontier_id)
        .bind(string_field(&task, "status"))
        .bind(string_field(&task, "priority"))
        .bind(raw_json(&task)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert task: {e}"))?;
    }
    Ok(())
}

async fn insert_proof_files(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    frontier_dir: &Path,
) -> Result<(), String> {
    let proof_dir = frontier_dir.join("proof");
    if !proof_dir.is_dir() {
        return Ok(());
    }
    for path in files(&proof_dir) {
        let proof_rel = path.strip_prefix(&proof_dir).unwrap_or(&path);
        let role = proof_rel
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_else(|| "root".to_string());
        sqlx::query(
            "insert into proof_files(path, frontier_id, role, sha256, size_bytes)
            values (?, ?, ?, ?, ?)",
        )
        .bind(display_path(&path))
        .bind(frontier_id)
        .bind(role)
        .bind(sha256_path(&path)?)
        .bind(path.metadata().map(|m| m.len() as i64).unwrap_or(0))
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert proof file: {e}"))?;
    }
    Ok(())
}

fn json_record_count(value: &Value) -> i64 {
    value
        .as_array()
        .map(|items| items.len() as i64)
        .or_else(|| value.as_object().map(|items| items.len() as i64))
        .unwrap_or(0)
}

async fn insert_proof_status(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    frontier_dir: &Path,
) -> Result<(), String> {
    let proof_dir = frontier_dir.join("proof");
    let manifest_path = proof_dir.join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(());
    }
    let manifest = read_json(&manifest_path)?;
    let replay_path = proof_dir.join("events/replay-report.json");
    let replay = if replay_path.is_file() {
        read_json(&replay_path)?
    } else {
        Value::Null
    };
    let check_summary_path = proof_dir.join("check-summary.json");
    let check_summary = if check_summary_path.is_file() {
        read_json(&check_summary_path)?
    } else {
        Value::Null
    };
    let source_table_path = proof_dir.join("source-table.json");
    let source_table = if source_table_path.is_file() {
        read_json(&source_table_path)?
    } else {
        Value::Null
    };
    let replay_hash_match = replay.get("current_hash") == replay.get("replayed_hash")
        && replay.get("current_hash").is_some();
    let raw = json!({
        "manifest": manifest,
        "replay": replay,
        "check_summary_records": json_record_count(&check_summary),
        "source_table_rows": json_record_count(&source_table),
        "claim_boundary": {
            "database_is_authority": false,
            "strict_clean": false,
        },
    });
    sqlx::query(
        "insert into proof_status(
            id, frontier_id, proof_dir, packet_format, packet_version, replay_ok,
            replay_status, replay_hash_match, check_summary_records, source_table_rows,
            strict_clean, manifest_sha256, raw_json
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(format!(
        "proof_{}",
        &sha256_bytes(display_path(&proof_dir).as_bytes())[..16]
    ))
    .bind(frontier_id)
    .bind(display_path(&proof_dir))
    .bind(string_field(&manifest, "packet_format"))
    .bind(string_field(&manifest, "packet_version"))
    .bind(if bool_field(&replay, "ok") {
        "true"
    } else {
        "false"
    })
    .bind(string_field(&replay, "status"))
    .bind(if replay_hash_match { "true" } else { "false" })
    .bind(json_record_count(&check_summary))
    .bind(json_record_count(&source_table))
    .bind("false")
    .bind(sha256_path(&manifest_path)?)
    .bind(raw_json(&raw)?)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("insert proof status: {e}"))?;
    Ok(())
}

async fn insert_score_returns(conn: &mut SqliteConnection) -> Result<(), String> {
    let dir = workspace_root().join("benchmarks/public/score-returns");
    if !dir.is_dir() {
        return Ok(());
    }
    for path in json_files(&dir) {
        let payload = read_json(&path)?;
        let scorer = string_field(&payload, "scorer_id").unwrap_or("");
        let local_only = scorer.starts_with("reviewer:will") || scorer.starts_with("reviewer:solo");
        sqlx::query(
            "insert into score_returns(path, schema, review_status, local_only, sha256, raw_json)
            values (?, ?, ?, ?, ?, ?)",
        )
        .bind(display_path(&path))
        .bind(string_field(&payload, "schema"))
        .bind(string_field(&payload, "review_status").or_else(|| string_field(&payload, "status")))
        .bind(if local_only { "true" } else { "false" })
        .bind(sha256_path(&path)?)
        .bind(raw_json(&payload)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert score return: {e}"))?;
    }
    Ok(())
}

fn score_return_paths() -> Vec<PathBuf> {
    let dir = workspace_root().join("benchmarks/public/score-returns");
    if !dir.is_dir() {
        return Vec::new();
    }
    json_files(&dir)
}

fn return_material_type(path: &Path, payload: &Value) -> &'static str {
    let schema = string_field(payload, "schema").unwrap_or("");
    let path_text = display_path(path);
    if schema.contains("review_event_drafts") || payload.get("draft_review_events").is_some() {
        "draft_review_events"
    } else if path_text.contains("import-preview") || schema.contains("validation_preview") {
        "score_return_import_preview"
    } else if path_text.contains("template") {
        "score_return_template"
    } else if schema.contains("adjudication") {
        "score_return_adjudication"
    } else {
        "score_return"
    }
}

fn return_material_local_only(payload: &Value) -> bool {
    if let Some(local_only) = payload.get("local_only").and_then(Value::as_bool) {
        return local_only;
    }
    let scorer = string_field(payload, "scorer_id")
        .or_else(|| {
            payload
                .get("scorer")
                .and_then(|scorer| scorer.get("id"))
                .and_then(Value::as_str)
        })
        .unwrap_or("");
    scorer.starts_with("reviewer:will")
        || scorer.starts_with("reviewer:solo")
        || scorer.contains("solo")
}

fn return_material_valid(payload: &Value) -> bool {
    payload
        .get("validation")
        .and_then(|validation| validation.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn return_material_writes_state(payload: &Value) -> bool {
    let Some(boundary) = payload.get("mutation_boundary") else {
        return false;
    };
    [
        "writes_frontier_state",
        "writes_review_events",
        "accepts_frontier_state",
    ]
    .iter()
    .any(|key| boundary.get(*key).and_then(Value::as_bool).unwrap_or(false))
}

fn return_material_external_validation(payload: &Value) -> bool {
    payload
        .get("claim_boundary")
        .and_then(|boundary| boundary.get("claims_external_validation"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn draft_event_count(payload: &Value) -> i64 {
    array_field(payload, "draft_review_events").len() as i64
        + array_field(payload, "rows").len() as i64
}

async fn insert_return_material(conn: &mut SqliteConnection) -> Result<(), String> {
    for path in score_return_paths() {
        let payload = read_json(&path)?;
        let path_text = display_path(&path);
        let material_id = format!("ret_{}", &sha256_bytes(path_text.as_bytes())[..16]);
        sqlx::query(
            "insert into return_material(
                id, source_path, schema, status, material_type, local_only,
                valid, writes_frontier_state, external_validation, draft_event_count,
                sha256, raw_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(material_id)
        .bind(path_text)
        .bind(string_field(&payload, "schema"))
        .bind(string_field(&payload, "review_status").or_else(|| string_field(&payload, "status")))
        .bind(return_material_type(&path, &payload))
        .bind(if return_material_local_only(&payload) {
            "true"
        } else {
            "false"
        })
        .bind(if return_material_valid(&payload) {
            "true"
        } else {
            "false"
        })
        .bind(if return_material_writes_state(&payload) {
            "true"
        } else {
            "false"
        })
        .bind(if return_material_external_validation(&payload) {
            "true"
        } else {
            "false"
        })
        .bind(draft_event_count(&payload))
        .bind(sha256_path(&path)?)
        .bind(raw_json(&payload)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert return material: {e}"))?;
    }
    Ok(())
}

async fn insert_benchmark_rows(conn: &mut SqliteConnection) -> Result<(), String> {
    let dir = workspace_root().join("benchmarks");
    if !dir.is_dir() {
        return Ok(());
    }
    for path in json_files(&dir) {
        if path
            .to_string_lossy()
            .contains("benchmarks/public/score-returns/")
        {
            continue;
        }
        let payload = read_json(&path)?;
        let path_text = display_path(&path);
        let row_id = format!("bench_{}", &sha256_bytes(path_text.as_bytes())[..16]);
        sqlx::query(
            "insert into benchmark_rows(id, source_path, schema, kind, raw_json)
            values (?, ?, ?, ?, ?)",
        )
        .bind(row_id)
        .bind(path_text)
        .bind(string_field(&payload, "schema"))
        .bind(string_field(&payload, "kind"))
        .bind(raw_json(&payload)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert benchmark row: {e}"))?;
    }
    Ok(())
}

fn benchmark_artifact_kind(path: &Path, payload: &Value) -> &'static str {
    let schema = string_field(payload, "schema").unwrap_or("");
    let path_text = display_path(path);
    if schema.contains("answer_key") || path_text.contains("answer-key") {
        "answer_key"
    } else if path_text.contains("/suites/") {
        "suite"
    } else if path_text.contains("/results/") || payload.get("aggregate").is_some() {
        "result"
    } else if path_text.contains("/baselines/") {
        "baseline"
    } else {
        "benchmark_artifact"
    }
}

fn benchmark_task_count(payload: &Value) -> Option<i64> {
    payload
        .get("task_count")
        .and_then(Value::as_i64)
        .or_else(|| Some(array_field(payload, "tasks").len() as i64).filter(|count| *count > 0))
        .or_else(|| {
            payload
                .get("summary")
                .and_then(|summary| summary.get("suite_task_count"))
                .and_then(Value::as_i64)
        })
        .or_else(|| {
            payload
                .get("aggregate")
                .and_then(|aggregate| aggregate.get("tasks"))
                .and_then(Value::as_i64)
        })
}

fn benchmark_answer_count(payload: &Value) -> Option<i64> {
    payload
        .get("answer_count")
        .and_then(Value::as_i64)
        .or_else(|| Some(array_field(payload, "answers").len() as i64).filter(|count| *count > 0))
}

fn benchmark_score_total(payload: &Value) -> Option<i64> {
    payload
        .get("aggregate")
        .and_then(|aggregate| aggregate.get("score"))
        .and_then(Value::as_i64)
        .or_else(|| {
            payload
                .get("aggregate")
                .and_then(|aggregate| aggregate.get("vela_backed_review_score"))
                .and_then(Value::as_i64)
        })
}

fn benchmark_score_max(payload: &Value) -> Option<i64> {
    payload
        .get("aggregate")
        .and_then(|aggregate| aggregate.get("max_score"))
        .and_then(Value::as_i64)
        .or_else(|| {
            let aggregate = payload.get("aggregate")?;
            let tasks = aggregate.get("tasks").and_then(Value::as_i64)?;
            let max_per_task = aggregate
                .get("max_score_per_task")
                .and_then(Value::as_i64)?;
            Some(tasks * max_per_task)
        })
}

fn benchmark_local_only(path: &Path, payload: &Value) -> bool {
    string_field(payload, "visibility") == Some("local_only")
        || display_path(path).contains(".local.")
        || payload
            .get("aggregate")
            .and_then(|aggregate| aggregate.get("local_comparison_only"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || payload
            .get("claim_boundary")
            .and_then(|boundary| boundary.get("local_scripted_rehearsal"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

async fn insert_benchmark_summaries(conn: &mut SqliteConnection) -> Result<(), String> {
    let dir = workspace_root().join("benchmarks");
    if !dir.is_dir() {
        return Ok(());
    }
    for path in json_files(&dir) {
        if path
            .to_string_lossy()
            .contains("benchmarks/public/score-returns/")
        {
            continue;
        }
        let payload = read_json(&path)?;
        let path_text = display_path(&path);
        let row_id = format!("bsum_{}", &sha256_bytes(path_text.as_bytes())[..16]);
        sqlx::query(
            "insert into benchmark_summaries(
                id, source_path, schema, suite_id, artifact_kind, task_count,
                answer_count, visibility, local_only, score_total, score_max,
                sha256, raw_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(row_id)
        .bind(path_text)
        .bind(string_field(&payload, "schema"))
        .bind(string_field(&payload, "suite_id"))
        .bind(benchmark_artifact_kind(&path, &payload))
        .bind(benchmark_task_count(&payload))
        .bind(benchmark_answer_count(&payload))
        .bind(string_field(&payload, "visibility"))
        .bind(if benchmark_local_only(&path, &payload) {
            "true"
        } else {
            "false"
        })
        .bind(benchmark_score_total(&payload))
        .bind(benchmark_score_max(&payload))
        .bind(sha256_path(&path)?)
        .bind(raw_json(&payload)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert benchmark summary: {e}"))?;
    }
    Ok(())
}

async fn insert_answer_path_indexes(
    conn: &mut SqliteConnection,
    frontier_id: &str,
    frontier_dir: &Path,
) -> Result<(), String> {
    let path = frontier_dir.join("review/answer-evidence-paths.v1.json");
    if !path.is_file() {
        return Ok(());
    }
    let payload = read_json(&path)?;
    for answer_path in array_field(&payload, "paths") {
        let answer_id = string_field(answer_path, "answer_id").unwrap_or("");
        let locator_health = answer_path.get("locator_health").unwrap_or(&Value::Null);
        let source_trails = array_field(answer_path, "source_trails");
        let evidence_atoms = array_field(answer_path, "evidence_atoms");
        let supporting_findings = array_field(answer_path, "supporting_findings");
        let counterweight_findings = array_field(answer_path, "counterweight_findings");
        sqlx::query(
            "insert into answer_paths(
                answer_id, frontier_id, question, answer, interpretation,
                stable_sources, preserved_locator_only_sources, missing_locator_sources,
                source_count, evidence_atom_count, supporting_count, counterweight_count,
                raw_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(answer_id)
        .bind(frontier_id)
        .bind(string_field(answer_path, "question"))
        .bind(string_field(answer_path, "answer"))
        .bind(string_field(answer_path, "interpretation"))
        .bind(u64_field(locator_health, "stable_sources") as i64)
        .bind(u64_field(locator_health, "preserved_locator_only_sources") as i64)
        .bind(u64_field(locator_health, "missing_locator_sources") as i64)
        .bind(source_trails.len() as i64)
        .bind(evidence_atoms.len() as i64)
        .bind(supporting_findings.len() as i64)
        .bind(counterweight_findings.len() as i64)
        .bind(raw_json(answer_path)?)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("insert answer path: {e}"))?;

        for (role, findings) in [
            ("supporting", supporting_findings),
            ("counterweight", counterweight_findings),
        ] {
            for finding in findings {
                let finding_id = string_field(finding, "finding_id").unwrap_or("");
                let row_id = format!(
                    "apf_{}",
                    &sha256_bytes(format!("{answer_id}:{role}:{finding_id}").as_bytes())[..16]
                );
                sqlx::query(
                    "insert into answer_path_findings(
                        id, frontier_id, answer_id, finding_id, role,
                        assertion, confidence, reviewed, raw_json
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(row_id)
                .bind(frontier_id)
                .bind(answer_id)
                .bind(finding_id)
                .bind(role)
                .bind(string_field(finding, "assertion"))
                .bind(finding.get("confidence").and_then(Value::as_f64))
                .bind(if bool_field(finding, "reviewed") {
                    "true"
                } else {
                    "false"
                })
                .bind(raw_json(finding)?)
                .execute(&mut *conn)
                .await
                .map_err(|e| format!("insert answer path finding: {e}"))?;
            }
        }

        for trail in source_trails {
            let source_id = string_field(trail, "source_id").unwrap_or("");
            let locator_health_text = string_field(trail, "locator_health");
            let evidence_atom_count = array_field(trail, "evidence_atom_ids").len() as i64;
            let finding_count = array_field(trail, "finding_ids").len() as i64;
            let row_id = format!(
                "aps_{}",
                &sha256_bytes(format!("{answer_id}:{source_id}").as_bytes())[..16]
            );
            sqlx::query(
                "insert into answer_path_sources(
                    id, frontier_id, answer_id, source_id, locator_health,
                    evidence_atom_count, finding_count, raw_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&row_id)
            .bind(frontier_id)
            .bind(answer_id)
            .bind(source_id)
            .bind(locator_health_text)
            .bind(evidence_atom_count)
            .bind(finding_count)
            .bind(raw_json(trail)?)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("insert answer path source: {e}"))?;

            let health_row_id = format!(
                "sh_{}",
                &sha256_bytes(format!("{answer_id}:{source_id}:health").as_bytes())[..16]
            );
            sqlx::query(
                "insert into source_health(
                    id, frontier_id, answer_id, source_id, locator_health,
                    stable_source, evidence_atom_count, raw_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(health_row_id)
            .bind(frontier_id)
            .bind(answer_id)
            .bind(source_id)
            .bind(locator_health_text)
            .bind(if locator_health_text == Some("stable_locator") {
                "true"
            } else {
                "false"
            })
            .bind(evidence_atom_count)
            .bind(raw_json(trail)?)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("insert source health: {e}"))?;
        }

        for atom in evidence_atoms {
            let atom_id = string_field(atom, "evidence_atom_id").unwrap_or("");
            let row_id = format!(
                "eal_{}",
                &sha256_bytes(format!("{answer_id}:{atom_id}").as_bytes())[..16]
            );
            sqlx::query(
                "insert into evidence_atom_locators(
                    id, frontier_id, answer_id, evidence_atom_id, finding_id,
                    source_id, locator, human_verified, supports_or_challenges, raw_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(row_id)
            .bind(frontier_id)
            .bind(answer_id)
            .bind(atom_id)
            .bind(string_field(atom, "finding_id"))
            .bind(string_field(atom, "source_id"))
            .bind(string_field(atom, "locator"))
            .bind(if bool_field(atom, "human_verified") {
                "true"
            } else {
                "false"
            })
            .bind(string_field(atom, "supports_or_challenges"))
            .bind(raw_json(atom)?)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("insert evidence atom locator: {e}"))?;
        }
    }
    Ok(())
}

async fn counts(conn: &mut SqliteConnection) -> Result<Value, String> {
    let mut out = serde_json::Map::new();
    for table in index_db_schema::TABLES {
        if *table == "index_metadata" {
            continue;
        }
        out.insert((*table).to_string(), json!(table_count(conn, table).await?));
    }
    Ok(Value::Object(out))
}

async fn metadata(conn: &mut SqliteConnection) -> Result<Value, String> {
    let rows = sqlx::query("select key, value from index_metadata order by key")
        .fetch_all(conn)
        .await
        .map_err(|e| format!("read index metadata: {e}"))?;
    let mut out = serde_json::Map::new();
    for row in rows {
        let key: String = row.get("key");
        let value: String = row.get("value");
        out.insert(key, json!(value));
    }
    Ok(Value::Object(out))
}

fn integrity(frontier: &Value, counts: &Value) -> Value {
    let mut issues = Vec::new();
    for key in ["findings", "sources", "evidence_atoms", "events"] {
        let expected = array_field(frontier, key).len() as i64;
        let indexed = counts.get(key).and_then(Value::as_i64).unwrap_or(-1);
        if expected != indexed {
            issues.push(json!({"table": key, "indexed": indexed, "canonical": expected}));
        }
    }
    json!({
        "ok": issues.is_empty(),
        "issues": issues,
        "checked_counts": {
            "findings": array_field(frontier, "findings").len(),
            "sources": array_field(frontier, "sources").len(),
            "evidence_atoms": array_field(frontier, "evidence_atoms").len(),
            "events": array_field(frontier, "events").len(),
        },
    })
}

async fn query_findings(
    conn: &mut SqliteConnection,
    q: &str,
    limit: usize,
) -> Result<Vec<Value>, String> {
    let pattern = format!("%{}%", q);
    let rows = sqlx::query(
        "select id, assertion, assertion_type, confidence, review_state, link_count
        from findings
        where lower(coalesce(assertion, '')) like lower(?)
        order by confidence desc, id asc
        limit ?",
    )
    .bind(pattern)
    .bind(limit as i64)
    .fetch_all(conn)
    .await
    .map_err(|e| format!("query findings: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "assertion": row.get::<Option<String>, _>("assertion"),
                "assertion_type": row.get::<Option<String>, _>("assertion_type"),
                "confidence": row.get::<Option<f64>, _>("confidence"),
                "review_state": row.get::<Option<String>, _>("review_state"),
                "link_count": row.get::<i64, _>("link_count"),
            })
        })
        .collect())
}

async fn query_sources(
    conn: &mut SqliteConnection,
    q: &str,
    limit: usize,
) -> Result<Vec<Value>, String> {
    let pattern = format!("%{}%", q);
    let rows = sqlx::query(
        "select id, title, kind, locator, doi, pmid, status
        from sources
        where lower(coalesce(title, '') || ' ' || coalesce(locator, '') || ' ' || coalesce(doi, '')) like lower(?)
        order by id asc
        limit ?",
    )
    .bind(pattern)
    .bind(limit as i64)
    .fetch_all(conn)
    .await
    .map_err(|e| format!("query sources: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "title": row.get::<Option<String>, _>("title"),
                "kind": row.get::<Option<String>, _>("kind"),
                "locator": row.get::<Option<String>, _>("locator"),
                "doi": row.get::<Option<String>, _>("doi"),
                "pmid": row.get::<Option<String>, _>("pmid"),
                "status": row.get::<Option<String>, _>("status"),
            })
        })
        .collect())
}

async fn query_answer_paths(
    conn: &mut SqliteConnection,
    q: &str,
    limit: usize,
) -> Result<Vec<Value>, String> {
    let pattern = format!("%{}%", q);
    let rows = sqlx::query(
        "select answer_id, question, answer, stable_sources,
            preserved_locator_only_sources, missing_locator_sources,
            source_count, evidence_atom_count, supporting_count, counterweight_count
        from answer_paths
        where lower(coalesce(answer_id, '') || ' ' || coalesce(question, '') || ' ' || coalesce(answer, '')) like lower(?)
        order by answer_id asc
        limit ?",
    )
    .bind(pattern)
    .bind(limit as i64)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("query answer paths: {e}"))?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let answer_id = row.get::<String, _>("answer_id");
            json!({
                "answer_id": answer_id,
                "question": row.get::<Option<String>, _>("question"),
                "answer": row.get::<Option<String>, _>("answer"),
                "answer_path_route": format!("/frontier/answer-paths/{answer_id}"),
                "supporting_findings": row.get::<i64, _>("supporting_count"),
                "counterweight_findings": row.get::<i64, _>("counterweight_count"),
                "source_count": row.get::<i64, _>("source_count"),
                "evidence_atom_count": row.get::<i64, _>("evidence_atom_count"),
                "source_health": {
                    "stable_sources": row.get::<i64, _>("stable_sources"),
                    "preserved_locator_only_sources": row.get::<i64, _>("preserved_locator_only_sources"),
                    "missing_locator_sources": row.get::<i64, _>("missing_locator_sources"),
                },
                "claim_boundary": {
                    "claims_external_validation": false,
                    "claims_treatment_advice": false,
                    "claims_target_validation": false,
                    "database_is_authority": false,
                },
            })
        })
        .collect())
}

async fn query_source_trails(
    conn: &mut SqliteConnection,
    q: &str,
    limit: usize,
) -> Result<Vec<Value>, String> {
    let pattern = format!("%{}%", q);
    let rows = sqlx::query(
        "select aps.answer_id, aps.source_id, aps.locator_health,
            aps.evidence_atom_count, aps.finding_count,
            ap.question, s.title, s.locator
        from answer_path_sources aps
        join answer_paths ap on ap.answer_id = aps.answer_id
        left join sources s on s.id = aps.source_id
        where lower(aps.source_id || ' ' || coalesce(s.title, '') || ' ' || coalesce(s.locator, '') || ' ' || ap.answer_id || ' ' || coalesce(ap.question, '')) like lower(?)
        order by aps.answer_id asc, aps.source_id asc
        limit ?",
    )
    .bind(pattern)
    .bind(limit as i64)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("query source trails: {e}"))?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let answer_id = row.get::<String, _>("answer_id");
            json!({
                "answer_id": answer_id,
                "source_id": row.get::<String, _>("source_id"),
                "source_title": row.get::<Option<String>, _>("title"),
                "source_locator": row.get::<Option<String>, _>("locator"),
                "question": row.get::<Option<String>, _>("question"),
                "answer_path_route": format!("/frontier/answer-paths/{answer_id}"),
                "question_route": format!("/frontier/questions/{answer_id}"),
                "locator_health": row.get::<Option<String>, _>("locator_health"),
                "evidence_atom_count": row.get::<i64, _>("evidence_atom_count"),
                "finding_count": row.get::<i64, _>("finding_count"),
                "claim_boundary": {
                    "database_is_authority": false,
                    "claims_external_validation": false,
                    "claims_treatment_advice": false,
                    "claims_target_validation": false,
                },
            })
        })
        .collect())
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_files(root, &mut out, false);
    out.sort();
    out
}

fn json_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_files(root, &mut out, true);
    out.sort();
    out
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>, json_only: bool) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out, json_only);
        } else if path.is_file()
            && (!json_only || path.extension().and_then(|s| s.to_str()) == Some("json"))
        {
            out.push(path);
        }
    }
}
