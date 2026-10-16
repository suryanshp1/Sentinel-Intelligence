pub mod adapters;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration as Timeout};
use vi_core::SOURCES;
use vi_db::{Batch, Database};

#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    cache: PathBuf,
}
#[derive(Clone)]
pub struct Document {
    pub bytes: Vec<u8>,
    pub url: String,
    pub sha256: String,
    pub fetched_at: String,
}
impl Document {
    pub fn json(&self) -> Result<Value, String> {
        serde_json::from_slice(&self.bytes).map_err(|e| format!("Invalid upstream JSON: {e}"))
    }
    pub fn provenance(&self, source: &str) -> Value {
        json!({"source":source,"url":self.url,"sha256":self.sha256,"retrieved_at":self.fetched_at})
    }
}
impl Fetcher {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            client: reqwest::Client::builder()
                .user_agent("Sentinel-Intelligence/0.2 (open-source vulnerability intelligence)")
                .connect_timeout(Timeout::from_secs(15))
                .timeout(Timeout::from_secs(180))
                .redirect(reqwest::redirect::Policy::limited(4))
                .build()
                .map_err(|e| e.to_string())?,
            cache: std::env::var("VI_FEED_CACHE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("backend/data/feed-cache")),
        })
    }
    pub async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Document, String> {
        if !url.starts_with("https://") {
            return Err("Feeds require HTTPS".into());
        }
        tokio::fs::create_dir_all(&self.cache)
            .await
            .map_err(|e| e.to_string())?;
        let key = format!("{:x}", Sha256::digest(url.as_bytes()));
        let path = self.cache.join(&key);
        let meta = self.cache.join(format!("{key}.json"));
        let old: Value = tokio::fs::read(&meta)
            .await
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let mut request = self.client.get(url);
        for (k, v) in headers {
            request = request.header(*k, *v)
        }
        if path.exists() {
            if let Some(etag) = old["etag"].as_str() {
                request = request.header("If-None-Match", etag)
            } else if let Some(modified) = old["last_modified"].as_str() {
                request = request.header("If-Modified-Since", modified)
            }
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| format!("Upstream transport failed: {e}"))?;
        let now = Utc::now().to_rfc3339();
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            let bytes = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
            let sha256 = format!("{:x}", Sha256::digest(&bytes));
            return Ok(Document {
                bytes,
                url: url.into(),
                sha256,
                fetched_at: now,
            });
        }
        if !response.status().is_success() {
            let retry = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("900");
            return Err(format!(
                "HTTP {} from {} (Retry-After: {retry})",
                response.status().as_u16(),
                url.split('?').next().unwrap_or(url)
            ));
        }
        let metadata = json!({"etag":response.headers().get("etag").and_then(|v|v.to_str().ok()),"last_modified":response.headers().get("last-modified").and_then(|v|v.to_str().ok())});
        let max = 128 * 1024 * 1024;
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > max {
                return Err("Upstream document exceeds 128 MB limit".into());
            }
            bytes.extend_from_slice(&chunk)
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::write(meta, serde_json::to_vec(&metadata).unwrap())
            .await
            .map_err(|e| e.to_string())?;
        Ok(Document {
            bytes,
            url: url.into(),
            sha256,
            fetched_at: now,
        })
    }
    pub async fn post(&self, url: &str, payload: &Value) -> Result<Value, String> {
        let mut response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Upstream API returned {}", response.status()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > 16 * 1024 * 1024 {
                return Err("Upstream API response too large".into());
            }
            bytes.extend_from_slice(&chunk)
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
}
pub async fn run_source(db: &Database, source: &str, force: bool) -> Result<usize, String> {
    let cadence = SOURCES
        .iter()
        .find(|(s, _)| *s == source)
        .ok_or("Unknown source")?
        .1;
    let mut cp = db
        .checkpoints()
        .await?
        .into_iter()
        .find(|v| v["source_name"] == source)
        .unwrap_or(json!({"source_name":source}));
    if source == "Vendor CSAF / OpenVEX"
        && !std::path::Path::new(
            &std::env::var("VI_VEX_IMPORT_DIR")
                .unwrap_or_else(|_| "backend/data/vex-import".into()),
        )
        .exists()
    {
        cp["status"] = json!("Disabled");
        cp["last_error"] = Value::Null;
        cp["backoff_until"] = Value::Null;
        cp["configuration_required"] =
            json!("Configure a publisher-verified CSAF/OpenVEX import directory");
        db.save_checkpoint(source, cp).await?;
        return Ok(0);
    }
    if cp["backoff_until"]
        .as_str()
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .is_some_and(|t| t > Utc::now())
    {
        return Err("Source is in persisted backoff".into());
    }
    if !force
        && cp["next_run_at"]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .is_some_and(|t| t > Utc::now())
    {
        return Ok(0);
    }
    if !db.claim(source).await? {
        return Ok(0);
    }
    cp["last_error"] = Value::Null;
    cp["configuration_required"] = Value::Null;
    cp["status"] = json!("Running");
    cp["last_started_at"] = json!(Utc::now().to_rfc3339());
    db.save_checkpoint(source, cp.clone()).await?;
    let fetcher = Fetcher::new()?;
    let result = adapters::ingest(db, &fetcher, source, &mut cp).await;
    match &result {
        Ok(count) => {
            cp["status"] = json!("Healthy");
            cp["last_success_at"] = json!(Utc::now().to_rfc3339());
            cp["next_run_at"] =
                json!((Utc::now() + Duration::seconds(cadence as i64)).to_rfc3339());
            cp["records"] = json!(count);
            cp["consecutive_failures"] = json!(0);
            cp["last_error"] = Value::Null;
            cp["backoff_until"] = Value::Null;
        }
        Err(error) => {
            let n = cp["consecutive_failures"].as_u64().unwrap_or(0) + 1;
            let retry = error
                .split("Retry-After: ")
                .nth(1)
                .and_then(|s| s.trim_end_matches(')').parse::<i64>().ok())
                .unwrap_or(60 * 2_i64.pow(n.min(10) as u32));
            cp["status"] = json!("Error");
            cp["last_error"] = json!(error);
            cp["consecutive_failures"] = json!(n);
            cp["backoff_until"] =
                json!((Utc::now() + Duration::seconds(retry.clamp(60, 86400))).to_rfc3339());
        }
    }
    db.save_checkpoint(source, cp).await?;
    db.release(source).await?;
    result
}
pub async fn commit(
    db: &Database,
    source: &str,
    batch: Batch,
    cp: &Value,
) -> Result<usize, String> {
    db.apply(source, batch, cp.clone()).await
}
pub async fn osv_analyze(purls: &[String]) -> Result<Vec<Value>, String> {
    let f = Fetcher::new()?;
    let mut findings = vec![];
    for chunk in purls.chunks(100) {
        let queries: Vec<_> = chunk
            .iter()
            .map(|p| json!({"package":{"purl":p}}))
            .collect();
        let result = f
            .post(
                "https://api.osv.dev/v1/querybatch",
                &json!({"queries":queries}),
            )
            .await?;
        let results = result["results"].as_array().ok_or("Invalid OSV response")?;
        if results.len() != chunk.len() {
            return Err("OSV response count mismatch".into());
        }
        for (purl, group) in chunk.iter().zip(results) {
            let mut page = group.clone();
            loop {
                for v in page["vulns"].as_array().unwrap_or(&vec![]) {
                    if let Some(id) = v["id"].as_str() {
                        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                            continue;
                        }
                        let doc = f
                            .get(&format!("https://api.osv.dev/v1/vulns/{id}"), &[])
                            .await?;
                        findings.push(json!({"purl":purl,"advisory":doc.json()?,"provenance":doc.provenance("OSV")}));
                    }
                }
                let Some(token) = page["next_page_token"].as_str() else {
                    break;
                };
                let response = f
                    .post(
                        "https://api.osv.dev/v1/querybatch",
                        &json!({"queries":[{"package":{"purl":purl},"page_token":token}]}),
                    )
                    .await?;
                page = response["results"][0].clone();
            }
        }
    }
    Ok(findings)
}
