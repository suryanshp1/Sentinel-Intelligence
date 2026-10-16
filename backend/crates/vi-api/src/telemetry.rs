use axum::{
    extract::{ConnectInfo, Request, State},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};
use tracing::{error, info, warn};

pub const HISTOGRAM_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Default)]
pub struct Histogram {
    pub buckets: [AtomicU64; 11],
    pub sum_millis: AtomicU64,
    pub count: AtomicU64,
}

impl Histogram {
    pub fn record(&self, duration_secs: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        let millis = (duration_secs * 1000.0) as u64;
        self.sum_millis.fetch_add(millis, Ordering::Relaxed);

        for (i, &upper_bound) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if duration_secs <= upper_bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub struct Metrics {
    pub in_flight: AtomicI64,
    // (method, normalized_route, status_code) -> count
    pub requests: RwLock<HashMap<(String, String, u16), u64>>,
    pub latency: Histogram,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            in_flight: AtomicI64::new(0),
            requests: RwLock::new(HashMap::new()),
            latency: Histogram::default(),
        }
    }
}

impl Metrics {
    pub fn record_request(&self, method: &str, route: &str, status: u16, duration_secs: f64) {
        {
            let mut reqs = self.requests.write().unwrap_or_else(|e| e.into_inner());
            let key = (method.to_string(), route.to_string(), status);
            *reqs.entry(key).or_insert(0) += 1;
        }
        self.latency.record(duration_secs);
    }

    pub fn render_prometheus(
        &self,
        db_stats: Option<&Value>,
        db_ready: bool,
        security_ready: bool,
    ) -> String {
        let mut out = String::with_capacity(4096);

        // Service & Component Health
        out.push_str(
            "# HELP sentinel_service_ready Service readiness status (1=ready, 0=not ready)\n",
        );
        out.push_str("# TYPE sentinel_service_ready gauge\n");
        out.push_str(&format!(
            "sentinel_service_ready {}\n",
            if db_ready && security_ready { 1 } else { 0 }
        ));

        out.push_str(
            "# HELP sentinel_db_ready PostgreSQL connection status (1=connected, 0=disconnected)\n",
        );
        out.push_str("# TYPE sentinel_db_ready gauge\n");
        out.push_str(&format!(
            "sentinel_db_ready {}\n",
            if db_ready { 1 } else { 0 }
        ));

        out.push_str("# HELP sentinel_security_ready Session/Rate-limit store status (1=ready, 0=not ready)\n");
        out.push_str("# TYPE sentinel_security_ready gauge\n");
        out.push_str(&format!(
            "sentinel_security_ready {}\n",
            if security_ready { 1 } else { 0 }
        ));

        // HTTP In-flight
        out.push_str("# HELP sentinel_http_requests_in_flight Current number of HTTP requests being processed\n");
        out.push_str("# TYPE sentinel_http_requests_in_flight gauge\n");
        let in_flight = self.in_flight.load(Ordering::Relaxed).max(0);
        out.push_str(&format!("sentinel_http_requests_in_flight {in_flight}\n"));

        // HTTP Request Total Counter
        out.push_str("# HELP sentinel_http_requests_total Total HTTP requests processed by method, path, and status code\n");
        out.push_str("# TYPE sentinel_http_requests_total counter\n");
        {
            let reqs = self.requests.read().unwrap_or_else(|e| e.into_inner());
            for ((method, route, status), count) in reqs.iter() {
                out.push_str(&format!(
                    "sentinel_http_requests_total{{method=\"{method}\",path=\"{route}\",status=\"{status}\"}} {count}\n"
                ));
            }
        }

        // Latency Histogram
        out.push_str(
            "# HELP sentinel_http_request_duration_seconds Latency of HTTP requests in seconds\n",
        );
        out.push_str("# TYPE sentinel_http_request_duration_seconds histogram\n");
        let mut cumulative = 0u64;
        for (i, &le) in HISTOGRAM_BUCKETS.iter().enumerate() {
            cumulative += self.latency.buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "sentinel_http_request_duration_seconds_bucket{{le=\"{le}\"}} {cumulative}\n"
            ));
        }
        let total_count = self.latency.count.load(Ordering::Relaxed);
        out.push_str(&format!(
            "sentinel_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {total_count}\n"
        ));
        let sum_secs = (self.latency.sum_millis.load(Ordering::Relaxed) as f64) / 1000.0;
        out.push_str(&format!(
            "sentinel_http_request_duration_seconds_sum {sum_secs:.3}\n"
        ));
        out.push_str(&format!(
            "sentinel_http_request_duration_seconds_count {total_count}\n"
        ));

        // Intelligence Catalog Metrics
        if let Some(stats) = db_stats {
            out.push_str("# HELP sentinel_vulnerabilities Ingested source-backed CVE records\n");
            out.push_str("# TYPE sentinel_vulnerabilities gauge\n");
            let total = stats["total"].as_u64().unwrap_or(0);
            out.push_str(&format!("sentinel_vulnerabilities {total}\n"));

            if let Some(kev) = stats["kev"].as_u64() {
                out.push_str("# HELP sentinel_cisa_kev_total Ingested CISA Known Exploited Vulnerabilities\n");
                out.push_str("# TYPE sentinel_cisa_kev_total gauge\n");
                out.push_str(&format!("sentinel_cisa_kev_total {kev}\n"));
            }

            out.push_str("# HELP sentinel_source_healthy Upstream intelligence feed status (1=Healthy, 0=Degraded/Failing)\n");
            out.push_str("# TYPE sentinel_source_healthy gauge\n");

            out.push_str(
                "# HELP sentinel_source_records Ingested record count per intelligence source\n",
            );
            out.push_str("# TYPE sentinel_source_records gauge\n");

            for source in stats["sources"].as_array().unwrap_or(&vec![]) {
                let name = source["source_name"]
                    .as_str()
                    .unwrap_or("")
                    .replace('"', "");
                let is_healthy = if source["status"] == "Healthy" { 1 } else { 0 };
                let records = source["records"].as_u64().unwrap_or(0);

                out.push_str(&format!(
                    "sentinel_source_healthy{{source=\"{name}\"}} {is_healthy}\n"
                ));
                out.push_str(&format!(
                    "sentinel_source_records{{source=\"{name}\"}} {records}\n"
                ));
            }
        }

        out
    }
}

/// Normalizes dynamic URI paths to avoid high cardinality in Prometheus metrics.
pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }

    let segments: Vec<&str> = trimmed.split('/').collect();
    let mut normalized = Vec::with_capacity(segments.len());

    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        // Normalize CVE IDs (e.g. CVE-2024-1234)
        if seg.starts_with("CVE-") || seg.starts_with("cve-") {
            normalized.push(":id");
        }
        // Normalize UUIDs
        else if seg.len() == 36 && seg.chars().filter(|&c| c == '-').count() == 4 {
            normalized.push(":id");
        }
        // Normalize numeric IDs
        else if seg.chars().all(|c| c.is_ascii_digit()) && !seg.is_empty() {
            normalized.push(":id");
        }
        // Detect :id after known resource routes: e.g. /api/vulnerabilities/<id>
        else if i > 0
            && (segments[i - 1] == "vulnerabilities" || segments[i - 1] == "collections")
            && (seg.contains('-') || seg.len() > 10)
        {
            normalized.push(":id");
        } else {
            normalized.push(*seg);
        }
    }

    format!("/{}", normalized.join("/"))
}

/// Initialize tracing subscriber with structured JSON for production and clean formatting for development.
pub fn init_tracing(service_name: &str) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,tower_http=info,axum=info,vi_api=info,vi_ingest=info")
    });

    let is_production = std::env::var("VI_ENV").as_deref() == Ok("production")
        || std::env::var("LOG_FORMAT").as_deref() == Ok("json");

    if is_production {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_target(false)
                    .with_thread_ids(false),
            )
            .init();
    }

    info!(
        service = service_name,
        production = is_production,
        "Telemetry and structured logging initialized"
    );
}

/// Axum middleware for HTTP metrics, request correlation ID propagation, and structured request logging.
pub async fn track_telemetry(
    State(metrics): State<Arc<Metrics>>,
    mut req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    metrics.in_flight.fetch_add(1, Ordering::Relaxed);

    // Extract or generate X-Request-ID
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let method = req.method().to_string();
    let raw_path = req.uri().path().to_string();
    let normalized = normalize_path(&raw_path);
    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());

    // Inject request-id into request headers so downstream handlers can access it if needed
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", val);
    }

    let response = next.run(req).await;

    let duration = start.elapsed();
    let duration_secs = duration.as_secs_f64();
    let duration_ms = duration.as_millis();
    let status = response.status();
    let status_code = status.as_u16();

    metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
    metrics.record_request(&method, &normalized, status_code, duration_secs);

    // Structured logging according to status severity
    if status.is_server_error() {
        error!(
            request_id = %request_id,
            method = %method,
            path = %raw_path,
            status = status_code,
            duration_ms = duration_ms,
            client_ip = %client_ip,
            "HTTP 5xx Server Error"
        );
    } else if status.is_client_error() {
        warn!(
            request_id = %request_id,
            method = %method,
            path = %raw_path,
            status = status_code,
            duration_ms = duration_ms,
            client_ip = %client_ip,
            "HTTP 4xx Client Warning"
        );
    } else {
        info!(
            request_id = %request_id,
            method = %method,
            path = %raw_path,
            status = status_code,
            duration_ms = duration_ms,
            client_ip = %client_ip,
            "HTTP Request Completed"
        );
    }

    // Attach X-Request-ID to response headers for end-to-end tracing
    let mut response = response;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_normalization_masks_dynamic_cve_and_uuid() {
        assert_eq!(
            normalize_path("/api/vulnerabilities/CVE-2024-38077"),
            "/api/vulnerabilities/:id"
        );
        assert_eq!(
            normalize_path("/api/vulnerabilities/cve-2021-44228/rules"),
            "/api/vulnerabilities/:id/rules"
        );
        assert_eq!(
            normalize_path("/api/vulnerabilities/12345"),
            "/api/vulnerabilities/:id"
        );
        assert_eq!(
            normalize_path("/api/v2/vulnerabilities/550e8400-e29b-41d4-a716-446655440000"),
            "/api/v2/vulnerabilities/:id"
        );
        assert_eq!(normalize_path("/api/stats/"), "/api/stats");
        assert_eq!(normalize_path("/health"), "/health");
    }

    #[test]
    fn metrics_rendering_formats_prometheus_lines() {
        let metrics = Metrics::default();
        metrics.record_request("GET", "/health", 200, 0.002);
        metrics.record_request("POST", "/api/v2/vulnerabilities/filter", 200, 0.045);
        metrics.record_request("GET", "/api/vulnerabilities/:id", 404, 0.012);

        let output = metrics.render_prometheus(None, true, true);
        assert!(output.contains("sentinel_service_ready 1"));
        assert!(output.contains("sentinel_db_ready 1"));
        assert!(output.contains("sentinel_security_ready 1"));
        assert!(output.contains(
            "sentinel_http_requests_total{method=\"GET\",path=\"/health\",status=\"200\"} 1"
        ));
        assert!(output.contains("sentinel_http_requests_total{method=\"GET\",path=\"/api/vulnerabilities/:id\",status=\"404\"} 1"));
        assert!(output.contains("sentinel_http_request_duration_seconds_count 3"));
        assert!(output.contains("sentinel_http_request_duration_seconds_bucket{le=\"+Inf\"} 3"));
    }
}
