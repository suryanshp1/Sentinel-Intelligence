use super::*;
use axum::{
    extract::ConnectInfo,
    http::{header, HeaderMap, HeaderValue},
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct Security {
    pub token: Option<String>,
    pub sessions: Arc<Mutex<HashMap<String, Instant>>>,
    pub redis: Option<redis::Client>,
    pub production: bool,
}
impl Security {
    pub fn new() -> Result<Self, String> {
        let production = std::env::var("VI_ENV").as_deref() == Ok("production");
        let token = std::env::var("VI_API_TOKEN").ok().filter(|s| !s.is_empty());
        if production && token.as_ref().is_none_or(|s| s.len() < 32) {
            return Err("Production requires VI_API_TOKEN with at least 32 characters".into());
        }
        let redis = std::env::var("REDIS_URL")
            .ok()
            .map(|s| redis::Client::open(s).map_err(|e| e.to_string()))
            .transpose()?;
        if production && redis.is_none() {
            return Err("Production requires REDIS_URL for shared rate limits".into());
        }
        Ok(Self {
            token,
            sessions: Default::default(),
            redis,
            production,
        })
    }
}
fn fingerprint(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn equal(a: &str, b: &str) -> bool {
    fingerprint(a)
        .as_bytes()
        .ct_eq(fingerprint(b).as_bytes())
        .into()
}
// Development always serves Vite on these two explicit loopback origins.
// The .env origin may belong to Compose (port 3000), even for a local API.
fn origin_allowed(headers: &HeaderMap, expected: &str, production: bool) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true; // Non-browser clients do not send Origin.
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin == expected
        || (!production && ["http://localhost:5173", "http://127.0.0.1:5173"].contains(&origin))
}
fn request_origin_allowed(headers: &HeaderMap, production: bool) -> bool {
    let expected =
        std::env::var("VI_PUBLIC_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".into());
    origin_allowed(headers, &expected, production)
}

pub async fn gate(State(app): State<App>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|s| s.trim().strip_prefix("sentinel_session="))
        });
    let mut authenticated = app.security.token.is_none();
    let mut identity = String::new();
    if let (Some(expected), Some(provided)) = (&app.security.token, bearer) {
        if equal(expected, provided) {
            authenticated = true;
            identity = fingerprint(provided)
        }
    }
    if !authenticated {
        if let Some(cookie) = cookie {
            let key = fingerprint(cookie);
            if let Some(redis) = &app.security.redis {
                match redis.get_multiplexed_async_connection().await {
                    Ok(mut c) => {
                        let exists: Result<bool, _> = redis::cmd("EXISTS")
                            .arg(format!(
                                "vi:session:{}:{key}",
                                fingerprint(app.security.token.as_deref().unwrap_or(""))
                            ))
                            .query_async(&mut c)
                            .await;
                        if exists.unwrap_or(false) {
                            authenticated = true;
                            identity = key
                        }
                    }
                    Err(_) => {
                        return err(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable")
                            .into_response()
                    }
                }
            } else {
                let mut sessions = app.security.sessions.lock().await;
                sessions.retain(|_, expires| *expires > Instant::now());
                if sessions.contains_key(&key) {
                    authenticated = true;
                    identity = key
                }
            }
        }
    }
    if !authenticated {
        return err(StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    }
    if req.uri().path().ends_with("/mcp")
        || !matches!(
            *req.method(),
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        )
    {
        if !request_origin_allowed(headers, app.security.production) {
            return err(StatusCode::FORBIDDEN, "Cross-origin mutation rejected").into_response();
        }
    }
    let remote = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|i| i.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    let key = if identity.is_empty() {
        fingerprint(&remote)
    } else {
        identity
    };
    let licensed = app.security.token.is_some();
    let limit = if licensed { 1000 } else { 100 };
    if let Some(redis) = &app.security.redis {
        let mut conn = match redis.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(_) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Rate-limit store unavailable",
                )
                .into_response()
            }
        };
        let result:Result<i64,_>=redis::Script::new("local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n").key(format!("vi:rate:{key}")).invoke_async(&mut conn).await;
        match result {
            Ok(n) if n > limit => return limited(),
            Err(_) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Rate-limit store unavailable",
                )
                .into_response()
            }
            _ => {}
        }
    } else {
        let mut buckets = app.buckets.lock().await;
        buckets.retain(|_, v| v.0.elapsed() < Duration::from_secs(60));
        let entry = buckets.entry(key).or_insert((Instant::now(), 0));
        entry.1 += 1;
        if entry.1 > limit as u32 {
            return limited();
        }
    }
    next.run(req).await
}
fn limited() -> Response {
    let mut response = err(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    response
}
pub async fn login(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Share the same per-IP login throttle across instances when Valkey is configured.
    if let Some(redis) = &app.security.redis {
        if let Ok(mut c) = redis.get_multiplexed_async_connection().await {
            let count:Result<i64,_>=redis::Script::new("local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],60) end;return n").key(format!("vi:login-attempts:{}",fingerprint(app.security.token.as_deref().unwrap_or("local")))).invoke_async(&mut c).await;
            if count.unwrap_or(100) > 20 {
                return limited();
            }
        } else {
            return err(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable")
                .into_response();
        }
    }
    if !request_origin_allowed(&headers, app.security.production) {
        return err(StatusCode::FORBIDDEN, "Cross-origin login rejected").into_response();
    }
    let Some(expected) = &app.security.token else {
        return Json(json!({"authenticated":true,"mode":"local"})).into_response();
    };
    if !equal(body["token"].as_str().unwrap_or(""), expected) {
        return err(StatusCode::UNAUTHORIZED, "Invalid access token").into_response();
    }
    let session = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let hash = fingerprint(&session);
    if let Some(redis) = &app.security.redis {
        match redis.get_multiplexed_async_connection().await {
            Ok(mut c) => {
                let r: Result<(), _> = redis::cmd("SETEX")
                    .arg(format!("vi:session:{}:{hash}", fingerprint(expected)))
                    .arg(28800)
                    .arg("1")
                    .query_async(&mut c)
                    .await;
                if r.is_err() {
                    return err(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable")
                        .into_response();
                }
            }
            Err(_) => {
                return err(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable")
                    .into_response()
            }
        }
    } else {
        app.security
            .sessions
            .lock()
            .await
            .insert(hash, Instant::now() + Duration::from_secs(28800));
    }
    let secure = if app.security.production {
        "; Secure"
    } else {
        ""
    };
    ([(header::SET_COOKIE,format!("sentinel_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{secure}"))],Json(json!({"authenticated":true}))).into_response()
}
pub async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(cookie) = headers
        .get(header::COOKIE)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|s| s.trim().strip_prefix("sentinel_session="))
        })
    {
        let key = fingerprint(cookie);
        if let Some(redis) = &app.security.redis {
            if let Ok(mut c) = redis.get_multiplexed_async_connection().await {
                let _: Result<i64, _> = redis::cmd("DEL")
                    .arg(format!(
                        "vi:session:{}:{key}",
                        fingerprint(app.security.token.as_deref().unwrap_or(""))
                    ))
                    .query_async(&mut c)
                    .await;
            }
        } else {
            app.security.sessions.lock().await.remove(&key);
        }
    }
    (
        [(
            header::SET_COOKIE,
            "sentinel_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"authenticated":false})),
    )
        .into_response()
}

impl Security {
    pub async fn ready(&self) -> bool {
        match &self.redis {
            Some(redis) => match redis.get_multiplexed_async_connection().await {
                Ok(mut c) => redis::cmd("PING")
                    .query_async::<String>(&mut c)
                    .await
                    .is_ok(),
                Err(_) => false,
            },
            None => !self.production,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_accepts_both_vite_origins_with_compose_configuration() {
        for origin in [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert!(
                origin_allowed(&headers, "http://localhost:3000", false),
                "{origin}"
            );
        }
    }

    #[test]
    fn production_requires_the_exact_configured_origin() {
        for origin in [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "https://sentinel.test",
            "https://evil.test",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert_eq!(
                origin_allowed(&headers, "https://sentinel.test", true),
                origin == "https://sentinel.test",
                "{origin}"
            );
        }
    }

    #[test]
    fn rejects_untrusted_origins_and_preserves_non_browser_access() {
        let mut headers = HeaderMap::new();
        for production in [false, true] {
            assert!(origin_allowed(
                &headers,
                "http://localhost:3000",
                production
            ));
            for origin in [
                "null",
                "https://evil.test",
                "http://localhost:5174",
                "http://localhost:5173.evil.test",
                "http://127.0.0.2:5173",
                "https://localhost:5173",
            ] {
                headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
                assert!(
                    !origin_allowed(&headers, "http://localhost:3000", production),
                    "{origin}"
                );
            }
            headers.insert(header::ORIGIN, HeaderValue::from_bytes(&[0xff]).unwrap());
            assert!(!origin_allowed(
                &headers,
                "http://localhost:3000",
                production
            ));
            headers.clear();
        }
    }
}
