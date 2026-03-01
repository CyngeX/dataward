use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::{DashboardState, SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECS};

type HmacSha256 = Hmac<Sha256>;

/// Allowed Host header values (without port).
const ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

/// Host header validation middleware.
///
/// Rejects requests with non-localhost Host headers to prevent DNS rebinding attacks.
/// Must be applied before auth middleware.
pub async fn validate_host(
    request: Request<Body>,
    next: Next,
) -> Response {
    let host_header = request.headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());

    match host_header {
        Some(host) => {
            let host_without_port = extract_host_without_port(host);
            let normalized = host_without_port.to_lowercase();

            if !ALLOWED_HOSTS.contains(&normalized.as_str()) {
                tracing::warn!(host = %host, "Rejected request: non-localhost Host header");
                return (
                    StatusCode::FORBIDDEN,
                    "Forbidden: Dashboard only accessible via localhost",
                ).into_response();
            }
        }
        None => {
            // HTTP/1.1 requires Host header; reject if missing
            tracing::warn!("Rejected request: missing Host header");
            return (
                StatusCode::BAD_REQUEST,
                "Bad Request: Missing Host header",
            ).into_response();
        }
    }

    next.run(request).await
}

/// Extracts host portion without port from a Host header value.
///
/// Handles IPv6 bracket notation: `[::1]:8080` → `[::1]`
/// Regular: `localhost:8080` → `localhost`
fn extract_host_without_port(host: &str) -> &str {
    let host = host.trim();

    // Reject null bytes (DNS rebinding defense)
    if host.bytes().any(|b| b == 0) {
        return "";
    }

    // Handle IPv6 bracket notation: [::1]:port
    if host.starts_with('[') {
        // Find closing bracket
        if let Some(bracket_end) = host.find(']') {
            return &host[..=bracket_end];
        }
        return host; // Malformed, will be rejected by allowlist
    }

    // Regular host:port
    match host.rfind(':') {
        Some(pos) => &host[..pos],
        None => host,
    }
}

/// Auth middleware: checks session cookie or Bearer token.
///
/// - Session cookie: HMAC-signed token hash, validated with constant-time comparison
/// - Bearer token: `Authorization: Bearer <token>`, constant-time comparison
/// - Unauthenticated browser requests redirect to /login
/// - Unauthenticated API requests get 401
pub async fn require_auth(
    State(state): State<DashboardState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check Bearer token first (API clients)
    if let Some(auth_header) = request.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if verify_token_constant_time(token, state.auth_token.expose_secret()) {
                    return next.run(request).await;
                }
            }
        }
        // Invalid Bearer token → 401 (don't fall through to cookie check)
        return super::DashboardError::Unauthorized.into_response();
    }

    // Check session cookie (browser)
    if let Some(cookie_header) = request.headers().get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            if let Some(session_value) = extract_cookie(cookie_str, SESSION_COOKIE_NAME) {
                if verify_session_cookie(session_value, &state) {
                    return next.run(request).await;
                }
            }
        }
    }

    // No valid auth — redirect browser to login, 401 for API
    let accepts_html = request.headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);

    if accepts_html {
        Redirect::to("/login").into_response()
    } else {
        super::DashboardError::Unauthorized.into_response()
    }
}

/// CSRF validation for POST requests (double-submit cookie pattern).
///
/// Accepts the CSRF token from either:
/// - X-CSRF-TOKEN header (htmx requests via hx-headers)
/// - Form body field named "csrf_token" (traditional form submissions)
///
/// The token is compared against the csrf_token cookie value.
pub fn verify_csrf(
    request: &Request<Body>,
) -> Result<(), super::DashboardError> {
    let header_token = request.headers()
        .get(super::CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cookie_token = request.headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| extract_cookie(cookies, crate::dashboard::CSRF_COOKIE_NAME))
        .unwrap_or("");

    if cookie_token.is_empty() {
        return Err(super::DashboardError::Forbidden("CSRF token missing".into()));
    }

    // Accept token from header (htmx) — primary path
    if !header_token.is_empty() {
        if constant_time_eq(header_token.as_bytes(), cookie_token.as_bytes()) {
            return Ok(());
        }
        return Err(super::DashboardError::Forbidden("CSRF token mismatch".into()));
    }

    // No header token — this will be checked from the form body by the caller
    // (login_submit parses the body and calls verify_csrf_form_token)
    Err(super::DashboardError::Forbidden("CSRF token missing".into()))
}

/// CSRF validation using a form body field value (for traditional form POSTs like login).
///
/// Called after the form body is parsed, since the Request body can only be consumed once.
/// Takes the cookie header string directly to avoid requiring access to the consumed request.
pub fn verify_csrf_form_token(
    cookie_header: Option<&str>,
    form_csrf_token: &str,
) -> Result<(), super::DashboardError> {
    let cookie_token = cookie_header
        .and_then(|cookies| extract_cookie(cookies, crate::dashboard::CSRF_COOKIE_NAME))
        .unwrap_or("");

    if cookie_token.is_empty() || form_csrf_token.is_empty() {
        return Err(super::DashboardError::Forbidden("CSRF token missing".into()));
    }

    if !constant_time_eq(form_csrf_token.as_bytes(), cookie_token.as_bytes()) {
        return Err(super::DashboardError::Forbidden("CSRF token mismatch".into()));
    }

    Ok(())
}

/// Generates a new CSRF token (random 32-byte hex string).
pub fn generate_csrf_token() -> Result<String, super::DashboardError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| super::DashboardError::Internal(format!("RNG error: {}", e)))?;
    Ok(hex::encode(bytes))
}

/// Creates a Set-Cookie header value for the CSRF token.
pub fn csrf_cookie_header(token: &str) -> String {
    format!(
        "{}={}; SameSite=Strict; Path=/",
        crate::dashboard::CSRF_COOKIE_NAME, token
    )
}

/// Creates a signed session cookie value.
///
/// Format: `base64(token_hash):base64(hmac):expiry_timestamp`
pub fn create_session_cookie(state: &DashboardState) -> Result<String, super::DashboardError> {
    let token_hash_b64 = &state.token_hash_b64;

    let expiry = chrono::Utc::now().timestamp() + SESSION_MAX_AGE_SECS;
    let payload = format!("{}:{}", token_hash_b64, expiry);

    let mut mac = HmacSha256::new_from_slice(state.session_secret.expose_secret())
        .map_err(|e| super::DashboardError::Internal(format!("HMAC error: {}", e)))?;
    mac.update(payload.as_bytes());
    let signature = mac.finalize().into_bytes();
    let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, signature);

    Ok(format!("{}.{}", payload, sig_b64))
}

/// Creates the Set-Cookie header value for a new session.
pub fn session_cookie_header(cookie_value: &str) -> String {
    format!(
        "{}={}; SameSite=Strict; Path=/; HttpOnly; Max-Age={}",
        SESSION_COOKIE_NAME, cookie_value, SESSION_MAX_AGE_SECS
    )
}

/// Creates a Set-Cookie header that clears the session cookie.
pub fn clear_session_cookie_header() -> String {
    format!(
        "{}=; SameSite=Strict; Path=/; HttpOnly; Max-Age=0",
        SESSION_COOKIE_NAME
    )
}

/// Verifies a session cookie value.
///
/// Checks: HMAC signature valid, token hash matches, not expired.
fn verify_session_cookie(cookie_value: &str, state: &DashboardState) -> bool {
    // Format: token_hash_b64:expiry.signature_b64
    let parts: Vec<&str> = cookie_value.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }
    let sig_b64 = parts[0];
    let payload = parts[1];

    // Verify HMAC signature
    let mut mac = match HmacSha256::new_from_slice(state.session_secret.expose_secret()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(payload.as_bytes());

    let expected_sig = match base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_b64) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if mac.finalize().into_bytes().ct_eq(&expected_sig).into() {
        // Signature valid — check payload
    } else {
        return false;
    }

    // Parse payload: token_hash_b64:expiry
    let payload_parts: Vec<&str> = payload.splitn(2, ':').collect();
    if payload_parts.len() != 2 {
        return false;
    }
    let token_hash_b64 = payload_parts[0];
    let expiry_str = payload_parts[1];

    // Check expiry
    let expiry: i64 = match expiry_str.parse() {
        Ok(e) => e,
        Err(_) => return false,
    };
    if chrono::Utc::now().timestamp() > expiry {
        return false;
    }

    // Check token hash matches (precomputed at startup)
    constant_time_eq(token_hash_b64.as_bytes(), state.token_hash_b64.as_bytes())
}

/// Constant-time string comparison using the `subtle` crate.
///
/// Hashes both sides with SHA-256 before comparing to prevent leaking
/// the expected value's length via timing side-channel.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::Digest;
    let ha = sha2::Sha256::digest(a);
    let hb = sha2::Sha256::digest(b);
    ha.ct_eq(&hb).into()
}

/// Constant-time token comparison.
fn verify_token_constant_time(provided: &str, expected: &str) -> bool {
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

/// Extracts a named cookie value from a Cookie header string.
fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_without_port() {
        assert_eq!(extract_host_without_port("localhost"), "localhost");
        assert_eq!(extract_host_without_port("localhost:8080"), "localhost");
        assert_eq!(extract_host_without_port("127.0.0.1"), "127.0.0.1");
        assert_eq!(extract_host_without_port("127.0.0.1:9847"), "127.0.0.1");
        assert_eq!(extract_host_without_port("[::1]"), "[::1]");
        assert_eq!(extract_host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(extract_host_without_port("LOCALHOST"), "LOCALHOST");
        assert_eq!(extract_host_without_port("evil.com"), "evil.com");
        assert_eq!(extract_host_without_port("localhost.evil.com"), "localhost.evil.com");
        // Null byte defense
        assert_eq!(extract_host_without_port("localhost\x00.evil.com"), "");
    }

    #[test]
    fn test_host_allowlist() {
        let allowed = |host: &str| -> bool {
            let h = extract_host_without_port(host);
            ALLOWED_HOSTS.contains(&h.to_lowercase().as_str())
        };

        assert!(allowed("localhost"));
        assert!(allowed("LOCALHOST"));
        assert!(allowed("localhost:8080"));
        assert!(allowed("127.0.0.1"));
        assert!(allowed("127.0.0.1:9847"));
        assert!(allowed("[::1]"));
        assert!(allowed("[::1]:8080"));

        assert!(!allowed("evil.com"));
        assert!(!allowed("localhost.evil.com"));
        assert!(!allowed("127.0.0.2"));
        assert!(!allowed(""));
        assert!(!allowed("localhost\x00.evil.com"));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_extract_cookie() {
        assert_eq!(extract_cookie("foo=bar; baz=qux", "foo"), Some("bar"));
        assert_eq!(extract_cookie("foo=bar; baz=qux", "baz"), Some("qux"));
        assert_eq!(extract_cookie("foo=bar; baz=qux", "missing"), None);
        assert_eq!(extract_cookie("", "foo"), None);
        assert_eq!(extract_cookie("foo=", "foo"), Some(""));
    }

    #[test]
    fn test_csrf_token_generation() {
        let token1 = generate_csrf_token().unwrap();
        let token2 = generate_csrf_token().unwrap();
        assert_eq!(token1.len(), 64); // 32 bytes hex-encoded
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_verify_csrf_form_token_valid() {
        let token = "abc123";
        let cookie = format!("{}={}", crate::dashboard::CSRF_COOKIE_NAME, token);
        assert!(verify_csrf_form_token(Some(&cookie), token).is_ok());
    }

    #[test]
    fn test_verify_csrf_form_token_mismatch() {
        let cookie = format!("{}=correct", crate::dashboard::CSRF_COOKIE_NAME);
        let result = verify_csrf_form_token(Some(&cookie), "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_csrf_form_token_missing_cookie() {
        let result = verify_csrf_form_token(None, "token");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_csrf_form_token_empty_form_token() {
        let cookie = format!("{}=token", crate::dashboard::CSRF_COOKIE_NAME);
        let result = verify_csrf_form_token(Some(&cookie), "");
        assert!(result.is_err());
    }

    #[test]
    fn test_csrf_cookie_not_httponly() {
        let header = csrf_cookie_header("test-token");
        // CSRF cookie must NOT be HttpOnly — JavaScript needs to read it for htmx headers
        assert!(!header.to_lowercase().contains("httponly"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("test-token"));
    }
}
