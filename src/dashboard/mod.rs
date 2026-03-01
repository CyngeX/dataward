pub mod auth;
pub mod handlers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Response};
use axum::Router;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::db;

/// Dashboard listen port (localhost only).
const DASHBOARD_PORT: u16 = 9847;

/// Maximum proof file size (10 MB).
pub const MAX_PROOF_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// CSRF cookie and header names.
pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Session cookie name.
pub const SESSION_COOKIE_NAME: &str = "dataward_session";

/// Session max age in seconds (30 minutes).
pub const SESSION_MAX_AGE_SECS: i64 = 1800;

/// Login rate limit: max attempts per minute.
pub const LOGIN_RATE_LIMIT: u32 = 5;

/// Shared dashboard state (Clone via Arc internals).
#[derive(Clone)]
pub struct DashboardState {
    /// Path to SQLCipher database file.
    pub db_path: PathBuf,
    /// Hex key for opening DB connections (SecretString for zeroize-on-drop).
    pub db_hex_key: SecretString,
    /// Channel to send write operations to the DB writer task.
    pub write_tx: mpsc::Sender<db::DbWriteMessage>,
    /// Channel to wake the scheduler for immediate re-run.
    pub scheduler_notify: mpsc::Sender<()>,
    /// Master encryption key for proof decryption.
    pub master_key: Arc<SecretBox<Vec<u8>>>,
    /// Dashboard auth token (shown to user at init).
    pub auth_token: SecretString,
    /// Secret key for HMAC session cookie signing (zeroized on drop via SecretBox).
    pub session_secret: Arc<SecretBox<Vec<u8>>>,
    /// Pre-computed base64(SHA-256(auth_token)) for session cookie verification.
    pub token_hash_b64: String,
    /// Data directory root (for proof file path resolution).
    pub data_dir: PathBuf,
    /// Login attempt tracker (ip is always 127.0.0.1, so just track timestamps).
    pub login_attempts: Arc<tokio::sync::Mutex<std::collections::VecDeque<std::time::Instant>>>,
}

/// Dashboard-specific error type for consistent error responses.
#[derive(Debug)]
pub enum DashboardError {
    /// 400 Bad Request.
    BadRequest(String),
    /// 401 Unauthorized.
    Unauthorized,
    /// 403 Forbidden (host validation, CSRF).
    Forbidden(String),
    /// 404 Not Found.
    NotFound,
    /// 409 Conflict (duplicate re-run, already resolved).
    Conflict(String),
    /// 413 Payload Too Large (proof file).
    PayloadTooLarge,
    /// 429 Too Many Requests (login rate limit).
    TooManyRequests,
    /// 500 Internal Server Error.
    Internal(String),
}

impl IntoResponse for DashboardError {
    fn into_response(self) -> Response {
        match self {
            DashboardError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Html(format!("<p>{}</p>", askama::MarkupDisplay::new_unsafe(&msg, askama::Html)))).into_response()
            }
            DashboardError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, Html("<p>Unauthorized. <a href=\"/login\">Log in</a></p>".to_string())).into_response()
            }
            DashboardError::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, Html(format!("<p>{}</p>", askama::MarkupDisplay::new_unsafe(&msg, askama::Html)))).into_response()
            }
            DashboardError::NotFound => {
                (StatusCode::NOT_FOUND, Html("<p>Not found</p>".to_string())).into_response()
            }
            DashboardError::Conflict(msg) => {
                (StatusCode::CONFLICT, Html(format!("<p>{}</p>", askama::MarkupDisplay::new_unsafe(&msg, askama::Html)))).into_response()
            }
            DashboardError::PayloadTooLarge => {
                (StatusCode::PAYLOAD_TOO_LARGE, Html("<p>File too large</p>".to_string())).into_response()
            }
            DashboardError::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, Html("<p>Too many login attempts. Try again in a minute.</p>".to_string())).into_response()
            }
            DashboardError::Internal(msg) => {
                tracing::error!("Dashboard internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, Html("<p>Internal server error</p>".to_string())).into_response()
            }
        }
    }
}

/// Builds the Axum router with all middleware and routes.
pub fn build_router(state: DashboardState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/login", axum::routing::get(handlers::login_page))
        .route("/login", axum::routing::post(handlers::login_submit))
        .route("/static/htmx.min.js", axum::routing::get(handlers::serve_htmx));

    // Authenticated routes
    let authed_routes = Router::new()
        .route("/", axum::routing::get(handlers::status::status_page))
        .route("/status-table", axum::routing::get(handlers::status::status_table_partial))
        .route("/history", axum::routing::get(handlers::history::history_page))
        .route("/history/proof/{task_id}", axum::routing::get(handlers::proof::serve_proof))
        .route("/captcha", axum::routing::get(handlers::captcha::captcha_page))
        .route("/captcha/queue", axum::routing::get(handlers::captcha::captcha_queue_partial))
        .route("/captcha/{id}/resolve", axum::routing::post(handlers::captcha::resolve_captcha))
        .route("/captcha/{id}/abandon", axum::routing::post(handlers::captcha::abandon_captcha))
        .route("/broker/{id}/rerun", axum::routing::post(handlers::trigger::trigger_rerun))
        .route("/health", axum::routing::get(handlers::health::health_page))
        .route("/logout", axum::routing::get(handlers::logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    // Combine with middleware stack (outermost listed first)
    // Security headers applied to all responses
    Router::new()
        .merge(public_routes)
        .merge(authed_routes)
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
            ),
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::validate_host,
        ))
        .with_state(state)
}

/// Starts the dashboard server as a Tokio task.
///
/// Returns a JoinHandle. The server will shut down when `cancel` is triggered.
pub async fn start(
    state: DashboardState,
    cancel: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>, anyhow::Error> {
    let app = build_router(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], DASHBOARD_PORT));
    let listener = tokio::net::TcpListener::bind(addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind dashboard to {}: {}", addr, e))?;

    tracing::info!(%addr, "Dashboard listening");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
            .unwrap_or_else(|e| {
                tracing::error!("Dashboard server error: {}", e);
            });
        tracing::info!("Dashboard stopped");
    });

    Ok(handle)
}

/// Opens a read-only database connection for dashboard queries.
///
/// Each handler calls this inside `spawn_blocking` to avoid Send/Sync issues
/// with rusqlite::Connection.
pub fn open_dashboard_db(state: &DashboardState) -> Result<rusqlite::Connection, DashboardError> {
    let conn = db::open_db_with_key(&state.db_path, state.db_hex_key.expose_secret())
        .map_err(|e| DashboardError::Internal(format!("DB connection failed: {}", e)))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| DashboardError::Internal(format!("Failed to set busy_timeout: {}", e)))?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for oneshot

    /// Creates a test DashboardState with a temporary database.
    fn create_test_state() -> (DashboardState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let (conn, _salt) = db::create_db_with_params(
            &db_path, "test-passphrase", &crate::crypto::TEST_PARAMS,
        ).unwrap();

        let hex_key = db::derive_db_key_with_params(
            "test-passphrase", &_salt, &crate::crypto::TEST_PARAMS,
        ).unwrap();

        // Create dashboard indexes
        db::create_dashboard_indexes(&conn).unwrap();

        // Insert test broker
        db::upsert_broker(&conn, &db::BrokerRow {
            id: "test-broker".into(),
            name: "Test Broker".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/test.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        drop(conn);

        let (write_tx, _write_rx) = mpsc::channel(16);
        let (notify_tx, _notify_rx) = mpsc::channel(1);

        let master_key = vec![0u8; 32]; // Dummy key for tests

        // Precompute token hash for test state
        use sha2::Digest;
        let auth_token_str = "test-token-abc123";
        let token_hash = sha2::Sha256::digest(auth_token_str.as_bytes());
        let token_hash_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD, token_hash,
        );

        let state = DashboardState {
            db_path,
            db_hex_key: SecretString::from(hex_key),
            write_tx,
            scheduler_notify: notify_tx,
            master_key: Arc::new(SecretBox::new(Box::new(master_key))),
            auth_token: SecretString::from(auth_token_str.to_string()),
            session_secret: Arc::new(SecretBox::new(Box::new(vec![0u8; 32]))),
            token_hash_b64,
            data_dir: dir.path().to_path_buf(),
            login_attempts: Arc::new(tokio::sync::Mutex::new(std::collections::VecDeque::new())),
        };

        (state, dir)
    }

    /// Helper to create a session cookie for authenticated requests.
    fn create_test_session(state: &DashboardState) -> String {
        auth::create_session_cookie(state).unwrap()
    }

    #[tokio::test]
    async fn test_unauthenticated_redirects_to_login() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Host", "localhost")
                    .header("Accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Browser request without auth should redirect to login
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_unauthenticated_api_returns_401() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Host", "localhost")
                    .header("Accept", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_auth_works() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Host", "localhost")
                    .header("Authorization", "Bearer test-token-abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_bearer_returns_401() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Host", "localhost")
                    .header("Authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_session_cookie_auth_works() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_non_localhost_host_returns_403() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .header("Host", "evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_missing_host_returns_400() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_login_page_returns_200() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_security_headers_present() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(resp.headers().get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(resp.headers().get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        assert!(resp.headers().get("content-security-policy").is_some());
        assert!(resp.headers().get("permissions-policy").is_some());
    }

    #[tokio::test]
    async fn test_status_page_renders_broker() {
        let (state, _dir) = create_test_state();
        let app = build_router(state.clone());
        let session = create_test_session(&state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Test Broker"));
        assert!(html.contains("Never Run"));
    }

    #[tokio::test]
    async fn test_htmx_served() {
        let (state, _dir) = create_test_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/static/htmx.min.js")
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/javascript"
        );
    }

    #[tokio::test]
    async fn test_history_page_empty_state() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/history")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("No opt-out attempts yet"));
    }

    #[tokio::test]
    async fn test_captcha_page_empty_state() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/captcha")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("No CAPTCHAs pending"));
    }

    #[tokio::test]
    async fn test_health_page_empty_state() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("No run data yet"));
    }

    #[tokio::test]
    async fn test_proof_invalid_task_id() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        // Non-numeric task ID
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/history/proof/abc")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_proof_negative_task_id() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/history/proof/-1")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_proof_nonexistent_task() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/history/proof/99999")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_logout_clears_session() {
        let (state, _dir) = create_test_state();
        let session = create_test_session(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/logout")
                    .header("Host", "localhost")
                    .header("Cookie", format!("dataward_session={}", session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should redirect to /login
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        // Should have a Set-Cookie header clearing the session
        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("Max-Age=0"));
    }

    // -- DB Query Tests --

    #[test]
    fn test_get_broker_statuses_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();
        db::create_dashboard_indexes(&conn).unwrap();

        let statuses = db::get_broker_statuses(&conn).unwrap();
        assert!(statuses.is_empty());
    }

    #[test]
    fn test_get_broker_statuses_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();
        db::create_dashboard_indexes(&conn).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker One".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/b1.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        // No tasks yet — should show as "never run"
        let statuses = db::get_broker_statuses(&conn).unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].name, "Broker One");
        assert!(statuses[0].latest_status.is_none()); // Never run
    }

    #[test]
    fn test_get_task_history_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();
        db::create_dashboard_indexes(&conn).unwrap();

        let history = db::get_task_history(&conn, None, None, 50).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_captcha_queue_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();
        db::create_dashboard_indexes(&conn).unwrap();

        let queue = db::get_captcha_queue(&conn).unwrap();
        assert!(queue.is_empty());
    }

    #[test]
    fn test_get_health_stats_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();
        db::create_dashboard_indexes(&conn).unwrap();

        let stats = db::get_health_stats(&conn).unwrap();
        assert_eq!(stats.total_brokers, 0);
        assert!(!stats.has_run_data);
    }

    #[test]
    fn test_trigger_broker_rerun_creates_task() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker One".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/b1.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        // First rerun should succeed
        match db::trigger_broker_rerun(&conn, "broker1").unwrap() {
            db::RerunResult::Created(name) => assert_eq!(name, "Broker One"),
            other => panic!("Expected Created, got {:?}", std::mem::discriminant(&other)),
        }

        // Second rerun should return AlreadyQueued
        match db::trigger_broker_rerun(&conn, "broker1").unwrap() {
            db::RerunResult::AlreadyQueued => {},
            other => panic!("Expected AlreadyQueued, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_trigger_rerun_disabled_broker() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker One".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/b1.yaml".into(),
            trust_tier: "official".into(),
            enabled: false,
        }).unwrap();

        match db::trigger_broker_rerun(&conn, "broker1").unwrap() {
            db::RerunResult::BrokerDisabled => {},
            other => panic!("Expected BrokerDisabled, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_trigger_rerun_nonexistent_broker() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        match db::trigger_broker_rerun(&conn, "nonexistent").unwrap() {
            db::RerunResult::BrokerNotFound => {},
            other => panic!("Expected BrokerNotFound, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_resolve_captcha_task() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "p.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, retry_count)
             VALUES ('broker1', 'captcha_blocked', 'web_form', datetime('now'), 0)",
            [],
        ).unwrap();
        let task_id = conn.last_insert_rowid();

        match db::resolve_captcha_task(&conn, task_id).unwrap() {
            db::CaptchaMutationResult::Success => {},
            _ => panic!("Expected Success"),
        }

        let status: String = conn.query_row(
            "SELECT status FROM opt_out_tasks WHERE id = ?1", [task_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(status, "pending");
    }

    #[test]
    fn test_abandon_captcha_increments_retry() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "p.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, retry_count)
             VALUES ('broker1', 'captcha_blocked', 'web_form', datetime('now'), 0)",
            [],
        ).unwrap();
        let task_id = conn.last_insert_rowid();

        match db::abandon_captcha_task(&conn, task_id).unwrap() {
            db::CaptchaMutationResult::Success => {},
            _ => panic!("Expected Success"),
        }

        let retry_count: i32 = conn.query_row(
            "SELECT retry_count FROM opt_out_tasks WHERE id = ?1", [task_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(retry_count, 1);
    }

    #[test]
    fn test_abandon_captcha_max_retries_fails_permanently() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "p.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, retry_count)
             VALUES ('broker1', 'captcha_blocked', 'web_form', datetime('now'), 4)",
            [],
        ).unwrap();
        let task_id = conn.last_insert_rowid();

        match db::abandon_captcha_task(&conn, task_id).unwrap() {
            db::CaptchaMutationResult::MaxRetriesExceeded => {},
            _ => panic!("Expected MaxRetriesExceeded (permanent failure)"),
        }

        let status: String = conn.query_row(
            "SELECT status FROM opt_out_tasks WHERE id = ?1", [task_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(status, "failure");
    }

    #[test]
    fn test_get_task_proof_path() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _) = db::create_db_with_params(&db_path, "test", &crate::crypto::TEST_PARAMS).unwrap();

        db::upsert_broker(&conn, &db::BrokerRow {
            id: "broker1".into(),
            name: "Broker".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "p.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        }).unwrap();

        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, proof_path)
             VALUES ('broker1', 'success', 'web_form', datetime('now'), 'proofs/test.png.enc')",
            [],
        ).unwrap();
        let task_id = conn.last_insert_rowid();

        let path = db::get_task_proof_path(&conn, task_id).unwrap();
        assert_eq!(path, Some("proofs/test.png.enc".to_string()));

        // Non-existent task
        let path = db::get_task_proof_path(&conn, 99999).unwrap();
        assert!(path.is_none());
    }
}
