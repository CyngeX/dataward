pub mod captcha;
pub mod health;
pub mod history;
pub mod proof;
pub mod status;
pub mod trigger;

use askama::Template;
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};

use super::auth;
use super::DashboardState;

/// Parses and validates a positive integer ID from a path segment.
pub(crate) fn parse_positive_id(id: &str) -> Result<i64, super::DashboardError> {
    let task_id: i64 = id
        .parse()
        .map_err(|_| super::DashboardError::BadRequest("Invalid task ID".into()))?;
    if task_id <= 0 {
        return Err(super::DashboardError::BadRequest("Invalid task ID".into()));
    }
    Ok(task_id)
}

/// Login page template.
#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    csrf_token: String,
}

/// Serves the login page.
pub async fn login_page(
    State(_state): State<DashboardState>,
) -> Result<Response, super::DashboardError> {
    let csrf_token = auth::generate_csrf_token()?;
    let template = LoginTemplate {
        error: None,
        csrf_token: csrf_token.clone(),
    };

    let html = template
        .render()
        .map_err(|e| super::DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok((
        [(header::SET_COOKIE, auth::csrf_cookie_header(&csrf_token))],
        Html(html),
    )
        .into_response())
}

/// Login form data.
#[derive(serde::Deserialize)]
pub struct LoginForm {
    token: String,
    csrf_token: String,
}

/// Handles login form submission.
pub async fn login_submit(
    State(state): State<DashboardState>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, super::DashboardError> {
    // Rate limiting: check and record attempt in single lock acquisition.
    // Records the attempt BEFORE CSRF/token verification so that CSRF brute-force
    // attempts also count toward the rate limit.
    {
        let mut attempts = state.login_attempts.lock().await;
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(60);
        while attempts.front().map_or(false, |t| *t < cutoff) {
            attempts.pop_front();
        }
        if attempts.len() >= super::LOGIN_RATE_LIMIT as usize {
            tracing::warn!("Login rate limit exceeded");
            return Err(super::DashboardError::TooManyRequests);
        }
        attempts.push_back(std::time::Instant::now());
    }

    // Extract cookie header before consuming the request body
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Parse form body (consumes request)
    let body_bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .map_err(|_| super::DashboardError::BadRequest("Invalid form data".into()))?;
    let form: LoginForm = serde_urlencoded::from_bytes(&body_bytes)
        .map_err(|_| super::DashboardError::BadRequest("Invalid form data".into()))?;

    // Verify CSRF using the form body field (login form is a traditional POST, not htmx)
    auth::verify_csrf_form_token(cookie_header.as_deref(), &form.csrf_token)?;

    // Verify token (constant-time comparison)
    use secrecy::ExposeSecret;
    use subtle::ConstantTimeEq;

    let provided = form.token.as_bytes();
    let expected = state.auth_token.expose_secret().as_bytes();

    let token_valid = if provided.len() == expected.len() {
        provided.ct_eq(expected).into()
    } else {
        false
    };

    if !token_valid {
        tracing::warn!("Failed login attempt");
        let csrf_token = auth::generate_csrf_token()?;
        let template = LoginTemplate {
            error: Some("Invalid token".into()),
            csrf_token: csrf_token.clone(),
        };
        let html = template
            .render()
            .map_err(|e| super::DashboardError::Internal(format!("Template error: {}", e)))?;

        return Ok((
            axum::http::StatusCode::UNAUTHORIZED,
            [(header::SET_COOKIE, auth::csrf_cookie_header(&csrf_token))],
            Html(html),
        )
            .into_response());
    }

    // Create session cookie
    let session_value = auth::create_session_cookie(&state)?;
    let csrf_token = auth::generate_csrf_token()?;

    tracing::info!("Successful login");

    Ok((
        [
            (
                header::SET_COOKIE,
                auth::session_cookie_header(&session_value),
            ),
            (header::SET_COOKIE, auth::csrf_cookie_header(&csrf_token)),
        ],
        Redirect::to("/"),
    )
        .into_response())
}

/// Handles logout (clears session).
pub async fn logout() -> Response {
    (
        [(header::SET_COOKIE, auth::clear_session_cookie_header())],
        Redirect::to("/login"),
    )
        .into_response()
}

/// Serves vendored htmx.min.js with immutable caching.
pub async fn serve_htmx() -> Response {
    // htmx vendored (embedded at compile time)
    const HTMX_JS: &str = include_str!("../htmx.min.js");
    (
        [
            (header::CONTENT_TYPE, "application/javascript"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        HTMX_JS,
    )
        .into_response()
}
