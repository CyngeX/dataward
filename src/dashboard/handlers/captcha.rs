use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};

use crate::dashboard::{open_dashboard_db, DashboardError, DashboardState};
use crate::dashboard::auth;
use crate::db;

/// CAPTCHA queue row for display in template.
pub struct CaptchaDisplay {
    pub id: i64,
    pub broker_id: String,
    pub broker_name: String,
    pub broker_url: String,
    pub created_at: String,
    pub retry_count: i32,
    /// Time remaining until 24h expiry, as human-readable string.
    pub time_remaining: String,
    /// Whether this CAPTCHA has expired (>24h old).
    pub expired: bool,
}

#[derive(Template)]
#[template(path = "captcha.html")]
struct CaptchaPageTemplate {
    items: Vec<CaptchaDisplay>,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "captcha_queue.html")]
struct CaptchaQueuePartialTemplate {
    items: Vec<CaptchaDisplay>,
    csrf_token: String,
}

/// Full CAPTCHA queue page (GET /captcha).
pub async fn captcha_page(
    State(state): State<DashboardState>,
) -> Result<Response, DashboardError> {
    let csrf_token = auth::generate_csrf_token()?;
    let items = fetch_captcha_queue(&state).await?;

    let template = CaptchaPageTemplate {
        items,
        csrf_token: csrf_token.clone(),
    };

    let html = template.render()
        .map_err(|e| DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok((
        [(axum::http::header::SET_COOKIE, auth::csrf_cookie_header(&csrf_token))],
        Html(html),
    ).into_response())
}

/// CAPTCHA queue partial for htmx polling (GET /captcha/queue).
///
/// Does not rotate CSRF token — the full page already sets one,
/// and rotating on every poll wastes entropy and causes cookie churn.
pub async fn captcha_queue_partial(
    State(state): State<DashboardState>,
) -> Result<Response, DashboardError> {
    let items = fetch_captcha_queue(&state).await?;

    let template = CaptchaQueuePartialTemplate {
        items,
        csrf_token: String::new(), // Not used in partial template buttons (they read from cookie)
    };

    let html = template.render()
        .map_err(|e| DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok(Html(html).into_response())
}

/// Mark a CAPTCHA task as resolved (POST /captcha/:id/resolve).
pub async fn resolve_captcha(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, DashboardError> {
    // CSRF validation
    auth::verify_csrf(&request)?;

    // Validate task ID
    let task_id: i64 = id.parse()
        .map_err(|_| DashboardError::BadRequest("Invalid task ID".into()))?;
    if task_id <= 0 {
        return Err(DashboardError::BadRequest("Invalid task ID".into()));
    }

    let state_clone = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = open_dashboard_db(&state_clone)?;
        db::resolve_captcha_task(&conn, task_id)
            .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))
    }).await
        .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))??;

    match result {
        db::CaptchaMutationResult::Success => {
            // Notify scheduler for immediate re-run
            let _ = state.scheduler_notify.try_send(());
            Ok(Html("<span class=\"badge success\">Re-queued</span>").into_response())
        }
        db::CaptchaMutationResult::NotFound => Err(DashboardError::NotFound),
        db::CaptchaMutationResult::WrongStatus => {
            Err(DashboardError::Conflict("Task is no longer captcha-blocked".into()))
        }
        db::CaptchaMutationResult::Expired => {
            Err(DashboardError::Conflict("Task has expired, you may only abandon it".into()))
        }
        db::CaptchaMutationResult::MaxRetriesExceeded => {
            // Cannot occur for resolve — only abandon can trigger this
            Err(DashboardError::Internal("Unexpected state".into()))
        }
    }
}

/// Abandon a CAPTCHA task (POST /captcha/:id/abandon).
pub async fn abandon_captcha(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, DashboardError> {
    // CSRF validation
    auth::verify_csrf(&request)?;

    // Validate task ID
    let task_id: i64 = id.parse()
        .map_err(|_| DashboardError::BadRequest("Invalid task ID".into()))?;
    if task_id <= 0 {
        return Err(DashboardError::BadRequest("Invalid task ID".into()));
    }

    let result = tokio::task::spawn_blocking({
        let state = state.clone();
        move || {
            let conn = open_dashboard_db(&state)?;
            db::abandon_captcha_task(&conn, task_id)
                .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))
        }
    }).await
        .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))??;

    match result {
        db::CaptchaMutationResult::Success => {
            Ok(Html("<span class=\"badge warning\">Returned to queue</span>").into_response())
        }
        db::CaptchaMutationResult::NotFound => Err(DashboardError::NotFound),
        db::CaptchaMutationResult::WrongStatus => {
            Err(DashboardError::Conflict("Task is no longer captcha-blocked".into()))
        }
        db::CaptchaMutationResult::Expired => {
            Err(DashboardError::Conflict("Task has expired".into()))
        }
        db::CaptchaMutationResult::MaxRetriesExceeded => {
            Ok(Html("<span class=\"badge danger\">Permanently failed (max retries)</span>").into_response())
        }
    }
}

/// Fetches the CAPTCHA queue from the database.
async fn fetch_captcha_queue(state: &DashboardState) -> Result<Vec<CaptchaDisplay>, DashboardError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let conn = open_dashboard_db(&state)?;
        let rows = db::get_captcha_queue(&conn)
            .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))?;

        let now = chrono::Utc::now();

        Ok(rows.into_iter().map(|row| {
            let created = chrono::DateTime::parse_from_rfc3339(&row.created_at)
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(&row.created_at, "%Y-%m-%d %H:%M:%S")
                    .map(|ndt| ndt.and_utc().fixed_offset()))
                .unwrap_or_else(|_| now.fixed_offset());

            // Clamp future timestamps to now (clock skew defense)
            let created_utc = if created > now { now } else { created.with_timezone(&chrono::Utc) };

            let expiry = created_utc + chrono::Duration::hours(24);
            let remaining = expiry - now;
            let expired = remaining.num_seconds() <= 0;

            let time_remaining = if expired {
                "Expired".to_string()
            } else {
                let hours = remaining.num_hours();
                let minutes = remaining.num_minutes() % 60;
                format!("{}h {}m", hours, minutes)
            };

            CaptchaDisplay {
                id: row.id,
                broker_id: row.broker_id,
                broker_name: row.broker_name,
                broker_url: row.broker_url,
                created_at: row.created_at,
                retry_count: row.retry_count,
                time_remaining,
                expired,
            }
        }).collect())
    }).await
        .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))?
}
