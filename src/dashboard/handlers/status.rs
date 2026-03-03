use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};

use crate::dashboard::auth;
use crate::dashboard::{open_dashboard_db, DashboardError, DashboardState};
use crate::db;

/// Status row for display in template.
pub struct BrokerStatusDisplay {
    pub id: String,
    pub name: String,
    pub category: String,
    pub channel: String,
    pub trust_tier: String,
    pub enabled: bool,
    /// Latest task status (None = never run).
    pub status: Option<String>,
    /// Color class for status badge.
    pub status_class: String,
    /// Human-readable status label.
    pub status_label: String,
    pub last_attempt: Option<String>,
    pub next_recheck: Option<String>,
    pub success_rate: f64,
    /// Whether a re-run button should be enabled.
    pub can_rerun: bool,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusPageTemplate {
    brokers: Vec<BrokerStatusDisplay>,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "status_table.html")]
struct StatusTablePartialTemplate {
    brokers: Vec<BrokerStatusDisplay>,
    csrf_token: String,
}

/// Full status page (GET /).
pub async fn status_page(State(state): State<DashboardState>) -> Result<Response, DashboardError> {
    let csrf_token = auth::generate_csrf_token()?;
    let brokers = fetch_broker_statuses(&state).await?;

    let template = StatusPageTemplate {
        brokers,
        csrf_token: csrf_token.clone(),
    };

    let html = template
        .render()
        .map_err(|e| DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok((
        [(
            axum::http::header::SET_COOKIE,
            auth::csrf_cookie_header(&csrf_token),
        )],
        Html(html),
    )
        .into_response())
}

/// Status table partial (htmx polling endpoint).
///
/// Does not rotate CSRF token — the full page already sets one,
/// and rotating on every 10s poll wastes entropy and causes cookie churn.
pub async fn status_table_partial(
    State(state): State<DashboardState>,
) -> Result<Response, DashboardError> {
    let brokers = fetch_broker_statuses(&state).await?;

    let template = StatusTablePartialTemplate {
        brokers,
        csrf_token: String::new(), // Not used in partial template buttons (they read from cookie)
    };

    let html = template
        .render()
        .map_err(|e| DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok(Html(html).into_response())
}

/// Fetches broker statuses from the database.
async fn fetch_broker_statuses(
    state: &DashboardState,
) -> Result<Vec<BrokerStatusDisplay>, DashboardError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let conn = open_dashboard_db(&state)?;
        let rows = db::get_broker_statuses(&conn)
            .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let (status_class, status_label) = match row.latest_status.as_deref() {
                    Some("success") | Some("completed") => ("success".into(), "Success".into()),
                    Some("failed") | Some("failure") => ("danger".into(), "Failed".into()),
                    Some("pending") => ("warning".into(), "Pending".into()),
                    Some("running") => ("info".into(), "Running".into()),
                    Some("captcha_blocked") => ("warning".into(), "Blocked".into()),
                    None => ("secondary".into(), "Never Run".into()),
                    Some(other) => ("secondary".into(), other.to_string()),
                };

                let can_rerun = match row.latest_status.as_deref() {
                    Some("pending") | Some("running") => false,
                    _ => row.enabled,
                };

                BrokerStatusDisplay {
                    id: row.id,
                    name: row.name,
                    category: row.category,
                    channel: row.channel,
                    trust_tier: row.trust_tier,
                    enabled: row.enabled,
                    status: row.latest_status,
                    status_class,
                    status_label,
                    last_attempt: row.last_attempt,
                    next_recheck: row.next_recheck,
                    success_rate: row.success_rate,
                    can_rerun,
                }
            })
            .collect())
    })
    .await
    .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))?
}
