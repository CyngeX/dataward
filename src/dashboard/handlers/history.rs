use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};

use crate::dashboard::{open_dashboard_db, DashboardError, DashboardState};
use crate::db;

/// Query parameters for history pagination.
#[derive(serde::Deserialize, Default)]
pub struct HistoryParams {
    /// Cursor timestamp for pagination (ISO 8601).
    pub cursor_ts: Option<String>,
    /// Cursor task ID for pagination.
    pub cursor_id: Option<i64>,
}

/// History row for display in template.
pub struct TaskHistoryDisplay {
    pub id: i64,
    pub broker_name: String,
    pub channel: String,
    pub status: String,
    pub status_class: String,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub has_proof: bool,
    pub error_message: Option<String>,
}

#[derive(Template)]
#[template(path = "history.html")]
struct HistoryPageTemplate {
    csrf_token: String,
    tasks: Vec<TaskHistoryDisplay>,
    next_cursor_ts: Option<String>,
    next_cursor_id: Option<i64>,
    has_more: bool,
}

/// Full history page (GET /history).
pub async fn history_page(
    State(state): State<DashboardState>,
    Query(params): Query<HistoryParams>,
) -> Result<Response, DashboardError> {
    let tasks = fetch_task_history(&state, params.cursor_ts, params.cursor_id).await?;

    let has_more = tasks.len() == 50;
    let (next_cursor_ts, next_cursor_id) = if has_more {
        tasks.last().map(|t| (Some(t.completed_at.clone().unwrap_or_default()), Some(t.id))).unwrap_or_default()
    } else {
        (None, None)
    };

    let csrf_token = crate::dashboard::auth::generate_csrf_token()?;
    let template = HistoryPageTemplate {
        csrf_token,
        tasks,
        next_cursor_ts,
        next_cursor_id,
        has_more,
    };

    let html = template.render()
        .map_err(|e| DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok(Html(html).into_response())
}

/// Fetches task history from the database.
async fn fetch_task_history(
    state: &DashboardState,
    cursor_ts: Option<String>,
    cursor_id: Option<i64>,
) -> Result<Vec<TaskHistoryDisplay>, DashboardError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let conn = open_dashboard_db(&state)?;
        let rows = db::get_task_history(&conn, cursor_ts.as_deref(), cursor_id, 50)
            .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))?;

        Ok(rows.into_iter().map(|row| {
            let status_class = match row.status.as_str() {
                "success" | "completed" => "success",
                "failed" | "failure" => "danger",
                "pending" => "warning",
                "running" => "info",
                "captcha_blocked" => "warning",
                _ => "secondary",
            }.to_string();

            TaskHistoryDisplay {
                id: row.id,
                broker_name: row.broker_name,
                channel: row.channel,
                status: row.status,
                status_class,
                created_at: row.created_at,
                completed_at: row.completed_at,
                duration_ms: row.duration_ms,
                has_proof: row.proof_path.is_some(),
                error_message: row.error_message,
            }
        }).collect())
    }).await
        .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))?
}
