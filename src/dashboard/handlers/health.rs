use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};

use crate::dashboard::{open_dashboard_db, DashboardError, DashboardState};
use crate::db;

/// Broker health row for display.
pub struct BrokerHealthDisplay {
    pub name: String,
    pub success_rate: f64,
    /// CSS class for health indicator.
    pub health_class: String,
    /// Text label: "Healthy" / "Degraded" / "Critical".
    pub health_label: String,
    pub total_attempts: i64,
    pub successful: i64,
}

#[derive(Template)]
#[template(path = "health.html")]
struct HealthPageTemplate {
    csrf_token: String,
    broker_health: Vec<BrokerHealthDisplay>,
    total_brokers: i64,
    active_brokers: i64,
    disabled_brokers: i64,
    pending_tasks: i64,
    last_run_summary: Option<RunSummaryDisplay>,
    emails_today: i32,
    email_limit: i32,
    has_run_data: bool,
}

pub struct RunSummaryDisplay {
    pub started_at: String,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub captcha_blocked: i64,
}

/// Health page (GET /health).
pub async fn health_page(State(state): State<DashboardState>) -> Result<Response, DashboardError> {
    let state_clone = state.clone();
    let stats = tokio::task::spawn_blocking(move || {
        let conn = open_dashboard_db(&state_clone)?;
        db::get_health_stats(&conn)
            .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))
    })
    .await
    .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))??;

    let broker_health: Vec<BrokerHealthDisplay> = stats
        .broker_health
        .into_iter()
        .map(|b| {
            let (health_class, health_label) = if b.success_rate >= 80.0 {
                ("success".into(), "Healthy".into())
            } else if b.success_rate >= 50.0 {
                ("warning".into(), "Degraded".into())
            } else {
                ("danger".into(), "Critical".into())
            };

            BrokerHealthDisplay {
                name: b.name,
                success_rate: b.success_rate,
                health_class,
                health_label,
                total_attempts: b.total_attempts,
                successful: b.successful,
            }
        })
        .collect();

    let last_run_summary = stats.last_run.map(|r| RunSummaryDisplay {
        started_at: r.started_at,
        total: r.total,
        succeeded: r.succeeded,
        failed: r.failed,
        captcha_blocked: r.captcha_blocked,
    });

    let csrf_token = crate::dashboard::auth::generate_csrf_token()?;
    let template = HealthPageTemplate {
        csrf_token,
        broker_health,
        total_brokers: stats.total_brokers,
        active_brokers: stats.active_brokers,
        disabled_brokers: stats.disabled_brokers,
        pending_tasks: stats.pending_tasks,
        last_run_summary,
        emails_today: stats.emails_today,
        email_limit: stats.email_limit,
        has_run_data: stats.has_run_data,
    };

    let html = template
        .render()
        .map_err(|e| DashboardError::Internal(format!("Template error: {}", e)))?;

    Ok(Html(html).into_response())
}
