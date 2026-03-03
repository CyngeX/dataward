use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};

use crate::dashboard::auth;
use crate::dashboard::{open_dashboard_db, DashboardError, DashboardState};
use crate::db;

/// Allowed characters for broker_id: lowercase alphanumeric, underscore, hyphen.
fn validate_broker_id(id: &str) -> Result<(), DashboardError> {
    if id.is_empty() {
        return Err(DashboardError::BadRequest(
            "Broker ID cannot be empty".into(),
        ));
    }
    if id.len() > 64 {
        return Err(DashboardError::BadRequest("Broker ID too long".into()));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(DashboardError::BadRequest(
            "Invalid broker ID characters".into(),
        ));
    }
    Ok(())
}

/// Triggers a re-run for a single broker (POST /broker/:id/rerun).
pub async fn trigger_rerun(
    State(state): State<DashboardState>,
    Path(broker_id): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, DashboardError> {
    // CSRF validation
    auth::verify_csrf(&request)?;

    // Validate broker_id
    validate_broker_id(&broker_id)?;

    let state_clone = state.clone();
    let broker_id_clone = broker_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = open_dashboard_db(&state_clone)?;
        db::trigger_broker_rerun(&conn, &broker_id_clone)
            .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))
    })
    .await
    .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))??;

    match result {
        db::RerunResult::Created(broker_name) => {
            // Notify scheduler for immediate pickup
            let _ = state.scheduler_notify.try_send(());
            Ok(Html(format!(
                "<span class=\"badge success\">Re-run queued for {}</span>",
                askama::MarkupDisplay::new_unsafe(&broker_name, askama::Html)
            ))
            .into_response())
        }
        db::RerunResult::AlreadyQueued => Err(DashboardError::Conflict(
            "Task already queued for this broker".into(),
        )),
        db::RerunResult::BrokerNotFound => Err(DashboardError::NotFound),
        db::RerunResult::BrokerDisabled => {
            Err(DashboardError::Conflict("Broker is disabled".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_broker_id() {
        assert!(validate_broker_id("acxiom").is_ok());
        assert!(validate_broker_id("data-broker-1").is_ok());
        assert!(validate_broker_id("broker_name").is_ok());

        assert!(validate_broker_id("").is_err());
        assert!(validate_broker_id(&"a".repeat(65)).is_err());
        assert!(validate_broker_id("Broker").is_err()); // uppercase
        assert!(validate_broker_id("broker/name").is_err()); // slash
        assert!(validate_broker_id("broker name").is_err()); // space
        assert!(validate_broker_id("broker\x00name").is_err()); // null byte
    }
}
