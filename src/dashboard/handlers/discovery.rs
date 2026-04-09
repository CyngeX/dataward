//! Phase 7.4 discovery triage handlers.
//!
//! **Scaffold only.** The full UI (askama templates for the triage queue,
//! sensitivity facets, cursor pagination) is deferred to a follow-up. The
//! handlers below establish the route contract and return structured 503
//! responses so the rest of the dashboard (and Phase 7.5 E2E validation)
//! can integrate against a stable surface.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::dashboard::{DashboardError, DashboardState};

/// GET /discovery — triage queue.
///
/// **TODO (Phase 7.4a)**: render `askama` template with findings ordered by
/// sensitivity desc, cursor-paginated at 50 rows (PERF-005), filter chips.
pub async fn triage_queue(
    State(_state): State<DashboardState>,
) -> Result<impl IntoResponse, DashboardError> {
    Ok((
        StatusCode::SERVICE_UNAVAILABLE,
        "Discovery triage UI is a Phase 7.4 follow-up. Route registered but not yet rendered.",
    ))
}

/// POST /discovery/accept/{id} — promote finding to platform_accounts.
pub async fn accept_finding(
    State(_state): State<DashboardState>,
    Path(_id): Path<i64>,
) -> Result<impl IntoResponse, DashboardError> {
    Ok((
        StatusCode::SERVICE_UNAVAILABLE,
        "Discovery accept action is a Phase 7.4 follow-up.",
    ))
}

/// POST /discovery/dismiss/{id} — mark a finding dismissed.
pub async fn dismiss_finding(
    State(_state): State<DashboardState>,
    Path(_id): Path<i64>,
) -> Result<impl IntoResponse, DashboardError> {
    Ok((
        StatusCode::SERVICE_UNAVAILABLE,
        "Discovery dismiss action is a Phase 7.4 follow-up.",
    ))
}

/// GET /discovery/preview/{account_id}/{playbook_version} — first-run
/// dry-preview (BLIND-04). Requires worker `preview_only` flag support.
pub async fn preview(
    State(_state): State<DashboardState>,
    Path((_account_id, _version)): Path<(String, String)>,
) -> Result<impl IntoResponse, DashboardError> {
    Ok((
        StatusCode::SERVICE_UNAVAILABLE,
        "First-run dry preview requires worker preview_only support (Phase 7.4a).",
    ))
}

/// POST /discovery/preview/{id}/approve — approve a first-run preview.
pub async fn approve_preview(
    State(_state): State<DashboardState>,
    Path(_id): Path<i64>,
) -> Result<impl IntoResponse, DashboardError> {
    Ok((
        StatusCode::SERVICE_UNAVAILABLE,
        "First-run preview approval is a Phase 7.4 follow-up.",
    ))
}
