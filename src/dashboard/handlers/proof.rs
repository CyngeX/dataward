use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;

use crate::crypto;
use crate::dashboard::{open_dashboard_db, DashboardError, DashboardState, MAX_PROOF_FILE_SIZE};
use crate::db;

/// Serves a decrypted proof screenshot (GET /history/proof/:task_id).
///
/// Security: path traversal prevention via canonicalization, file size limit,
/// generic 404 on all errors (no information leakage).
pub async fn serve_proof(
    State(state): State<DashboardState>,
    Path(task_id): Path<String>,
) -> Result<Response, DashboardError> {
    // Validate task_id: must be positive integer
    let task_id = super::parse_positive_id(&task_id)?;

    // Look up proof path from database
    let proof_path = {
        let state_clone = state.clone();
        tokio::task::spawn_blocking(move || {
            let conn = open_dashboard_db(&state_clone)?;
            db::get_task_proof_path(&conn, task_id)
                .map_err(|e| DashboardError::Internal(format!("Query error: {}", e)))
        })
        .await
        .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))??
    };

    let relative_path = proof_path.ok_or(DashboardError::NotFound)?;

    // Reject paths with ".." segments (defense in depth before canonicalization)
    if relative_path.contains("..") {
        tracing::warn!(task_id, path = %relative_path, "Path traversal attempt in proof path");
        return Err(DashboardError::NotFound);
    }

    let data_dir = state.data_dir.clone();

    // Move blocking fs operations (canonicalize, metadata) into spawn_blocking
    let (canonical_proof, file_size) = {
        let relative_path = relative_path.clone();
        tokio::task::spawn_blocking(move || {
            let full_path = data_dir.join(&relative_path);

            // Canonicalize and verify prefix (canonicalize resolves symlinks)
            let canonical_data_dir =
                std::fs::canonicalize(&data_dir).map_err(|_| DashboardError::NotFound)?;
            let canonical_proof =
                std::fs::canonicalize(&full_path).map_err(|_| DashboardError::NotFound)?;

            if !canonical_proof.starts_with(&canonical_data_dir) {
                tracing::warn!(
                    path = %canonical_proof.display(),
                    "Path traversal: proof path escapes data directory"
                );
                return Err(DashboardError::NotFound);
            }

            // Validate file extension (.png.enc)
            let path_str = canonical_proof.to_string_lossy().to_lowercase();
            if !path_str.ends_with(".png.enc") {
                tracing::warn!(path = %path_str, "Invalid proof file extension");
                return Err(DashboardError::NotFound);
            }

            // Get file size (canonicalize already resolved symlinks, use regular metadata)
            let metadata =
                std::fs::metadata(&canonical_proof).map_err(|_| DashboardError::NotFound)?;

            if metadata.len() > MAX_PROOF_FILE_SIZE {
                tracing::warn!(size = metadata.len(), "Proof file exceeds size limit");
                return Err(DashboardError::PayloadTooLarge);
            }

            Ok((canonical_proof, metadata.len()))
        })
        .await
        .map_err(|e| DashboardError::Internal(format!("Task join error: {}", e)))??
    };

    let _ = file_size; // Used for validation above; binding kept for clarity

    // Decrypt in memory (with timeout)
    let master_key = state.master_key.clone();
    let proof_path_owned = canonical_proof.clone();

    let decrypt_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            crypto::decrypt_file_to_memory(master_key.expose_secret(), &proof_path_owned)
        }),
    )
    .await;

    match decrypt_result {
        Ok(Ok(Ok(decrypted))) => Ok((
            [
                (header::CONTENT_TYPE, "image/png"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            decrypted,
        )
            .into_response()),
        Ok(Ok(Err(e))) => {
            tracing::error!(task_id, "Proof decryption failed: {}", e);
            Err(DashboardError::NotFound) // Generic error — don't reveal decryption failure
        }
        Ok(Err(e)) => {
            tracing::error!(task_id, "Proof decrypt task panicked: {}", e);
            Err(DashboardError::NotFound)
        }
        Err(_) => {
            tracing::error!(task_id, "Proof decryption timed out");
            Err(DashboardError::NotFound)
        }
    }
}
