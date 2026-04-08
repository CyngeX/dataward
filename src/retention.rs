//! Phase 7.1 §J.7: retention job for account_discovery_findings.
//!
//! Deletes old discovery findings according to triage status:
//!   - `dismissed` / `already_tracked`: age > 30 days
//!   - `accepted`:                       age > 90 days
//!
//! Config flags in the encrypted config table can extend or disable the
//! retention window:
//!   - `retention.findings.dismissed_days` (default 30)
//!   - `retention.findings.accepted_days`  (default 90)
//!   - `retention.findings.disabled`       (any non-empty value disables the job)

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::db;

const DEFAULT_DISMISSED_DAYS: i64 = 30;
const DEFAULT_ACCEPTED_DAYS: i64 = 90;

#[allow(dead_code)]
pub struct RetentionConfig {
    pub dismissed_days: i64,
    pub accepted_days: i64,
    pub disabled: bool,
}

#[allow(dead_code)]
pub fn load_config(conn: &Connection) -> Result<RetentionConfig> {
    let dismissed_days = db::get_config(conn, "retention.findings.dismissed_days")?
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_DISMISSED_DAYS);
    let accepted_days = db::get_config(conn, "retention.findings.accepted_days")?
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_ACCEPTED_DAYS);
    let disabled = db::get_config(conn, "retention.findings.disabled")?
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    Ok(RetentionConfig {
        dismissed_days,
        accepted_days,
        disabled,
    })
}

/// Runs the retention sweep. Returns the total number of rows deleted.
///
/// `now_rfc3339` is injectable to support time-travel tests.
#[allow(dead_code)]
pub fn run(conn: &Connection, now_rfc3339: &str) -> Result<usize> {
    let cfg = load_config(conn)?;
    if cfg.disabled {
        return Ok(0);
    }

    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339)
        .context("Invalid now timestamp for retention sweep")?;

    let dismissed_cutoff = (now - chrono::Duration::days(cfg.dismissed_days)).to_rfc3339();
    let accepted_cutoff = (now - chrono::Duration::days(cfg.accepted_days)).to_rfc3339();

    let dismissed_deleted = conn.execute(
        "DELETE FROM account_discovery_findings
            WHERE triage_status IN ('dismissed','already_tracked')
              AND COALESCE(triaged_at, last_seen_at) < ?1",
        [&dismissed_cutoff],
    )?;
    let accepted_deleted = conn.execute(
        "DELETE FROM account_discovery_findings
            WHERE triage_status = 'accepted'
              AND COALESCE(triaged_at, last_seen_at) < ?1",
        [&accepted_cutoff],
    )?;

    Ok(dismissed_deleted + accepted_deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::TEST_PARAMS;
    use crate::db::{create_db_with_params, DiscoveryFindingRow};
    use tempfile::tempdir;

    fn setup() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _salt) =
            create_db_with_params(&db_path, "retention-test-pass", &TEST_PARAMS).unwrap();
        (dir, conn)
    }

    fn make_finding(id_suffix: u8, status: &str, last_seen: &str) -> DiscoveryFindingRow {
        DiscoveryFindingRow {
            id: None,
            domain: format!("example-{}.com", id_suffix),
            username_hmac: vec![id_suffix; 32],
            dedup_hash: vec![id_suffix; 32],
            k_dedup_version: 1,
            sensitivity: "low".to_string(),
            discovery_source: "test".to_string(),
            triage_status: status.to_string(),
            promoted_to_platform_account_id: None,
            first_seen_at: last_seen.to_string(),
            last_seen_at: last_seen.to_string(),
            triaged_at: Some(last_seen.to_string()),
        }
    }

    #[test]
    fn test_retention_deletes_old_dismissed() {
        let (_dir, conn) = setup();
        // Old dismissed finding (100 days ago)
        db::insert_discovery_finding(
            &conn,
            &make_finding(1, "dismissed", "2026-01-01T00:00:00+00:00"),
        )
        .unwrap();
        // Fresh accepted finding (today) — should survive.
        db::insert_discovery_finding(
            &conn,
            &make_finding(2, "accepted", "2026-04-08T00:00:00+00:00"),
        )
        .unwrap();

        let deleted = run(&conn, "2026-04-08T00:00:00+00:00").unwrap();
        assert_eq!(deleted, 1);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM account_discovery_findings", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_retention_keeps_fresh_dismissed() {
        let (_dir, conn) = setup();
        // Dismissed 10 days ago — should survive (default 30d window).
        db::insert_discovery_finding(
            &conn,
            &make_finding(1, "dismissed", "2026-03-29T00:00:00+00:00"),
        )
        .unwrap();
        let deleted = run(&conn, "2026-04-08T00:00:00+00:00").unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_retention_deletes_old_accepted() {
        let (_dir, conn) = setup();
        // Accepted 100 days ago — exceeds 90-day window.
        db::insert_discovery_finding(
            &conn,
            &make_finding(1, "accepted", "2026-01-01T00:00:00+00:00"),
        )
        .unwrap();
        let deleted = run(&conn, "2026-04-08T00:00:00+00:00").unwrap();
        assert_eq!(deleted, 1);
    }

    #[test]
    fn test_retention_disabled_flag_skips() {
        let (_dir, conn) = setup();
        db::set_config(&conn, "retention.findings.disabled", "1").unwrap();
        db::insert_discovery_finding(
            &conn,
            &make_finding(1, "dismissed", "2026-01-01T00:00:00+00:00"),
        )
        .unwrap();
        let deleted = run(&conn, "2026-04-08T00:00:00+00:00").unwrap();
        assert_eq!(deleted, 0);
    }
}
