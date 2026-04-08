//! Legal acknowledgment scaffold (Phase 7.0).
//!
//! Dataward refuses to run any `discover` or scheduler task until the user has
//! explicitly acknowledged the legal disclaimer. Acknowledgment is stored in
//! the encrypted config table as an ISO-8601 timestamp.
//!
//! Per Phase 7 plan §J.2 / issue #14.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::io::{self, Write};

use crate::db;

/// Config key for the initial legal acknowledgment timestamp.
const ACK_KEY: &str = "legal_ack_accepted_at";

/// Config key for the "regulated categories" automation flag acknowledgment.
/// Re-prompted whenever the user toggles regulated automation on.
const ACK_REGULATED_KEY: &str = "legal_ack_regulated_at";

/// The legal disclaimer text shown to the user at first run.
const DISCLAIMER: &str = "\
Dataward automates data broker opt-out requests on your behalf.

By continuing, you acknowledge that:
  1. You are the individual whose PII will be submitted, OR you have explicit
     written authorization to act on their behalf.
  2. Some jurisdictions regulate automated interaction with third-party
     websites — you are responsible for ensuring your use complies with
     local law (CFAA, CCPA, GDPR, etc.).
  3. Dataward provides no warranty and no guarantee of successful opt-out.
  4. Proof screenshots may contain sensitive PII and are stored encrypted on
     this machine — do NOT share the data directory.
  5. You will not use Dataward to submit requests for individuals without
     their consent.
";

/// Returns true if the user has previously accepted the legal disclaimer.
pub fn is_accepted(conn: &Connection) -> Result<bool> {
    Ok(db::get_config(conn, ACK_KEY)?.is_some())
}

/// Returns true if the user has acknowledged the regulated-category flag.
#[allow(dead_code)]
pub fn is_regulated_accepted(conn: &Connection) -> Result<bool> {
    Ok(db::get_config(conn, ACK_REGULATED_KEY)?.is_some())
}

/// Prompts the user to accept the legal disclaimer, blocking until they do.
///
/// Records the acceptance timestamp in the config table on success. If the
/// user declines or the input stream is closed, returns an error and the
/// caller MUST refuse to proceed.
pub fn prompt_and_record(conn: &Connection) -> Result<()> {
    eprintln!();
    eprintln!("=== Legal acknowledgment required ===");
    eprintln!();
    eprintln!("{}", DISCLAIMER);
    eprint!("Type 'I AGREE' to continue: ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("Failed to read legal acknowledgment")?;

    if input.trim() != "I AGREE" {
        anyhow::bail!("Legal acknowledgment declined — cannot proceed");
    }

    let now = chrono::Utc::now().to_rfc3339();
    db::set_config(conn, ACK_KEY, &now)?;
    eprintln!("Acknowledgment recorded at {}.", now);
    Ok(())
}

/// Prompts for acknowledgment of regulated-category automation (separate from
/// the base disclaimer). Called when the user toggles regulated automation on.
#[allow(dead_code)]
pub fn prompt_and_record_regulated(conn: &Connection) -> Result<()> {
    eprintln!();
    eprintln!("=== Regulated-category automation acknowledgment ===");
    eprintln!();
    eprintln!(
        "Enabling regulated-category automation (e.g. credit bureaus, healthcare data) \n\
         carries additional legal risk. By continuing you acknowledge you have reviewed \n\
         the compliance implications for your jurisdiction."
    );
    eprint!("Type 'I AGREE' to continue: ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim() != "I AGREE" {
        anyhow::bail!("Regulated-category acknowledgment declined");
    }

    let now = chrono::Utc::now().to_rfc3339();
    db::set_config(conn, ACK_REGULATED_KEY, &now)?;
    Ok(())
}

/// Enforces that the legal acknowledgment has been recorded.
///
/// Returns an error if not accepted. Intended to be called at the entry point
/// of `discover` and the scheduler, per the Phase 7 plan.
pub fn require_accepted(conn: &Connection) -> Result<()> {
    if !is_accepted(conn)? {
        anyhow::bail!(
            "Legal acknowledgment required. Run `dataward init` (or re-run init) to accept."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::TEST_PARAMS;
    use tempfile::tempdir;

    fn test_conn() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _salt) = db::create_db_with_params(&db_path, "test-passphrase", &TEST_PARAMS)
            .expect("create_db");
        (dir, conn)
    }

    #[test]
    fn test_not_accepted_by_default() {
        let (_dir, conn) = test_conn();
        assert!(!is_accepted(&conn).unwrap());
        assert!(require_accepted(&conn).is_err());
    }

    #[test]
    fn test_require_accepted_passes_after_record() {
        let (_dir, conn) = test_conn();
        // Simulate a prior acceptance by writing the config key directly.
        db::set_config(&conn, ACK_KEY, "2026-04-08T00:00:00Z").unwrap();
        assert!(is_accepted(&conn).unwrap());
        assert!(require_accepted(&conn).is_ok());
    }

    #[test]
    fn test_regulated_separate_from_base() {
        let (_dir, conn) = test_conn();
        db::set_config(&conn, ACK_KEY, "2026-04-08T00:00:00Z").unwrap();
        assert!(is_accepted(&conn).unwrap());
        assert!(!is_regulated_accepted(&conn).unwrap());
    }
}
