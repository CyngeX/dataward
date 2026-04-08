//! Firefox `places.sqlite` importer — SCAFFOLD ONLY (Phase 7.2).
//!
//! Full implementation is deferred. A correct implementation must:
//!
//!   - Attempt `PRAGMA query_only=1` read-only open first (PERF-002)
//!   - On WAL lock failure, atomically copy `places.sqlite`,
//!     `places.sqlite-wal`, `places.sqlite-shm` to a tempfile in
//!     `$XDG_RUNTIME_DIR` (mode 0700) with fallback to
//!     `~/.local/state/dataward/run/` — NOT `/tmp` (SEC-002)
//!   - Use `tempfile::NamedTempFile` + `OpenOptions::mode(0o600)`
//!   - Handle microsecond timestamps (`last_visit_date` / 1_000_000) — EC-002
//!   - Multi-profile handling via `--profile NAME` (FLOW-006)
//!   - Startup sweep for orphan `dataward-places-*` tempfiles, using
//!     `O_NOFOLLOW` to block TOCTOU (SEC-R2-009)
//!   - DB-locked → exit 2 with an actionable "Firefox is running" message
//!     (FLOW-003)
//!
//! For Phase 7.2, invoking this importer returns
//! [`DiscoveryError::NotImplemented`] so the CLI can surface a clear error
//! and the pipeline contract stays honest.

use super::{DiscoveryError, Importer, RawRecord};
use std::path::PathBuf;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FirefoxImporter {
    pub profile_dir: Option<PathBuf>,
    pub force_copy: bool,
}

impl Importer for FirefoxImporter {
    fn source_name(&self) -> &'static str {
        "firefox"
    }

    fn import(&self) -> Result<Vec<RawRecord>, DiscoveryError> {
        Err(DiscoveryError::NotImplemented("firefox"))
    }
}
