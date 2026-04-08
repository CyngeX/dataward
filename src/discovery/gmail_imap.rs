//! Gmail IMAP discovery — SCAFFOLD ONLY (Phase 7.2).
//!
//! Full implementation is deferred and requires adding `async-imap >= 0.11`
//! with the `rustls-tls` feature. The correct implementation must:
//!
//!   - Use an **ephemeral** connection only — open at the start of
//!     `discover --source gmail`, close at the end. NO background session.
//!     (Phase 7 plan §J.3)
//!   - Store the Gmail App Password in `credential_store` encrypted with
//!     the `k_credstore` HKDF subkey from Phase 7.0
//!   - Display a scope-disclosure warning at credential entry: App Password
//!     grants full mailbox read including 2FA codes
//!   - After discovery, print a revoke-link prompt pointing at
//!     https://myaccount.google.com/apppasswords
//!   - Dashboard must show App Password age and highlight red at >7 days
//!   - Server-side SEARCH first (PERF-001): batch-FETCH headers only on
//!     matches; never download bodies
//!   - Folder enumeration via LIST + SPECIAL-USE `\\All` for locale safety
//!     (EC-006) — never silently return zero findings on a locale mismatch
//!   - Auth rejection → actionable "generate a new App Password" message
//!     (FLOW-002)
//!
//! For Phase 7.2, invoking this importer returns
//! [`DiscoveryError::NotImplemented`] so the CLI surfaces a clear error.

use super::{DiscoveryError, Importer, RawRecord};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GmailImapImporter {
    pub username: String,
}

impl Importer for GmailImapImporter {
    fn source_name(&self) -> &'static str {
        "gmail"
    }

    fn import(&self) -> Result<Vec<RawRecord>, DiscoveryError> {
        Err(DiscoveryError::NotImplemented("gmail_imap"))
    }
}
