//! Host/username normalization for discovery.
//!
//! Phase 7.2 shipping implementation uses ASCII case-fold + trim and a
//! hand-rolled eTLD-like extraction (last two labels, or whole host for
//! single-label hosts). Full NFC + Unicode case-fold + eTLD+1 via the `psl`
//! crate + punycode decoding + mixed-script detection is the target
//! implementation (EC-005/007/008) — tracked as a Phase 7.2 follow-up
//! because it adds 3 new crates and is not on the #16 critical path.
//!
//! The dedup hash is computed downstream by `db::compute_dedup_hash` using
//! HMAC-SHA256 with `k_dedup`, so a normalizer upgrade only changes how
//! aliases collapse — it does not break storage compatibility.

use super::{DiscoveryError, NormalizedRecord, RawRecord};
use anyhow::Result;

/// Normalizes a single raw record.
pub fn normalize_record(raw: &RawRecord) -> Result<NormalizedRecord> {
    let host = extract_host(&raw.host);
    let etld_plus_one = etld_plus_one(&host);
    let username_normalized = raw.username.trim().to_lowercase();
    Ok(NormalizedRecord {
        etld_plus_one,
        username_normalized,
        source: raw.source,
    })
}

/// Strips a URL scheme and path, returning the bare host string.
pub fn extract_host(input: &str) -> String {
    let trimmed = input.trim();
    // Strip scheme.
    let without_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };
    // Strip userinfo.
    let without_userinfo = if let Some(idx) = without_scheme.find('@') {
        &without_scheme[idx + 1..]
    } else {
        without_scheme
    };
    // Strip path/query/fragment.
    let host = without_userinfo.split(['/', '?', '#']).next().unwrap_or("");
    // Strip port.
    let host = host.split(':').next().unwrap_or("");
    host.to_ascii_lowercase()
}

/// Returns the last two labels of a host (e.g., `foo.bar.example.com` →
/// `example.com`). Single-label hosts are returned unchanged.
///
/// This is a simplification — real eTLD+1 needs the public suffix list
/// (psl crate) to handle `co.uk`, `github.io`, etc. Tracked as follow-up.
pub fn etld_plus_one(host: &str) -> String {
    if host.is_empty() {
        return String::new();
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
}

/// Sanity check: reject inputs with null bytes or control chars.
#[allow(dead_code)]
pub fn reject_control_chars(s: &str) -> Result<(), DiscoveryError> {
    if s.chars()
        .any(|c| c == '\0' || (c.is_control() && c != '\n'))
    {
        return Err(DiscoveryError::Parse("control characters in input".into()));
    }
    Ok(())
}
