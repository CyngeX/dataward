//! Credential scrubber for Result error chains (SEC-R2-006).
//!
//! Discovery importers may receive raw credentials as part of their input
//! (e.g., a Bitwarden vault). If any of that data leaks into an error chain
//! via `format!("{:?}", err)` or anyhow's wrapping, it could end up in logs
//! or crash reports. This module provides a sanitizer that walks an error's
//! `Display` and `Debug` output and masks anything matching a deny regex set.
//!
//! The scrubber is defensive-in-depth: ideally no credential ever enters an
//! error chain in the first place. The log-canary test in `tests.rs` asserts
//! that mock credentials cannot be recovered from sanitized error chains.

use std::fmt::Write;

/// Substrings that, if found in an error message, are fully redacted.
///
/// Extend cautiously — over-zealous scrubbing makes debugging harder.
/// Prefer structural fixes (don't format raw credentials into errors).
const DENY_SUBSTRINGS: &[&str] = &["password=", "token=", "secret=", "app_password=", "apikey="];

/// Redacts any occurrence of the deny substrings and the value that follows
/// them (up to the next whitespace or quote). Returns a new string.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for pat in DENY_SUBSTRINGS {
            if let Some(idx) = rest.to_ascii_lowercase().find(pat) {
                out.push_str(&rest[..idx]);
                out.push_str(pat);
                out.push_str("[REDACTED]");
                // Skip forward until whitespace/quote/end.
                let after = &rest[idx + pat.len()..];
                let skip = after
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .unwrap_or(after.len());
                rest = &after[skip..];
                continue 'outer;
            }
        }
        // No more matches — append remainder and finish.
        out.push_str(rest);
        break;
    }
    out
}

/// Walks an `anyhow::Error` chain, formatting each link through the
/// sanitizer. Safe to log.
#[allow(dead_code)]
pub fn sanitize_error_chain(err: &anyhow::Error) -> String {
    let mut out = String::new();
    let _ = write!(out, "{}", sanitize(&format!("{}", err)));
    for cause in err.chain().skip(1) {
        let _ = write!(out, ": {}", sanitize(&format!("{}", cause)));
    }
    out
}
