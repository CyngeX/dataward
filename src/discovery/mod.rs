//! Phase 7.2: account discovery pipeline.
//!
//! Architecture: four importers produce [`RawRecord`]s, a [`DiscoveryPipeline`]
//! owns the normalize → dedupe → score → write sequence. Importers MUST NOT
//! call the deduper/scorer/writer directly — all coordination goes through the
//! pipeline.
//!
//! ## Status
//!
//! - [x] `bitwarden` — full implementation with resource caps and streaming
//! - [x] `keychain_csv` — full implementation
//! - [ ] `firefox` — scaffold only; returns `DiscoveryError::NotImplemented`
//! - [ ] `gmail_imap` — scaffold only; requires `async-imap 0.11+` (not yet added)
//! - [x] `normalize` — ASCII case-fold + trim (NFC upgrade TODO when
//!   `unicode-normalization` is added)
//! - [x] `scoring` — 3-tier category map
//! - [x] `scrub` — credential scrubber for Result chains

use anyhow::Result;
use thiserror::Error;

pub mod bitwarden;
pub mod dedup;
pub mod firefox;
pub mod gmail_imap;
pub mod keychain_csv;
pub mod normalize;
pub mod scoring;
pub mod scrub;

#[cfg(test)]
mod tests;

/// Raw record emitted by an importer before normalization.
///
/// Importers populate this; no downstream processing happens until the
/// pipeline normalizes and dedupes.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    /// Full host/URI as it appeared in the source.
    pub host: String,
    /// Username/email as it appeared in the source.
    pub username: String,
    /// Which importer produced this record (e.g. "bitwarden", "keychain").
    pub source: &'static str,
}

/// Normalized record ready for hashing and scoring.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRecord {
    pub etld_plus_one: String,
    pub username_normalized: String,
    pub source: &'static str,
}

/// Sensitivity tier, per SIMP-002 (not 0-100 scoring).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}

impl Sensitivity {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Low => "low",
            Sensitivity::Medium => "medium",
            Sensitivity::High => "high",
        }
    }
}

/// Discovery-pipeline errors. Uses `thiserror` so callers get structured
/// variants and `scrub::sanitize_error_chain` can walk the chain without
/// risk of credential leakage via `Debug`.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("importer not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("input file appears encrypted — export as Unencrypted JSON from Bitwarden → Settings → Export Vault")]
    EncryptedBitwardenExport,

    #[error("input file too large: {size} bytes (limit: {limit})")]
    FileTooLarge { size: u64, limit: u64 },

    #[error("too many items in vault: {count} (limit: {limit})")]
    TooManyItems { count: usize, limit: usize },

    #[error("invalid CSV header — expected 'website,username,password'")]
    InvalidCsvHeader,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(String),
}

/// Trait that all importers implement.
///
/// Importers are pure producers: they return an iterator of [`RawRecord`]s
/// and do NOT interact with the database, deduper, or scorer. All coordination
/// happens in [`DiscoveryPipeline`].
#[allow(dead_code)]
pub trait Importer {
    fn source_name(&self) -> &'static str;
    fn import(&self) -> Result<Vec<RawRecord>, DiscoveryError>;
}

/// Coordinator that runs importer → normalize → dedupe → score → write.
#[allow(dead_code)]
pub struct DiscoveryPipeline;

#[allow(dead_code)]
impl DiscoveryPipeline {
    pub fn new() -> Self {
        DiscoveryPipeline
    }

    /// Runs an importer and returns the normalized+deduped findings without
    /// writing to the database. Database persistence is wired in the CLI
    /// layer so tests can exercise the pipeline in isolation.
    pub fn run<I: Importer>(&self, importer: &I) -> Result<Vec<(NormalizedRecord, Sensitivity)>> {
        let raw = importer.import()?;
        let mut out = Vec::with_capacity(raw.len());
        let mut seen = std::collections::HashSet::new();
        for rec in raw {
            let norm = normalize::normalize_record(&rec)?;
            // In-memory dedup by (etld+1, username) — DB layer enforces
            // persistent dedup via the UNIQUE index on dedup_hash.
            let key = (norm.etld_plus_one.clone(), norm.username_normalized.clone());
            if !seen.insert(key) {
                continue;
            }
            let sensitivity = scoring::score(&norm.etld_plus_one);
            out.push((norm, sensitivity));
        }
        Ok(out)
    }
}

impl Default for DiscoveryPipeline {
    fn default() -> Self {
        Self::new()
    }
}
