//! iOS Keychain CSV importer.
//!
//! Strict 3-column header validation: `website, username, password` — fails
//! loudly on any mismatch (SEC-016 / format drift). CSV parsing uses the
//! `csv` crate so commas in passwords are handled correctly.

use super::{DiscoveryError, Importer, RawRecord};
use std::path::PathBuf;

pub const EXPECTED_HEADERS: &[&str] = &["website", "username", "password"];

#[derive(Debug, Clone)]
pub struct KeychainCsvImporter {
    pub path: PathBuf,
}

impl KeychainCsvImporter {
    #[allow(dead_code)]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Importer for KeychainCsvImporter {
    fn source_name(&self) -> &'static str {
        "keychain"
    }

    fn import(&self) -> Result<Vec<RawRecord>, DiscoveryError> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(&self.path)
            .map_err(|e| DiscoveryError::Parse(format!("keychain csv open: {}", e)))?;

        // Strict header validation.
        let headers = reader
            .headers()
            .map_err(|e| DiscoveryError::Parse(format!("keychain csv headers: {}", e)))?;
        let actual: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
        if actual.len() != EXPECTED_HEADERS.len()
            || actual
                .iter()
                .zip(EXPECTED_HEADERS.iter())
                .any(|(a, e)| a != e)
        {
            return Err(DiscoveryError::InvalidCsvHeader);
        }

        let mut out = Vec::new();
        for result in reader.records() {
            let record =
                result.map_err(|e| DiscoveryError::Parse(format!("keychain csv row: {}", e)))?;
            let website = record.get(0).unwrap_or("").trim();
            let username = record.get(1).unwrap_or("").trim();
            if website.is_empty() || username.is_empty() {
                continue;
            }
            out.push(RawRecord {
                host: website.to_string(),
                username: username.to_string(),
                source: "keychain",
            });
        }
        Ok(out)
    }
}
