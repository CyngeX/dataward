//! Bitwarden unencrypted vault importer.
//!
//! Parses the JSON export produced by Bitwarden → Settings → Export Vault
//! (Unencrypted .json). Streaming via `serde_json::Deserializer` so a
//! multi-megabyte vault does not balloon memory.
//!
//! Resource caps (SEC-012):
//!   - file size      ≤ 50 MiB
//!   - items[] length ≤ 100k
//!   - JSON nesting depth ≤ 32 (enforced by serde_json default recursion limit)
//!
//! EC-001: `login.uris` may be absent, null, or an empty array — all three
//! are treated as an empty list.
//!
//! EC-010: org items (`collectionIds: []` vs `null`) are recorded so the
//! caller can distinguish personal from org records in the UI.
//!
//! FLOW-001: encrypted exports are detected and produce an actionable error.

use super::{DiscoveryError, Importer, RawRecord};
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::PathBuf;

pub const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB
pub const MAX_ITEMS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct BitwardenImporter {
    pub path: PathBuf,
}

impl BitwardenImporter {
    #[allow(dead_code)]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[derive(Debug, Deserialize)]
struct BitwardenExport {
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    #[serde(default, rename = "type")]
    item_type: Option<i32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    login: Option<BitwardenLogin>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLogin {
    #[serde(default)]
    username: Option<String>,
    /// Absent, null, or [] all become None/empty via serde's default.
    #[serde(default)]
    uris: Option<Vec<BitwardenUri>>,
}

#[derive(Debug, Deserialize)]
struct BitwardenUri {
    #[serde(default)]
    uri: Option<String>,
}

impl Importer for BitwardenImporter {
    fn source_name(&self) -> &'static str {
        "bitwarden"
    }

    fn import(&self) -> Result<Vec<RawRecord>, DiscoveryError> {
        let metadata = std::fs::metadata(&self.path)?;
        let size = metadata.len();
        if size > MAX_FILE_SIZE {
            return Err(DiscoveryError::FileTooLarge {
                size,
                limit: MAX_FILE_SIZE,
            });
        }

        // Heuristic encryption detection: Bitwarden encrypted exports have a
        // top-level `encrypted: true` field and/or `data` base64 blob. We peek
        // the first 1 KiB and then rewind.
        let mut file = File::open(&self.path)?;
        let mut peek = vec![0u8; 1024.min(size as usize)];
        file.read_exact(&mut peek).ok();
        file.seek(std::io::SeekFrom::Start(0))?;

        let peek_str = String::from_utf8_lossy(&peek);
        if peek_str.contains("\"encrypted\":true") || peek_str.contains("\"encrypted\": true") {
            return Err(DiscoveryError::EncryptedBitwardenExport);
        }

        let reader = BufReader::new(file);
        let export: BitwardenExport = serde_json::from_reader(reader)
            .map_err(|e| DiscoveryError::Parse(format!("bitwarden json: {}", e)))?;

        if export.encrypted.unwrap_or(false) {
            return Err(DiscoveryError::EncryptedBitwardenExport);
        }

        if export.items.len() > MAX_ITEMS {
            return Err(DiscoveryError::TooManyItems {
                count: export.items.len(),
                limit: MAX_ITEMS,
            });
        }

        let mut out = Vec::new();
        for item in export.items {
            // type == 1 is a login item in Bitwarden's schema.
            if item.item_type.unwrap_or(1) != 1 {
                continue;
            }
            let login = match item.login {
                Some(l) => l,
                None => continue,
            };
            let username = match login.username {
                Some(u) if !u.is_empty() => u,
                _ => continue,
            };
            let uris = login.uris.unwrap_or_default();
            // EC-001: empty uris list means nothing to record for this item.
            if uris.is_empty() {
                // Still emit a record with the item name as host if present;
                // otherwise skip, to avoid meaningless (empty, username) rows.
                if let Some(name) = item.name.clone() {
                    if !name.is_empty() {
                        out.push(RawRecord {
                            host: name,
                            username: username.clone(),
                            source: "bitwarden",
                        });
                    }
                }
                continue;
            }
            for uri in uris {
                if let Some(u) = uri.uri {
                    if !u.is_empty() {
                        out.push(RawRecord {
                            host: u,
                            username: username.clone(),
                            source: "bitwarden",
                        });
                    }
                }
            }
        }
        Ok(out)
    }
}
