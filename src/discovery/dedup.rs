//! Cross-source dedup merge.
//!
//! Phase 7.1's `db::compute_dedup_hash` produces the persistent dedup key
//! (length-prefixed HMAC-SHA256 with `k_dedup`). This module provides an
//! in-memory merge helper used by the CLI layer to collapse records that
//! appear in multiple importers into a single finding with comma-separated
//! `discovery_source`.

use super::NormalizedRecord;
use std::collections::BTreeMap;

/// Merges records that share the same `(etld_plus_one, username_normalized)`
/// key, joining their `source` fields alphabetically.
///
/// The output is deterministic (sorted by key + source) so test assertions
/// do not depend on hash iteration order.
#[allow(dead_code)]
pub fn merge_cross_source(records: Vec<NormalizedRecord>) -> Vec<MergedRecord> {
    let mut bucket: BTreeMap<(String, String), Vec<&'static str>> = BTreeMap::new();
    for r in records {
        let key = (r.etld_plus_one, r.username_normalized);
        bucket.entry(key).or_default().push(r.source);
    }
    bucket
        .into_iter()
        .map(|((etld, user), mut sources)| {
            sources.sort_unstable();
            sources.dedup();
            MergedRecord {
                etld_plus_one: etld,
                username_normalized: user,
                sources,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MergedRecord {
    pub etld_plus_one: String,
    pub username_normalized: String,
    pub sources: Vec<&'static str>,
}
