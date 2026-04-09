//! Phase 7.5 security-audit consolidated test module.
//!
//! This module exists purely for `cargo test`. It runs every Phase 7
//! invariant check that can honestly be exercised against the currently
//! merged codebase — the E2E flow tests from issue #19 that depend on
//! scaffolded features (Firefox real impl, Gmail IMAP real impl, first-run
//! preview, lockout scheduler, full discovery CLI wiring) are marked
//! `#[ignore]` with a pointer to the follow-up issue.
//!
//! The goal is to surface regressions in any of the landed Phase 7
//! invariants in one place, so `cargo test phase7_audit` is a single
//! green light before shipping.

#![cfg(test)]

use crate::crypto::{
    generate_install_salt, harden_core_dumps, hkdf_subkey, HKDF_INSTALL_SALT_LEN, INFO_CREDSTORE,
    INFO_DEDUP, TEST_PARAMS,
};
use crate::db;
use crate::discovery::scrub::sanitize_error_chain;
use crate::legal_ack;
use crate::retention;
use tempfile::tempdir;

/// 7.0 §K / SEC-R2-002: HKDF subkeys with distinct `info` labels must be
/// pairwise distinct and distinct from the master key.
#[test]
fn audit_hkdf_subkey_domain_separation() {
    let master = [0x11u8; 32];
    let salt = [0x22u8; HKDF_INSTALL_SALT_LEN];
    let credstore = hkdf_subkey(&master, &salt, INFO_CREDSTORE).unwrap();
    let dedup = hkdf_subkey(&master, &salt, INFO_DEDUP).unwrap();
    assert_ne!(credstore, dedup, "INFO label domain separation broken");
    assert_ne!(&credstore[..], &master[..], "credstore key == master");
    assert_ne!(&dedup[..], &master[..], "dedup key == master");
}

/// 7.0 §K: each install must get a fresh salt → cross-install subkeys differ.
#[test]
fn audit_hkdf_install_separation() {
    let master = [0u8; 32];
    let s1 = generate_install_salt().unwrap();
    let s2 = generate_install_salt().unwrap();
    assert_ne!(s1, s2, "two generate_install_salt calls returned same salt");
    let k1 = hkdf_subkey(&master, &s1, INFO_CREDSTORE).unwrap();
    let k2 = hkdf_subkey(&master, &s2, INFO_CREDSTORE).unwrap();
    assert_ne!(k1, k2);
}

/// 7.0 §L: harden_core_dumps must succeed on Linux.
#[cfg(target_os = "linux")]
#[test]
fn audit_core_dump_hardening() {
    harden_core_dumps().expect("harden_core_dumps failed on Linux");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn audit_core_dump_hardening() {
    // No-op on non-Linux — assert the function is callable and returns Ok.
    harden_core_dumps().unwrap();
}

/// 7.0 §J.2: fresh DB blocks any action that calls `require_accepted`.
#[test]
fn audit_legal_ack_blocks_fresh_install() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, _salt) =
        db::create_db_with_params(&db_path, "phase7-audit-pass", &TEST_PARAMS).unwrap();
    assert!(
        !legal_ack::is_accepted(&conn).unwrap(),
        "fresh DB should not be pre-accepted"
    );
    assert!(
        legal_ack::require_accepted(&conn).is_err(),
        "require_accepted must reject a fresh DB"
    );
}

/// 7.1: migrate_v1_to_v2 must be idempotent (second run is no-op).
#[test]
fn audit_migration_idempotent() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, _salt) =
        db::create_db_with_params(&db_path, "audit-mig-pass", &TEST_PARAMS).unwrap();
    let backup = dir.path().join("backup.db");
    db::migrate_v1_to_v2(&conn, &backup).unwrap();
    db::migrate_v1_to_v2(&conn, &backup).unwrap();
    db::migrate_v1_to_v2(&conn, &backup).unwrap();
    let version: i32 = conn
        .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
}

/// 7.1 / 7.0 §K: migrate_v1_to_v2 must produce a readable backup file.
#[test]
fn audit_migration_creates_recoverable_backup() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, salt) =
        db::create_db_with_params(&db_path, "audit-backup-pass", &TEST_PARAMS).unwrap();
    db::set_config(&conn, "canary", "phase7-audit-value").unwrap();

    // create_db stamps the DB at v2 directly. To exercise the v1→v2 path,
    // simulate an old install by forcing schema_version back to 1.
    conn.execute("UPDATE schema_version SET version = 1", [])
        .unwrap();

    let backup = dir.path().join("pre-migration-backup.db");
    db::migrate_v1_to_v2(&conn, &backup).unwrap();

    assert!(backup.exists(), "migration must leave a backup file");

    let restored =
        db::open_db_with_params(&backup, "audit-backup-pass", &salt, &TEST_PARAMS).unwrap();
    let canary = db::get_config(&restored, "canary").unwrap();
    assert_eq!(canary.as_deref(), Some("phase7-audit-value"));
}

/// 7.1 §B: credential_store CHECK constraint forbids both FKs set.
#[test]
fn audit_credential_store_two_fk_check() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, _salt) = db::create_db_with_params(&db_path, "audit-ck-pass", &TEST_PARAMS).unwrap();

    conn.execute(
        "INSERT INTO brokers (id, name, category, opt_out_channel, recheck_days, playbook_path)
         VALUES ('b', 'B', 'people_search', 'email', 90, '/tmp/p.yaml')",
        [],
    )
    .unwrap();
    let pa = db::PlatformAccountRow {
        id: "pa".into(),
        name: "P".into(),
        category: "forum".into(),
        sensitivity: "low".into(),
        playbook_path: None,
        manual_instructions: None,
        discovery_source: None,
        status: "pending".into(),
        enabled: true,
        created_at: "2026-04-08T00:00:00Z".into(),
        updated_at: "2026-04-08T00:00:00Z".into(),
        last_action_at: None,
    };
    db::insert_platform_account(&conn, &pa).unwrap();

    let result = conn.execute(
        "INSERT INTO credential_store (broker_id, platform_account_id, label, ciphertext, created_at)
         VALUES ('b', 'pa', 'x', x'00', '2026-04-08T00:00:00Z')",
        [],
    );
    assert!(result.is_err(), "CHECK constraint should forbid both FKs");
}

/// 7.1 / ARCH-R5: unique index forbids double-promotion of findings.
#[test]
fn audit_no_double_promotion() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, _salt) = db::create_db_with_params(&db_path, "audit-dp-pass", &TEST_PARAMS).unwrap();

    let pa = db::PlatformAccountRow {
        id: "pa".into(),
        name: "P".into(),
        category: "forum".into(),
        sensitivity: "low".into(),
        playbook_path: None,
        manual_instructions: None,
        discovery_source: None,
        status: "active".into(),
        enabled: true,
        created_at: "2026-04-08T00:00:00Z".into(),
        updated_at: "2026-04-08T00:00:00Z".into(),
        last_action_at: None,
    };
    db::insert_platform_account(&conn, &pa).unwrap();

    let finding = db::DiscoveryFindingRow {
        id: None,
        domain: "x.com".into(),
        username_hmac: vec![1u8; 32],
        dedup_hash: vec![0x01; 32],
        k_dedup_version: 1,
        sensitivity: "low".into(),
        discovery_source: "audit".into(),
        triage_status: "accepted".into(),
        promoted_to_platform_account_id: Some("pa".into()),
        first_seen_at: "2026-04-08T00:00:00Z".into(),
        last_seen_at: "2026-04-08T00:00:00Z".into(),
        triaged_at: Some("2026-04-08T00:00:00Z".into()),
    };
    db::insert_discovery_finding(&conn, &finding).unwrap();

    // Second finding pointing at the same platform_account must be rejected.
    let result = conn.execute(
        "INSERT INTO account_discovery_findings (
            domain, username_hmac, dedup_hash, k_dedup_version, sensitivity,
            discovery_source, triage_status, promoted_to_platform_account_id,
            first_seen_at, last_seen_at, triaged_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            "x2.com",
            vec![2u8; 32],
            vec![0x02u8; 32],
            1_i32,
            "low",
            "audit",
            "accepted",
            "pa",
            "2026-04-08T00:00:00Z",
            "2026-04-08T00:00:00Z",
            "2026-04-08T00:00:00Z",
        ],
    );
    assert!(result.is_err(), "double-promotion must be rejected");
}

/// 7.1 §J.7: retention sweep purges old dismissed findings.
#[test]
fn audit_retention_purges_old_dismissed() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, _salt) =
        db::create_db_with_params(&db_path, "audit-ret-pass", &TEST_PARAMS).unwrap();

    let old = db::DiscoveryFindingRow {
        id: None,
        domain: "old.example".into(),
        username_hmac: vec![1u8; 32],
        dedup_hash: vec![0x11; 32],
        k_dedup_version: 1,
        sensitivity: "low".into(),
        discovery_source: "audit".into(),
        triage_status: "dismissed".into(),
        promoted_to_platform_account_id: None,
        first_seen_at: "2026-01-01T00:00:00+00:00".into(),
        last_seen_at: "2026-01-01T00:00:00+00:00".into(),
        triaged_at: Some("2026-01-01T00:00:00+00:00".into()),
    };
    db::insert_discovery_finding(&conn, &old).unwrap();
    let deleted = retention::run(&conn, "2026-04-08T00:00:00+00:00").unwrap();
    assert_eq!(deleted, 1);
}

/// 7.2 SEC-R2-006: log canary — injected credential must not survive the
/// error-chain sanitizer.
#[test]
fn audit_log_canary_credential_scrubbed() {
    let canary = "CANARY-AUDIT-PW-DO-NOT-LEAK-9999";
    let err = anyhow::anyhow!("imap login password={}", canary)
        .context("discovery")
        .context("pipeline");
    let sanitized = sanitize_error_chain(&err);
    assert!(
        !sanitized.contains(canary),
        "Phase 7.2 canary leaked: {}",
        sanitized
    );
}

/// 7.2: Bitwarden resource caps are declared.
#[test]
fn audit_bitwarden_caps_declared() {
    use crate::discovery::bitwarden::{MAX_FILE_SIZE, MAX_ITEMS};
    assert_eq!(MAX_FILE_SIZE, 50 * 1024 * 1024, "50 MiB cap");
    assert_eq!(MAX_ITEMS, 100_000, "100k items cap");
}

/// 7.3: regulated playbooks cannot use non-manual_only channels.
///
/// This is a compile-time guarantee via broker_registry validation; we
/// assert the validator rejects a forged playbook at runtime.
#[test]
fn audit_regulated_category_requires_manual_only() {
    let yaml = r#"
broker:
  id: regulated-forged
  name: Forged
  url: https://bank.example.com
  category: financial
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [bank.example.com]

required_fields: [email]
steps:
  - navigate: "https://bank.example.com"
"#;
    let dir = tempdir().unwrap();
    let subdir = dir.path().join("official");
    std::fs::create_dir_all(&subdir).unwrap();
    std::fs::write(subdir.join("regulated.yaml"), yaml).unwrap();

    let playbooks = crate::broker_registry::load_playbooks(dir.path()).unwrap();
    assert!(
        playbooks.is_empty(),
        "Phase 7.3 regulated-category gate failed — playbook loaded: {:?}",
        playbooks
    );
}

/// 7.4 SEC-R2-004: post-migration banner helpers round-trip.
#[test]
fn audit_post_migration_banner_roundtrip() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let (conn, _salt) =
        db::create_db_with_params(&db_path, "audit-banner-pass", &TEST_PARAMS).unwrap();
    assert!(db::post_migration_banner_visible(&conn).unwrap());
    db::dismiss_post_migration_banner(&conn).unwrap();
    assert!(!db::post_migration_banner_visible(&conn).unwrap());
}

// -- Intentionally ignored: scaffolded-feature E2E flows from issue #19 --

/// Full discovery → triage → accept → preview → approve → execute flow.
/// Depends on the scaffolded pieces from #16/#17 (discovery CLI, first-run
/// preview, triage UI, lockout scheduler). Kept here as a pointer so when
/// the follow-ups land, re-enabling this test reminds the developer to
/// exercise the complete path end-to-end.
#[ignore = "Phase 7.5 E2E flow — pending scaffolded features from #16/#17"]
#[test]
fn audit_e2e_bitwarden_to_execute() {
    unimplemented!("re-enable when discovery CLI + triage UI + preview worker land");
}

#[ignore = "Phase 7.5 E2E flow — pending Firefox real implementation"]
#[test]
fn audit_e2e_firefox_flow() {
    unimplemented!("re-enable when firefox importer lands");
}

#[ignore = "Phase 7.5 E2E flow — pending Gmail IMAP real implementation"]
#[test]
fn audit_e2e_gmail_flow() {
    unimplemented!("re-enable when gmail_imap importer lands");
}
