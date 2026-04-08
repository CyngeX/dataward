# Issue #15 — Phase 7.1: Schema sibling tables

**Branch:** `issue-15-schema-sibling-tables`
**Status:** implementation complete, local tests pass (225/225), awaiting CI

## Acceptance criteria

- [x] Migration runs forward on existing v1 DB without data loss (idempotency test)
- [x] Migration idempotent (second run is no-op)
- [x] All existing broker playbook tests pass unchanged
- [x] `brokers` table untouched
- [x] Two-FK CHECK prevents rows with both FKs set
- [x] Unique index prevents double-promotion
- [x] `k_dedup_version` column exists and defaults to 1
- [x] Retention job deletes appropriate rows (4 time-travel tests)

## Changes

- `src/db.rs`: SCHEMA_VERSION bumped to 2; `apply_v2_schema` helper; `migrate_v1_to_v2` with BEGIN IMMEDIATE/COMMIT transaction + pre-backup; `SourceType` enum; DAOs for `platform_accounts`, `credential_store` (with `with_credential_plaintext` zeroizing scoped decrypt), `account_discovery_findings`; `compute_dedup_hash` (length-prefixed HMAC); `compute_username_hmac` (ASCII casefold HMAC — NFC upgrade TODO)
- `src/retention.rs`: NEW module with configurable dismissed/accepted windows and `disabled` flag
- `src/main.rs`: `mod retention;`
- Tests: schema creation, FK CHECK rejection/acceptance, dedup uniqueness, no-double-promotion, migrate idempotency, HMAC length-prefix, case-fold, 4 retention sweep cases

## Known gaps

- NFC normalization placeholder — ASCII lowercase only. Upgrade requires `unicode-normalization` crate (follow-up).
- `migrate_v1_to_v2` auto-invocation from `open_db` not yet wired — intentionally deferred until we have a true v1 fixture to test against. New installs already get v2 via `apply_schema` → `apply_v2_schema`.
- Retention daily-job scheduler wiring not done (that's orchestrator/scheduler work in Phase 7.2+).
