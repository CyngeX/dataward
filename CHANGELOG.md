# Changelog

All notable changes to Dataward are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — Phase 7: Breach-Minimization Purge

Phase 7 introduces account discovery and opt-out automation for
platforms (not just data brokers), plus security hardening across the
Dataward surface. Scope has been deliberately narrowed to scaffolds for
Firefox, Gmail IMAP, discovery CLI wiring, first-run preview, and the
discovery triage UI — see `docs/phase7-discovery.md` for the full
"what's landed / what's pending" list.

### Added

- **HKDF subkey derivation** (`crypto::hkdf_subkey`) with
  `INFO_CREDSTORE` / `INFO_DEDUP` domain-separation labels. Per-install
  salt via `crypto::generate_install_salt()`. Domain separation lives in
  `info`, not salt, per RFC 5869 (SEC-R2-002).
- **Core-dump hardening** (`crypto::harden_core_dumps`) — `prctl`
  `PR_SET_DUMPABLE=0` + `setrlimit` `RLIMIT_CORE=0` at startup.
- **`db::backup_to`** using SQLite's `VACUUM INTO` (SQLCipher disables
  the C-level backup API). Destination inherits the source key.
- **Phase 7.1 sibling tables** — `platform_accounts`, `credential_store`,
  `account_discovery_findings` landed as an additive v1→v2 migration
  (`db::migrate_v1_to_v2`). The existing `brokers` table is untouched
  per ARCH-001/002/003. Migration wraps in `BEGIN IMMEDIATE`/`COMMIT`
  with pre-backup; idempotent on replay.
- **Retention job** (`src/retention.rs`) — daily sweep of dismissed /
  already_tracked findings > 30 days, accepted > 90 days, configurable
  via encrypted config keys.
- **Legal acknowledgment scaffold** (`src/legal_ack.rs`) — first-run
  `I AGREE` gate, ISO-8601 timestamp in encrypted config table,
  separate regulated-category ack.
- **Discovery pipeline scaffold** (`src/discovery/`) — trait-based
  `Importer`, `DiscoveryPipeline` coordinator, `RawRecord` →
  `NormalizedRecord` → sensitivity scoring.
- **Bitwarden importer** — streaming `serde_json`, resource caps
  (50 MiB / 100k items), encrypted-export detection, EC-001 absent/null/
  empty `uris` handling.
- **macOS Keychain CSV importer** — strict 3-column header validation
  (SEC-016), correct handling of commas in quoted passwords.
- **Credential scrubber** (`discovery::scrub`) — walks `anyhow::Error`
  chains and redacts `password=` / `token=` / `secret=` /
  `app_password=` / `apikey=` values. Covered by a **log-canary test**
  asserting injected credentials do not survive sanitization.
- **Playbook loader extensions** — `source_type` (default
  `data_broker`), `sensitivity_default`, `manual_instructions`. Category
  list expanded to include `financial`, `health`, `dating`, `forum`,
  `cloud`, `social`, `shopping`, `government`.
- **Regulated-category playbook gate** — `financial`, `health`,
  `government` REJECT any channel other than `manual_only`.
- **`dataward playbook verify`** — plain `sha256sum -c`-style drift
  check against `playbooks/platform.sums`. No crypto signing (§L).
- **Three reference platform playbooks** — `example-web-form.yaml`,
  `example-email.yaml`, `example-manual-only.yaml`.
- **Dashboard Origin header validation** — rejects any state-changing
  request whose `Origin`/`Referer` does not parse to a localhost URL
  (SEC-R2-004, DNS-rebinding defense layer 2).
- **Discovery triage route scaffold** — `GET /discovery`,
  `POST /discovery/{accept,dismiss}/{id}`, `GET /discovery/preview/{id}/
  {version}`, `POST /discovery/preview/{id}/approve`. Returns 503 with
  actionable follow-up messages; full UI deferred.
- **Post-migration banner helpers** (`db::post_migration_banner_visible`
  / `dismiss_post_migration_banner`).
- **Phase 7 audit test module** (`src/phase7_audit.rs`) — 13
  consolidated invariant checks runnable via
  `cargo test phase7_audit`. 3 E2E flow tests marked `#[ignore]` for
  features still pending.

### Changed

- **Min passphrase length** — init now enforces 16 characters.
- **Playbook step requirement** — `email` and `manual_only` channels
  now legitimately accept `steps: []`.
- **`.gitignore`** — `.claude/` session state excluded.
- **rusqlite feature** — added `backup` alongside `bundled-sqlcipher`.

### Security

See the per-area notes above. Key invariants (all covered by tests):

- HKDF subkeys are pairwise distinct and distinct from the master.
- Domain separation lives in `info`, not salt (RFC 5869).
- Install salts are per-install random.
- Credential store forbids rows with both FKs set (CHECK constraint).
- Findings cannot be promoted twice (UNIQUE partial index).
- Migration is idempotent and produces a recoverable backup.
- Regulated-category playbooks cannot use non-`manual_only` channels.
- Dashboard state-changing requests require a localhost Origin.
- Log-canary credentials do not survive `sanitize_error_chain`.

### Dependencies

- `hkdf = "0.12"`, `libc = "0.2"`, `csv = "1"` added
- `rusqlite` features: added `backup`

### Not landed (Phase 7 follow-ups)

- Firefox `places.sqlite` real implementation (SEC-002 / SEC-R2-009 /
  EC-002 / FLOW-003/006)
- Gmail IMAP real implementation (needs `async-imap >= 0.11` with
  `rustls-tls`)
- `dataward discover` CLI subcommand wiring into `main.rs`
- First-run dry preview worker action (BLIND-04)
- Discovery triage UI templates + cursor pagination (PERF-005)
- Per-route rate limits on `/discovery/*`
- Scheduler lockout protection (per-domain 6h spacing, circuit breaker,
  3-attempt cap)
- NFC + `psl`-based eTLD+1 normalization (ASCII placeholder in place)
- Migration auto-invocation from `open_db` (new installs get v2
  directly; auto-upgrade deferred until a v1 fixture exists)
- Gmail App Password age display on dashboard (J.3)
- Post-migration banner rendering
- Dashboard-side legal ack prompt
