---
title: "Phase 7: Breach-Minimization Purge (schema generalization + account discovery + platform playbooks)"
date: 2026-04-08
type: comprehensive
status: approved
tags: [schema-migration, account-discovery, breach-minimization, playbooks, imap, bitwarden, firefox, security-sensitive]
risk_flags: [SECURITY_SENSITIVE, BREAKING_CHANGE]
confidence: MEDIUM_CONFIDENCE
deepened: true
deepened_date: 2026-04-08
research_agents: [codebase-researcher, best-practices-researcher]
review_agents: [architecture-reviewer, simplicity-reviewer, security-reviewer, performance-reviewer, edge-case-reviewer, spec-flow-reviewer]
---

> **[DEEPENED 2026-04-08]** This plan was reviewed by 6 review agents and 2 research agents. Multiple original assumptions were contradicted by the codebase (no backup helper, no `src/types.rs`, dashboard uses **askama** not minijinja, no `migrations/` directory, `deny_unknown_fields` on playbook structs, `brokers` table name referenced in 15+ places in `db.rs`). The architectural approach of "rename + additive columns" was flagged as NOT actually transparent. See **Deepening Revisions** at the bottom of this document for the authoritative corrections — the body text above has been left intact for historical reference but must be read through the lens of the revisions section.

# Phase 7: Breach-Minimization Purge

## Problem

Dataward today is a broker opt-out daemon with 3 playbooks and a schema hardcoded to the people-search broker use case. The user's actual threat model is broader and sharper than that: **every third party holding their data is a future breach victim**, and the goal is to shrink the blast radius of the inevitable compromise by deleting data at rest wherever possible, *before* those services get breached.

Three concrete gaps block this:

1. **Schema assumes "broker"** — there is no first-class way to represent a Google/Reddit/bank account as something to be minimized or deleted.
2. **You cannot delete what you don't remember signing up for** — the single biggest gap in commercial tools (Incogni, DeleteMe, Optery). No existing tool helps enumerate the long tail of forgotten accounts living in inboxes and password vaults.
3. **No high-value platform playbooks** — the 3 shipped playbooks all target people-search sites. The services most likely to hold truly sensitive data (financial, health, dating, old forums) have no coverage.

The user has no HIBP subscription and does not want to buy one, so v1 deliberately does **not** include active breach monitoring. The work here is pre-breach footprint reduction, not incident response.

## Goals

1. Generalize dataward's schema so a "data source" can be a broker, a platform account, or a search engine — without rewriting the orchestrator, scheduler, crypto, or dashboard.
2. Ship an **account-discovery ingester** that reads Bitwarden JSON, iOS Keychain CSV, Gmail IMAP (signup/receipt heuristics), and Firefox `places.sqlite` and produces a deduped, sensitivity-scored triage queue.
3. Ship **15–20 high-value platform deletion playbooks** focused on financial, health, dating, and legacy-forum categories.
4. Extend the dashboard with a triage queue UI and sensitivity filters.
5. Do all of this additively — no breaking changes to existing broker flows or shipped playbooks.

**Non-goals (explicitly deferred):**
- AI training opt-out flows (not breach-relevant; revisit if threat model shifts)
- HIBP / breach monitoring (user declined; revisit in a later phase)
- Archive.org / search-cache purging
- Machine-unlearning research
- Long-tail broker coverage (delegated to Incogni subscription)
- OAuth-based Gmail integration (App Password is sufficient for v1 and avoids a Google Cloud project)

## Solution

**Approach C from the 2026-04-08 brainstorm**: generalize the dataward schema in place rather than forking a new `purge` repo or grafting new concepts onto the broker model.

Three net-new subsystems, one schema migration, zero rewrites:

- **Schema migration (Phase 7.1)** — additive SQL: new columns on `brokers` (soon `data_sources`), new `credential_store` table, new `account_discovery_findings` table. Existing broker rows keep working with `source_type='data_broker'` as the default.
- **Account discovery module (Phase 7.2)** — a new `src/discovery/` module with four importers (Bitwarden, Keychain CSV, Gmail IMAP, Firefox), a normalizer, a deduper, and a sensitivity scorer. Produces rows in `account_discovery_findings` that the user triages in the dashboard. On acceptance, rows graduate into `data_sources` with `source_type='platform_account'` and `status='pending'` — at which point dataward's existing scheduler picks them up.
- **Platform playbook category (Phase 7.3)** — extend the playbook YAML schema with `source_type` and `category` fields. Write 15–20 real playbooks for financial/health/dating/forum services. Some will be `manual_only` (where deletion requires phone/ID verification) and those are fine — they still show up in the triage queue with step-by-step instructions.
- **Dashboard additions (Phase 7.4)** — triage queue page, sensitivity filter on the main table, findings-review workflow.

## Technical Approach

### 7.1 Schema Generalization

**Migration strategy:** purely additive. Rename table `brokers` → `data_sources` via SQL `ALTER`. All existing rows get `source_type='data_broker'` and `category='people_search'` (or whatever they had). No data loss, no config churn.

**New columns on `data_sources`:**
- `source_type TEXT NOT NULL DEFAULT 'data_broker'` — enum: `data_broker | platform_account | search_engine`
- `sensitivity_score INTEGER DEFAULT 0` — 0–100, populated by discovery scorer or playbook default
- `last_known_login_domain TEXT` — for platform accounts, the domain the user actually logs into (disambiguates forks like `reddit.com` vs `old.reddit.com`)
- `discovery_source TEXT` — which importer found it (`bitwarden|keychain|gmail|firefox|manual`), NULL for manually-added brokers

**New table: `credential_store`**
```
id INTEGER PRIMARY KEY
data_source_id INTEGER REFERENCES data_sources(id) ON DELETE CASCADE
kind TEXT NOT NULL                -- 'password' | 'app_password' | 'oauth_token' | 'api_key' | 'session_cookie'
ciphertext BLOB NOT NULL          -- encrypted with existing AES-GCM key from crypto.rs
nonce BLOB NOT NULL
created_at INTEGER NOT NULL
last_used_at INTEGER
notes TEXT
```
Reuses the existing `crypto::encrypt`/`decrypt` helpers. No new key material. Access is gated through a new `CredentialStore` struct in `src/db.rs` that returns plaintext only inside a short-lived scope.

**New table: `account_discovery_findings`**
```
id INTEGER PRIMARY KEY
discovery_source TEXT NOT NULL    -- 'bitwarden' | 'keychain' | 'gmail' | 'firefox'
discovered_at INTEGER NOT NULL
domain TEXT NOT NULL              -- normalized: lowercased, psl-trimmed to eTLD+1
raw_name TEXT                     -- what the importer saw (e.g., 'Old Forum Login')
raw_username TEXT                 -- masked when displayed
first_seen_hint INTEGER           -- epoch, best-effort from source
last_activity_hint INTEGER        -- epoch, best-effort
sensitivity_score INTEGER NOT NULL
dedup_hash TEXT NOT NULL          -- sha256(domain || '|' || username) for cross-source dedup
triage_status TEXT NOT NULL DEFAULT 'pending'  -- 'pending' | 'accepted' | 'dismissed' | 'already_tracked'
promoted_to_data_source_id INTEGER REFERENCES data_sources(id)
```

**Migration file:** `migrations/YYYYMMDD_phase7_schema_generalization.sql`. Guarded by schema version bump in `db.rs`. Down-migration is best-effort (can reverse column additions, cannot un-rename rows already in `data_sources`).

### 7.2 Account Discovery Module

**New module:** `src/discovery/` with submodules:
- `mod.rs` — `DiscoveryPipeline` coordinator, dedup, scoring, persistence
- `bitwarden.rs` — parses unencrypted Bitwarden JSON export (`.json`). The user must export themselves; we do not handle Bitwarden master passwords. Extracts `login.uris`, `name`, `login.username`, `creationDate`, `revisionDate`.
- `keychain_csv.rs` — parses iOS Keychain CSV export (iOS 17+ Passwords app → Export). Schema: `Title, URL, Username, Password, Notes, OTPAuth`.
- `gmail_imap.rs` — IMAPS with user-supplied Gmail App Password. Connects, scans `INBOX` + `[Gmail]/All Mail` for sender-domain patterns (`noreply@`, `no-reply@`, `welcome@`, `receipts@`, `security@`) and subject heuristics (`Welcome to`, `Verify your`, `Your receipt`, `Confirm your account`). Never downloads bodies — headers only, via `FETCH BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)]`. Stores nothing locally except the finding row.
- `firefox.rs` — reads `places.sqlite` read-only (ATTACH a tempfile copy to avoid locking). Groups by eTLD+1, extracts `moz_places.last_visit_date`, visit count, title.
- `scoring.rs` — sensitivity heuristics (see below)
- `dedup.rs` — cross-source merge on `sha256(etld1 || '|' || normalized_username)`

**Sensitivity scoring (0–100):**
Category-based floor with modifiers:
- Financial (matches bank/brokerage/crypto/payment keywords) → base 90
- Health (medical/pharmacy/insurance/telehealth) → base 85
- Government/ID (IRS, DMV, passport services) → base 85
- Dating (match/tinder/bumble/hinge/okcupid/grindr) → base 80
- Cloud storage (drive/dropbox/icloud/onedrive/box) → base 70
- Social (facebook/x/instagram/reddit/linkedin) → base 60
- Shopping w/ stored payment (amazon/etsy/ebay/doordash) → base 55
- Forums / legacy accounts (phpBB/vBulletin/Discourse, age-hint > 5y) → base 50
- Other → base 30
- Modifiers: `+10` if password is in a known breach (not in v1, HIBP deferred — leave hook), `+5` per year since `last_activity_hint` over 3 years, `-10` if already in `data_sources`.

**Pipeline flow:**
1. User runs `dataward discover --source bitwarden --file ~/exports/vault.json` (and similarly for other sources).
2. Importer parses → yields `RawFinding` structs.
3. Normalizer lowercases domains, trims to eTLD+1, masks usernames for display.
4. Deduper merges by `dedup_hash`, takes max sensitivity, unions discovery_sources.
5. Scorer assigns final score.
6. Check against existing `data_sources` — if the domain already exists, mark finding `already_tracked`.
7. Persist to `account_discovery_findings` with `triage_status='pending'`.
8. User reviews in dashboard triage queue → accepts/dismisses.
9. On accept, a new row is inserted into `data_sources` with `source_type='platform_account'`, linked to a playbook by domain match (or `manual_only` if no playbook exists), and the finding is marked `promoted_to_data_source_id=X`.

**Security posture for discovery:**
- **Bitwarden JSON** must be an *unencrypted* export — we warn the user that this file is sensitive and offer to shred it after import (`shred -u`).
- **Keychain CSV** same treatment.
- **Gmail App Password** is stored in `credential_store` under a synthetic `data_sources` row for "Gmail IMAP (discovery)". Rotatable from the dashboard. Never logged.
- **Firefox places.sqlite** is copied to a tempfile (`/tmp/dataward-places-XXXXXX`) and deleted in a `Drop` impl. Original file is never written.
- **IMAP connection** uses rustls with cert validation, no plaintext fallback. Fails closed.

### 7.3 Platform Playbook Category

**Playbook YAML extension (backward-compatible):**
```yaml
# existing fields unchanged
name: "Example Bank"
domain: "examplebank.com"
# NEW:
source_type: "platform_account"   # defaults to 'data_broker' if omitted → existing playbooks unchanged
category: "financial"             # free text, UI groups by this
sensitivity_default: 90           # used if discovery didn't score it
deletion_channels:                # at least one required
  - web_form
  - email
  - manual_only
manual_instructions: |            # required when any channel is manual_only
  1. Log in at https://examplebank.com
  2. Navigate to Profile → Close Account
  3. Call 1-800-XXX-XXXX to verify
```

Loader in `broker_registry.rs` adds defaulting logic: missing `source_type` → `data_broker`, missing `category` → `people_search` (preserves current behavior exactly).

**Target playbook list (final list confirmed with user during implementation):**

| Category | Example targets (pick 15–20 total based on user's actual accounts) |
|---|---|
| Financial | Old PayPal / Venmo / Cash App, abandoned brokerage, defunct crypto exchanges |
| Health | Old telehealth, pharmacy rewards, gym/fitness apps with health data |
| Dating | Tinder, Bumble, Hinge, OkCupid, Match, Grindr |
| Legacy forums | Reddit (manual_only — Reddit doesn't honor bulk delete post-2023), phpBB-style old forums, Discourse instances |
| Shopping w/ stored payment | Amazon order history purge, DoorDash, Uber, eBay |
| Cloud storage | Dropbox/Box/Drive old-file cleanup flows |

The user triages discovered accounts first, then we write playbooks for whatever has ≥5 accounts in their actual vault. This is better than speculating.

### 7.4 Dashboard Additions

**New pages:**
- `/discovery` — triage queue. Table of pending findings with columns: domain, discovery_source, first_seen, sensitivity, suggested action. Row actions: Accept (→ creates data_source row) / Dismiss / View details. Bulk-accept by category.
- `/credentials` — list of credential_store entries (masked), rotation/deletion actions.

**Main `/` table changes:**
- Add `source_type` and `sensitivity` columns.
- Filter chips: `data_broker | platform_account | search_engine`, sensitivity ≥N slider, category facet.
- Sort by sensitivity default.

All new pages follow the existing Axum + minijinja pattern in `src/dashboard/`. No new framework dependencies.

## Implementation Steps

### Phase 7.1 — Schema generalization (1–2 days)
1. Write migration SQL (`migrations/phase7_schema.sql`)
2. Bump schema version in `db.rs`, implement `migrate_to_v2()` guarded path
3. Add `SourceType` enum in `src/types.rs`
4. Add `CredentialStore` struct in `src/db.rs` with `insert`, `get_decrypted_scoped`, `rotate`, `delete`
5. Add `AccountDiscoveryFindings` DAO
6. Unit tests for migration (forward and idempotency), credential round-trip, finding CRUD
7. Verify all existing broker playbook tests still pass unchanged

### Phase 7.2 — Account discovery module (3–5 days)
1. Scaffold `src/discovery/` module tree
2. `bitwarden.rs` importer + golden-file tests against a fake vault JSON
3. `keychain_csv.rs` importer + tests
4. `firefox.rs` importer (ATTACH temp copy pattern) + tests
5. `gmail_imap.rs` importer: rustls IMAP client, header-only fetch, heuristics + tests against a mock IMAP server (`imap` crate's test utilities)
6. `scoring.rs` with category matchers and unit tests
7. `dedup.rs` with cross-source merge tests
8. `DiscoveryPipeline` coordinator
9. CLI subcommand: `dataward discover <source>`
10. Integration test: run all importers against fixture data → verify findings table

### Phase 7.3 — Platform playbook category (2–3 days)
1. Extend playbook YAML schema (`broker_registry.rs`) with `source_type`, `category`, `sensitivity_default`, `manual_instructions`
2. Add backward-compat defaulting; run existing validation suite
3. Write 3 reference playbooks (one web_form, one email, one manual_only) as implementation templates
4. Document playbook authoring in `playbooks/README.md`
5. Write remaining playbooks based on user's post-discovery triage list (can continue post-merge)

### Phase 7.4 — Dashboard (2–3 days)
1. Triage queue route + template
2. Credentials management route + template
3. Main table filter/sort updates
4. Accept-finding workflow (creates data_source, marks finding promoted)
5. Dashboard integration tests for new routes

### Phase 7.5 — End-to-end validation (1 day)
1. Full flow test: export Bitwarden JSON → `dataward discover` → triage in dashboard → new platform_account runs through existing orchestrator → deletion attempted
2. Verify no regressions on existing broker playbooks
3. Security review (see Security Review section)

**Total rough effort:** 9–14 days of focused work.

## Affected Files

**Modified:**
- `src/db.rs` — migration, new DAOs, CredentialStore
- `src/types.rs` — SourceType enum
- `src/broker_registry.rs` — extended playbook schema + defaulting
- `src/main.rs` — new `discover` subcommand
- `src/dashboard/mod.rs` — new routes
- `src/dashboard/templates/` — new templates, table updates
- `Cargo.toml` — add `imap`, `rustls-connector`, `csv`, `publicsuffix`, `rusqlite` features for ATTACH if not present

**New:**
- `migrations/phase7_schema.sql`
- `src/discovery/mod.rs`
- `src/discovery/bitwarden.rs`
- `src/discovery/keychain_csv.rs`
- `src/discovery/gmail_imap.rs`
- `src/discovery/firefox.rs`
- `src/discovery/scoring.rs`
- `src/discovery/dedup.rs`
- `src/dashboard/routes/discovery.rs`
- `src/dashboard/routes/credentials.rs`
- `playbooks/platform/<15-20 new files>.yaml`
- `docs/phase7-discovery.md` (user-facing usage doc)

**Unchanged (critical — do not touch):**
- `src/orchestrator.rs`, `src/scheduler.rs` — the whole point is that they don't need to change
- `src/crypto.rs` — reuse existing helpers
- `src/subprocess.rs`, `worker/` — Patchright worker handles platform_account browser steps identically to broker steps

## Acceptance Criteria

**Schema:**
- [ ] Migration runs forward on an existing dataward DB without data loss
- [ ] Migration is idempotent (running twice is a no-op)
- [ ] All existing broker playbooks load and schedule unchanged after migration
- [ ] `data_sources` table has `source_type`, `sensitivity_score`, `discovery_source` columns
- [ ] `credential_store` and `account_discovery_findings` tables exist with correct indexes

**Discovery:**
- [ ] `dataward discover --source bitwarden --file X.json` produces findings for every login entry with a domain
- [ ] `dataward discover --source keychain --file X.csv` parses iOS 17+ Passwords export
- [ ] `dataward discover --source firefox` reads places.sqlite without locking Firefox
- [ ] `dataward discover --source gmail` connects via IMAPS + App Password, scans headers only, produces findings
- [ ] Dedup: same account in Bitwarden + Gmail produces one finding with both in `discovery_source`
- [ ] Findings matching an existing `data_sources` row are marked `already_tracked`
- [ ] Sensitivity scores match the category rules above
- [ ] Bitwarden/Keychain export files can be shredded via CLI flag `--shred-after`

**Playbooks:**
- [ ] Existing 3 broker playbooks load with zero changes
- [ ] New playbook schema supports `source_type`, `category`, `sensitivity_default`, `manual_instructions`
- [ ] At least 3 reference playbooks ship (one per channel type)
- [ ] `manual_only` playbooks surface instructions in the dashboard

**Dashboard:**
- [ ] `/discovery` triage queue displays pending findings, sorted by sensitivity desc
- [ ] Accept action creates a `data_sources` row and marks finding promoted
- [ ] Dismiss action marks finding dismissed without creating a data_source
- [ ] Main table filters by source_type and sensitivity
- [ ] `/credentials` page shows masked credential entries and allows rotation/deletion

**Security:**
- [ ] No credential plaintext ever touches logs (verified via a log-scraping test)
- [ ] Firefox places.sqlite is copied, not opened in place
- [ ] IMAP connection fails closed without valid TLS
- [ ] All ciphertext round-trips via existing `crypto.rs` — no new key material introduced

## Test Strategy

- **Unit tests:** each importer against golden fixture files; scoring rules; dedup merge; migration idempotency; credential encrypt/decrypt round-trip.
- **Integration tests:** full `discover` → triage → promote → scheduler pickup flow, against a fresh DB.
- **Regression tests:** existing broker playbook suite must pass without modification.
- **Mock IMAP:** stand up an ephemeral IMAP server in tests (using `imap` crate's test helpers or a local stub) to exercise `gmail_imap.rs` without a real Gmail account.
- **Security tests:** grep-based log audit; tempfile cleanup verification via `Drop`; TLS downgrade attempt.

## Security Review (SECURITY_SENSITIVE)

This phase handles credentials, email headers, and browsing history — all highly sensitive. Checklist:

1. **Import files contain plaintext credentials** — Bitwarden JSON and Keychain CSV are ultra-sensitive. Mitigation: (a) loud CLI warning, (b) `--shred-after` flag using `shred -u`, (c) docs emphasize "run on a trusted machine, delete export immediately."
2. **Gmail App Password storage** — stored in `credential_store`, encrypted with existing AES-GCM key. Never logged. Rotation path exposed in dashboard.
3. **IMAP TLS** — rustls only, no fallback to STARTTLS without cert validation, no plaintext IMAP.
4. **Firefox places.sqlite** — opened as read-only, via ATTACH of a tempfile copy, tempfile wiped on Drop.
5. **Log hygiene** — extend existing log redaction (if any) to cover usernames, email addresses, and finding content. Add a log-scraping test.
6. **PII in database** — findings contain usernames and domains. Already covered by SQLCipher encryption at rest.
7. **Database migration safety** — take a pre-migration backup automatically (`db.rs` already has a backup helper per Phase 6).
8. **Bitwarden JSON parsing** — use `serde_json` with a strict schema, reject unknown fields to avoid attacker-crafted exports triggering unexpected behavior.
9. **eTLD+1 normalization** — use the `publicsuffix` crate, not a hand-rolled heuristic, to avoid `evil.github.io` collapsing to `github.io`.
10. **Dedup hash** — includes username precisely so two Gmail accounts on the same service don't merge.

**Not addressed in v1 (known gap):** we are not verifying that a playbook actually deleted data, only that it ran. Post-deletion verification is a future phase. Manual_only playbooks rely on the user confirming they completed the steps.

## Past Learnings Applied

Learnings search on 2026-04-08 found **no prior solutions** in `docs/solutions/` for personal data deletion, discovery pipelines, IMAP ingesters, or Bitwarden imports. This phase will likely generate several new `/learn` entries — candidates:
- Firefox places.sqlite read-while-running via ATTACH + tempfile copy
- Gmail IMAP App Password flow vs OAuth tradeoffs
- Bitwarden export schema gotchas
- Additive SQLCipher migration patterns (reinforces existing Phase 1 learnings if any)

## Alternatives Considered

**Approach A — Extend dataward in place without schema rename.** Rejected: "broker" naming would leak into unrelated flows, OAuth storage grafted onto broker state machine, playbook YAML overloaded. Debt accumulates within 10 new playbooks.

**Approach B — Separate `~/Projects/purge` orchestrator that shells out to dataward.** Rejected: two codebases, two state stores, two dashboards, duplicated crypto/scheduling, highest effort, no technical justification.

**Approach C — Generalize schema in place (chosen).** Additive migration, one repo, one dashboard, reuses everything, makes platform accounts first-class without disrupting brokers.

**HIBP-based breach monitoring** — deferred at user request; the core work of reducing data at rest is independent of active monitoring. Revisit if user's stance changes.

**OAuth for Gmail** — rejected for v1. App Password is simpler, needs no Google Cloud project, no redirect URIs, no token refresh logic. Users can revoke from their Google account at any time.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Migration corrupts existing broker DB | HIGH | Auto-backup before migrate; migration tested against realistic fixture; idempotency test |
| Bitwarden export left on disk after import | HIGH | `--shred-after` flag + loud doc warning |
| Gmail App Password leaked in logs | HIGH | Log redaction test; never stringify credential structs; use `zeroize` crate on in-memory buffers |
| IMAP heuristics miss real signup emails | MEDIUM | Heuristics are additive — missed accounts remain in password manager / browser imports; user can also add manually |
| Firefox places.sqlite locked during import | MEDIUM | ATTACH a tempfile copy, never open original |
| Dedup collisions across legit multi-account users | MEDIUM | Dedup hash includes username, not just domain |
| Playbook backlog eats infinite time | MEDIUM | Scope capped at 15–20; discovery triage decides which ones are worth writing first |
| User has accounts we can't programmatically delete | LOW | `manual_only` playbooks with instructions; dashboard tracks completion |
| iOS Keychain export format changes | LOW | CSV schema version check on import |
| AI training data leak still happens regardless | ACCEPTED | Out of scope; this plan is about breach minimization, not AI |

## Open Questions

Resolved during planning:
- **Password manager:** Bitwarden (primary) + iOS Keychain CSV (secondary) ✓
- **Email:** Gmail only, via App Password ✓
- **HIBP:** deferred entirely ✓
- **Browser:** Firefox only ✓

Remaining for implementation-time discussion:
- Which 15–20 platforms to write playbooks for (decide after first discovery run reveals user's actual account list)
- Whether to integrate `zeroize` crate for in-memory credential buffers (recommended; adds ~1 dep)
- Whether to auto-run discovery on a schedule or keep it user-initiated (v1: user-initiated only)

## Rollback Plan

- All changes are additive behind a schema version bump. If Phase 7 misbehaves, `db.rs` can refuse to load v2 and fall back to v1 for read-only operation while fixes land.
- New `discover` subcommand is isolated — removing it does not affect broker flows.
- New dashboard routes are mounted under new paths; can be feature-flagged off via a config toggle.
- Playbooks with `source_type='platform_account'` can be filtered out at load time if they prove unstable, without affecting broker playbooks.
- Worst case: drop the new tables and revert schema columns. Existing broker data is untouched because the migration only adds columns and renames one table.

---

# [DEEPENED] Revisions — Authoritative Corrections

This section supersedes conflicting statements in the body above. Ordered by severity.

## A. Codebase Ground-Truth Corrections (from codebase research agent)

| Assumption in body | Reality | Required plan change |
|---|---|---|
| "Phase 6 backup helper" exists | **Does not exist.** Only `rekey_db` (in-place PRAGMA rekey). | Implement `db::backup_to(path)` using SQLite online backup API before the migration step. Add as Phase 7.0. |
| `src/types.rs` holds shared enums | **No such file.** `BrokerRow`, `DueTask`, etc. all live in `src/db.rs`. | Add the new `SourceType` enum to `src/db.rs` alongside existing types. Remove all "in `types.rs`" references. |
| Dashboard is Axum + minijinja | Axum + **askama** (compile-time checked templates via `#[derive(Template)]`). | New routes use `askama::Template`. Templates go under `src/dashboard/templates/` with askama syntax. Add `askama_axum` handler integration. |
| `migrations/` directory exists | **No directory, no migration framework.** Schema created inline in `db.rs` via `CREATE TABLE IF NOT EXISTS` + a `schema_version` stamp at v1. | Do NOT create `migrations/*.sql` files. Implement forward migration as a Rust function `migrate_v1_to_v2(conn)` in `db.rs`, guarded by reading the version stamp. Build a minimal framework: `fn migrate(conn) -> Result<()>` that dispatches on current version and applies each step in a single `BEGIN IMMEDIATE` transaction. |
| Playbook YAML extension is transparent | `RawPlaybook` and `BrokerDefinition` use `#[serde(deny_unknown_fields)]`. | New fields MUST be added as `#[serde(default)]` optional fields on the Rust struct. Existing playbooks without the new fields will deserialize fine (defaults kick in). The concern is only if someone writes a NEW playbook with a typo in a new field — that will be rejected, which is correct. |
| `zeroize` needs to be added | **Already a direct dependency.** | Remove "add zeroize" from dependency list. |
| `imap`, `csv`, `publicsuffix` in `Cargo.toml` | **Not present.** | Add explicitly. Use **`async-imap` 0.11+ with `rustls-tls` feature** (not the unmaintained sync `imap` crate). Use **`psl` 2.x** (compile-time PSL) instead of runtime `publicsuffix` crate. |
| Orchestrator transparently handles table rename | `db.rs` has **15+ places** referencing `brokers` by name in raw SQL. `get_due_tasks` does `JOIN brokers b ON ...`. A rename is not transparent — every SQL query in `db.rs` must be updated. | **Abandon the rename.** See Architecture Revision below. |
| Actual `crypto.rs` signatures | `encrypt_aes256gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>` returns `nonce \|\| ciphertext` (12-byte nonce prepended). `decrypt_aes256gcm(key, encrypted)`. Key is derived from passphrase via Argon2id on `open_db`. | New credential storage calls these directly with the existing DB key. No separate nonce column needed — the nonce is the first 12 bytes of the ciphertext blob. Update schema accordingly. |
| Test pattern | `tempfile::tempdir()` + `create_db_with_params(path, "test-passphrase", &TEST_PARAMS)` with fast Argon2 params. No in-memory SQLite; tests use real SQLCipher on disk. | New tests follow the same pattern. No shared test harness outside each module. |

## B. Architecture Revision (supersedes §7.1 "Migration strategy")

**ARCH-001/002/003 (critical):** The "rename + additive columns" approach is unsound:
1. `db.rs` references `brokers` by name in 15+ SQL queries — rename is not transparent.
2. A synthetic `data_sources` row for the Gmail discovery credential would be picked up by the scheduler (which the plan forbade touching), causing it to try to run a removal playbook against Gmail itself.
3. Collapsing brokers and platform accounts into one table forces every downstream query to branch on `source_type`.

**Revised architecture (REPLACE §7.1):**

1. **Do NOT rename `brokers`.** Keep the table, keep all existing SQL untouched.
2. **Add a new sibling table `platform_accounts`** with its own lifecycle columns. This is where promoted discovery findings live. Structure mirrors `brokers` where shared, but has its own `sensitivity_score`, `category`, `manual_instructions`, `status`.
3. **Add a new sibling table `credential_store`** with a **nullable** `owner_kind` + `owner_id` pair (or separate nullable FKs to `brokers` / `platform_accounts` / `NULL` for standalone credentials like the Gmail App Password). Credentials are peers, not children, of data sources.
4. **Add `account_discovery_findings`** as-is (the design was fine).
5. **The scheduler stays untouched** because it continues to query `brokers` only. `platform_accounts` gets its own runner (can reuse the worker code paths via `broker_registry::load_playbook` which now also loads `platform_accounts` playbooks — the playbook loader IS shared, just the table of rows to schedule differs).
6. **Rejected:** option (b) from the architecture review ("never promote findings, keep them as a terminal state"). Reason: the orchestrator needs a row to schedule, and findings-as-rows would require the scheduler to query the findings table too, which defeats the isolation. The `platform_accounts` sibling table is the right middle ground.

**New table definitions (replace the `data_sources` modifications in §7.1):**

```sql
-- KEEP brokers AS-IS (no changes, no renames, no new columns).

CREATE TABLE IF NOT EXISTS platform_accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT NOT NULL,              -- eTLD+1, from psl crate
  category TEXT NOT NULL,            -- 'financial'|'health'|'dating'|'forum'|'cloud'|'social'|'shopping'|'other'
  sensitivity TEXT NOT NULL,         -- 'high'|'medium'|'low' (3-tier, see Simplification below)
  playbook_path TEXT,                -- NULL if manual_only with no playbook
  manual_instructions TEXT,          -- populated when playbook is NULL or playbook is manual_only
  discovery_source TEXT,             -- 'bitwarden'|'keychain'|'firefox'|'gmail'|'manual'
  status TEXT NOT NULL DEFAULT 'pending',  -- 'pending'|'in_progress'|'done'|'manual_required'|'failed'
  enabled INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_platform_accounts_status ON platform_accounts(status);
CREATE INDEX idx_platform_accounts_sensitivity ON platform_accounts(sensitivity);

CREATE TABLE IF NOT EXISTS credential_store (
  id TEXT PRIMARY KEY,
  owner_kind TEXT,                   -- 'broker'|'platform_account'|NULL (standalone, e.g. Gmail for discovery)
  owner_id TEXT,                     -- NULL iff owner_kind is NULL
  label TEXT NOT NULL,               -- user-visible, e.g. "Gmail IMAP (discovery)"
  kind TEXT NOT NULL,                -- 'password'|'app_password'|'oauth_token'|'api_key'|'session_cookie'
  ciphertext BLOB NOT NULL,          -- output of crypto::encrypt_aes256gcm (nonce || ct)
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  rotated_at INTEGER
);
CREATE INDEX idx_credential_store_owner ON credential_store(owner_kind, owner_id);

CREATE TABLE IF NOT EXISTS account_discovery_findings (
  id TEXT PRIMARY KEY,
  discovery_source TEXT NOT NULL,
  discovered_at INTEGER NOT NULL,
  domain TEXT NOT NULL,              -- NFC-normalized + case-folded + psl eTLD+1
  raw_name TEXT,
  username_hmac BLOB NOT NULL,       -- HMAC-SHA256(k_dedup, NFC(case_fold(username))) — NOT raw sha256
  first_seen_hint INTEGER,
  last_activity_hint INTEGER,
  sensitivity TEXT NOT NULL,         -- 'high'|'medium'|'low'
  dedup_hash BLOB NOT NULL,          -- HMAC(k_dedup, length_prefixed(domain, username)) — see EC-003 fix
  triage_status TEXT NOT NULL DEFAULT 'pending',
  promoted_to_platform_account_id TEXT REFERENCES platform_accounts(id)
);
CREATE INDEX idx_findings_triage ON account_discovery_findings(triage_status, sensitivity);
CREATE UNIQUE INDEX idx_findings_dedup ON account_discovery_findings(dedup_hash);
```

Note: PRIMARY KEYs switched to TEXT (UUIDv4) instead of INTEGER per SEC-011 — the dedup hash must never leak into URLs/logs as an identifier, so a random UUID is used for row identity and the dedup hash is an indexed column used only internally.

## C. Security Revisions (supersedes §Security Review)

These fixes are **blocking**. All must be implemented or explicitly accepted-with-waiver before merge.

1. **[SEC-001] Separate subkey per credential store.** Derive via HKDF: `k_credstore = HKDF-SHA256(master, salt=b"dataward/credstore/v1", info=b"")`. Broker state and credential_store use distinct subkeys so compromise of one doesn't cascade. Implement in `crypto.rs`.
2. **[SEC-002] Tempfile location and mode.** Do NOT use `/tmp/dataward-places-*`. Use `$XDG_RUNTIME_DIR` (0700) with fallback to `~/.local/state/dataward/run/` (created 0700, verified on startup). Create tempfile via `tempfile::NamedTempFile` with explicit `OpenOptions::mode(0o600)`. Register `ctrlc` + `signal-hook` handlers to unlink on SIGTERM/SIGINT. Add a startup sweep that removes stale `dataward-places-*` files owned by current uid. Document SIGKILL as a known residue path.
3. **[SEC-003] Remove `shred` from UX entirely.** Rename `--shred-after` to `--delete-after`. Implementation: `File::set_len(0)` → `fsync` → `unlink`. Print explicit warning: *"Secure deletion is not possible on journaled/CoW filesystems or SSDs with wear leveling. Rely on full-disk encryption (LUKS/FileVault). The export file contained plaintext credentials — treat the disk as if it still does until re-encrypted."*
4. **[SEC-004] Concrete log deny-regex list.** Add a log-scraping test that asserts captured logs (at all levels including TRACE) never match:
   - `(?i)password["\s:=]+\S`
   - `(?i)app[-_ ]?password`
   - Gmail App Password shape: `[a-z]{4}([ -]?[a-z]{4}){3}`
   - Bitwarden token prefix: `0\.[A-Za-z0-9+/=]{20,}`
   - Base64 blobs > 40 chars
   - Any email-address regex in INFO/DEBUG (receipts sender leak path)
   - A canary row value injected into `credential_store.ciphertext` before the test
   
   Enforce by type: forbid `#[derive(Debug)]` on any struct holding a secret. Use `secrecy::Secret<T>` which redacts in `Debug`.
5. **[SEC-005] Core dump hardening.** At startup: `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`. Use `region::lock` (mlock) on pages holding credentials. Check `/proc/swaps` at startup and WARN if unencrypted swap is active. Use `secrecy::SecretVec<u8>` with preallocated capacity to prevent realloc-leak. Document that swap must be encrypted or disabled.
6. **[SEC-006] Nonce generation.** Use `rand::rngs::OsRng` → 96-bit random nonce per `encrypt_aes256gcm` call. (This is already the behavior of the existing `crypto.rs` per the code audit — just verify and document.) Add a debug-assert rejecting all-zero nonces. Optionally switch credential_store to XChaCha20-Poly1305 (192-bit nonces) via `chacha20poly1305` crate to remove birthday-bound concerns — decided at implementation time based on how much the existing AES-GCM code is relied upon.
7. **[SEC-007] `async-imap` credential leak audit.** Before merge, run a canary test: create a mock IMAP server that rejects auth, capture the `async-imap` error chain, grep for the canary password. Wrap the session builder so the `Secret<String>` is consumed by value. Set `tracing` filter to exclude `async_imap=trace,rustls=trace` in release builds.
8. **[SEC-008] DB file permissions + passphrase strength.** At startup, verify `~/.local/share/dataward/dataward.db` is mode 0600 and parent dir is 0700; refuse to run if looser. At `init`, enforce passphrase strength via `zxcvbn` crate, minimum score 3. Argon2id parameters for production: `m=256 MiB, t=3, p=1` (test profile stays fast).
9. **[SEC-009] Playbook sandbox + signing.** Playbooks must be declarative-only — no shell, no arbitrary HTTP, no file I/O outside a whitelisted output dir. The worker already parses them as YAML with a fixed action set; keep it that way. Credentials must NEVER be passed to playbook context except via dedicated `fill` actions that reference a credential by ID. Pin playbooks by SHA-256 in a `playbooks.lock` file (signed or checksummed); refuse unsigned/unpinned playbooks unless `--allow-unsigned-playbooks` is passed, which prints a red warning on every run.
10. **[SEC-010/011] Dedup hash hygiene.** Use HMAC-SHA256 with a local secret key (`k_dedup`, HKDF-derived from master) instead of raw SHA-256. The dedup hash MUST NOT appear in URLs, logs, or error messages. Row identity uses UUIDv4 (see schema revisions above).
12. **[SEC-012] Resource limits on Bitwarden JSON.** Cap input file at 50 MiB, reject larger. Cap `items[]` length at 100k. Use `serde_json::Deserializer::from_reader` with streaming (also addresses PERF-003).
13. **[SEC-013] Firefox WAL correctness.** When copying `places.sqlite`, also copy `places.sqlite-wal` and `places.sqlite-shm` atomically. Research finding: reading the main file alone while Firefox is running in WAL mode produces stale/inconsistent data. Document the gap if copying all three proves fragile: "Close Firefox before running discovery for complete results."
14. **[SEC-014] `psl` crate freshness.** Use the `psl` crate (compile-time list); bump dependency on a schedule (not runtime auto-refresh). Pin version with a known-good PSL snapshot date in `Cargo.toml` comments.
15. **[SEC-016] Keychain CSV strict headers.** The iOS export has exactly 3 columns: `website, username, password`. No OTP, no notes. Validate headers strictly on parse; fail loudly on mismatch (iOS version changed format).

## D. Simplicity Revisions (partial acceptance)

- **[SIMP-002] ACCEPTED** — Replace 0–100 sensitivity scoring with a 3-tier enum (`high`|`medium`|`low`). Updated throughout the schema above. The 9-category scoring rules become a small keyword→tier map. Precision implied by 0–100 isn't delivered by keyword matching anyway. Revisit if real discovery data shows the coarse bins hide useful signal.
- **[SIMP-003] ACCEPTED** — Remove `search_engine` from any enum. Add it when the first search-engine importer ships.
- **[SIMP-006] ACCEPTED** — Replace `dedup_hash` computation with DB-level unique index on `(domain, username_hmac)` as well. The hash column still exists (needed because we HMAC the concatenation) but the dedup-on-insert path is enforced by the index, not application code.
- **[SIMP-007] ACCEPTED** — Remove `last_known_login_domain`. Speculative. Re-add when a feature needs it.
- **[SIMP-001] REJECTED** — Do not defer Gmail IMAP to v2. Bitwarden + Firefox + Keychain alone miss 30–50% of the typical account long tail (signup emails are the canonical source for accounts the user forgot). Deferring would gut the core value proposition. Credential_store and hardening ride along — the cost is real but justified.
- **[SIMP-005] ACCEPTED (partial)** — Skip a dedicated `/credentials` page for v1. Instead add a "Connected sources" section at the top of the existing settings/status page with rotate/delete actions. Upgrade to a full page if v2 adds OAuth tokens or more credentials.
- **[SIMP-008] REJECTED** — Keep iOS Keychain CSV importer. The user explicitly mentioned using it alongside Bitwarden during planning.

## E. Performance Revisions

- **[PERF-001] REQUIRED** — Gmail IMAP must use server-side `SEARCH` first: `OR OR OR FROM "noreply" FROM "no-reply" FROM "welcome" SUBJECT "verify"` then batch-`FETCH` headers only for matching UIDs. Target: reduce round trips from O(mailbox) to O(matches). For a 100k-message mailbox, expect <2k matches.
- **[PERF-002] REQUIRED (but with SEC-013 constraint)** — Attempt to open `places.sqlite` via read-only + `query_only=1` first. If that fails due to WAL lock, fall back to copying the main file + WAL + SHM sidecars to the secure tempfile location (§SEC-002).
- **[PERF-003] REQUIRED** — Stream Bitwarden JSON via `serde_json::Deserializer::from_reader(BufReader::new(file))`. Combined with SEC-012 resource caps.
- **[PERF-004] REQUIRED** — Indexes added in the new schema above: `idx_findings_triage (triage_status, sensitivity)`, `idx_findings_dedup UNIQUE (dedup_hash)`, `idx_platform_accounts_status`, `idx_platform_accounts_sensitivity`, `idx_credential_store_owner`.
- **[PERF-005] REQUIRED** — Triage queue dashboard route must enforce a hard page size (50 rows) at the query layer. Use cursor pagination on `(sensitivity, id)`.

## F. Edge-Case Revisions

- **[EC-001]** Bitwarden `login.uris` may be absent, null, or empty — default to `[]` before iterating. Treat all three identically.
- **[EC-002]** Firefox `last_visit_date` is **microseconds** since epoch. Divide by 1_000_000 before treating as seconds, or `* 1000` before a millisecond API. Add a debug-assert: value > 1e15 ⇒ microseconds.
- **[EC-003]** Dedup hash delimiter ambiguity fixed by HMAC input encoding: `HMAC(k_dedup, len(domain) || ":" || domain || ":" || len(username) || ":" || username)`. Length-prefixed, no bare delimiter.
- **[EC-004]** Migration wrapped in `BEGIN IMMEDIATE ... COMMIT` single transaction. Version stamp updated only on COMMIT. Per-step granularity within the transaction so re-run after crash is idempotent.
- **[EC-005]** Unicode normalization: apply `unicode_normalization::UnicodeNormalization::nfc()` then Unicode case-fold (use `caseless` crate or `unicase`) before hashing. Strip leading/trailing whitespace.
- **[EC-006]** Gmail locale-aware folder enumeration: use IMAP `LIST` with `SPECIAL-USE` extension and match `\All` flag instead of hardcoding `[Gmail]/All Mail`. Fall back to `XLIST` for older servers.
- **[EC-007]** Decode punycode domains to Unicode before keyword matching. Flag any mixed-script domain (cyrillic-in-latin etc.) as automatically `high` sensitivity — an IDN homograph in a user's vault is a strong signal of phishing.
- **[EC-008]** Keyword matching runs against the eTLD+1 (from `psl`), not the raw host — so `login.bankofamerica.com` → `bankofamerica.com` → matches financial keyword.
- **[EC-010]** Bitwarden org items (`collectionIds: []` vs null) distinguished in parser. Null = personal, `[]` = org but uncollected; log the distinction but treat both as valid findings.

## G. Spec-Flow Revisions (new acceptance criteria)

Add to **§Acceptance Criteria**:

**Error states:**
- [ ] `dataward discover --source bitwarden` with missing file → exit 2, actionable message
- [ ] Bitwarden file that is encrypted (not an unencrypted export) → detect and print: "File appears encrypted — export as **Unencrypted JSON** from Bitwarden → Settings → Export Vault."
- [ ] Malformed JSON → print the parse error location, not a raw panic
- [ ] Gmail auth rejection → exit 2, message: "Gmail rejected the App Password. Generate a new one at myaccount.google.com/apppasswords."
- [ ] Gmail locale mismatch where no canonical folders matched → WARN with discovered folder list, do not silently return zero findings
- [ ] Firefox DB lock detected → exit 2, message: "Firefox is running. Close it and retry, or use `--force-copy` to proceed with a stale snapshot."
- [ ] Multiple Firefox profiles detected → error unless `--profile NAME` is specified; list available profiles

**Empty states:**
- [ ] `/discovery` triage queue: pre-scan empty state shows CTA "Run `dataward discover` to populate the queue"
- [ ] `/discovery` post-scan empty state shows "No new accounts found" with timestamp of last scan per source

**Post-migration:**
- [ ] Dashboard shows a dismissible banner after v1→v2 migration: "Migration complete. Run `dataward discover` to scan for new accounts."

**Manual-only accept flow:**
- [ ] Accepting a finding with no matching playbook prompts: "No automation available for DOMAIN. This will be added as a manual task." The resulting `platform_accounts` row has `status='manual_required'` and surfaces in a distinct dashboard section with manual_instructions if any.

**Credential rotation:**
- [ ] Rotating the Gmail credential while a scan is running cancels the in-flight IMAP session, commits any findings collected so far with a `scan_interrupted=true` flag, and prompts a rescan after rotation.

**Multi-source dedup audit:**
- [ ] When the same dedup_hash appears from multiple sources, the finding row's `discovery_source` column stores a comma-separated list in order of detection, and the audit log records one event per source contributing to the finding.

## H. Revised Scope Summary

| Phase | Original effort | Revised effort | Change |
|---|---|---|---|
| 7.0 Backup helper + HKDF subkeys + core-dump hardening | — | 1–2 days | **NEW** (security prerequisite) |
| 7.1 Schema (sibling tables, no rename) | 1–2d | 2–3d | +1 day (more tables, proper migration fn) |
| 7.2 Discovery module + async-imap SEARCH + streaming JSON + Unicode handling | 3–5d | 5–7d | +2 days |
| 7.3 Playbook YAML extension + sandbox + signing | 2–3d | 3–4d | +1 day (signing infra) |
| 7.4 Dashboard additions (askama, not minijinja; no dedicated /credentials page) | 2–3d | 2d | -1 day |
| 7.5 E2E + security audit (canary password test, log deny-regex, FDE/swap check) | 1d | 2d | +1 day |
| **Total** | **9–14d** | **15–20d** | **+6 days** |

The extra effort is entirely security hardening and correctness — it's the cost of the tool living up to its own threat model.

## I. Enhancement Summary

**Counts:**
- Research findings applied: 2 agents (codebase contradictions + best-practices corrections)
- Review findings: 6 agents, ~40 issues total
  - CRITICAL: 7 (3 security, 3 architecture, 1 performance)
  - HIGH: 12
  - MEDIUM: 13
  - LOW: 8
- Plan sections rewritten: schema (§7.1), security review, risks
- New acceptance criteria: 14
- New dependencies: `async-imap`, `csv`, `psl`, `secrecy`, `unicode-normalization`, `caseless` or `unicase`, `zxcvbn`, `region`, `signal-hook`, `rand` (if not present), `ctrlc`
- New Rust features: HKDF subkey derivation in `crypto.rs`, proper migration framework in `db.rs`, backup helper, core-dump hardening at startup

**Top priority fixes before implementation:**
1. Replace table-rename strategy with sibling tables (ARCH-001/002/003)
2. HKDF subkeys + core-dump hardening (SEC-001/005)
3. Drop `shred` terminology, replace with `--delete-after` + FDE warning (SEC-003)
4. `async-imap` (not sync `imap`) with server-side SEARCH (PERF-001 + best-practices)
5. Unicode NFC + case-fold + length-prefixed HMAC for dedup (EC-003/005)
6. Migration in single transaction with per-step idempotency (EC-004)
7. Playbook signing + sandbox (SEC-009)
8. Askama templates, not minijinja (codebase reality)

**Suggestions for future phases (do NOT do in 7):**
- OAuth for Gmail (replaces App Password once Google deprecates it further)
- HIBP integration for breach monitoring
- Post-deletion verification worker
- `zxcvbn` passphrase re-check with nag on weak
- Dedicated `/credentials` page once there are more than 1–2 credentials
- Playbook auto-refresh from a signed repository

---

# [REVIEW ROUND 2 — APPROVED] Final Revisions

The round-2 plan review added 5 reviewers including an adversarial validator. These are the authoritative final revisions — they supersede any conflicting guidance in the body or the [DEEPENED] section above.

## J. Blockers Found in Round 2 (none of the 10 prior agents caught these)

### J.1 Target-service lockout protection (BLIND-01)

**Problem:** Running deletion playbooks against live financial/health/dating sites can trip fraud detection and lock the user out of their own bank account. This is direct user harm, not hypothetical.

**Required mitigations (new):**
- **Per-domain serialization:** the scheduler must never run two tasks against the same eTLD+1 concurrently, and must enforce a minimum inter-attempt spacing of **6 hours** for `category IN ('financial','health','government','dating')`, 1 hour for others.
- **Circuit breaker:** on any response matching CAPTCHA markers, "account locked" strings, or HTTP 429, mark the `platform_accounts` row as `status='circuit_broken'` and refuse to retry for 72 hours.
- **Max 3 attempts per account, ever,** without user re-acknowledgment.
- **Manual_only is the DEFAULT** for `financial`, `health`, `government` categories regardless of whether a playbook has a `web_form` channel. Automation for these categories requires the user to flip an explicit per-category flag in config AND a per-account confirmation at accept time.

**New acceptance criteria:**
- [ ] Scheduler refuses to queue two tasks against same eTLD+1 within 6h for high-sensitivity categories
- [ ] Circuit breaker trips on mock CAPTCHA response and sets status to `circuit_broken`
- [ ] Financial/health/government playbooks default to manual_only even when web_form channel exists
- [ ] Config flag `automation_allowed_for_regulated_categories = false` by default

### J.2 Legal/ToS acknowledgment (BLIND-02)

**Problem:** Automated form submission on financial/health sites may violate site ToS ("no automated access") and CFAA-adjacent statutes. People-search opt-out has strong legal footing; bank account closure automation does not.

**Required:**
- First-run legal acknowledgment prompt (CLI + dashboard) covering: "You are automating actions against third-party services. ToS may prohibit this. You are solely responsible. Regulated categories (financial/health/government) default to manual-only — do not override without consulting the relevant ToS."
- Per-category acknowledgment stored in DB; re-prompted on config changes.
- Logs of all automated submissions retained for 90 days (evidence of user authorization in case of dispute).

**New AC:**
- [ ] First run shows legal ack prompt; dataward refuses to run until accepted
- [ ] Enabling automation for a regulated category requires a second acknowledgment with the category name shown

### J.3 Gmail IMAP scope disclosure (BLIND-03)

**Problem:** The Gmail App Password grants read of the entire mailbox including 2FA codes and password resets for *every other service*. It is strictly more dangerous than any individual credential it will help discover. The tool holding it becomes a breach vector worse than several of the services being purged.

**Required:**
- **Ephemeral IMAP session only.** The App Password is held in `credential_store` but the IMAP connection exists only for the duration of a `dataward discover --source gmail` command. No persistent daemon connection. No background rescan.
- **Explicit scope disclosure at credential entry:**
  > *"This App Password grants READ access to your entire Gmail inbox, including password reset emails and 2FA codes for other services. Dataward will use it only during explicit `discover` runs, never in the background. Consider generating it, running discovery, and revoking it at myaccount.google.com/apppasswords when done. Dataward will remind you every 7 days to rotate or revoke."*
- **Rotation reminder:** the dashboard shows the App Password's `created_at` and highlights in red if > 7 days old.
- **Post-discovery cleanup prompt:** after a successful discovery run, CLI prints: *"Gmail discovery complete. You may now revoke the App Password at myaccount.google.com/apppasswords. Press Enter to confirm you've done so, or Ctrl+C to keep it."* (user can skip but is prompted.)
- **No auto-scheduled Gmail discovery** in v1. Ever. Re-scan is manual.

**New ACs:**
- [ ] IMAP connection opens only during `discover --source gmail` command execution
- [ ] No background `imap_worker` spawned in `orchestrator.rs` for Gmail
- [ ] Post-discovery CLI prompts user to revoke the App Password
- [ ] Dashboard shows App Password age and highlights > 7 days in red

### J.4 Dashboard CSRF + localhost-bind (SEC-R2-004)

**Problem:** The new `/discovery` and credential management routes are state-changing. A malicious browser tab on any site can `fetch('http://127.0.0.1:PORT/discovery/accept/UUID')` via DNS rebinding or plain cross-origin requests, auto-promoting or dismissing findings without user interaction.

**Required:**
- **Bind to `127.0.0.1:PORT` only** — verify existing Phase 4 dashboard config and enforce. Refuse to start if config specifies `0.0.0.0` without an explicit `--allow-remote-dashboard` flag.
- **CSRF token on all state-changing routes** (accept, dismiss, rotate, delete). Use axum's `tower-sessions` + a double-submit cookie pattern. All POST/PUT/DELETE require the token.
- **`Origin` / `Host` header validation:** reject requests whose `Origin` doesn't match the bound host:port or whose `Host` isn't `127.0.0.1` / `localhost`. Blocks DNS rebinding attacks.
- **Session cookies:** `HttpOnly`, `SameSite=Strict`, `Secure` even on localhost.
- **Per-route rate limit:** accept/dismiss capped at 60/min; credential rotation capped at 10/min. Use `tower::limit::RateLimitLayer` or similar.

**New ACs:**
- [ ] Dashboard refuses to bind non-loopback without `--allow-remote-dashboard`
- [ ] State-changing routes reject requests without valid CSRF token
- [ ] Origin-mismatch requests return 403
- [ ] Rate limits enforced and tested
- [ ] Session cookies set with `HttpOnly; SameSite=Strict; Secure`

### J.5 Worker capability verification (ASSUMP-B)

**Problem:** The plan assumes the existing Patchright worker (designed for public broker opt-out forms) can handle platform deletion flows, which require logged-in sessions and 2FA. This is unverified and likely false.

**Required before any Phase 7.3 playbook authoring begins:**
- **Phase 7.0.5 (new prerequisite investigation task):** read `worker/` and `src/subprocess.rs` to determine:
  - Does the worker support cookie/session persistence between steps?
  - Is there any 2FA-handling primitive (TOTP prompt, SMS wait state, passkey)?
  - Does the playbook YAML have actions like `wait_for_user_input` or `wait_for_totp`?
- **Decision gate:** if the worker cannot handle logged-in + 2FA flows, then Phase 7.3 is scoped DOWN to: (a) `manual_only` playbooks with instructions for the user to execute, and (b) a small number of truly public deletion endpoints (e.g., Mozilla/Firefox account, some legacy forums). Financial/health are manual_only anyway per J.1/J.2.
- **Do not begin Phase 7.3 until this investigation is complete and its findings are written into the plan.**

**New ACs:**
- [ ] Phase 7.0.5 investigation complete and documented in this plan before Phase 7.3 starts
- [ ] Phase 7.3 scope locked against the investigation findings, not the original assumption

### J.6 First-run dry preview per playbook (BLIND-04)

**Problem:** Accepting a finding triggers an irreversible action. No preview is specified.

**Required:**
- The first time a playbook runs against any account (broker or platform), the worker executes in **preview mode**: navigate + fill + screenshot, but **do not submit**. The screenshot + rendered form field values are surfaced in the dashboard for user approval before the real submission.
- After the first successful real run, subsequent runs on the same account skip preview unless the playbook version changes.

**New AC:**
- [ ] First run per account per playbook-version produces a preview with screenshot + filled-form capture, blocks on user approval

### J.7 Findings retention policy (BLIND-05)

**Problem:** `account_discovery_findings` is a complete map of the user's digital life — higher-value than any single credential.

**Required:**
- Auto-purge findings with `triage_status IN ('dismissed','already_tracked')` after 30 days.
- Auto-purge findings with `triage_status='accepted'` (successfully promoted) after 90 days — the `platform_accounts` row is the canonical state at that point.
- Config flag to extend or disable.

**New AC:**
- [ ] Retention job runs daily; dismissed findings > 30d and promoted findings > 90d are deleted

## K. Security Corrections (Round 2)

- **[SEC-R2-002] HKDF encoding fixed.** RFC 5869 compliance: domain separation goes in `info`, not `salt`. Correct form:
  ```
  salt = random_per_install (16 bytes, generated at init, stored in DB alongside master KDF salt)
  info_credstore = b"dataward/credstore/v1"
  info_dedup     = b"dataward/dedup/v1"
  info_future    = b"dataward/<purpose>/v<N>"
  k_credstore = HKDF-SHA256(master, salt, info_credstore, 32)
  k_dedup     = HKDF-SHA256(master, salt, info_dedup, 32)
  ```
  **Distinct `info` values are mandatory.** Add a constant table in `crypto.rs` enumerating all current subkey labels.

- **[SEC-R2-006] Error-chain credential scrubbing.** The log-scraping canary test must ALSO grep:
  - `format!("{:?}", anyhow_error)` for the full chain
  - `format!("{}", anyhow_error)` for the Display chain
  - `thiserror` `#[error("...")]` outputs that wrap transport error bodies
  Use `tracing-error`'s `SpanTrace` only in debug builds; strip from release. Before logging any `Result::Err`, route through a sanitizer that removes anything matching the deny-regex set.

- **[SEC-R2-005] SEC-015 restored.** Previous numbering dropped it. SEC-015: when removing `--shred-after`, provide a migration message for users who scripted the old flag name. Implementation: `--shred-after` is accepted as a deprecated alias for one release with a stderr warning, then removed.

- **[SEC-R2-008] Key rotation column.** Add `k_dedup_version INTEGER NOT NULL DEFAULT 1` to `account_discovery_findings`. On master key rotation, rebuild dedup hashes in a background task and bump the version. Document rotation runbook in `docs/phase7-discovery.md`.

- **[ARCH-R2] Two-FK CHECK instead of polymorphic owner.** Replace `credential_store.owner_kind` + `owner_id` with two nullable FK columns:
  ```sql
  broker_id TEXT REFERENCES brokers(id) ON DELETE CASCADE,
  platform_account_id TEXT REFERENCES platform_accounts(id) ON DELETE CASCADE,
  CHECK (
    (broker_id IS NOT NULL AND platform_account_id IS NULL) OR
    (broker_id IS NULL AND platform_account_id IS NOT NULL) OR
    (broker_id IS NULL AND platform_account_id IS NULL)  -- standalone (Gmail discovery cred)
  )
  ```

- **[ARCH-R5] No double-promotion.** Add:
  ```sql
  CREATE UNIQUE INDEX idx_findings_promoted ON account_discovery_findings(promoted_to_platform_account_id)
    WHERE promoted_to_platform_account_id IS NOT NULL;
  ```

## L. Dropped from Scope (Round 2)

The following items were added during deepening but are now REMOVED. Rationale: threat model doesn't justify them for a solo-user local tool, and the security reviewers' insistence on them was reviewer overreach per the adversarial validator.

- **Playbook SHA-256 lockfile signing.** The playbooks live on the user's own disk; the user wrote or curated them. There is no supply chain to defend against. Replace with an optional plain `sha256sum -c playbooks.sums` drift check — no crypto signing, no pubkey baked in binary, no `--allow-unsigned-playbooks` flag.
- **`mlock` / `region` crate / `/proc/swaps` parsing / `signal-hook`.** FDE covers the same ground with orders of magnitude less complexity. Keep ONLY: `prctl(PR_SET_DUMPABLE, 0)` + `setrlimit(RLIMIT_CORE, 0)` at startup — both are one-liners, both are free. Drop the `region` and `signal-hook` dependencies entirely. `tempfile::NamedTempFile` already unlinks on drop; SIGKILL residue is accepted and documented. The startup sweep stays (cleans orphaned files), with `O_NOFOLLOW` to prevent symlink TOCTOU.
- **`zxcvbn` passphrase strength gate.** Replace with a simple minimum length of **16 characters** at `init`. Print a recommendation ("use a diceware-style passphrase") but don't block. Single-user tool, user picks their own passphrase.
- **`set_len(0) → fsync → unlink` theater.** On CoW filesystems and journaled filesystems this overwrites nothing. Drop the dance. Implementation of `--delete-after` is just `unlink` + the FDE warning text from SEC-003. Honesty over theater.

**Dependencies removed:** `region`, `signal-hook`, `zxcvbn`, any playbook-signing crate (minisign/ed25519-dalek unless already needed). Net: ~3 fewer deps.

## M. Effort Re-estimate (Honest)

| Phase | Deepened estimate | Round-2 honest estimate |
|---|---|---|
| 7.0 Backup + HKDF (correct info/salt) + minimal core-dump hardening | 1–2d | 1d |
| 7.0.5 Worker capability investigation (new) | — | 0.5d |
| 7.1 Schema (sibling tables, two-FK CHECK) | 2–3d | 2d |
| 7.2 Discovery module + Unicode correctness + lockout/rate limits | 5–7d | 5–6d |
| 7.3 Playbook YAML extension (scaffold only; actual playbooks are a tail) | 3–4d | 2d scaffold + open-ended tail |
| 7.4 Dashboard additions (askama, CSRF, localhost bind, rate limits, first-run preview) | 2d | 3d (preview is new work) |
| 7.5 E2E + security audit (canary password, error-chain scrubbing, lockout/ToS tests) | 2d | 2d |
| **Core total** | **15–20d** | **~15–17d core + playbook tail** |

Playbook tail is genuinely open-ended. Realistic velocity per real-world playbook: 0.5–1 day each for a truly public deletion endpoint, longer for anything requiring session/2FA. Plan Phase 7.3 as "scaffold + pick 3 reference playbooks + backlog the rest" rather than "ship 15–20."

## N. Files Affected — Additions from Round 2

- `src/dashboard/csrf.rs` (new) — token middleware
- `src/dashboard/rate_limit.rs` (new) — per-route layer
- `src/scheduler.rs` — **small modification allowed (was "do not touch")** to add per-domain serialization + 6h spacing for high-sensitivity categories. The "do not touch" rule is relaxed here because the new constraint is a guardrail, not a behavioral rewrite.
- `src/legal_ack.rs` (new) — first-run acknowledgment flow
- `src/retention.rs` (new) — daily findings purge job
- `src/worker_capability_check.rs` OR `docs/phase7-worker-investigation.md` (new) — Phase 7.0.5 findings

## O. Revised Priority Order (What To Do When)

1. **Phase 7.0.5 FIRST** — investigate worker session/2FA capability. Block on the result. It may shrink Phase 7.3 dramatically.
2. **Phase 7.0** — backup helper, HKDF with correct info labels, `PR_SET_DUMPABLE` + `RLIMIT_CORE`, legal ack scaffolding.
3. **Phase 7.1** — schema with sibling tables, two-FK CHECK, `k_dedup_version`, retention job skeleton.
4. **Phase 7.2** — discovery importers with lockout/rate limits and Gmail ephemeral session.
5. **Phase 7.4** — dashboard with CSRF, localhost bind, preview-before-first-run.
6. **Phase 7.3** — playbook scaffolding + 3 reference playbooks. Real playbook authoring is the tail.
7. **Phase 7.5** — end-to-end + security audit including error-chain scrubbing canary.

## P. Final Status

**Status:** APPROVED (with the above revisions folded in)
**Confidence:** MEDIUM — the plan is sound but Phase 7.0.5 is a real gate that could reshape Phase 7.3. Reassess after that investigation.

---

**Learnings candidates (to capture via `/learn` after implementation):**
- SQLCipher online backup + in-place migration patterns
- HKDF subkey separation in a single-KDF environment
- async-imap + rustls IMAPS + server-side SEARCH pattern
- Firefox places.sqlite WAL-safe read strategy
- Unicode-correct dedup hashing with length-prefixed HMAC
- `secrecy` + `region::lock` + PR_SET_DUMPABLE for Rust credential handling
- Askama + Axum route pattern for new dashboard pages

