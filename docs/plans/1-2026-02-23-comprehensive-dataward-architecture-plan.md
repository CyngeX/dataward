---
type: comprehensive
title: "Dataward: Automated Data Broker Opt-Out Daemon"
date: 2026-02-23
status: deepened_ready_for_review
security_sensitive: true
priority: high
breaking_change: false
github_issues: [1, 2, 3, 4, 5, 6]
---

# Plan: Dataward — Automated Data Broker Opt-Out Daemon

## Document Info
- **Author:** AI + Human
- **Date:** 2026-02-23
- **Status:** approved
- **Brainstorm:** docs/brainstorms/2026-02-23-dataward-architecture-brainstorm.md
- **Review:** 5-agent review completed 2026-02-23 (Architecture, Simplicity, Spec-Flow, Security, Adversarial)

## Problem

750+ data brokers collect and sell personal information without meaningful consent. Opting out requires navigating hundreds of different websites, forms, and email processes — each with unique flows, CAPTCHAs, and verification requirements. Commercial services charge $100-250/year. No mature open-source alternative exists.

Users affected: anyone with a digital presence in the US/EU who wants to minimize their data footprint.

## Goals
- Automatically opt users out of data brokers via web forms, email, and API channels
- Run as a local daemon with no cloud dependency — user controls their PII
- Support community-contributed YAML playbooks for broker definitions
- Provide a web dashboard for status monitoring and manual CAPTCHA resolution
- Re-check brokers on configurable intervals (30-180 days) to catch re-listings
- Encrypt all PII at rest and in all storage locations

## Non-Goals
- Not a VPN, tracker blocker, or browser privacy extension
- Not a hosted/SaaS service — local-only
- Not a data broker monitoring service (detecting new listings) — only handles opt-out for known brokers
- No mobile app — CLI + web dashboard only
- No California DROP API integration in MVP (API spec not yet public, mandatory Aug 2026)
- No AI-powered form detection — playbooks are explicit, not inferred

## Solution

A Rust daemon (`dataward`) that orchestrates three opt-out channels:

1. **Browser automation** — Patchright (TypeScript) long-lived worker process executes YAML playbooks against broker web forms using isolated browser contexts
2. **Email** — Templated legal demand letters (CCPA, GDPR, state laws) sent via user-configured SMTP with TLS required
3. **API** — Direct HTTP requests for brokers that expose deletion APIs

The daemon manages scheduling (interval-based per-broker), state tracking (SQLite with SQLCipher encryption + WAL mode), retry logic (exponential backoff), crash recovery, and an authenticated localhost web dashboard (axum + htmx) for monitoring and manual CAPTCHA solving.

## Technical Approach

### Architecture

```
~/.dataward/
├── dataward                    # Rust binary
├── config.toml                 # Non-sensitive config (no credentials)
├── dataward.db                 # SQLCipher-encrypted SQLite (PII + SMTP creds)
├── worker/                     # Extracted TypeScript worker
│   ├── worker.js               # Patchright runner (long-lived)
│   ├── package.json
│   └── node_modules/
├── playbooks/                  # YAML broker definitions
│   ├── official/               # Shipped with binary (trusted)
│   ├── community/              # Downloaded from repo (checksummed)
│   └── local/                  # User-added (warned as unreviewed)
├── proofs/                     # Encrypted screenshot evidence
│   └── spokeo/
│       └── 2026-02-23-confirmation.png.enc
├── logs/
│   └── dataward.log            # PII-sanitized structured logs
└── chromium/                   # Auto-downloaded browser binary
```

**Rust crates (daemon core):**

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime, process spawning, channels |
| `clap` | CLI argument parsing |
| `axum` | Embedded web server for dashboard |
| `rusqlite` + `bundled-sqlcipher` | Encrypted SQLite state storage (WAL mode) |
| `lettre` | SMTP email sending (TLS required) |
| `reqwest` | HTTP client for API opt-outs |
| `serde` + `serde_yaml` | Config and playbook parsing |
| `argon2` | Key derivation from user passphrase |
| `tracing` + `tracing-subscriber` | PII-sanitized structured logging |

**TypeScript packages (worker):**

| Package | Purpose |
|---------|---------|
| `patchright` | Anti-detection browser automation (reduces basic detection — not a complete solution) |
| `js-yaml` | Playbook parsing |

### Threat Model

| Adversary | Capabilities | Trust Boundary |
|-----------|-------------|----------------|
| Malicious playbook author | Can craft YAML to exfiltrate PII via navigate/fill | Playbook validation + domain allowlisting |
| Data brokers | Can deploy CAPTCHAs, change forms, rate limit | Playbook brittleness detection + manual fallback |
| Local malware / other processes | Can read localhost ports, read files as same user | Dashboard auth token, SQLCipher encryption, encrypted proofs |
| Network observer | Can intercept SMTP, see browser traffic | TLS-required SMTP, HTTPS-only broker sites |

### PII Data Flow Map

Every location where PII exists:

| Location | PII Present | Protection |
|----------|------------|------------|
| SQLCipher database | Full profile (name, email, phone, address) | AES-256 full-DB encryption, Argon2id key |
| Worker stdin pipe | Filtered to required_fields only | Ephemeral (memory only), never written to disk |
| Browser form fields | Subset per broker | Ephemeral browser context, destroyed after task |
| Proof screenshots | May contain filled forms | Encrypted at rest (AES-256-GCM per file) |
| Email templates | Name, email, address | TLS-required SMTP transmission |
| Log files | NEVER — sanitized | PII redaction filter on all log output |
| Process arguments | NEVER — stdin only | Not visible via `ps` |
| Environment variables | Passphrase (if used) | Stripped after read, not propagated to children |
| OS swap/pagefile | Potentially | Document risk; recommend encrypted swap |
| config.toml | Non-sensitive settings only | SMTP creds moved to SQLCipher DB |

### Data Flow

```
User runs `dataward init`
  → Prompts for PII (name, email, address, phone) with input validation
  → Prompts for passphrase (document: no recovery if forgotten)
  → Derives encryption key via Argon2id (memory=64MB, iterations=3, parallelism=4)
  → Creates SQLCipher DB, stores PII + SMTP credentials (if provided)
  → Generates dashboard auth token, stores in DB
  → Downloads Patchright + Chromium (with SHA-256 checksum verification)
  → Extracts worker + playbooks to ~/.dataward/
  → Validates all playbook schemas

User runs `dataward run` (or daemon via systemd)
  → Startup recovery: reset orphaned `running` tasks to `pending`
  → Opens SQLCipher DB (prompts passphrase or reads from env, then strips env var)
  → Spawns long-lived worker subprocess (1 Chromium instance)
  → Loads scheduler, reads broker registry from DB
  → For each broker due for opt-out (serialized, 1 at a time by default):
      → Determines channel (web_form | email | api)
      → Web form: sends task to worker via JSON-lines stdin
          → Worker filters user_data to playbook's required_fields
          → Worker validates navigate URLs against broker domain
          → Worker creates fresh browser context, executes playbook
          → Worker destroys browser context, outputs JSON result via stdout
          → Daemon parses result (strict serde, deny_unknown_fields, max payload 1MB)
          → Daemon updates DB via channel-based single writer, encrypts + stores proof
      → Email: constructs legal template with minor variation, sends via lettre/SMTP (TLS required)
      → API: sends HTTP DELETE/POST via reqwest
  → Failed tasks: retry with exponential backoff (1h, 4h, 24h, 72h), max 5 retries
  → CAPTCHA-blocked tasks: queued with 24h TTL for manual resolution via dashboard
  → DB write failures: retry 3x with backoff, fallback to journal file, surface in status

Graceful shutdown (SIGTERM/SIGINT):
  → Stop accepting new tasks
  → Wait up to 30s for active worker to complete current task
  → Force-kill worker if timeout exceeded
  → Record interrupted tasks as `pending` (not `running`)

Dashboard (localhost:9847, auth-token required)
  → Read: broker status table, opt-out history, run logs
  → Interactive: manual CAPTCHA queue (24h TTL, abandonment handling), trigger single-broker re-run
  → Auth: bearer token generated at init, required for all requests
  → Security: Host header validation (reject non-localhost), CSRF token on mutations
  → No config editing via dashboard
```

### Worker Architecture (Revised: Long-Lived Process)

Instead of spawning a fresh Node+Chromium process per task (750 × 2-5s startup = hours of overhead), the worker runs as a **long-lived subprocess** with one persistent Chromium instance.

**Lifecycle:**
1. Rust daemon spawns `node worker.js` once on `dataward run`
2. Worker launches Chromium via Patchright, keeps it alive
3. Daemon sends tasks as JSON lines via stdin (one per line)
4. Worker creates a fresh **browser context** per task (isolated cookies/storage, ~50MB overhead vs ~500MB for new instance)
5. Worker destroys context after task completion
6. Worker outputs result as JSON line via stdout
7. On daemon shutdown: daemon sends `{"command": "shutdown"}`, worker closes Chromium and exits

**Concurrency:** Default 1 task at a time (sequential). Configurable up to 3 concurrent browser contexts. Resource budget: ~500MB-1GB for Chromium + contexts, ~50MB for Rust daemon. Target: machines with 4GB+ RAM.

**Input contract (one JSON line per task):**
```json
{
  "task_id": "uuid",
  "broker_id": "spokeo",
  "playbook_path": "playbooks/official/spokeo.yaml",
  "user_data": { "first_name": "...", "last_name": "...", "email": "..." },
  "timeout_ms": 120000,
  "proof_dir": "proofs/spokeo/",
  "allowed_domains": ["spokeo.com", "www.spokeo.com"]
}
```

Note: `user_data` contains ONLY the fields listed in the playbook's `required_fields` — the orchestrator filters before transmission.

**Output contract (one JSON line per result):**
```json
{
  "task_id": "uuid",
  "status": "success",
  "proof": { "screenshot_path": "proofs/spokeo/2026-02-23-confirmation.png", "confirmation_text": "Your request has been received" },
  "duration_ms": 8500
}
```

**Status enum:** `success`, `failure`, `captcha_blocked`, `timeout`, `playbook_error`, `domain_violation`

**Failure modes:**
- Task timeout → daemon sends cancel signal, worker aborts current context, records `timeout`
- Browser crash → worker detects, restarts Chromium, reports `failure` for current task
- Domain violation → worker blocks `navigate()` to non-allowed domain, reports `domain_violation`
- Playbook step failed → `playbook_error` with step index, error category (`selector_not_found`, `page_structure_changed`, `unexpected_navigation`), and error detail
- Worker process dies → daemon detects via stdout EOF, restarts worker, resets current task to `pending`

**Environment isolation:** Worker spawned with `Command::env_clear()` — only explicitly needed env vars passed (PATH, HOME). Passphrase NEVER propagated.

### Playbook Schema & Security

```yaml
# playbooks/official/spokeo.yaml
broker:
  id: spokeo
  name: Spokeo
  url: https://www.spokeo.com
  category: people_search       # people_search | marketing | background_check | ad_tech
  recheck_days: 90
  opt_out_channel: web_form     # web_form | email | api | manual_only
  parent_company: null          # For deduplication — e.g., "peopleconnect"
  allowed_domains:              # URL allowlist — navigate() restricted to these
    - spokeo.com
    - www.spokeo.com

required_fields: [first_name, last_name, email]

steps:
  - navigate: "https://www.spokeo.com/optout"
  - fill: { selector: "#first_name", field: "first_name" }
  - fill: { selector: "#last_name", field: "last_name" }
  - fill: { selector: "#email", field: "email" }
  - click: { selector: "#submit-btn" }
  - wait: { seconds: 3 }
  - screenshot: { name: "confirmation" }

on_error: retry    # retry | skip | fail
max_retries: 3
```

**MVP action types (6 core):**

| Action | Parameters | Description |
|--------|-----------|-------------|
| `navigate` | url | Go to URL (MUST match allowed_domains) |
| `fill` | selector, field | Fill form field with user data |
| `click` | selector | Click element |
| `select` | selector, value_or_field | Select dropdown option |
| `wait` | seconds | Fixed delay (max 30s) |
| `screenshot` | name | Capture proof screenshot |

**Deferred to v1.1:** `wait_for`, `assert_text`, `if_exists`, `type_slowly` — add when specific playbooks require them.

**Playbook validation (Phase 1, at load time):**
1. Strict YAML schema check — reject unknown fields
2. All `navigate` URLs must be `https://` and match `broker.allowed_domains`
3. Block `javascript:`, `data:`, `file:`, `blob:` URL schemes
4. Maximum 50 steps per playbook
5. All `field` references must exist in `required_fields`
6. `on_error` must be a valid enum value

**Trust tiers:**
- `playbooks/official/` — shipped with binary, implicitly trusted
- `playbooks/community/` — from official repo, SHA-256 checksummed at download
- `playbooks/local/` — user-created, warning displayed on first load: "Unreviewed playbook — verify before running"

### Email Templates & Deliverability

Legal demand letters generated per applicable regulation:

| Template | Jurisdiction | Legal Basis |
|----------|-------------|-------------|
| `ccpa_delete.txt` | California | CCPA §1798.105 — Right to Delete |
| `gdpr_erasure.txt` | EU/EEA | GDPR Art. 17 — Right to Erasure |

**Deferred:** `ccpa_optout.txt`, `generic_delete.txt` — add when brokers require them.

**Deliverability mitigations (research-informed):**
- Templates include minor per-broker variation (broker name, specific data types held) to avoid pattern detection
- Emails sent in batches: max 20/day by default (configurable), spread across the day
- TLS required for SMTP connections — `lettre` configured with `require_tls: true`
- Warn user if personal Gmail used (100 email/day SMTP limit)
- Track delivery status: sent, bounced, no-reply. Surface persistent failures in dashboard.
- Honest expectation: ~60-84% inbox placement. Some emails will be filtered. Recommend dedicated opt-out email address.

**SMTP credentials:** Stored in SQLCipher database (NOT config.toml). Encrypted at rest with the same Argon2id-derived key.

### Database Schema (SQLCipher + WAL Mode)

```sql
PRAGMA journal_mode=WAL;  -- Enable Write-Ahead Logging for read concurrency

CREATE TABLE brokers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    opt_out_channel TEXT NOT NULL,
    recheck_days INTEGER NOT NULL,
    parent_company TEXT,
    playbook_path TEXT NOT NULL,
    trust_tier TEXT NOT NULL DEFAULT 'official',  -- official | community | local
    enabled INTEGER DEFAULT 1,
    success_rate REAL DEFAULT 0.0,  -- For brittleness detection
    last_success_at TEXT
);

CREATE TABLE opt_out_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    broker_id TEXT NOT NULL REFERENCES brokers(id),
    status TEXT NOT NULL,         -- pending | running | success | failure | captcha_blocked | timed_out
    channel TEXT NOT NULL,        -- web_form | email | api
    created_at TEXT NOT NULL,
    completed_at TEXT,
    next_recheck_at TEXT,
    retry_count INTEGER DEFAULT 0,
    proof_path TEXT,
    proof_missing INTEGER DEFAULT 0,  -- 1 if opt-out succeeded but proof capture failed
    confirmation_text TEXT,
    error_code TEXT,              -- selector_not_found | page_structure_changed | etc.
    error_message TEXT,
    error_retryable INTEGER,
    duration_ms INTEGER
);

CREATE TABLE user_profile (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL           -- Encrypted via SQLCipher
);

CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL            -- SMTP creds, dashboard token, settings
);

CREATE TABLE run_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    total_tasks INTEGER,
    succeeded INTEGER,
    failed INTEGER,
    captcha_blocked INTEGER
);

CREATE INDEX idx_tasks_status ON opt_out_tasks(status);
CREATE INDEX idx_tasks_recheck ON opt_out_tasks(next_recheck_at);
CREATE INDEX idx_tasks_broker ON opt_out_tasks(broker_id);
```

**Write strategy:** All DB writes funneled through a single `tokio::sync::mpsc` channel to a dedicated writer task. Workers send completion messages to the channel; the writer drains and batches writes. Prevents SQLite write contention.

**DB write failure handling:** Writer retries 3x with 100ms backoff. On persistent failure, writes to a `~/.dataward/journal.jsonl` fallback file. On next successful DB connection, replays journal. Surfaces failure count in `dataward status` output and dashboard.

### Security Design

- **PII at rest:** Entire SQLite database encrypted via SQLCipher (AES-256-CBC + HMAC-SHA512 per page). Key derived from user passphrase via Argon2id (memory=64MB, iterations=3, parallelism=4).
- **SMTP credentials:** Stored in SQLCipher `config` table — NOT in plaintext config.toml.
- **Proof screenshots:** Encrypted per-file using AES-256-GCM with a key derived from the master passphrase. Stored as `.png.enc` files.
- **PII in transit to worker:** Filtered to `required_fields` only, passed via stdin pipe. Never on disk, never in process args.
- **Config file:** `config.toml` contains ONLY non-sensitive settings (schedule intervals, log level, concurrency). No credentials.
- **Dashboard:** Binds to `127.0.0.1:9847`. Requires bearer token (generated at `dataward init`, stored in SQLCipher). Host header validation rejects non-localhost. CSRF token on all mutation endpoints.
- **Worker isolation:** `Command::env_clear()` prevents passphrase propagation. Each task runs in isolated browser context (no shared cookies/state).
- **Passphrase handling:** If via env var (`DATAWARD_PASSPHRASE`), stripped from environment immediately after read via `std::env::remove_var()`. Not propagated to child processes.
- **Log sanitization:** PII-aware filter on all `tracing` output. Known PII fields (first_name, last_name, email, address, phone) redacted. JSON payloads never logged at any level.
- **Playbook sandboxing:** Domain allowlisting per broker, URL scheme blocking, strict schema validation, trust tiers, max step count.
- **Auto-downloads:** Chromium and Patchright downloads verified against SHA-256 checksums pinned in the binary.
- **File permissions:** Created with explicit modes — directories 0700, files 0600. Verified at startup with warning if loosened.

### Brittleness Strategy (Research-Informed)

Instead of screenshot diffing (high false positive rate, complex), use structured error detection:

1. **Error categorization** — Worker reports specific error codes: `selector_not_found`, `page_structure_changed`, `unexpected_navigation`, `timeout`, `captcha_blocked`. Each maps to a different recovery action.
2. **Per-broker success rate tracking** — `brokers.success_rate` updated after each task. If a previously 100% broker drops to 0% over 3 runs, flag as `playbook_stale` in dashboard and CLI status.
3. **Confirmation assertion** — Playbooks should include a `screenshot` after expected completion. Absence of expected confirmation text (future `assert_text` action) signals the flow changed.
4. **Community reporting (opt-in)** — When a playbook breaks, the daemon can optionally (with explicit user consent, disabled by default) report the error code and broker ID (NO PII) to a central health endpoint. Enables community-driven maintenance.
5. **Degradation** — Brokers with stale playbooks are automatically disabled after 5 consecutive failures. User notified via dashboard and `dataward status`.

## Implementation Steps

### Phase 1: Foundation (Rust Skeleton + CLI + Validation)
1. Initialize Cargo workspace — `Cargo.toml`, `src/main.rs`, basic `clap` CLI with subcommands: `init`, `run`, `status`, `purge`
2. Implement `dataward init` — passphrase prompt (with "no recovery" warning), Argon2id key derivation, SQLCipher database creation with WAL mode, schema migration, PII collection with input validation (length limits, email format, no null bytes), SMTP credential storage in DB, dashboard auth token generation
3. Implement config loading — `config.toml` parsing (non-sensitive only), data directory paths
4. Implement broker registry — load YAML playbooks, **strict schema validation** (reject unknown fields, URL scheme check, domain allowlist check, max 50 steps, field references), populate `brokers` table
5. Add PII-sanitized structured logging via `tracing` + file rotation + redaction filter
6. Implement `dataward purge` — delete all PII, proofs, and DB. Clean shutdown for users leaving the tool.

### Phase 2: Subprocess Worker (TypeScript + Patchright)
7. Create TypeScript worker project — `package.json`, `tsconfig.json`, Patchright dependency
8. Implement long-lived worker — launch Chromium once, accept JSON-lines tasks via stdin, create/destroy browser contexts per task
9. Implement 6 MVP action types — `navigate` (with domain allowlist enforcement), `fill`, `click`, `select`, `wait` (max 30s), `screenshot`
10. Implement stdin/stdout JSON-lines IPC — read task lines, output result lines
11. Add error handling — categorized error codes (`selector_not_found`, `page_structure_changed`, `domain_violation`, etc.), step index in errors
12. Implement graceful shutdown — respond to `{"command": "shutdown"}` by closing Chromium and exiting

### Phase 3: Orchestrator (Scheduler + Task Execution)

**[DEEPENED] Architecture decomposition:** Orchestrator has three distinct subsystems. `src/orchestrator.rs` owns the top-level lifecycle (startup, shutdown, PID lock) and composes: (a) Scheduler — decides what runs when, (b) Dispatcher — routes tasks to channel-specific workers, (c) SubprocessManager — owns worker process lifecycle. Each is independently testable.

**[DEEPENED] Concurrency model clarified:** Default concurrency=1. For concurrency > 1, spawn multiple worker subprocesses (not multiplexed over single stdin). The JSON-lines protocol already includes task_id for correlation. Concurrency setting controls the number of worker processes, NOT internal browser contexts per worker.

**[DEEPENED] Per-task timeouts required:** Browser tasks 120s, email 30s, API 15s. Dispatcher wraps each task future with `tokio::time::timeout()`. Timed-out tasks marked failed with retryable error code.

13. Implement task scheduler — `tokio::time::interval()` with `MissedTickBehavior::Skip` (not manual sleep) + DB `next_recheck_at` timestamp comparison. **[DEEPENED]** Run one immediate tick at startup to dispatch overdue tasks. Use `LIMIT N` on scheduler query (N = concurrency ceiling). Handle `next_recheck_at IS NULL` rows. Add composite index `(status, next_recheck_at)` replacing two single-column indexes.
14. ~~Implement channel-based DB writer~~ **[DEEPENED] Already implemented** in Phase 1 (`DbWriteMessage`, `spawn_writer()`, journal fallback). Phase 3 extends with new message types (ProofUpdate, EmailLog, TaskRetry). Use `send().await` (not `try_send`) for back-pressure; if channel full, log WARN and yield.
15. Implement crash recovery — on startup: (a) check/kill orphaned worker processes first, (b) replay journal entries, (c) reset all `running` tasks to `pending`, (d) reconcile orphaned tasks at `retry_count >= max` as permanently failed, (e) verify PID file via `flock()` (not check-then-write), warn about incomplete previous runs. **[DEEPENED]** Journal replay BEFORE orphan reset — ordering matters.
16. Implement subprocess manager — spawn long-lived worker with `HOME` set to isolated temp directory (not user HOME), handle stdout EOF (restart with circuit breaker: max 3 crashes per 5 minutes, then halt), send shutdown on daemon exit. **[DEEPENED]** Use `BufReader` with max line length 1MB to prevent OOM from partial/malicious output. On EOF, check for non-empty line buffer and log partial fragment. Worker crash restarts use exponential cooldown.
17. Implement email opt-out worker — `lettre` SMTP (TLS 1.2+ required), template rendering with per-broker variation, daily batch limit (default 20). **[DEEPENED]** Persist daily email counter + date in DB (not in-memory — survives restart). Validate no CRLF in template interpolation values (SMTP header injection prevention). Define terminal state for exhausted retries: task `failed`, surface in `dataward status`.
18. Implement API opt-out worker — `reqwest` HTTP client (single pooled client, reused) for brokers with deletion APIs. **[DEEPENED]** Validate 2xx response bodies against expected schema — treat malformed 2xx as `playbook_error`. Group tasks by broker; parallelize within broker up to concurrency ceiling.
19. Implement retry logic — exponential backoff (1h, 4h, 24h, 72h), max 5 retries, use boolean `error_retryable` flag (not code-aware routing table). **[DEEPENED]** Add per-broker circuit breaker: after N consecutive failures, mark broker `degraded` and skip scheduling until health check succeeds. Add `retry_exhausted` terminal state distinct from permanent failure.
20. Implement `dataward run` — single-run mode and daemon mode, PID file lock via `flock()` (atomic, stale-safe), graceful shutdown via `CancellationToken` (SIGTERM/SIGINT → cancel token → stop new tasks → wait configurable timeout for active task → force kill → flush DB writer with 5s timeout → direct DB write fallback → record interrupted tasks as pending → remove PID file). **[DEEPENED]** Signal handler is idempotent (AtomicBool — subsequent SIGTERMs are no-ops). Print summary on `--once` with no due tasks.
21. Implement PII field filtering — orchestrator sends only `required_fields` subset to worker. **[DEEPENED]** Validate all required_fields exist and are non-empty in user profile BEFORE dispatching task. Missing fields → task status `needs_user_data`, surface notification.
22. Implement proof encryption — AES-256-GCM encrypt screenshots before writing to disk. **[DEEPENED]** Already implemented (`crypto::encrypt_file`). Use random 96-bit nonces (OsRng) per file. Derive proof-specific subkey via HKDF with context "proof-encryption". On encryption failure → task `proof_error`, never write unencrypted proof to disk.

### Phase 4: Web Dashboard
23. Implement axum web server — bind `127.0.0.1:9847`, bearer token auth middleware, Host header validation, CSRF tokens
24. Build status page — broker table with status, last attempt, next recheck, success rate, trust tier. Empty state: "No brokers loaded — run `dataward init`"
25. Build opt-out history page — timeline with encrypted proof viewing (decrypt in-memory for display)
26. Build CAPTCHA queue page — list of `captcha_blocked` tasks with 24h TTL, session expiry warning, "Solve" button opens broker URL in system browser, "Mark resolved" triggers immediate re-run, "Abandon" returns task to retry queue. Empty state: "No CAPTCHAs pending."
27. Build single-broker re-run trigger — button with CSRF token
28. Build health indicators — per-broker success rate, stale playbook warnings, SMTP delivery stats

### Phase 5: Distribution + Playbooks
29. Implement `dataward init` auto-download — fetch Patchright + Chromium with SHA-256 checksum verification
30. Write initial playbooks for top 20 brokers (research-informed priority order):
    - **Basic forms (no CAPTCHA):** TruePeopleSearch, Radaris, USPhoneBook, FastPeopleSearch, Nuwber
    - **reCAPTCHA + email verification:** Spokeo, BeenVerified, Intelius, PeopleFinder
    - **Manual-only (phone/mail verification):** WhitePages (categorized as `manual_only`, skipped by automation)
31. Build release pipeline — cross-compile for Linux/macOS, embed worker tarball
32. Create Dockerfile with everything pre-bundled
33. Write playbook contributor guide with schema documentation and validation instructions

### Phase 6: Polish
34. Add `dataward status` — CLI output with broker table, CAPTCHA queue count, stale playbook warnings, SMTP delivery stats, next scheduled run
35. Add `dataward rekey` — passphrase rotation (re-encrypt DB with new key)
36. Add idempotent `dataward init` re-run — detect existing config, offer update-only vs. full reset with confirmation
37. Add run summary reporting — per-run stats, optional email digest
38. Security audit — full audit against threat model and PII data flow map

## Affected Files

This is a greenfield project. All files are new:

**Rust (daemon core):**
- `Cargo.toml` — workspace manifest with dependencies
- `src/main.rs` — CLI entry point (clap)
- `src/config.rs` — TOML config loading (non-sensitive only)
- `src/db.rs` — SQLCipher database, WAL mode, schema, migrations, channel-based writer
- `src/crypto.rs` — Argon2id key derivation, AES-256-GCM proof encryption, passphrase handling
- `src/scheduler.rs` — Interval-based scheduling with DB timestamps
- `src/orchestrator.rs` — Task dispatch, PII field filtering, concurrency control
- `src/workers/browser.rs` — Long-lived subprocess management, JSON-lines IPC, timeout
- `src/workers/email.rs` — SMTP sending (TLS required), template rendering, batch limiting
- `src/workers/api.rs` — HTTP deletion requests
- `src/dashboard/mod.rs` — Axum web server, auth middleware, CSRF
- `src/dashboard/routes.rs` — Dashboard page handlers
- `src/dashboard/templates/` — HTML templates (htmx)
- `src/broker_registry.rs` — YAML playbook loading, strict validation, trust tiers
- `src/init.rs` — First-run setup, Patchright download with checksum verification
- `src/recovery.rs` — Crash recovery, orphaned task reset, journal replay
- `src/logging.rs` — PII-sanitized tracing filter

**TypeScript (worker):**
- `worker/package.json` — Patchright + js-yaml dependencies
- `worker/worker.ts` — Long-lived entry: Chromium lifecycle, JSON-lines IPC
- `worker/interpreter.ts` — Playbook action interpreter with domain enforcement
- `worker/actions/*.ts` — Per-action-type implementations (6 MVP actions)

**Playbooks:**
- `playbooks/official/*.yaml` — Top 20 broker definitions
- `playbooks/community/.checksums` — SHA-256 checksums for community playbooks

**Config/Infra:**
- `config.example.toml` — Example configuration (non-sensitive only)
- `dataward.service` — systemd unit file
- `com.dataward.daemon.plist` — macOS launchd plist
- `Dockerfile` — Container build
- `.github/workflows/release.yml` — CI/CD release pipeline

**Email templates:**
- `templates/email/ccpa_delete.txt`
- `templates/email/gdpr_erasure.txt`

## Acceptance Criteria
- [ ] `dataward init` collects PII with validation, encrypts with SQLCipher, generates auth token, downloads Patchright + Chromium with checksum verification
- [ ] `dataward run` executes opt-outs for all due brokers across all three channels with bounded concurrency
- [ ] Browser opt-outs complete successfully for at least 15 of the top 20 broker playbooks
- [ ] Email opt-outs send valid CCPA/GDPR demand letters via TLS-required SMTP with batch limiting
- [ ] Failed tasks retry with exponential backoff, CAPTCHA-blocked tasks queue with 24h TTL
- [ ] Crash recovery resets orphaned tasks on startup, graceful shutdown preserves state
- [ ] Web dashboard shows status, history, and CAPTCHA queue behind bearer token auth
- [ ] All PII encrypted at rest — DB (SQLCipher), proofs (AES-256-GCM), SMTP creds (in DB)
- [ ] Playbook validation rejects malformed/unsafe playbooks at load time (domain allowlist, schema check)
- [ ] PII filtered to required_fields before sending to worker
- [ ] PII never appears in logs at any level
- [ ] `dataward purge` cleanly removes all user data
- [ ] Tests passing with >80% coverage on Rust core
- [ ] Security audit completed against threat model

## Test Strategy

**Unit tests (Rust):**
- Config parsing — valid TOML, missing fields, invalid values
- Crypto — Argon2id derivation produces consistent keys, SQLCipher roundtrip, AES-256-GCM proof encrypt/decrypt
- Broker registry — valid playbook loading, schema validation rejection (bad URL scheme, missing allowed_domains, unknown fields, >50 steps, field reference mismatch)
- PII field filtering — only required_fields passed to worker
- Scheduler — correct next-run calculation, recheck interval arithmetic
- Retry logic — backoff timing, max retry enforcement, error-code-aware retry skip
- Email template rendering — PII substitution, per-broker variation, TLS enforcement
- DB writer — channel drain, journal fallback on failure, journal replay
- Crash recovery — orphaned task reset, PID file handling
- Dashboard auth — token validation, Host header rejection, CSRF verification
- Log sanitization — PII fields redacted in all log levels

**Integration tests (Rust + Worker):**
- Full subprocess lifecycle — spawn worker, send JSON-lines tasks, read results
- Long-lived worker — multiple tasks on same Chromium instance, context isolation verification
- Timeout handling — task exceeding timeout is cancelled, worker continues for next task
- Worker crash and restart — daemon detects EOF, respawns, resets task
- Browser context isolation — cookies/storage not shared between tasks
- Domain enforcement — worker rejects navigate to non-allowed domain

**Worker tests (TypeScript):**
- Playbook interpreter — each of 6 action types against mock browser
- Domain allowlist enforcement — navigate to non-allowed domain returns `domain_violation`
- Error categorization — `selector_not_found` vs `page_structure_changed` vs `timeout`
- JSON-lines contract compliance — multiple tasks per session

**Edge cases:**
- Empty user data fields (null, empty string)
- Playbook with no steps
- Playbook with invalid selectors
- Network failure during browser automation
- SQLCipher database locked (concurrent access via WAL)
- Worker stdout is not valid JSON (strict parsing, max 1MB)
- Broker that requires fields not in user profile
- Unicode in user names and addresses
- init re-run on existing installation
- Proof capture fails but opt-out succeeded (`proof_missing` flag)

**Security tests:**
- PII never appears in logs at any log level (scrub test)
- PII never in process arguments (`ps` check)
- Passphrase env var not propagated to child processes
- SMTP credentials not in config.toml
- Dashboard rejects requests without auth token
- Dashboard rejects non-localhost Host headers
- Playbook with `javascript:` URL rejected at load time
- Playbook navigate to non-broker domain rejected at runtime
- Proof files are encrypted on disk

## Security Review
- [x] PII encrypted at rest — SQLCipher DB + AES-256-GCM proof files + SMTP creds in DB
- [x] PII in transit to worker — filtered to required_fields, stdin pipe only
- [x] Playbook sandboxing — domain allowlisting, URL scheme blocking, trust tiers, schema validation
- [x] No hardcoded secrets — passphrase prompted, stripped from env after read
- [x] SQL injection prevented — rusqlite parameterized queries
- [x] XSS prevented — htmx server-rendered templates with auto-escaping
- [x] Dashboard auth — bearer token + Host header validation + CSRF tokens
- [x] SMTP credentials in encrypted DB, not plaintext config
- [x] Proof screenshots encrypted at rest (AES-256-GCM)
- [x] Worker env isolation — env_clear() + selective var passing
- [x] Log sanitization — PII redaction filter on all tracing output
- [x] Auto-download integrity — SHA-256 checksum verification
- [x] File permissions — explicit 0700/0600 creation, startup verification

## Spec-Flow Analysis

### Primary Flow: Automated Browser Opt-Out
1. Daemon starts → Success: loads config, opens DB, runs crash recovery, starts scheduler | Error: config missing → exit with actionable error | Error: wrong passphrase → clear message, no corruption | Empty: no brokers enabled → warn and idle
2. Scheduler triggers broker → Success: creates pending task | Error: DB write fails → channel-based writer retries 3x, falls back to journal
3. Send task to worker → Success: worker receives JSON-line | Error: worker process dead → restart worker, reset task to pending | Error: Chromium crashed → worker restarts browser, reports failure
4. Worker executes playbook → Success: steps complete, proof captured and encrypted | Error: selector not found → `playbook_error` with `selector_not_found` code | Error: domain violation → immediate abort | CAPTCHA: `captcha_blocked` | Timeout: task cancelled
5. Daemon records result → Success: DB updated via writer channel, next_recheck_at set | Error: DB write fails → journal fallback, surfaced in status
6. Recheck cycle → Success: broker re-checked on schedule | Empty: already opted-out → skip until recheck_at | Stale: 5 consecutive failures → broker auto-disabled, warning surfaced

### Alternative Flow: Email Opt-Out
1. Broker has `opt_out_channel: email` → construct legal template with per-broker variation
2. Check daily batch limit → over limit → queue for tomorrow
3. Send via SMTP → Success: record sent, set recheck | Error: SMTP auth failure → fail with clear message, surface in dashboard | Error: TLS negotiation fails → fail, do not fallback to plaintext | Error: connection refused → retry with backoff (max 5)

### Alternative Flow: Manual CAPTCHA Resolution
1. Worker returns `captcha_blocked` → task queued in dashboard with 24h TTL
2. User opens dashboard (with auth token) → sees CAPTCHA queue with broker name, screenshot, and time remaining
3. User clicks "Solve" → system browser opens to broker opt-out page
4. User completes CAPTCHA manually → clicks "Mark Resolved" in dashboard (CSRF-protected)
5. Daemon immediately re-runs the broker opt-out (new task)
6. If re-run fails again → back to `captcha_blocked` or other error state
7. If user doesn't act within 24h → task expires, returns to `pending` for next scheduled run
8. Empty queue state: "No CAPTCHAs pending. Brokers requiring manual intervention will appear here."

### Edge States
- **First-use:** `dataward init` not yet run → all commands except `init` print setup instructions with `dataward init` command
- **Init re-run:** Detect existing installation, offer: update PII / update SMTP / full reset (confirmation required before destructive action)
- **No SMTP configured:** Email opt-outs surface as "skipped — SMTP not configured" in dashboard and status (not just log)
- **All brokers succeeded:** Dashboard shows clean status with next recheck dates
- **Concurrent access:** Single daemon instance enforced via PID file lock. Second `dataward run` prints: "Daemon already running (PID 12345). Use `dataward status` to check."
- **Passphrase wrong:** SQLCipher open fails → "Incorrect passphrase. Your data is safe — try again."
- **Passphrase change:** `dataward rekey` prompts old + new passphrase, re-encrypts DB
- **User leaves tool:** `dataward purge` deletes DB, proofs, logs, config. Confirmation required.

## Alternatives Considered

| Approach | Pros | Cons | Why Not |
|----------|------|------|---------|
| Rust Monolith (CDP) | Single binary, max efficiency | Immature browser automation, DIY anti-detection | Would rebuild Playwright poorly; high risk of breakage |
| TypeScript/Bun Monolith | Single language, fastest MVP | Memory overhead, GC pauses, Bun compilation maturity | Not "best tech"; daemon stability concerns for 24/7 operation |
| Process-per-task (original plan) | Simple failure isolation | 750× process spawn overhead, 500MB+ per Chromium instance, OOM risk | Replaced with long-lived worker + context-per-task after resource modeling |

See: `docs/brainstorms/2026-02-23-dataward-architecture-brainstorm.md`

## Past Learnings Applied
- (None found — greenfield project, `docs/solutions/` does not exist yet)

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Broker sites change opt-out flows, breaking playbooks | High | High | Structured error codes, per-broker success rate tracking, auto-disable after 5 failures, community reporting (opt-in) |
| Patchright project goes unmaintained | Medium | High | Worker abstracts browser init — swap to vanilla Playwright + stealth plugin or rebrowser-patches. Design: only browser init code changes, not playbook interpreter. |
| Patchright anti-detection insufficient for major brokers | Medium | Medium | Patchright handles basic detection only (navigator.webdriver, CDP). Brokers with Cloudflare/DataDome → fall back to email channel or manual-only classification. Don't overpromise. |
| CAPTCHAs unsolvable by automation | High | Medium | Manual CAPTCHA queue with 24h TTL in dashboard. No Whisper/audio solving in MVP — add only if prototyping validates viability. |
| User SMTP emails filtered as spam | Medium | Medium | Per-broker template variation, batch limiting (20/day), TLS required. Honest docs: ~60-84% inbox rate. Recommend dedicated email address. |
| Malicious community playbook exfiltrates PII | Low | Critical | Domain allowlisting, URL scheme blocking, trust tiers, PII field filtering, schema validation |
| SQLCipher adds compilation complexity | Low | Medium | Use `bundled-sqlcipher` — statically links, no system dependency |
| Double opt-out submission after timeout/retry | Medium | Low | Document as known limitation. Most brokers handle duplicate requests gracefully. Future: idempotency keys if broker APIs support them. |
| Aggregate Dataward users detectable by brokers | Low | Medium | Each user runs on their own IP with human-like timing. No coordination between instances. If detected, fall back to email channel. |

## Rollback Plan

Not applicable — greenfield project. Each phase is independently deployable:
1. Phase 1 alone = useful CLI tool for managing broker list + PII vault
2. Phase 1+2 = can run individual opt-outs manually via worker
3. Phase 1+2+3 = full automation without dashboard
4. All phases = complete system

If any phase fails, earlier phases remain functional.

## Dependencies

**Build-time:**
- Rust toolchain (stable)
- Node.js 20+ (for worker development and testing)
- SQLCipher (statically linked via `bundled-sqlcipher`)

**Runtime:**
- Node.js 20+ (auto-downloaded or pre-installed)
- Chromium (auto-downloaded via Patchright on `dataward init`, SHA-256 verified)

**External services:**
- User's SMTP server (for email opt-outs, TLS required)
- Internet access (for browser automation and API calls)

---

## [DEEPENED] Enhancement Summary — Phase 3 Focus

**Date:** 2026-02-24
**Agents:** 7 (Architecture opus, Simplicity sonnet, Security opus, Performance sonnet, Edge Case sonnet, Spec-Flow sonnet, Best Practices haiku)
**Total findings:** 48 (8 per reviewer)
**Cross-agent duplicates (3+ agents):** 3 HIGH PRIORITY issues

### Priority Fixes (Must address before Phase 3 implementation)

| # | Issue | Agents | Resolution |
|---|-------|--------|------------|
| 1 | **Journal replay not integrated into crash recovery** | ARCH, SIMP, EC, PERF, FLOW | Recovery order: replay journal → kill orphans → reset running → reconcile max-retry. Annotated in step 15. |
| 2 | **Scheduler query unbounded + wrong indexes** | PERF, EC, ARCH | Add LIMIT, composite index `(status, next_recheck_at)`, handle NULL. Annotated in step 13. |
| 3 | **Worker crash restart has no circuit breaker** | ARCH, SEC, EC | Max 3 crashes per 5 min → halt daemon. Annotated in step 16. |
| 4 | **Concurrency model contradictory** | ARCH | Clarified: concurrency = number of worker subprocesses, not internal contexts. Annotated at top of Phase 3. |
| 5 | **Per-task timeouts missing** | ARCH, PERF | Browser 120s, email 30s, API 15s via `tokio::time::timeout`. Annotated at top of Phase 3. |
| 6 | **Partial JSON line on crash / stdout OOM** | SEC, EC | BufReader with 1MB max line length. Log partial fragments. Annotated in step 16. |
| 7 | **PID file TOCTOU race** | SEC, EC | Use `flock()` instead of check-then-write. Detect stale PIDs. Annotated in steps 15, 20. |
| 8 | **Argon2id re-derived per open_db()** | PERF | Derive once at startup, cache in SecretVec. (Phase 1 TODO — must fix before Phase 3 daemon loop.) |

### Architecture Decisions Made

| Decision | Rationale |
|----------|-----------|
| Orchestrator owns lifecycle; Scheduler, Dispatcher, SubprocessManager are composable subsystems | Prevents god-module orchestrator (ARCH-001) |
| No shared Worker trait for now — three concrete async functions with shared retry/PII helpers | Simplicity wins over premature abstraction (SIMP-004 vs ARCH-004). Add trait when 4th channel emerges. |
| Don't re-implement DB writer or crash recovery — extend existing code | Already built in Phase 1 (SIMP-001) |
| Boolean `error_retryable` flag, not error-code routing table | One routing rule doesn't justify a dispatch table (SIMP-003) |
| Keep journal fallback but scope it tightly | It's already built; removing it is more work than keeping it. But cap journal size (10MB) and add chunked replay (PERF-006). |
| 30s shutdown timeout configurable via config | Avoid hardcoding unjustified number (SIMP-006). Default 30s, override in config.toml. |

### Security Enhancements

| Enhancement | Source |
|-------------|--------|
| Worker HOME set to isolated temp dir (not user HOME) | SEC-003 |
| Derive proof encryption subkey via HKDF (not raw master key) | SEC-005 |
| Validate no CRLF in email template interpolation values | SEC-007 |
| Worker crash circuit breaker prevents fork-bomb restart loops | SEC-004 |
| PID file via flock() — atomic, stale-safe | SEC-006 |
| Stdout line length capped at 1MB at byte-read level | SEC-002 |

### Edge Cases to Handle

| Edge Case | Source | Fix |
|-----------|--------|-----|
| Partial JSON on worker crash | EC-001 | Log fragment, reset task to pending |
| Stale PID file from crash | EC-002 | kill(pid, 0) check, remove if dead |
| Channel-full back-pressure | EC-003 | send().await (blocking), log WARN |
| NULL next_recheck_at rows invisible | EC-004 | IS NULL OR clause, or NOT NULL constraint |
| Email counter resets on restart | EC-005 | Persist in DB with date |
| Multiple SIGTERMs | EC-006 | AtomicBool, idempotent handler |
| Missing required_fields in profile | EC-007 | Validate before dispatch, `needs_user_data` status |
| Orphaned tasks at max retry | EC-008 | Reconcile on startup as permanently_failed |

### Spec-Flow Gaps Closed

| Gap | Source | Resolution |
|-----|--------|------------|
| Proof encryption failure | FLOW-001 | Task `proof_error`, never write unencrypted |
| Orphan worker on daemon crash | FLOW-002 | Kill orphan workers before task reset |
| Email retry exhaustion terminal state | FLOW-003 | Task `failed`, surface in status |
| Malformed 2xx API response | FLOW-004 | Validate response schema, treat bad 2xx as `playbook_error` |
| `run --once` with no due tasks | FLOW-005 | Print summary: "0 tasks due. Next: [timestamp]." |
| Startup-to-first-tick gap | FLOW-006 | Immediate tick at startup |
| CAPTCHA/stale auto-disable notification | FLOW-007 | WARN log + structured notification |
| Shutdown journal flush ordering | FLOW-008 | 5s flush timeout, direct DB fallback |

### Best Practices Applied

| Pattern | Source |
|---------|--------|
| `CancellationToken` for coordinated shutdown | tokio-util docs |
| `tokio::time::interval` with `MissedTickBehavior::Skip` | Prevents scheduler drift |
| `BufReader` + `select!` for subprocess stdout | tokio::process docs |
| `flock()` via `fs2` crate for PID file | Standard UNIX daemon pattern |
| Single `reqwest::Client` with connection pooling | reqwest docs |
| `lettre` TLS 1.2+ enforcement | SMTP security best practice |
| Bounded channels with explicit back-pressure policy | tokio mpsc docs |

### Simplicity Notes (Deferred as YAGNI)

- **Batched DB transactions:** Write volume too low at scheduler cadence. Add if profiling shows bottleneck.
- **Worker trait abstraction:** Three structurally different channels don't benefit from a shared trait yet.
- **Error-code routing table:** Boolean `error_retryable` is sufficient for now.
- **Elaborate subprocess lifecycle state machine:** Simple spawn-and-restart with circuit breaker is enough for one subprocess type.

### Status
- **Deepened:** 2026-02-24
- **Status:** DEEPENED_READY_FOR_REVIEW
- **Recommended next step:** Generate Phase 3 implementation plan (Standard tier) incorporating these deepened annotations, then implement.
