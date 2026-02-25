---
type: comprehensive
title: "Phase 4: Web Dashboard — Axum + htmx with Auth"
date: 2026-02-25
status: in_progress
security_sensitive: true
priority: high
breaking_change: false
github_issue: 4
---

# Plan: Phase 4 — Web Dashboard (Axum + htmx with Auth)

## Document Info
- **Author:** AI + Human
- **Date:** 2026-02-25
- **Status:** deepened_ready_for_review
- **Source Plan:** `docs/plans/1-2026-02-23-comprehensive-dataward-architecture-plan.md` (Phase 4, steps 23-28)
- **Issue:** #4
- **Review:** 8-agent review completed 2026-02-25 (Architecture, Simplicity, Security, Performance, Edge Case, Spec-Flow + 2 research agents)

## Problem

The dataward daemon runs headless — users have no way to monitor broker status, view opt-out history, inspect encrypted proofs, or resolve CAPTCHAs that block automated opt-outs. Without a dashboard, users must query the SQLCipher DB directly or rely on CLI output, which makes CAPTCHA resolution (a time-sensitive action with 24h TTL) impractical.

## Goals

- Provide a localhost-only web dashboard for monitoring and limited interaction
- Support manual CAPTCHA resolution workflow (solve/mark-resolved/abandon)
- Display broker status, opt-out history with encrypted proof viewing, and health indicators
- Secure all endpoints with bearer token auth, Host header validation, and CSRF protection

## Non-Goals

- No config editing via dashboard (read-only + CAPTCHA actions + re-run trigger)
- No user management / multi-user auth (single-user, localhost-only)
- No TLS (localhost HTTP is sufficient, avoids cert management)
- No WebSocket/SSE for live updates in MVP (htmx polling is sufficient)
- No mobile-responsive design (desktop browser on localhost)

## Technical Approach

### Architecture

Dashboard runs as a Tokio task within the existing daemon process (not a separate binary). **[DEEPENED]** Dashboard opens its own dedicated read-only DB connection (not shared with orchestrator). WAL mode enables true concurrent reads — sharing a single `Arc<Mutex<Connection>>` would negate this benefit and serialize all dashboard reads behind a lock. Writes go through the existing `DbWriteMessage` channel (clone the sender). The master encryption key (derived once at startup) is passed to dashboard state for proof decryption.

```
┌──────────────────────────────────────────────────────┐
│                    Daemon Process                     │
│                                                       │
│  ┌──────────────┐    ┌───────────────────┐            │
│  │ Orchestrator  │    │    Dashboard      │            │
│  │  (scheduler,  │    │  (Axum server,    │            │
│  │   dispatch)   │    │   templates)      │            │
│  └──────┬───────┘    └───┬───────────┬───┘            │
│         │                │           │                 │
│         │ reads          │ reads     │ writes          │
│         ▼                ▼           ▼                 │
│  ┌──────────────┐ ┌───────────┐ ┌─────────────┐      │
│  │ Orch Read    │ │ Dashboard │ │ DB Writer   │      │
│  │ Connection   │ │ Read Conn │ │ (channel)   │      │
│  └──────────────┘ └───────────┘ └─────────────┘      │
│         │                │           │                 │
│         └────────────────┴───────────┘                 │
│                          ▼                             │
│                  ┌──────────────┐                      │
│                  │   SQLCipher  │                      │
│                  └──────────────┘                      │
└──────────────────────────────────────────────────────┘
```

### Key Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Template engine | **Askama** | Compile-time type safety, auto-escaping by default for HTML, `askama_axum` integration. Research confirms best htmx compatibility. |
| CSRF strategy | **Double-submit cookie** via `axum-csrf-sync-pattern` | Purpose-built for Axum. htmx integration via `<body hx-headers='{"X-CSRF-TOKEN": "..."}'>` for automatic inclusion on all mutations. **[DEEPENED]** Audit crate source before integration — it's small enough to review fully. Pin exact version. Fallback: manual double-submit (trivial in Axum). |
| Auth mechanism | **[DEEPENED] Session cookie after initial token exchange** | Browsers cannot send `Authorization: Bearer` headers on page navigation. Auth flow: user visits `GET /login` → enters token in form → `POST /login` validates token → sets session cookie (`HttpOnly; SameSite=Strict; Path=/`) → redirects to `/`. All subsequent requests authenticated via cookie. Token still used for programmatic access via `Authorization` header. |
| Host validation | **Custom middleware** | Allowlist: `localhost`, `127.0.0.1`, `[::1]` (with/without port). **[DEEPENED]** Parse Host header precisely: split on `:` for port (handle `[::1]:port` bracket notation), normalize to lowercase, reject empty/absent/malformed. Test cases: `localhost:8080`, `LOCALHOST`, `127.0.0.1:443`, `[::1]:8080`, `localhost.evil.com`, `localhost\x00.evil.com`, empty, missing. |
| Content Security Policy | **[DEEPENED] Pragmatic CSP** | htmx requires `unsafe-eval` for some features (e.g., `hx-on` attributes). Minimal viable CSP: `default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'`. XSS defense relies primarily on Askama auto-escaping + input validation, with CSP as a secondary layer. |
| htmx delivery | **Vendored static file** | Embed htmx.min.js in binary via `include_str!` or serve from templates dir. No CDN dependency. |
| Token comparison | **[DEEPENED] `subtle` crate** | `ConstantTimeEq` trait for constant-time token comparison. Compile in release mode (debug builds have secret-dependent branches). |
| Secret storage | **[DEEPENED] `secrecy` crate** | `SecretString` for auth token, `SecretBox<[u8; 32]>` for master key. Prevents accidental logging via `Debug`/`Display`. Zeroized on drop. |

### Dashboard State

**[DEEPENED]** Corrected based on codebase research findings. `rusqlite::Connection` is not `Send + Sync` — cannot be wrapped in `Arc<Mutex<>>` safely across async boundaries. Dashboard opens its own connection at startup.

```rust
#[derive(Clone)]
struct DashboardState {
    db_path: PathBuf,                       // [DEEPENED] Path to SQLCipher DB
    db_hex_key: SecretString,               // [DEEPENED] Hex key for opening connections
    write_tx: mpsc::Sender<DbWriteMessage>, // Existing write channel (cloned)
    scheduler_notify: mpsc::Sender<()>,     // [DEEPENED] Wake scheduler for immediate re-run
    master_key: SecretBox<[u8; 32]>,        // [DEEPENED] secrecy wrapper, zeroized on drop
    auth_token: SecretString,               // [DEEPENED] secrecy wrapper, never logged
    session_secret: [u8; 32],               // [DEEPENED] For signing session cookies
    data_dir: PathBuf,                      // For locating .png.enc proof files
}
```

**[DEEPENED] DB access pattern in handlers:** Each handler opens a connection in `spawn_blocking`, performs the query, and drops the connection. This is cheap for SQLite (no TCP handshake) and avoids lifetime/Send issues entirely. For optimization, use a thread-local connection pool per blocking thread.

**[DEEPENED] Scheduler notification channel:** Orchestrator loop adds `notify_rx.recv()` to `tokio::select!` alongside `tick_interval.tick()` and `cancel.cancelled()`. When dashboard sends `()` on resolve, scheduler runs an immediate tick. Channel capacity = 1 (coalesce multiple notifications).

### Security Layers (Defense in Depth)

1. **Bind to 127.0.0.1 only** — OS-level, no external network access
2. **[DEEPENED] Request tracing** — Outermost middleware, logs all requests including rejected ones (for attack detection)
3. **Host header validation** — Rejects DNS rebinding (middleware, reject with 403 + human-readable message)
4. **[DEEPENED] Session/Bearer auth** — Session cookie for browser access, Bearer token for programmatic. `subtle::ConstantTimeEq` for comparison
5. **CSRF tokens** — Double-submit cookie on all POST endpoints. **[DEEPENED]** Token delivered via `<meta>` tag + global `hx-headers` config. Cookie flags: `SameSite=Strict; HttpOnly; Path=/`
6. **[DEEPENED] Security headers** — CSP + `X-Frame-Options: DENY` + `X-Content-Type-Options: nosniff` + `Referrer-Policy: no-referrer` + `Cache-Control: no-store` on authenticated pages + `Permissions-Policy: camera=(), microphone=(), geolocation=()`
7. **Askama auto-escaping** — All template output HTML-escaped by default
8. **No inline scripts** — htmx attribute-driven, no `<script>` blocks needed
9. **Proof decryption in-memory only** — Never written to disk. **[DEEPENED]** Validate file size < 10MB before decrypt. Validate canonicalized path within `data_dir`. Zeroize partial buffers on decryption failure. Return generic 404 (never reveal "decryption failed" vs "file not found"). Log decryption failures as security events.

## Implementation Steps

### Step 1: Dashboard module scaffold + dependencies

**New dependencies in Cargo.toml:**
- `askama = "0.12"` with `with-axum` feature
- `askama_axum = "0.4"`
- `tower-http = "0.6"` (for `SetResponseHeaderLayer`, static serving)
- `axum-csrf-sync-pattern` (CSRF double-submit) — **[DEEPENED]** audit source first, pin exact version
- `subtle` — **[DEEPENED]** for constant-time token comparison
- `secrecy` — **[DEEPENED]** for `SecretString` / `SecretBox` wrappers

**[DEEPENED] Simplified file structure** (per simplicity review — inline small modules into mod.rs):
- `src/dashboard/mod.rs` — Router, middleware stack, `DashboardState`, CSRF config, `DashboardError` (inlined from separate state/csrf/error files)
- `src/dashboard/auth.rs` — Bearer token + session cookie auth, Host header validation, login page
- `src/dashboard/handlers/status.rs` — Status page handler
- `src/dashboard/handlers/history.rs` — History page handler
- `src/dashboard/handlers/proof.rs` — Proof decryption endpoint
- `src/dashboard/handlers/captcha.rs` — CAPTCHA queue + resolve/abandon
- `src/dashboard/handlers/trigger.rs` — Broker re-run trigger
- `src/dashboard/handlers/health.rs` — Health indicators

**[DEEPENED] Middleware stack (corrected order):**
1. **Request tracing** via `tracing` (outermost — logs all requests including rejected ones)
2. Host header validation (reject with 403 + human-readable page)
3. Session/Bearer auth (reject with 401, redirect to `/login` for browser)
4. CSRF validation (on POST routes only)
5. Security headers (CSP, X-Frame-Options, etc. on all responses)

**Integration point:** Modify `src/orchestrator.rs`:
- Open a dedicated dashboard read connection: `db::open_db_with_key(&db_path, &hex_key)?`
- Clone `db_tx` sender for dashboard writes
- **[DEEPENED]** Create `mpsc::channel::<()>(1)` notification channel; add `notify_rx.recv()` to scheduler `select!` loop
- Spawn dashboard Tokio task with `CancellationToken`
- **[DEEPENED]** Wrap dashboard in `catch_unwind`-safe JoinHandle — log and restart on panic rather than crashing orchestrator
- **[DEEPENED]** Dashboard shutdown with 5s timeout before DB writer shutdown

### Step 2: Login page + base template + static assets

**[DEEPENED] Login flow (FLOW-004 fix):**
- `GET /login` — Public endpoint (no auth required). Renders login form with token input field
- `POST /login` — Validates token (constant-time comparison), sets session cookie (`HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`), redirects to `/`
- `GET /logout` — Clears session cookie, redirects to `/login`
- Session cookie contains HMAC-signed token hash (not the raw token). Session expires after 30 minutes of inactivity
- **[DEEPENED]** Failed login attempts logged with timestamp. Rate limit: 5 attempts per minute, then 429

**Files:**
- `src/dashboard/templates/base.html` — Askama base template with `{% block content %}`, htmx script tag, nav bar, CSRF token in `<meta>` + `<body hx-headers>`, minimal CSS
- `src/dashboard/templates/login.html` — Token input form
- `src/dashboard/templates/` — All page templates extend `base.html`
- htmx.min.js vendored (embedded via `include_str!` or served from templates dir)

**Design approach:** Minimal, functional CSS. No framework — just enough for tables, cards, and status badges. Dark/light follows `prefers-color-scheme`.

### Step 3: Status page — `GET /`

**[DEEPENED] Query:** Use window function instead of correlated subquery for latest task per broker:
```sql
WITH latest_tasks AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY broker_id ORDER BY created_at DESC) AS rn
    FROM opt_out_tasks
)
SELECT b.*, lt.*
FROM brokers b
LEFT JOIN latest_tasks lt ON b.id = lt.broker_id AND lt.rn = 1
ORDER BY b.name
```
Requires SQLite 3.25+ (window function support). **[DEEPENED]** Add index `idx_tasks_broker_created` on `(broker_id, created_at DESC)` for optimal performance.

**Template renders:**
- Broker table: name, status (color-coded badge **[DEEPENED]** with text label — "Success"/"Failed"/"Pending"/"Blocked"/"Never Run"), last attempt timestamp, next recheck date, success rate (%), trust tier
- **[DEEPENED]** "Never Run" status badge for brokers loaded but never executed (distinguishes init-only state from pending)
- Re-run button per broker (disabled if task already pending/running, **[DEEPENED]** with `hx-indicator` spinner)
- Empty state: "No brokers loaded — run `dataward init`"
- htmx: `hx-trigger="every 30s"` on table body for auto-refresh. **[DEEPENED]** Component-scoped polling (only table body, not whole page) to avoid disrupting user interaction

**File:** `src/dashboard/handlers/status.rs`

### Step 4: Opt-out history page — `GET /history`

**[DEEPENED] Query:** Use cursor-based pagination instead of LIMIT/OFFSET:
```sql
SELECT t.*, b.name as broker_name
FROM opt_out_tasks t
JOIN brokers b ON t.broker_id = b.id
WHERE t.completed_at < ?cursor_timestamp OR (t.completed_at = ?cursor_timestamp AND t.id < ?cursor_id)
ORDER BY t.completed_at DESC, t.id DESC
LIMIT 50
```
**[DEEPENED]** Add index `idx_tasks_completed_at` on `(completed_at DESC, id DESC)`. Cursor = `(completed_at, id)` tuple passed as query param. First page: no cursor.

**Template renders:**
- Timeline of opt-out attempts with status, broker name, channel, duration, timestamp
- "View Proof" button on successful tasks that have `proof_path`
- **[DEEPENED]** Loading indicator on pagination controls (`hx-indicator`)
- Empty state: "No opt-out attempts yet. Run `dataward run` to start."

**Proof viewing endpoint:** `GET /history/proof/:task_id`
- **[DEEPENED]** Validate `task_id`: parse as `i64`, reject `<= 0` with 400
- Loads `proof_path` from task record
- **[DEEPENED] Path traversal defense:** Canonicalize both `data_dir` and `data_dir.join(proof_path)` via `std::fs::canonicalize()`. Assert canonical proof path starts with canonical data dir. Reject paths containing `..` segments as defense-in-depth. Reject symlinks. Validate extension `.png.enc` (case-insensitive)
- **[DEEPENED]** Validate file size < 10MB before reading. Return 413 if exceeded
- Calls `crypto::decrypt_file_to_memory(master_key, proof_path)` — **[DEEPENED]** wrap in timeout (5s). On failure: zeroize buffers, log as security event, return generic 404
- Returns `Content-Type: image/png` + `Cache-Control: no-store` with decrypted bytes
- Never touches disk
- **[DEEPENED] Error states:** File missing → 404 "Proof unavailable". Decryption failure → 404 "Proof unavailable" (generic, no distinction). Task not found → 404. Proof displayed in `<img>` tag; on error, inline message replaces image area

**Files:** `src/dashboard/handlers/history.rs`, `src/dashboard/handlers/proof.rs`

### Step 5: CAPTCHA queue page — `GET /captcha`

**[DEEPENED] Query:** Add composite index `idx_tasks_status_created` on `(status, created_at ASC)` for efficient polling query:
```sql
SELECT t.id, t.broker_id, b.name, b.url, t.created_at, t.proof_path, t.retry_count
FROM opt_out_tasks t
JOIN brokers b ON t.broker_id = b.id
WHERE t.status = 'captcha_blocked'
ORDER BY t.created_at ASC
```

**Template renders:**
- List of blocked tasks: broker name, screenshot thumbnail (decrypted), time remaining (calculated from `created_at + 24h` — **[DEEPENED]** all timestamps UTC, use `chrono::DateTime<Utc>` not `NaiveDateTime`), **[DEEPENED]** retry count badge
- Per-task actions:
  - **"Solve"** — `<a>` tag with `target="_blank"` to broker URL (opens in system browser). **[DEEPENED]** Inline note: "Click 'Mark Resolved' when done" shown after clicking Solve
  - **"Mark Resolved"** — `hx-post="/captcha/:id/resolve"` with `hx-confirm="Mark this CAPTCHA as resolved?"` — CSRF-protected. **[DEEPENED]** `hx-indicator` spinner, `hx-disabled-elt="this"` to prevent double-click
  - **"Abandon"** — `hx-post="/captcha/:id/abandon"` with `hx-confirm` — returns task to pending. **[DEEPENED]** `hx-indicator` + `hx-disabled-elt="this"`
- Expired tasks (>24h, strictly greater-than): shown with "Expired" badge, abandon-only. **[DEEPENED]** Clamp: if `created_at > now()` (clock skew), treat as `created_at = now()`
- **[DEEPENED]** Max retry limit: after 5 abandons, task permanently marked failed with "Max retries exceeded" — shown in history, not CAPTCHA queue
- Empty state: "No CAPTCHAs pending. Brokers requiring manual intervention will appear here."
- htmx: `hx-trigger="every 10s"` for TTL countdown refresh. **[DEEPENED]** Component-scoped polling (table only). Pause polling when POST in-flight (cancel on `htmx:beforeRequest`)

**Mutation endpoints:**
- `POST /captcha/:id/resolve`
  - **[DEEPENED]** Validate `id` as `i64 > 0`. Verify task status is `captcha_blocked` (not already resolved/expired)
  - Sets task status to `pending` with `retry_count = 0` via single atomic `UPDATE` statement
  - **[DEEPENED]** Sends `()` on `scheduler_notify` channel to trigger immediate re-run
  - **[DEEPENED]** Response states: success → row removed from table, flash "Task re-queued". Conflict (already resolved) → "Already resolved" badge. Error → row remains, inline error, retry available. Expired → 409 "Task has expired, you may only abandon it"
- `POST /captcha/:id/abandon`
  - **[DEEPENED]** Single atomic UPDATE: `SET status = 'pending', retry_count = retry_count + 1 WHERE id = ? AND status = 'captcha_blocked' AND retry_count < 5`
  - If retry_count >= 5: `SET status = 'failure', error_code = 'max_retries_exceeded'`
  - **[DEEPENED]** Response states: success → row removed, flash "Task returned to queue". Max retries → "Task permanently failed" message

**File:** `src/dashboard/handlers/captcha.rs`

### Step 6: Single-broker re-run trigger

**Endpoint:** `POST /broker/:id/rerun` (CSRF-protected)

**Logic:**
1. **[DEEPENED]** Validate `broker_id`: non-empty, max 64 chars, allowlist charset `[a-z0-9_-]`. Reject before DB lookup
2. Validate broker exists and is enabled
3. **[DEEPENED]** Atomic insert: `INSERT INTO opt_out_tasks (broker_id, ...) SELECT ... WHERE NOT EXISTS (SELECT 1 FROM opt_out_tasks WHERE broker_id = ? AND status IN ('pending', 'running'))` — prevents TOCTOU race from concurrent requests
4. **[DEEPENED]** Send `()` on `scheduler_notify` for immediate pickup
5. **[DEEPENED]** Response states: success → htmx partial "Re-run queued for {broker_name}", button shows "Queued..." temporarily. Duplicate → 409 "Task already queued". Broker disabled → 409 "Broker is disabled". Broker not found → 404
6. **[DEEPENED]** Re-run button disabled via htmx when broker status is "running" or "pending" (template conditional)

**File:** `src/dashboard/handlers/trigger.rs`

### Step 7: Health indicators page — `GET /health`

**Queries:** Aggregate stats from `opt_out_tasks`, `brokers`, `run_log`

**Template renders:**
- Per-broker success rates (color-coded: green >80%, yellow 50-80%, red <50% — **[DEEPENED]** paired with text labels "Healthy"/"Degraded"/"Critical" for accessibility)
- SMTP delivery stats: emails sent today / daily limit, recent failures
- Last run summary from `run_log`
- Overall stats: total brokers, active, disabled, pending tasks
- **[DEEPENED]** Empty state: "No run data yet. Run `dataward run` to generate health statistics." Distinguish "never run" from "ran with no results"
- **[DEEPENED]** Descoped: stale playbook warnings (requires instrumentation not yet in orchestrator — file follow-on issue if needed)

**File:** `src/dashboard/handlers/health.rs`

### Step 8: DB query functions for dashboard

Add read-only query functions to `src/db.rs`:
- `get_broker_statuses(conn) -> Vec<BrokerStatusRow>` — **[DEEPENED]** uses window function CTE for latest task per broker
- `get_task_history(conn, cursor, limit) -> Vec<TaskHistoryRow>` — **[DEEPENED]** cursor-based pagination
- `get_captcha_queue(conn) -> Vec<CaptchaQueueRow>` — blocked tasks
- `get_health_stats(conn) -> HealthStats` — aggregate health data
- `get_task_proof_path(conn, task_id) -> Option<String>` — proof path for a task

**[DEEPENED] New indexes (add in schema migration):**
- `idx_tasks_broker_created` on `(broker_id, created_at DESC)` — for status page window function
- `idx_tasks_status_created` on `(status, created_at ASC)` — for CAPTCHA queue polling
- `idx_tasks_completed_id` on `(completed_at DESC, id DESC)` — for cursor-based history pagination

All wrapped in `spawn_blocking()` at the handler level. **[DEEPENED]** Each handler opens its own connection via `DashboardState.db_path` + `db_hex_key` inside `spawn_blocking` (avoids Send/Sync issues with rusqlite::Connection).

### Step 9: Tests

**Unit tests:**
- Auth middleware: valid token, invalid token, missing token, empty token, **[DEEPENED]** session cookie valid/invalid/expired, login rate limiting
- Host validation: `localhost`, `127.0.0.1`, `[::1]`, `evil.com`, `localhost.evil.com`, **[DEEPENED]** `LOCALHOST` (case), `localhost:8080` (port), `[::1]:8080`, `localhost\x00.evil.com` (null byte), empty, missing, whitespace-only
- CSRF: valid token, missing token, expired token, **[DEEPENED]** empty token value, cross-session token
- DB queries: each query function with test data. **[DEEPENED]** Empty tables, single row, boundary pagination
- Proof serving: successful decryption, missing file, corrupt file, **[DEEPENED]** file > 10MB rejected, path traversal (`../../etc/passwd.png.enc`, symlink), file deleted between check and read

**Integration tests:**
- Full request cycle: authenticated GET to each page
- **[DEEPENED]** Login flow: GET /login → POST /login with valid token → session cookie set → GET / succeeds
- CAPTCHA resolve flow: create captcha_blocked task → POST resolve → verify task status change → **[DEEPENED]** verify scheduler notified
- Re-run trigger: POST rerun → verify new pending task created. **[DEEPENED]** Double POST → second returns 409
- Proof viewing: encrypt test image → request via endpoint → verify decrypted bytes match

**Security tests:**
- Unauthenticated requests return 401 (or redirect to /login)
- Non-localhost Host header returns 403
- CSRF-protected endpoints reject GET and tokenless POST
- XSS payloads in broker names are escaped in rendered HTML
- Proof endpoint doesn't serve non-existent or non-proof files (path traversal check)
- **[DEEPENED]** Constant-time comparison prevents timing attacks
- **[DEEPENED]** Auth token never appears in logs or error responses
- **[DEEPENED]** Login brute-force returns 429 after 5 attempts

**[DEEPENED] Input validation tests:**
- `task_id`: 0, -1, MAX_I64, non-numeric → proper 400 responses
- `broker_id`: empty, oversized (>64 chars), unicode, null bytes, URL-encoded `/` → proper 400 responses
- Pagination cursor: malformed, future dates, empty → defaults applied

## Affected Files

**New files:**
- `src/dashboard/mod.rs` — Router, middleware stack, `DashboardState`, CSRF config, `DashboardError`
- `src/dashboard/auth.rs` — Session cookie + Bearer token auth, Host header validation, login/logout handlers
- `src/dashboard/handlers/status.rs` — Status page handler
- `src/dashboard/handlers/history.rs` — History page handler
- `src/dashboard/handlers/proof.rs` — Proof decryption endpoint
- `src/dashboard/handlers/captcha.rs` — CAPTCHA queue + resolve/abandon
- `src/dashboard/handlers/trigger.rs` — Broker re-run trigger
- `src/dashboard/handlers/health.rs` — Health indicators
- `src/dashboard/templates/base.html` — Base layout with CSRF meta, nav, htmx
- `src/dashboard/templates/login.html` — Token login form
- `src/dashboard/templates/status.html` — Broker status table
- `src/dashboard/templates/history.html` — History timeline
- `src/dashboard/templates/captcha.html` — CAPTCHA queue
- `src/dashboard/templates/health.html` — Health page

**Modified files:**
- `Cargo.toml` — Add askama, askama_axum, tower-http, axum-csrf-sync-pattern, subtle, secrecy
- `src/orchestrator.rs` — Spawn dashboard task, scheduler notification channel, catch_unwind wrapper
- `src/db.rs` — Add dashboard read-only query functions, new indexes
- `src/main.rs` — Add `mod dashboard`

## Acceptance Criteria

- [ ] Dashboard binds to `127.0.0.1:9847` only
- [ ] **[DEEPENED]** Login page accepts token, sets session cookie, redirects to dashboard
- [ ] All authenticated requests require valid session cookie or bearer token (401 without)
- [ ] Host header validation rejects non-localhost (403 with human-readable message)
- [ ] CSRF tokens on all POST endpoints
- [ ] **[DEEPENED]** Full security header set on all responses (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cache-Control, Permissions-Policy)
- [ ] Status page shows broker table with: name, status (with text labels), last attempt, next recheck, success rate, trust tier
- [ ] **[DEEPENED]** Status page shows "Never Run" badge for brokers loaded but never executed
- [ ] Status page shows empty state when no brokers loaded
- [ ] History page shows opt-out timeline, cursor-paginated
- [ ] History page decrypts and serves proof screenshots in-memory (never disk)
- [ ] **[DEEPENED]** Proof path traversal prevented via canonicalization
- [ ] CAPTCHA queue shows blocked tasks with 24h TTL countdown
- [ ] "Mark Resolved" triggers immediate re-run via scheduler notification (CSRF-protected)
- [ ] "Abandon" returns task to pending (CSRF-protected)
- [ ] **[DEEPENED]** Tasks permanently failed after 5 abandon cycles
- [ ] Expired CAPTCHA tasks shown with "Expired" badge
- [ ] Single-broker re-run trigger works (CSRF-protected, atomic insert)
- [ ] **[DEEPENED]** Health page shows per-broker success rates with accessible labels, SMTP stats
- [ ] **[DEEPENED]** Health page shows empty state before first run
- [ ] All empty states have descriptive messages
- [ ] XSS prevented via Askama auto-escaping
- [ ] No config editing via dashboard
- [ ] **[DEEPENED]** Auth token and master key use `secrecy` crate wrappers (zeroized on drop, never logged)
- [ ] **[DEEPENED]** All POST buttons have loading indicators and double-click prevention
- [ ] **[DEEPENED]** All input params validated (task_id bounds, broker_id charset, pagination cursor)

## Test Strategy

- **Unit tests** for all middleware (auth, host, CSRF), DB query functions, input validation, and error handling
- **Integration tests** using `axum::test` helpers — full HTTP request/response cycles including login flow
- **Security tests** for auth bypass, CSRF bypass, XSS, path traversal, timing attacks, brute-force rate limiting
- **[DEEPENED]** Edge case tests for empty collections, boundary values, concurrent mutations, expired TTL handling
- Existing orchestrator/DB tests must continue passing (no regressions)

## Security Review

| Area | Risk | Mitigation |
|------|------|------------|
| DNS rebinding | External sites could make requests to localhost | Host header allowlist middleware with precise parsing (strip port, lowercase, reject malformed) |
| Auth token leakage | Token in logs = full access | `SecretString` wrapper prevents `Debug`/`Display` leaks. Explicit token redaction in logging |
| CSRF on mutations | Cross-origin POST to resolve/rerun | Double-submit cookie pattern. Token via `<meta>` tag + `hx-headers`. Cookie: `SameSite=Strict; HttpOnly` |
| XSS via broker names | Malicious playbook could inject HTML | Askama auto-escaping (compile-time enforced) + CSP as secondary layer |
| Path traversal on proofs | `../../../etc/passwd` in proof_path | **[DEEPENED]** `std::fs::canonicalize()` both paths, assert prefix match. Reject `..` segments and symlinks |
| Proof on disk | Decrypted proof written to temp file | In-memory only. **[DEEPENED]** Zeroize partial buffers on failure. Size limit 10MB. Timeout 5s |
| Timing attack on auth | Token comparison leaks length info | **[DEEPENED]** `subtle::ConstantTimeEq` in release mode |
| **[DEEPENED]** Key in memory | Master key extractable from process dump | `secrecy::SecretBox` with zeroize on drop. Document: disable core dumps (`ulimit -c 0`) |
| **[DEEPENED]** TOCTOU on re-run | Concurrent requests create duplicate tasks | Atomic `INSERT ... WHERE NOT EXISTS` at DB level |
| **[DEEPENED]** Session fixation | Attacker pre-sets session cookie | Generate new session on each login. `SameSite=Strict` prevents cross-origin cookie setting |

## Spec-Flow Analysis

### [DEEPENED] Flow 0: Authentication
1. User navigates to `http://127.0.0.1:9847/` → no session cookie → **Redirect:** to `/login`
2. User enters token → `POST /login` → **Happy:** session cookie set, redirect to `/` → **Error:** invalid token → "Invalid token" message, retry available → **Rate limit:** 5 failed attempts → 429 "Too many attempts, try again later"

### Flow 1: View Status Page
1. User navigates to `/` (authenticated) → **Happy:** broker table renders → **Empty:** "No brokers loaded" message → **[DEEPENED] First-run:** brokers loaded but never run → "Never Run" badges → **Error:** 500 page with generic message (no DB details leaked) → **[DEEPENED] Loading:** table auto-refreshes every 30s (component-scoped, no full-page replacement)

### Flow 2: View Proof Screenshot
1. User clicks "View Proof" on history item → **Happy:** decrypted image renders inline → **Empty:** no proof_path on task (button hidden) → **Error:** file missing/corrupt → **[DEEPENED]** inline "Proof unavailable" message (not a full error page) → **[DEEPENED]** file deleted from disk but DB has path → graceful 404 inline

### Flow 3: CAPTCHA Resolution
1. User sees blocked task → clicks "Solve" → opens broker URL in new tab → **[DEEPENED]** inline note appears "Click 'Mark Resolved' when done" → completes CAPTCHA → clicks "Mark Resolved" (**[DEEPENED]** button shows spinner, disabled during POST) → **Happy:** row removed, flash "Task re-queued", scheduler notified for immediate run
2. **Abandon path:** User clicks "Abandon" → task returns to pending with incremented retry_count. **[DEEPENED]** After 5 abandons: task permanently failed
3. **Expired path:** Task >24h old → shown with "Expired" badge → only "Abandon" available. **[DEEPENED]** POST resolve on expired → 409 "Task has expired"
4. **Edge:** User marks resolved but CAPTCHA wasn't actually solved → worker will fail again → returns to captcha_blocked (natural retry)
5. **Edge:** Two browser tabs → user clicks resolve on same task twice → second POST returns conflict → **[DEEPENED]** htmx partial shows "Already resolved" badge
6. **[DEEPENED] Error:** POST fails (500/DB error) → row remains in table, inline error message, retry available

### Flow 4: Single Broker Re-run
1. User clicks "Re-run" on broker → **[DEEPENED]** button shows spinner → **Happy:** new pending task created atomically, confirmation shown → **Duplicate:** task already pending/running → 409 "Task already queued" → **Error:** broker disabled → 409 "Broker is disabled"
2. **[DEEPENED]** Re-run button disabled when broker status is "running" or "pending" (template conditional)

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `axum-csrf-sync-pattern` crate immature/unmaintained | Low | Medium | Audit source before use. Fall back to manual double-submit implementation (simple, well-understood pattern) |
| Askama template compile errors hard to debug | Medium | Low | Start with simple templates, iterate. Askama errors are compile-time (caught early) |
| Proof decryption OOM on very large screenshots | Low | Medium | **[DEEPENED]** 10MB file size limit before decrypt. Timeout on decrypt operation |
| **[DEEPENED]** Dashboard panic crashes orchestrator | Low | High | Wrap in catch_unwind-safe JoinHandle. Log and restart dashboard on panic |
| **[DEEPENED]** htmx CSP incompatibility | Medium | Low | Pragmatic CSP with `unsafe-eval`. Primary XSS defense is Askama auto-escaping |

## Rollback Plan

Dashboard is an additive feature behind `config.dashboard.enabled` flag (already in `DashboardConfig`). If issues arise:
1. Set `dashboard.enabled = false` in config.toml
2. Daemon continues without dashboard
3. No data migration needed — dashboard is read-only + CAPTCHA actions

---

## Enhancement Summary

**Review agents:** 6 (Architecture, Simplicity, Security, Performance, Edge Case, Spec-Flow)
**Research agents:** 2 (Codebase integration, Best practices)
**Total findings:** 57 raw findings across all agents

**Priority fixes applied (HIGH/CRITICAL):**
1. **DB connection:** Replaced `Arc<Mutex<Connection>>` with dedicated dashboard connection (3 agents flagged)
2. **Browser auth:** Added login page + session cookie flow (Bearer-only incompatible with browsers)
3. **CSP corrected:** htmx requires `unsafe-eval` — adjusted to pragmatic CSP
4. **Scheduler notification:** Added `mpsc::channel` for immediate CAPTCHA re-run trigger
5. **Secret wrappers:** `secrecy` crate for auth token and master key (2 agents flagged)
6. **Constant-time comparison:** `subtle` crate specified
7. **Path traversal:** Canonicalization-based defense specified precisely
8. **TOCTOU race:** Atomic INSERT for broker re-run (edge case agent flagged)
9. **Middleware reordering:** Tracing moved to outermost position
10. **Security headers:** Full set beyond CSP (X-Frame-Options, X-Content-Type-Options, etc.)

**Simplifications applied:**
1. Inlined `state.rs`, `csrf.rs`, `error.rs` into `mod.rs` (3 files eliminated)
2. Descoped stale playbook warnings from health page (requires orchestrator instrumentation)

**Performance optimizations applied:**
1. Window function CTE for status page query (avoids N+1 subquery)
2. Cursor-based pagination for history page (O(1) vs O(n) offset)
3. Composite index for CAPTCHA queue polling
4. New indexes for dashboard queries

**Spec-flow gaps filled:**
1. Login/auth flow for browsers
2. POST error/loading states for all mutation endpoints
3. Health page empty state
4. "Never Run" broker status after init
5. Retry count limit on CAPTCHA abandon
6. Proof endpoint error states
7. Rate limiting on login
8. Auto-refresh scoped to components (not full page)
