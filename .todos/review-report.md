---
verdict: BLOCK
timestamp: 2026-02-25T22:30:00
branch: issue-4-web-dashboard
agents: [security-reviewer, code-quality-reviewer, edge-case-reviewer, performance-reviewer, api-contract-reviewer, concurrency-reviewer, error-handling-reviewer, dependency-reviewer, testing-adequacy-reviewer, documentation-reviewer, ui-reviewer, supervisor, adversarial-validator]
findings_total: 50
findings_critical: 2
findings_high: 10
---

# Review Report — Phase 4 Web Dashboard (Round 1)

## Adversarial Validation Adjustments
- CONS-003 downgraded CRITICAL -> MEDIUM (deliberate architectural choice for single-user localhost SQLite)
- CONS-004 downgraded CRITICAL -> MEDIUM (11 test cases already exist, "untested" was overstatement)
- CONS-009 downgraded HIGH -> MEDIUM (busy_timeout(5s) IS set; finding description inaccurate)
- CONS-014 downgraded HIGH -> MEDIUM (constant_time_eq helper IS tested with 5 assertions)

## MUST FIX (CRITICAL/HIGH)

[CONS-001] CRITICAL: resolve_captcha_task TOCTOU race — src/db.rs
  Original: EC-001, CONC-001, ERR-001, CQ-008 (4 specialists)
  Fix: Replace SELECT+UPDATE with single atomic UPDATE WHERE, check rows_affected | Acceptance: concurrent resolve returns error on second call

[CONS-002] CRITICAL: abandon_captcha_task TOCTOU race on retry_count — src/db.rs
  Original: EC-002, CONC-002 (2 specialists)
  Fix: Atomic UPDATE SET retry_count=retry_count+1 with RETURNING, check rows_affected | Acceptance: no double-increment under concurrency

[CONS-005] HIGH: trigger_broker_rerun SELECT then INSERT TOCTOU — src/db.rs
  Original: CONC-003
  Fix: Single INSERT...SELECT WHERE enabled=1 | Acceptance: disabled broker produces zero reruns

[CONS-006] HIGH: broker_url href renders playbook_path — javascript: URI injection — templates/captcha_queue.html
  Original: SEC-007
  Fix: Validate http/https scheme before rendering as href; display path as plain text | Acceptance: javascript:alert(1) not clickable

[CONS-007] HIGH: Login CSRF broken — form field vs header mismatch — src/dashboard/handlers/mod.rs
  Original: SEC-002, UI-002 (2 specialists)
  Fix: Make verify_csrf also check form body for non-htmx submissions, or add hx-headers to login form | Acceptance: login POST without valid CSRF returns 403

[CONS-008] HIGH: Symlink check on canonicalized path is dead code — src/dashboard/handlers/proof.rs
  Original: ERR-005
  Fix: Check symlink on pre-canonicalized path, or rely on canonicalize+prefix check and remove dead code | Acceptance: symlink outside proof dir rejected

[CONS-010] HIGH: get_health_stats runs 6 sequential queries — src/db.rs
  Original: PERF-002
  Fix: Combine into CTEs in single query | Acceptance: one SQL statement per call

[CONS-011] HIGH: htmx.min.js served with no-store — src/dashboard/handlers/mod.rs
  Original: PERF-004
  Fix: Add Cache-Control immutable to static route, exclude from global no-store | Acceptance: browser caches htmx.js

[CONS-012] HIGH: Blocking fs calls outside spawn_blocking — src/dashboard/handlers/proof.rs
  Original: CONC-006
  Fix: Move canonicalize/symlink_metadata into spawn_blocking | Acceptance: no std::fs:: outside spawn_blocking

[CONS-013] HIGH: CSRF validation has no direct unit tests — src/dashboard/auth.rs
  Original: TEST-002
  Fix: Add tests for empty/mismatch/missing tokens | Acceptance: verify_csrf tested directly

[SEC-001/CQ-004] HIGH: CSRF cookie HttpOnly defeats double-submit — src/dashboard/auth.rs
  Fix: Remove HttpOnly from CSRF cookie | Acceptance: JS can read csrf cookie

[PERF-008/UI-006] HIGH: CSRF rotated on every 10s poll — src/dashboard/handlers/captcha.rs
  Fix: Don't rotate CSRF on polling partials | Acceptance: polling doesn't invalidate in-flight tokens

## SHOULD FIX (MEDIUM) — 25 findings

[CONS-003] MEDIUM: New DB connection per request (acceptable for localhost single-user)
[CONS-004] MEDIUM: Some host parsing edge cases missing from tests
[CONS-009] MEDIUM: DB connection establishment timeout (busy_timeout IS set)
[CONS-014] MEDIUM: Session comparison tested via helper but not full integration
[CONS-015] MEDIUM: Partial cursor params silently fall through
[CONS-016] MEDIUM: Constant-time comparison leaks token length
[CONS-017] MEDIUM: CSRF token not session-bound
[CONS-018] MEDIUM: has_more == 50 spurious next link
[CONS-019] MEDIUM: cursor_ts lacks format validation
[CONS-020] MEDIUM: CSRF failure not counted toward rate limit
[CONS-021] MEDIUM: Expired variant reused for max retries
[CONS-022] MEDIUM: broker_url field should be playbook_path
[CONS-023] MEDIUM: Hand-rolled cookie parsing
[CONS-024] MEDIUM: Unparseable timestamp treated as non-expired
[CONS-025] MEDIUM: SHA-256 of auth token recomputed per request
[CONS-026] MEDIUM: std::sync::Mutex in async context
[CONS-027] MEDIUM: get_daily_email_count failure silently returns 0
[CONS-028] MEDIUM: Poisoned mutex breaks rate limiter permanently
[CONS-029] MEDIUM: Login failure returns 401 with cookies
[CONS-030] MEDIUM: Cursor pagination includes NULL completed_at on every page
[CONS-031] MEDIUM: Scheduler notification errors swallowed
[CONS-032] MEDIUM: Content-Type as string tuple
[CONS-033] MEDIUM: Login POST handler untested
[CONS-034] MEDIUM: Proof path traversal untested
[CONS-035] MEDIUM: Token input type unknown (ensure type="password")

## CONSIDER (LOW) — 12 findings

[CONS-038-049] Various LOW items (type cast, CSRF dedup, proof 404, i18n, logout GET, docs, test gaps, aria-live, email_limit)

## TODO SPECIFICATIONS
- File: src/db.rs | resolve_captcha_task | Action: atomic UPDATE WHERE + rows_affected check | Reason: CONS-001
- File: src/db.rs | abandon_captcha_task | Action: atomic UPDATE SET retry_count=retry_count+1 RETURNING | Reason: CONS-002
- File: src/db.rs | trigger_broker_rerun | Action: INSERT...SELECT WHERE enabled=1 | Reason: CONS-005
- File: templates/captcha_queue.html | broker_url href | Action: validate http/https or render as text | Reason: CONS-006
- File: src/dashboard/handlers/mod.rs | login_submit | Action: fix CSRF to check form body or add hx-headers | Reason: CONS-007
- File: src/dashboard/handlers/proof.rs | symlink check | Action: remove dead code, rely on canonicalize+prefix | Reason: CONS-008
- File: src/db.rs | get_health_stats | Action: combine 6 queries into CTE | Reason: CONS-010
- File: src/dashboard/handlers/mod.rs | serve_htmx | Action: add Cache-Control immutable | Reason: CONS-011
- File: src/dashboard/handlers/proof.rs | fs calls | Action: move into spawn_blocking | Reason: CONS-012
- File: src/dashboard/auth.rs | tests | Action: add verify_csrf unit tests | Reason: CONS-013
- File: src/dashboard/auth.rs | csrf_cookie_header | Action: remove HttpOnly | Reason: SEC-001
- File: src/dashboard/handlers/captcha.rs | polling partials | Action: don't rotate CSRF | Reason: PERF-008
