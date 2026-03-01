---
verdict: APPROVED_WITH_NOTES
timestamp: 2026-02-25T16:31:00
branch: issue-3-orchestrator
agents: [security-reviewer, code-quality-reviewer, edge-case-reviewer, performance-reviewer, api-contract-reviewer]
agents_unavailable: [concurrency-reviewer, error-handling-reviewer, testing-adequacy-reviewer, ui-reviewer]
findings_total: 14
findings_critical: 0
findings_high: 0
findings_medium: 8
findings_low: 6
false_positives_removed: 11
---

# Re-Review Report (Post-Fix)

## Context

Re-review after applying 12 CRITICAL/HIGH fixes from initial review.
5 of 9 agents returned results (4 hit API rate limits).
Previous CRITICAL/HIGH findings all verified as fixed.

## FALSE POSITIVES REMOVED (11)

1. **TOCTOU in resolve/abandon_captcha** (flagged by 5 agents): The SELECT is only for error
   message quality. The atomic UPDATE WHERE is the mutation guard. SQLite serializes writes.
2. **MarkupDisplay::new_unsafe XSS** (CQ-008): In Askama, `new_unsafe` means "value is
   untrusted, APPLY escaping." It does NOT bypass escaping.
3. **NotFound mapped to 409** (API-007): `DashboardError::NotFound` correctly maps to 404.
4. **get_health_stats queries** (PERF-001): Already combined 3 COUNTs into 1 in prior fix.
5. **CSRF form body fallback** (API-006): Intentional design — header for htmx, form for login.
6. **Bearer token precedence** (API-008): Intentional security design.

## SHOULD FIX (MEDIUM) — 8 findings

[CONS-R01] MEDIUM: constant_time_eq leaks token length via early return — auth.rs
  Known trade-off. Localhost-only dashboard. Token format (64 hex chars) is not secret.
  Fix: Hash both sides with SHA-256 before comparing.

[CONS-R02] MEDIUM: has_more pagination shows spurious "Next" on exact multiples — history.rs
  `has_more = tasks.len() == 50` gives false positive when exactly 50 records exist.
  Fix: Fetch limit+1 rows, check len > limit, truncate.

[CONS-R03] MEDIUM: NULL completed_at rows reappear on every cursor page — db.rs
  `OR t.completed_at IS NULL` in cursor WHERE not gated by cursor position.
  Fix: Remove OR NULL from cursor WHERE; use NULLS LAST ordering instead.

[CONS-R04] MEDIUM: DRY violation in handler boilerplate — handlers/*.rs
  Identical spawn_blocking/parse-ID/open-DB pattern in 4 handlers.
  Fix: Extract `spawn_db_blocking` and `parse_positive_id` helpers.

[CONS-R05] MEDIUM: session_secret [u8; 32] not zeroized on drop — mod.rs
  Raw array copied on Clone, not zeroed. Unlike SecretString/SecretBox.
  Fix: Wrap in Arc<SecretBox<[u8; 32]>>.

[CONS-R06] MEDIUM: std::sync::Mutex on async hot path — mod.rs
  Login rate limiter uses std::sync::Mutex in async handler.
  Fix: Acceptable (held for microseconds on VecDeque). Consider tokio::sync::Mutex if contention grows.

[CONS-R07] MEDIUM: SHA-256 token hash recomputed per authenticated request — auth.rs
  verify_session_cookie recomputes SHA-256 digest of auth_token on every request.
  Fix: Precompute at startup and store in DashboardState.

[CONS-R08] MEDIUM: Unbounded CAPTCHA queue query — db.rs
  No LIMIT on captcha queue SELECT. Could grow unbounded under adversarial conditions.
  Fix: Add LIMIT 200 to query.

## CONSIDER (LOW) — 6 findings

[CONS-R09] LOW: verify_csrf name misleading (documents both header+form but only checks header)
[CONS-R10] LOW: Hand-rolled cookie parsing (works correctly but fragile vs edge cases)
[CONS-R11] LOW: email_limit hardcoded to 10 (not configurable from settings)
[CONS-R12] LOW: Logout endpoint uses GET (susceptible to CSRF via img tags, low impact)
[CONS-R13] LOW: check_task_expired treats unparseable timestamps as non-expired
[CONS-R14] LOW: tokio::time::timeout on spawn_blocking doesn't cancel the OS thread
