# Issue #4 — Phase 4: Web Dashboard (Axum + htmx with Auth)

**Branch:** `issue-4-web-dashboard`
**Plan:** `docs/plans/2026-02-25-comprehensive-web-dashboard-plan.md`
**Approach:** Single-agent

## Acceptance Criteria

- [ ] Dashboard binds to 127.0.0.1:9847 only
- [ ] Login page accepts token, sets session cookie, redirects to dashboard
- [ ] All authenticated requests require valid session cookie or bearer token
- [ ] Host header validation rejects non-localhost (403)
- [ ] CSRF tokens on all POST endpoints
- [ ] Full security header set on all responses
- [ ] Status page with broker table (name, status, last attempt, next recheck, success rate)
- [ ] "Never Run" badge for brokers loaded but never executed
- [ ] History page with cursor-based pagination and proof viewing
- [ ] Proof path traversal prevented via canonicalization
- [ ] CAPTCHA queue with 24h TTL countdown, resolve/abandon actions
- [ ] "Mark Resolved" triggers immediate re-run via scheduler notification
- [ ] Tasks permanently failed after 5 abandon cycles
- [ ] Single-broker re-run trigger (atomic insert)
- [ ] Health page with per-broker success rates, SMTP stats
- [ ] All empty states have descriptive messages
- [ ] XSS prevented via Askama auto-escaping
- [ ] Auth token and master key use secrecy crate wrappers
- [ ] All POST buttons have loading indicators and double-click prevention
- [ ] All input params validated

## Implementation Steps

1. [x] Setup — branch, labels, living plan
2. [x] Dashboard module scaffold + dependencies
3. [x] Login page + base template + static assets
4. [x] Status page — GET /
5. [x] History page — GET /history + proof endpoint
6. [x] CAPTCHA queue — GET /captcha + resolve/abandon
7. [x] Broker re-run trigger — POST /broker/:id/rerun
8. [x] Health page — GET /health
9. [x] DB query functions + indexes
10. [x] Tests + validation (36 dashboard tests, all passing)

## Progress Log

- 2026-02-25: Branch created, issue labeled, living plan created
- 2026-02-25: Full implementation complete — all handlers, templates, auth, DB queries, orchestrator integration, 36 tests passing
