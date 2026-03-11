---
verdict: FIX_BEFORE_COMMIT
timestamp: 2026-03-01T19:45:00
branch: issue-5-distribution-playbooks
agents: [security-reviewer, code-quality-reviewer, edge-case-reviewer, concurrency-reviewer, error-handling-reviewer, dependency-reviewer, testing-adequacy-reviewer, documentation-reviewer, supervisor, adversarial-validator]
findings_total: 17
findings_critical: 0
findings_high: 2
review_pass: 2
---

# Review Report (Re-Review After Fixes)

## MUST FIX (HIGH)

[CONS-004] HIGH: No tests for setup_worker core flows — src/worker_setup.rs
  Source: TEST-001, TEST-002, TEST-003, TEST-004 (4 specialists)
  Impact: run_command_with_timeout, run_npm_ci, run_patchright_install have zero tests. Regressions invisible.
  Fix: Add tests for timeout kill path and install failure branches.
  Acceptance: cargo test exercises timeout and both install failure paths.

[CONS-005] HIGH: verify_sha256 length check before ct_eq defeats timing-safety — src/download.rs:20-25
  Source: CQ-005
  Impact: Early return on length mismatch leaks whether hash is correct length, invalidating constant-time claim.
  Fix: Remove explicit length check; let ct_eq handle differing-length slices, or hex::decode error.
  Acceptance: No branch on len() before ct_eq.

## SHOULD FIX (MEDIUM)

[CONS-001] MEDIUM: 200ms busy-poll loop in run_command_with_timeout — src/worker_setup.rs:~499
  Fix: Increase sleep to 1s for long-running commands.

[CONS-006] MEDIUM: PID-only temp file name predictable under concurrent calls — src/download.rs:~79
  Fix: Append thread ID or random suffix.

[CONS-007] MEDIUM: I/O errors silently dropped in reader threads — src/worker_setup.rs:~471
  Fix: Log warning on I/O failure in reader threads.

[CONS-008] MEDIUM: Second rename failure leaves no worker directory — src/worker_setup.rs:~263
  Fix: Attempt to restore old_dir on second rename failure.

[CONS-009] MEDIUM: verify_chromium exposes node-reported path in error — src/worker_setup.rs:~438
  Fix: Truncate or log at debug level only.

[CONS-010] MEDIUM: try_lock_exclusive discards original io::Error — src/worker_setup.rs:~325
  Fix: Preserve OS error for non-contention failures.

[CONS-011] MEDIUM: Scopeguard version constraint too loose — Cargo.toml
  Fix: Pin to scopeguard = "1.1".

## CONSIDER (LOW)

[CONS-003] LOW: stderr included in CLI init error messages — src/worker_setup.rs
[CONS-012] LOW: Init lock file no restrictive permissions — src/worker_setup.rs
[CONS-013] LOW: Mutable @stable Rust toolchain tag in CI — ci.yml
[CONS-014] LOW: hex in build-dependencies may be unused — Cargo.toml
[CONS-015] LOW: No cargo audit in CI — ci.yml
[CONS-016] LOW: verify_sha256 accepts uppercase hex silently — src/download.rs
[CONS-017] LOW: Empty required_fields prints empty string — src/main.rs

## AV ADJUSTMENTS

- CONS-002 (build.rs sha256_file duplication) REMOVED: Build scripts cannot import from src/ — architecturally necessary separation.
- CONS-003 (stderr in errors) DOWNGRADED HIGH→LOW: CLI init diagnostic, correct behavior.
- CONS-001 (200ms poll) DOWNGRADED HIGH→MEDIUM: Acceptable tradeoff for CLI init simplicity.

## TODO SPECIFICATIONS

- File: src/download.rs | Lines: 20-25 | Action: Remove length check before ct_eq | Reason: CONS-005
- File: src/worker_setup.rs | Lines: tests section | Action: Add timeout and install failure tests | Reason: CONS-004
