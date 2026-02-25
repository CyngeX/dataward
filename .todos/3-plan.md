# Living Plan: Issue #3 — Phase 3 Orchestrator

**Issue:** #3 — Phase 3 Orchestrator: Scheduler, Task Execution, Crash Recovery
**Branch:** `issue-3-orchestrator`
**Approach:** Single-agent
**Started:** 2026-02-24

## Acceptance Criteria
1. [x] `dataward run` launches scheduler and processes all due brokers
2. [x] `dataward run --once` processes due tasks and exits with summary
3. [x] Crash recovery: orphaned running->pending reset on startup
4. [x] Per-task timeouts: browser=120s, email=30s, API=15s
5. [x] Retry logic: exponential backoff 1h/4h/24h/72h with configurable max_retries
6. [x] Worker subprocess launched with JSON-lines IPC and cleanup on exit
7. [x] PID file prevents duplicate daemon instances
8. [x] Graceful shutdown on SIGTERM/SIGINT: finish current task, then exit
9. [x] Email worker sends via SMTP with daily rate limiting
10. [x] API worker makes HTTP requests with response validation
11. [x] All errors captured with error_code, error_message, error_retryable
12. [x] Run log entries created for each scheduler run

## Architecture (from deepened plan)
- **Orchestrator** = lifecycle owner composing Scheduler + Dispatcher + Workers
- **Concurrency** = number of worker subprocesses (not internal contexts)
- **No shared Worker trait** — three concrete async functions
- **Boolean error_retryable** flag (not error-code routing table)
- **PID file** via flock() (atomic, stale-safe)
- **CancellationToken** for coordinated shutdown

## Implementation Steps
1. [x] Add Cargo.toml deps (tokio-util, fs2, uuid)
2. [x] Extend db.rs (open_db_with_key, scheduler queries, retry logic)
3. [x] Create scheduler.rs
4. [x] Create subprocess.rs
5. [x] Create email_worker.rs
6. [x] Create api_worker.rs
7. [x] Create orchestrator.rs
8. [x] Wire up main.rs
9. [x] Write tests (109 Rust + 90 TypeScript = 199 total)
10. [x] Validate (cargo test, clippy, build)

## Files Changed/Created
- `Cargo.toml` — Added tokio-util, fs2, uuid dependencies
- `src/db.rs` — Extended: open_db_with_key, derive_db_key, get_due_tasks, create_missing_tasks, mark_task_running, update_task_for_retry, complete_task_success, insert/update_run_log, get_daily_email_count, replay_journal, new DbWriteMessage variants (14 new tests)
- `src/scheduler.rs` — NEW: scheduler_tick, validate_required_fields (5 tests)
- `src/subprocess.rs` — NEW: SubprocessManager, WorkerTaskInput/Result, spawn/execute/shutdown (6 tests)
- `src/email_worker.rs` — NEW: send_opt_out_email, SMTP transport, email body builder (4 tests)
- `src/api_worker.rs` — NEW: send_opt_out_api, reqwest client, response validation (3 tests)
- `src/orchestrator.rs` — NEW: run, PID lock, signal handlers, dispatch_tasks, run_once/run_daemon (5 tests)
- `src/main.rs` — Wired Run command to orchestrator, added new modules

## Progress Log
- 2026-02-24: Started implementation, read all source files
- 2026-02-24: Completed all implementation steps, 109 Rust tests passing
