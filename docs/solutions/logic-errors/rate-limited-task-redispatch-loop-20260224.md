---
module: "Orchestrator"
date: 2026-02-24
problem_type: logic_error
component: background_job
symptoms:
  - "Rate-limited email tasks immediately re-dispatched every scheduler tick"
  - "Daily email quota exhausted in one daemon cycle"
  - "Error message says 'Will retry tomorrow' but task retries immediately"
root_cause: logic_error
resolution_type: code_fix
severity: high
tags: [rate-limit, task-scheduling, next-recheck, sqlite, pending-status, dispatch-loop]
language: rust
issue_ref: "#3"
related_solutions: []
---

# Rate-Limited Task Re-Dispatch Loop

## Problem

When an email opt-out task was rate-limited by the SMTP server, the orchestrator reset the task to `status = "pending"` via an `UpdateTask` DB message. However, the `UpdateTask` SQL did not update `next_recheck_at`, leaving it as NULL (for first-run tasks) or as a past timestamp.

The scheduler's `get_due_tasks` query selects tasks `WHERE next_recheck_at IS NULL OR next_recheck_at <= datetime('now')`. A task with NULL `next_recheck_at` is immediately eligible again, creating a tight re-dispatch loop that hammers the rate limit every tick.

## Symptoms

- Rate-limited tasks reappear in `get_due_tasks` results on the very next tick
- Error logs show repeated "rate_limited" entries for the same task every tick cycle
- The error message says "Will retry tomorrow" but the behavior contradicts this

## Root Cause

The `UpdateTask` DB message had no mechanism to set `next_recheck_at`. When resetting a task to "pending", only the status changed — the recheck timestamp was left untouched (NULL or stale).

The key SQL was:
```sql
UPDATE opt_out_tasks SET status = ?1, error_code = ?2, ...
WHERE id = ?8
-- next_recheck_at NOT updated
```

## Solution

Added `delay_recheck_days: Option<i32>` to the `UpdateTask` message variant. Updated the SQL to conditionally set `next_recheck_at`:

```sql
next_recheck_at = CASE WHEN ?9 IS NOT NULL
    THEN datetime('now', '+' || ?9 || ' days')
    ELSE next_recheck_at END
```

The rate-limited branch now passes `delay_recheck_days: Some(1)`, ensuring the task is deferred by 24 hours. Other callers pass `None` to preserve the existing value.

## Why This Works

The `CASE WHEN` expression only modifies `next_recheck_at` when a delay is explicitly requested. This is backward-compatible with existing `UpdateTask` callers (they pass `None` and the column stays unchanged). The `i32` type and parameterized binding prevent SQL injection through the `||` concatenation.

## Prevention

- **Any "reset to pending" operation must explicitly consider `next_recheck_at`**. NULL means "immediately eligible", not "unchanged".
- When adding transient error handling (rate limits, temporary failures), always pair the status reset with a recheck delay.
- Test the full cycle: trigger rate limit -> verify task NOT in next `get_due_tasks` result.

## Gotchas

- SQLite's `datetime('now', '+' || ?9 || ' days')` works with integer parameters via `||` concatenation — the bound parameter is coerced to its string representation.
- `COALESCE` alone won't work here because NULL means "don't change", not "use default". The `CASE WHEN` pattern is clearer.
