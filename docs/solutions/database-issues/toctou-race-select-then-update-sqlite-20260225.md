---
module: Database
date: 2026-02-25
problem_type: database_issue
component: database
symptoms:
  - "SELECT-then-UPDATE pattern allows race condition between check and mutation"
  - "Task status changes between SELECT validation and UPDATE execution"
  - "Concurrent requests can both pass validation but cause invalid state"
root_cause: race_condition
resolution_type: code_fix
severity: critical
tags: [toctou, race-condition, sqlite, rusqlite, atomic-update, select-then-update]
language: rust
framework: axum
issue_ref: "#4"
related_solutions:
  - docs/solutions/best-practices/atomic-file-ops-crash-recovery-20260224.md
---

# Troubleshooting: TOCTOU Race in SELECT-then-UPDATE Database Patterns

## Problem

SELECT-then-UPDATE patterns in database handlers create a time-of-check-to-time-of-use (TOCTOU) window where concurrent requests can bypass validation guards.

## Environment

- Module: Dashboard handlers / Database layer
- Language/Framework: Rust / Axum + rusqlite (SQLite)
- Affected Component: CAPTCHA resolve/abandon, broker re-run trigger
- Date: 2026-02-25

## Symptoms

- Two concurrent "resolve CAPTCHA" requests could both succeed for the same task
- Abandon + resolve racing could leave task in inconsistent state
- Re-run trigger could duplicate tasks if two requests arrive simultaneously

## What Didn't Work

**Attempted Solution 1:** SELECT to validate status, then UPDATE to mutate.
- **Why it failed:** Window between SELECT and UPDATE allows concurrent request to pass same validation. Even with SQLite's serialized writes, the SELECT reads stale data.

## Solution

Move ALL guard conditions into the UPDATE WHERE clause and check `rows_affected()` to determine outcome.

**Code changes:**

```rust
// Before (broken — TOCTOU):
let status: String = conn.query_row(
    "SELECT status FROM tasks WHERE id = ?1", [id], |r| r.get(0)
)?;
if status != "captcha_blocked" { return Err(WrongStatus); }
conn.execute("UPDATE tasks SET status = 'pending' WHERE id = ?1", [id])?;

// After (fixed — atomic):
let rows = conn.execute(
    "UPDATE opt_out_tasks SET status = 'pending', retry_count = 0
     WHERE id = ?1 AND status = 'captcha_blocked'
       AND created_at > datetime('now', '-24 hours')",
    [task_id],
)?;
match rows {
    0 => {
        // Disambiguate: not found vs wrong status vs expired
        // This SELECT is safe — it's only for error message quality,
        // not a guard. The atomic UPDATE already did the real work.
        let exists = conn.query_row(
            "SELECT status, created_at FROM opt_out_tasks WHERE id = ?1",
            [task_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        ).optional()?;
        match exists {
            None => Ok(NotFound),
            Some((_, created_at)) if is_expired(&created_at) => Ok(Expired),
            Some(_) => Ok(WrongStatus),
        }
    }
    _ => Ok(Success),
}
```

## Why This Works

1. **ROOT CAUSE:** The SELECT and UPDATE are separate operations with a race window between them. Any concurrent request can read the same pre-mutation state.
2. The atomic UPDATE WHERE combines validation and mutation into a single statement — SQLite guarantees this executes atomically. Only one concurrent request can match the WHERE clause.
3. The post-UPDATE SELECT for error disambiguation is safe because it doesn't guard any mutation — it only determines which error message to return.

## Prevention

- **Never use SELECT-to-validate then UPDATE-to-mutate** for state transitions. Always put guards in the UPDATE WHERE clause.
- **Check `rows_affected()`** — 0 means the guard conditions weren't met; disambiguate with a follow-up SELECT for error quality only.
- **Pattern: atomic UPDATE WHERE + rows_affected + optional SELECT for error messages.** The SELECT after UPDATE is a read-only diagnostic, not a guard.
- AI code reviewers will flag the post-UPDATE diagnostic SELECT as a TOCTOU — it's a false positive. The guard is the UPDATE WHERE, not the SELECT.

## Related Issues

- See also: [atomic-file-ops-crash-recovery](../best-practices/atomic-file-ops-crash-recovery-20260224.md)
