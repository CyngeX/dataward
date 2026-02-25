---
module: "Database"
date: 2026-02-24
problem_type: best_practice
component: database
symptoms:
  - "Journal entries duplicated after crash during merge"
  - "Orphaned temp files left on disk with no recovery path"
  - "Silent data loss in crash recovery code"
root_cause: logic_error
resolution_type: code_fix
severity: medium
tags: [atomic-rename, crash-recovery, journal, file-operations, temp-files, write-rename-pattern]
language: rust
issue_ref: "#3"
related_solutions: []
---

# Atomic File Operations in Crash Recovery Code

## Problem

A journal merge operation used `std::fs::write()` + `std::fs::remove_file()` to merge two files. This is NOT atomic — a crash between the write and the delete leaves both files on disk. On next startup, the merge logic runs again, prepending already-merged content a second time, duplicating journal entries.

## Symptoms

- Duplicated journal entries after a crash during the merge window
- Orphaned `.replaying` or `.merging` files left on disk
- Replayed journal entries applied twice, overwriting valid task state

## Root Cause

The write-then-delete pattern has a failure window:
```rust
// NOT ATOMIC: crash between these two lines corrupts state
std::fs::write(journal_path, merged_content)?;
std::fs::remove_file(&replaying_path)?;
```

## Solution

Use the write-to-temp + atomic-rename pattern:

```rust
let merging_path = journal_path.with_extension("merging");

// Step 1: Write merged content to temp file
std::fs::write(&merging_path, &merged)?;

// Step 2: Atomic rename (on same filesystem)
std::fs::rename(&merging_path, journal_path)?;

// Step 3: Clean up old file (demote failure to warning)
if let Err(e) = std::fs::remove_file(&replaying_path) {
    tracing::warn!("Failed to remove .replaying: {}", e);
}
```

Additionally, add startup recovery for EVERY temp file extension:
```rust
// At start of replay_journal:
let merging_path = journal_path.with_extension("merging");
if merging_path.exists() {
    tracing::warn!("Found orphaned .merging — recovering");
    std::fs::rename(&merging_path, journal_path)?;
}
```

## Why This Works

`std::fs::rename()` is atomic on the same filesystem (POSIX guarantee). If the process crashes:
- Before write: `.merging` doesn't exist or is partial — no harm
- After write, before rename: `.merging` contains the full merged content — recovered at startup
- After rename, before remove: `.replaying` still exists but `.merging` is gone — handled by existing recovery
- After remove: clean state

## Prevention

- **Every temp file extension needs a startup recovery check**. Missing one creates a silent data loss window.
- **Never use write + delete for critical file operations**. Always use write-to-temp + rename.
- **Demote cleanup operations to warnings**, not errors. The primary operation (rename) succeeded; failing to clean up is recoverable.
- **Use a checklist**: for each file extension in your recovery code (.replaying, .merging, etc.), verify there is a startup handler.

## Gotchas

- `std::fs::rename()` is only atomic on the same filesystem. Cross-device renames fall back to copy+delete, which is NOT atomic.
- The order of startup recovery checks matters. Check for `.merging` BEFORE `.replaying`, since `.merging` represents a more complete state.
- Empty files can appear from crashes at rename boundaries. Always handle zero-byte files gracefully (treat as "no content").
