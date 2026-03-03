---
module: "Worker Setup"
date: 2026-03-01
problem_type: best_practice
component: tooling
symptoms:
  - "Subprocess hangs indefinitely during init (npm ci, browser install)"
  - "No way to recover from stuck network-dependent processes"
  - "Pipe buffer deadlock when reading stdout/stderr from child process"
root_cause: missing_validation
resolution_type: code_fix
severity: high
tags: [subprocess, timeout, pipe-deadlock, child-process, spawn, thread, rust, cli]
language: rust
issue_ref: "#5"
related_solutions:
  - "docs/solutions/best-practices/atomic-file-ops-crash-recovery-20260224.md"
---

# Subprocess Timeout Pattern with Pipe Deadlock Prevention (Rust)

## Problem

Network-dependent subprocesses (`npm ci`, `npx patchright install`) can hang indefinitely during `dataward init`. Rust's `std::process::Command` has no built-in timeout. Naively reading stdout/stderr sequentially causes pipe buffer deadlock when the child writes to both.

## Environment

- Module: Worker Setup (CLI init)
- Language: Rust (std::process)
- Affected Component: Any synchronous subprocess with piped stdout+stderr
- Date: 2026-03-01

## Symptoms

- `dataward init` hangs forever on network failure
- Process appears stuck with no timeout or error message
- Deadlock when child fills stderr pipe buffer while parent reads stdout

## Root Cause

1. **No timeout**: `Command::output()` blocks indefinitely until the child exits.
2. **Pipe deadlock**: OS pipe buffers are typically 64KB. If the child writes >64KB to stderr while the parent is blocked reading stdout (or vice versa), both processes block forever — the child can't write because the pipe is full, and the parent can't read because it's stuck on the other pipe.

## Solution

Three-part pattern: background reader threads + poll loop + timeout.

```rust
fn run_command_with_timeout(
    cmd: &mut std::process::Command,
    timeout: Duration,
    description: &str,
) -> Result<std::process::Output> {
    let mut child = cmd.spawn()
        .with_context(|| format!("Failed to spawn: {}", description))?;

    // 1. Take ownership of piped streams and read in background threads
    //    to prevent pipe buffer deadlock.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut out) = stdout_handle {
            if let Err(e) = std::io::Read::read_to_end(&mut out, &mut buf) {
                eprintln!("Warning: failed to read subprocess stdout: {}", e);
            }
        }
        buf
    });

    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut err) = stderr_handle {
            if let Err(e) = std::io::Read::read_to_end(&mut err, &mut buf) {
                eprintln!("Warning: failed to read subprocess stderr: {}", e);
            }
        }
        buf
    });

    // 2. Poll for completion with timeout
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("{} timed out after {}s", description, timeout.as_secs());
                }
                // 3. Sleep 1s between polls (not 200ms — avoid CPU waste for multi-minute installs)
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    Ok(std::process::Output { status, stdout, stderr })
}
```

## Why This Works

1. **Background reader threads** drain both pipes concurrently, preventing deadlock regardless of which pipe the child writes to first or how much data it produces.
2. **Poll loop with `try_wait()`** is non-blocking — the parent thread can check the timeout between polls.
3. **`child.kill()` + `child.wait()`** ensures the child is fully cleaned up on timeout (kill sends SIGKILL, wait reaps the zombie).
4. **Thread `join().unwrap_or_default()`** gracefully handles thread panics (returns empty Vec instead of propagating).

## Gotchas

1. **Poll interval matters**: 200ms burns CPU for 5-10 minute installs (1500-3000 wakes). Use 1s for CLI tools where sub-second precision isn't needed.
2. **Don't forget `child.wait()` after `kill()`**: Without it, the child becomes a zombie process.
3. **Reader thread I/O errors**: Don't silently discard them with `let _ =`. At minimum log a warning — truncated output makes debugging impossible.
4. **Timeout granularity**: The actual timeout is `configured_timeout + poll_interval` in the worst case. For a 30s timeout with 1s polls, the process may run up to 31s.
5. **Tiered timeouts**: Use different durations for different operations:
   - Local commands (node --version, chromium check): 30s
   - Network installs (npm ci): 5 minutes
   - Large downloads (patchright chromium ~150MB): 10 minutes

## What Didn't Work

- **`Command::output()`**: No timeout support, blocks forever.
- **`tokio::process::Command` with `tokio::time::timeout()`**: Would work but requires async runtime. For a sync CLI init path, pulling in tokio is overkill.
- **200ms poll interval**: Functionally correct but wastes CPU. Multiple review agents flagged this independently.
- **Sequential pipe reading** (read stdout first, then stderr): Deadlocks when child fills stderr buffer while parent blocks on stdout.

## Prevention

- Always set explicit timeouts on subprocess calls, especially network-dependent ones.
- Always pipe both stdout AND stderr when you need to capture output — never inherit one and pipe the other (asymmetric pipe handling risks deadlock).
- Add tests: spawn `sleep 30` with a 2s timeout to verify the kill path works.

## Related Issues

- #5 (Phase 5: Distribution + Initial Broker Playbooks)
- `docs/solutions/best-practices/atomic-file-ops-crash-recovery-20260224.md` — related atomic operations pattern
