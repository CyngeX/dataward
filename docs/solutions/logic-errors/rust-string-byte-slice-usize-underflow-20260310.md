---
module: "CLI"
date: 2026-03-10
problem_type: logic_error
component: view
symptoms:
  - "truncate() panics when max < 3 due to usize underflow"
  - "format_datetime() panics on multi-byte UTF-8 input at byte boundary"
  - "Tests pass because they never exercise boundary values"
root_cause: type_error
resolution_type: code_fix
severity: critical
tags: [rust, usize, underflow, truncate, byte-slice, utf-8, string, panic, boundary, chars]
language: rust
issue_ref: "#6"
related_solutions: []
---

# Rust &str Byte Slicing and usize Underflow in String Helpers

## Problem

Two common string helper functions had latent panics:
1. `truncate(s, max)` computed `max - 3` for the ellipsis suffix. When `max < 3`, usize underflow causes a panic (debug) or wraps to `usize::MAX` (release), consuming all memory.
2. `format_datetime(dt)` used `dt[..16]` which is byte indexing. If byte 16 falls within a multi-byte UTF-8 character, Rust panics at runtime.

## Environment

- Module: CLI status display
- Language: Rust
- Affected Component: `src/status.rs` — `truncate()` and `format_datetime()`

## Symptoms

- No panics observed in normal usage (inputs happen to be ASCII and max is always >= 3)
- Tests pass because they never test boundary values (max=0, max=1, max=2) or multi-byte input for datetime
- Code review catches the latent bugs

## What Didn't Work

**Relying on "inputs are always ASCII":** The function signature accepts `&str`, so any caller can pass multi-byte input. Defending based on current callers is fragile.

**Testing only happy paths:** Tests covered truncation at normal lengths but never tested the boundary where `max < 3`.

## Solution

**Fix 1: Guard usize underflow in truncate()**

```rust
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max < 3 {
        // Can't fit "..." — return dots up to max length
        ".".repeat(max)
    } else {
        let truncated: String = s.chars().take(max - 3).collect();
        format!("{}...", truncated)
    }
}
```

**Fix 2: Use char-based slicing in format_datetime()**

```rust
fn format_datetime(dt: &str) -> String {
    if dt.is_empty() {
        return "-".to_string();
    }
    if dt.chars().count() >= 16 {
        dt.chars().take(16).collect()
    } else {
        dt.to_string()
    }
}
```

**Fix 3: Add boundary tests**

```rust
#[test]
fn test_truncate_small_max() {
    assert_eq!(truncate("hello", 0), "");
    assert_eq!(truncate("hello", 1), ".");
    assert_eq!(truncate("hello", 2), "..");
}

#[test]
fn test_format_datetime_multibyte() {
    let dt = "2026-03-10\u{00A0}14:30:00"; // non-breaking space
    let result = format_datetime(dt);
    assert_eq!(result.chars().count(), 16);
}
```

## Why This Works

- `usize` in Rust is unsigned — subtraction that would go negative panics in debug mode and wraps to `usize::MAX` in release mode. Both are wrong. The guard clause prevents the subtraction from ever executing with unsafe values.
- `&str[..n]` is byte indexing, not character indexing. `chars().take(n)` is character-aware and safe for all UTF-8 input.
- Boundary tests exercise the exact inputs that trigger the bugs, preventing regression.

## Prevention

- **Never subtract from `usize` without a guard.** Always check `if value >= subtrahend` before `value - subtrahend`.
- **Never use `&str[..n]` on user-facing strings.** Use `.chars().take(n).collect::<String>()` instead. The only safe use of byte indexing is when you've verified the string is ASCII.
- **Always test boundary values:** 0, 1, 2 for any function that takes a size/length parameter. This is the #1 AI blind spot in generated code.
- **Test with multi-byte input** for any string manipulation function, even if current callers only pass ASCII.

## Gotchas

- `".repeat(0)` returns `""` — this is correct for max=0 (no space available, return empty).
- `.chars().count()` is O(n) for UTF-8 strings. For performance-critical code, consider caching or using `.len()` with ASCII validation. For CLI display helpers, the overhead is negligible.
- `\u{00A0}` (non-breaking space) is a 2-byte UTF-8 character that looks like a regular space but breaks byte-based slicing — good test input.
