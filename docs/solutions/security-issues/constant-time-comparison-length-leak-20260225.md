---
module: Authentication
date: 2026-02-25
problem_type: security_issue
component: auth
symptoms:
  - "ct_eq comparison leaks relative length of expected value via timing"
  - "Short-circuit on length mismatch reveals whether attacker's guess is correct length"
  - "Even with constant-time byte comparison, differing lengths take different time"
root_cause: logic_error
resolution_type: code_fix
severity: high
tags: [constant-time, timing-attack, length-leak, sha256, subtle, csrf, session, auth]
language: rust
issue_ref: "#4"
---

# Troubleshooting: Constant-Time Comparison Length Leak via Timing Side-Channel

## Problem

Using `ct_eq` (from the `subtle` crate) directly on variable-length inputs leaks the expected value's length. An attacker can determine when their input matches the target length by measuring response time differences.

## Environment

- Module: Authentication (session cookies, CSRF tokens, Bearer tokens)
- Language/Framework: Rust / subtle crate
- Affected Component: All constant-time comparison points
- Date: 2026-02-25

## Symptoms

- CSRF token comparison, session cookie validation, and Bearer token checks all use variable-length inputs
- `ct_eq` on slices of different lengths must handle the length difference somehow — either short-circuiting or padding, both of which leak timing information

## What Didn't Work

**Attempted Solution 1:** Direct `ct_eq` on raw byte slices.
- **Why it failed:** When `a.len() != b.len()`, the comparison either returns immediately (leaking that lengths differ) or must iterate over different counts of bytes (leaking the length of the longer input).

## Solution

Hash both sides with SHA-256 before comparing. SHA-256 always produces 32 bytes regardless of input length, eliminating the length signal entirely.

**Code changes:**

```rust
// Before (leaks length):
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// After (fixed — length-independent):
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::Digest;
    let ha = sha2::Sha256::digest(a);
    let hb = sha2::Sha256::digest(b);
    ha.ct_eq(&hb).into()
}
```

## Why This Works

1. **ROOT CAUSE:** `ct_eq` on variable-length slices cannot hide the length difference. Even if byte-level comparison is constant-time, the operation's total duration correlates with input lengths.
2. SHA-256 always outputs exactly 32 bytes regardless of input length. After hashing, `ct_eq` compares two fixed-size 32-byte arrays — no length signal exists.
3. SHA-256 is a one-way function, so the hashes don't leak any information about the original values.

## Prevention

- **Always hash variable-length secrets before constant-time comparison.** SHA-256 is the standard choice.
- **Apply to all comparison points:** CSRF tokens, session cookies, Bearer tokens, API keys — anywhere timing matters.
- **Alternative:** HMAC-based comparison (compute HMAC of both inputs with a shared key, compare MACs). This is what `hmac.verify()` does internally.
- The `subtle` crate's `ct_eq` is only safe for fixed-length comparisons (e.g., two `[u8; 32]` arrays). For variable-length, always normalize first.

## Related Issues

- CSRF double-submit cookie pattern relies on this for token comparison
- Session cookie HMAC signature verification uses this for the token hash check
