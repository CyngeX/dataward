---
module: Dashboard
date: 2026-02-25
problem_type: best_practice
component: auth
symptoms:
  - "Building localhost web dashboard with authentication and CSRF protection"
  - "Need defense-in-depth for local-only dashboard"
  - "Multiple security layers required for mutation endpoints"
root_cause: missing_validation
resolution_type: code_fix
severity: high
tags: [axum, dashboard, csrf, session-cookie, hmac, host-validation, dns-rebinding, spawn-blocking, secrecy, zeroize, htmx]
language: rust
framework: axum
issue_ref: "#4"
---

# Best Practice: Axum Localhost Dashboard Security Patterns

## Problem

Building a secure localhost-only web dashboard in Axum requires coordinating multiple security layers: authentication, session management, CSRF protection, host validation, and proper async handling of blocking operations.

## Environment

- Module: Web Dashboard
- Language/Framework: Rust / Axum + htmx + Askama
- Affected Component: Auth middleware, session cookies, CSRF, handlers
- Date: 2026-02-25

## Key Patterns

### 1. CSRF Double-Submit Cookie for htmx

CSRF cookie MUST NOT be `HttpOnly` — JavaScript (htmx) needs to read it for request headers.

```rust
// CSRF cookie: readable by JS, SameSite=Strict
fn csrf_cookie_header(token: &str) -> String {
    format!("csrf_token={}; SameSite=Strict; Path=/", token)
}

// Session cookie: HttpOnly (JS must NOT read it)
fn session_cookie_header(value: &str) -> String {
    format!("session={}; SameSite=Strict; Path=/; HttpOnly; Max-Age=86400", value)
}
```

htmx sends the token via `hx-headers='{"X-CSRF-TOKEN": "..."}` read from the cookie.

For traditional form POSTs (login), the body is consumed by parsing — extract cookie header BEFORE consuming the request body, then call a separate `verify_csrf_form_token(cookie_header, form_field)`.

### 2. Don't Rotate CSRF on Polling Partials

htmx polling endpoints (e.g., `hx-trigger="every 5s"`) should NOT rotate the CSRF token. Rotating on every poll wastes entropy and causes cookie churn. Only rotate on full page loads.

### 3. Host Header Validation (DNS Rebinding Defense)

Allowlist localhost variants. Handle IPv6 bracket notation. Reject null bytes.

```rust
const ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

fn extract_host_without_port(host: &str) -> &str {
    // Reject null bytes (DNS rebinding payload)
    if host.bytes().any(|b| b == 0) { return ""; }
    // Handle [::1]:port
    if host.starts_with('[') {
        return host.find(']').map_or(host, |i| &host[..=i]);
    }
    host.rfind(':').map_or(host, |i| &host[..i])
}
```

### 4. Session Secret Zeroization

Use `SecretBox` from the `secrecy` crate for session signing keys. Raw `[u8; 32]` stays in memory after drop.

```rust
use secrecy::{ExposeSecret, SecretBox};
// In DashboardState:
session_secret: Arc<SecretBox<Vec<u8>>>,  // zeroize-on-drop
```

### 5. Precompute Token Hash

Don't hash the auth token on every request. Compute once at startup and store in state.

```rust
use sha2::Digest;
let token_hash = sha2::Sha256::digest(token.as_bytes());
let token_hash_b64 = base64::encode(token_hash);
// Store token_hash_b64 in DashboardState, use in session cookie creation/verification
```

### 6. spawn_blocking for fs Operations

`std::fs::canonicalize()`, `std::fs::metadata()`, and similar block the thread. In Axum handlers, wrap in `spawn_blocking`.

```rust
let result = tokio::task::spawn_blocking(move || {
    let canonical = std::fs::canonicalize(&path)?;
    let metadata = std::fs::metadata(&canonical)?;
    Ok((canonical, metadata.len()))
}).await??;
```

Note: after `canonicalize()`, symlinks are already resolved — a separate `symlink_metadata().is_symlink()` check is dead code.

### 7. tokio::sync::Mutex for Async State

Use `tokio::sync::Mutex` (not `std::sync::Mutex`) for state shared across async handlers. `std::sync::Mutex` blocks the Tokio worker thread while held.

### 8. Pagination: Fetch limit+1

To detect "has more pages" without an extra COUNT query, fetch `limit + 1` rows. If `result.len() > limit`, there are more pages — truncate to `limit` before returning.

```rust
const PAGE_SIZE: usize = 50;
let mut tasks = db::get_task_history(&conn, cursor, PAGE_SIZE as i64 + 1)?;
let has_more = tasks.len() > PAGE_SIZE;
if has_more { tasks.truncate(PAGE_SIZE); }
```

### 9. Askama Auto-Escaping

`MarkupDisplay::new_unsafe` means the VALUE is unsafe (needs escaping) — it APPLIES escaping. `new_safe` means the value is already safe — it SKIPS escaping. The naming is counter-intuitive but correct for XSS prevention.

### 10. Cache-Control: Per-Handler Override

Use `SetResponseHeaderLayer::if_not_present` for the global `Cache-Control: no-store` so individual handlers (like static JS serving) can set their own caching headers.

## Prevention

- Always start with this checklist when building Axum dashboards
- CSRF cookie: NOT HttpOnly. Session cookie: HttpOnly. Get this backwards and either htmx breaks or session is exposed to XSS.
- All `std::fs` calls in async handlers → `spawn_blocking`
- All shared mutable state → `tokio::sync::Mutex`
- Variable-length secret comparison → hash first, then `ct_eq`
