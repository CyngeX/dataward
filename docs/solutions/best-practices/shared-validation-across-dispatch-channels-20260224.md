---
module: "Orchestrator"
date: 2026-02-24
problem_type: best_practice
component: service
symptoms:
  - "PII size validation only applied to web_form channel, not email or api"
  - "Inconsistent security boundaries across dispatch paths"
  - "Validation logic duplicated or missing in some match arms"
root_cause: scope_error
resolution_type: code_fix
severity: medium
tags: [validation, dispatch, match-arms, shared-function, pii, security-boundary, consistency]
language: rust
issue_ref: "#3"
related_solutions: []
---

# Shared Validation Across Dispatch Channels

## Problem

A task dispatcher had three match arms for different channels (web_form, email, api). PII field size validation was added inline to the `web_form` arm but not to the `email` or `api` arms. This created an inconsistent security boundary where oversized PII values were rejected for web_form tasks but passed through for email and API tasks.

## Symptoms

- Fresh-eyes review flagged PII size check as web_form-only
- Email and API arms called `validate_fields_from_cache()` but had no size guard
- Adding validation to each arm individually would create DRY violations

## Root Cause

Validation was added inline inside one match arm instead of in the shared pre-processing function that all arms already called. This is a scope error — the developer put the check in the specific arm they were working on, not in the common path.

## Solution

Moved the size check INTO the shared `validate_fields_from_cache()` function:

```rust
fn validate_fields_from_cache(
    all_profile: &HashMap<String, String>,
    required_fields: &[String],
) -> Result<HashMap<String, String>> {
    // ... existing missing-field checks ...

    // Size validation for ALL channels (not just web_form)
    for (key, value) in &user_data {
        if value.len() > MAX_PII_FIELD_BYTES {
            anyhow::bail!(
                "PII field '{}' exceeds {} byte limit ({} bytes)",
                key, MAX_PII_FIELD_BYTES, value.len()
            );
        }
    }

    Ok(user_data)
}
```

This also improved the error message by including the field name (previously only reported the byte count).

## Why This Works

All three dispatch channels already called `validate_fields_from_cache()`. By putting the size check inside the shared function, every channel inherits it automatically. Future channels will also be protected without needing to remember to add the check.

## Prevention

- **When a codebase has multiple dispatch paths (match arms, if-else chains), validation must go in the common pre-processing step**, not inside individual branches.
- **Review checklist for match-based dispatchers**: for each validation applied in one arm, verify it exists (or isn't needed) in every other arm.
- **Prefer shared helper functions over inline checks**. A helper called by all arms is self-enforcing; inline checks require manual replication.
- **Fresh-eyes review catches this pattern well** — zero-context reviewers spot inconsistencies between arms that the implementer (who focused on one arm) missed.

## Gotchas

- Moving validation into a shared function can change the error behavior for channels that previously had no validation. Ensure the error messages and error codes are appropriate for all channels.
- Including the field name in validation errors (e.g., "PII field 'email' exceeds 512 byte limit") is much more debuggable than just reporting the byte count.
- The scope of validation matters: checking only `required_fields` (not all profile fields) is intentional — non-required fields are never sent to workers.
