---
module: "Crypto"
date: 2026-03-10
problem_type: security_issue
component: auth
symptoms:
  - "DB rekeyed but proof files still encrypted with old key after partial failure"
  - "Inconsistent encryption state with no rollback path"
  - "Silent error swallowing in proof file re-encryption loop"
root_cause: logic_error
resolution_type: code_fix
severity: critical
tags: [rekey, passphrase, encryption, atomic, ordering, rollback, sqlcipher, aes-256-gcm, zeroize]
language: rust
issue_ref: "#6"
related_solutions:
  - "docs/solutions/best-practices/atomic-file-ops-crash-recovery-20260224.md"
---

# Multi-Resource Rekey Must Order Reversible Operations First

## Problem

A passphrase rotation command re-encrypted the SQLCipher database first (via `PRAGMA rekey`), then re-encrypted proof screenshot files. If proof file re-encryption failed partway through, the system was left in an inconsistent state: DB using the new passphrase, some proof files using the old key, some using the new key.

## Environment

- Module: Crypto (passphrase rotation / rekey command)
- Language/Framework: Rust / SQLCipher + AES-256-GCM
- Affected Component: `src/rekey.rs` — `run_rekey()` and `rekey_encrypted_files()`

## Symptoms

- After a partial failure, the user's DB requires the new passphrase but some proof files still require the old passphrase
- No error reported to the user — decrypt failures were swallowed with `eprintln!` warnings
- No way to recover without manual intervention

## What Didn't Work

**Original ordering:** DB rekey first, then file re-encryption.
- **Why it failed:** SQLCipher `PRAGMA rekey` is irreversible once the connection closes. If file re-encryption fails after DB rekey, there's no way to roll back the DB to the old passphrase.

**Silent error swallowing:** Decrypt failures logged but not propagated.
- **Why it failed:** The function returned `Ok(())` even when files failed to re-encrypt, giving the user false confidence that everything worked.

## Solution

Three changes:

1. **Reorder operations:** Re-encrypt proof files FIRST (reversible with atomic writes), then rekey DB (irreversible).

```rust
// Re-encrypt proof files FIRST (reversible -- originals not yet lost)
rekey_encrypted_files(data_dir, &old_passphrase, &new_passphrase, &salt)?;

// Then rekey the database (irreversible -- proof files already updated)
db::rekey_db(&db_path, &old_passphrase, &new_passphrase, &salt)?;
```

2. **Atomic file writes:** Write to `.enc.tmp`, then rename over original. If rename fails, clean up temp file.

```rust
let tmp_path = path.with_extension("enc.tmp");
std::fs::write(&tmp_path, &encrypted)?;
if let Err(e) = std::fs::rename(&tmp_path, &path) {
    let _ = std::fs::remove_file(&tmp_path);
    return Err(e).context("Failed to rename");
}
```

3. **Error collection and propagation:** Collect decrypt errors and bail after processing all files, instead of silently continuing.

```rust
let mut errors: Vec<String> = Vec::new();
// ... in loop:
Err(e) => { errors.push(format!("{}: {}", path.display(), e)); }
// ... after loop:
if !errors.is_empty() {
    anyhow::bail!("Failed to re-encrypt {} proof file(s):\n  {}", errors.len(), errors.join("\n  "));
}
```

## Why This Works

- File re-encryption with atomic rename is reversible: if the process is interrupted, either the original or the new version exists, never a corrupted state.
- DB `PRAGMA rekey` is irreversible, so it must be the LAST operation. If anything before it fails, the DB is still on the old key.
- Error propagation ensures the user knows exactly which files failed, rather than discovering it later when trying to view proof screenshots.

## Prevention

- **Order multi-resource mutations by reversibility.** Reversible operations first, irreversible last.
- **Never swallow errors in security-sensitive code.** Collect and propagate, or fail fast.
- **Always use atomic writes for file mutations** (temp + rename pattern). See related solution.
- **Zeroize all passphrases on ALL exit paths** — including error paths and early returns, not just the happy path.

## Gotchas

- SQLCipher `PRAGMA rekey` is irreversible once the connection is dropped. There is no `PRAGMA unkey` or rollback mechanism.
- `zeroize` crate requires `mut` binding. If the original binding is immutable, you need `let mut x = x;` to rebind — or just declare it `mut` from the start.
- The user-facing warning to "back up before rekeying" is a valid safety net, but shouldn't be relied upon as the primary recovery mechanism.
