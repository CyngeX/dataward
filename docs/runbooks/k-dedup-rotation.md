# Runbook: k_dedup key rotation (SEC-R2-008)

## When to rotate

- Suspected compromise of the master key or a prior `k_dedup` subkey
- Scheduled rotation per your organization's key lifecycle policy
- Major release bump that invalidates the HKDF `info` label format

The `account_discovery_findings` table stores `k_dedup_version` per row so
multiple generations can coexist during migration.

## Preconditions

- Backup exists (`dataward` auto-backups before migration steps, but take
  an explicit one for rotation).
- Dashboard is stopped. Scheduler is stopped. No `discover` runs in flight.
- You have the current passphrase.

## Procedure

1. **Backup.** Copy `~/.dataward/dataward.db` (and `.db-wal`, `.db-shm`)
   to a safe location. Use `dataward playbook verify` style sha256 of the
   backup for integrity.

2. **Bump `k_dedup_version`.** (Follow-up: CLI wiring is pending — for now,
   this is a manual SQL operation via a rusqlite REPL or a one-shot
   migration function.)

   ```sql
   -- Inside the rotation tool, reached via dataward internal rekey path.
   UPDATE account_discovery_findings SET k_dedup_version = 2;
   ```

3. **Recompute dedup hashes.** For each row, recompute `dedup_hash` and
   `username_hmac` using the new `k_dedup` subkey derived via
   `crypto::hkdf_subkey(master, install_salt, INFO_DEDUP_V2)` where
   `INFO_DEDUP_V2 = b"dataward/dedup/v2"`. This requires walking the
   findings table and re-hashing deterministically.

   > **Important:** The HMAC inputs MUST be reconstructed from the
   > normalized domain + username strings, NOT from the old `dedup_hash`
   > (HMACs are one-way).

4. **Update the INFO label constant.** In `crypto.rs`, introduce
   `INFO_DEDUP_V2` and update callers to prefer it. Keep the v1 label
   available for at least one release for rollback.

5. **Verify.** Run `cargo test phase7_audit` — all 13 tests must pass.
   Run `dataward discover --source bitwarden --file ...` on a known
   fixture and confirm the new findings land with `k_dedup_version = 2`.

6. **Retire v1.** After one full release cycle with no rollback, remove
   the `INFO_DEDUP` v1 constant and drop rows with `k_dedup_version = 1`
   that have not been re-keyed.

## Rollback

If the rekey produces inconsistent dedup hashes, restore the pre-rotation
backup and leave `k_dedup_version = 1` in place. Do NOT attempt a partial
rollback — dedup relies on a single consistent version across all rows.

## Open items

- Actual rotation CLI subcommand (`dataward rekey-dedup`) is not yet
  implemented. This runbook documents the intended flow so the operator
  has a pre-committed procedure before the first incident.
