# Phase 7: Breach-Minimization Purge — User Guide

Phase 7 adds account discovery and opt-out automation for platforms you use
(not just data brokers). This document covers end-user workflows.

> **Status:** Phases 7.0–7.4 have landed as scaffolds + hardening. Several
> features referenced here are **not yet fully implemented**; those are
> called out inline as _(follow-up)_.

---

## What changed in Phase 7

- **Encrypted credential store** — HKDF-derived subkey (`k_credstore`) stores
  platform credentials separately from the SQLCipher master key.
- **Discovery pipeline** — four importers (Bitwarden, macOS Keychain CSV,
  Firefox, Gmail IMAP) feed a normalizer → deduper → scorer → triage queue.
- **Platform accounts** — sibling tables to `brokers` holding account
  metadata, credentials, and discovery findings. Does NOT touch the existing
  brokers table.
- **Dashboard discovery triage** — review discovered accounts, accept, or
  dismiss _(follow-up: UI templates pending)_.
- **First-run dry preview** — Dataward screenshots the first attempt on a
  new platform before actually submitting anything _(follow-up: worker
  preview_only mode pending)_.
- **Legal acknowledgment gate** — refuses to discover/schedule anything
  until the user accepts the disclaimer.
- **Core-dump hardening** — `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE=0`
  at startup.

---

## Running discovery

```bash
# Bitwarden: export an Unencrypted JSON from Settings → Export Vault.
dataward discover --source bitwarden --file ~/Downloads/vault.json
# (follow-up) not yet wired into main.rs — invokes via integration tests
# only in the current build.

dataward discover --source keychain --file ~/Downloads/passwords.csv

dataward discover --source firefox --profile my-profile
# (follow-up) returns NotImplemented in current build.

dataward discover --source gmail
# (follow-up) returns NotImplemented in current build — requires async-imap.
```

After discovery, open the dashboard at <http://127.0.0.1:9847> and visit
`/discovery` to triage findings. _(The triage UI currently returns 503 —
routes are reserved and wired, template rendering is the Phase 7.4a
follow-up.)_

## Regulated categories

Playbooks with categories `financial`, `health`, or `government` MUST use
`opt_out_channel: manual_only` and supply `manual_instructions:`. Dataward
will NOT attempt to log in to your bank, health portal, or government
account. This is an intentional foot-gun guard; see
[`playbooks/README.md`](../playbooks/README.md) for the rationale.

## Privacy hygiene

- The data directory (`~/.dataward`) contains PII. Full-disk encryption is
  strongly recommended; Dataward does NOT attempt to "shred" files, since
  on modern filesystems (ext4 journaling, btrfs COW, SSD wear-leveling)
  shredding is theater.
- Proof screenshots are stored encrypted with the master key-derived file
  key.
- Gmail App Passwords are stored in the encrypted credential_store. The
  dashboard _(follow-up)_ will flag App Passwords older than 7 days for
  rotation.

---

## Verifying drift on shipped playbooks

```bash
dataward playbook verify --sums playbooks/platform.sums --root playbooks
```

Plain SHA-256 manifest check. No cryptographic signing (see
[`playbooks/README.md`](../playbooks/README.md#drift-check-optional)).

---

## Running the security audit

```bash
cargo test --bin dataward phase7_audit
```

Runs the consolidated Phase 7 audit: HKDF domain separation, migration
idempotency + recoverable backup, credential_store CHECK constraint,
no-double-promotion invariant, retention sweep, log-canary credential
scrubbing, regulated-category playbook gate, and the post-migration
banner round-trip.

Three tests are marked `#[ignore]` for the E2E flows that depend on
features still scaffolded (Firefox real impl, Gmail IMAP real impl,
first-run preview worker).

---

## Known gaps (Phase 7.4a / 7.5 follow-up)

- Discovery CLI subcommand (`dataward discover`) not wired into `main.rs`
- Firefox `places.sqlite` importer — returns `NotImplemented`
- Gmail IMAP importer — requires `async-imap`, returns `NotImplemented`
- First-run preview worker action
- Discovery triage UI templates (routes return 503)
- Per-route dashboard rate limits on discovery endpoints
- Main status table `source_type`/`sensitivity` columns
- `migrate_v1_to_v2` auto-invocation from `open_db` (new installs get v2
  directly; auto-upgrade wiring deferred until a fixture v1 DB exists)
- NFC + `psl`-based eTLD+1 normalization (ASCII placeholder is in place)
- Scheduler lockout protection (per-domain 6h spacing, circuit breaker,
  3-attempt cap)
