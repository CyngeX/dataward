---
title: "Phase 5: Distribution + Initial Broker Playbooks"
date: 2026-03-01
type: comprehensive
status: in_progress
issue: 5
tags: [distribution, playbooks, auto-download, release-pipeline, docker]
risk_flags: [SECURITY_SENSITIVE]
confidence: MEDIUM_CONFIDENCE
deepened: true
deepened_date: 2026-03-01
research_agents: [codebase-researcher, learnings-researcher, best-practices-researcher]
review_agents: [architecture-reviewer, simplicity-reviewer, security-reviewer, performance-reviewer, edge-case-reviewer, spec-flow-reviewer]
---

# Phase 5: Distribution + Initial Broker Playbooks

## Problem

Dataward's core engine (scheduler, orchestrator, worker, dashboard) is complete but has no distribution story. Users can't install it without building from source. No playbooks are shipped, so even a built binary has no brokers to opt out from. The worker requires Node.js + Patchright + Chromium, which need to be auto-provisioned.

## Goals

1. `dataward init` auto-downloads Patchright + Chromium with SHA-256 checksum verification
2. Ship initial broker playbooks for 10+ data brokers across 3 tiers (basic, CAPTCHA, manual-only)
3. Release pipeline producing Linux + macOS binaries with worker source
4. ~~Docker image as an alternative distribution path~~ **[DEEPENED] DEFERRED** — no demonstrated user need; Chromium-in-Docker is complex (sandbox flags, UID mapping); revisit when requested
5. ~~Contributor guide documenting the playbook schema and submission process~~ **[DEEPENED] DEFERRED** — no external contributors yet; write when first contributor appears

## Technical Approach

### Auto-Download System (Step 29)

- Add a `download` module (`src/download.rs`) with streaming download + SHA-256 verification
- Patchright + Chromium are installed via `npx patchright install chromium` — this is the official mechanism and handles platform detection
- **[DEEPENED]** Pin exact Patchright version: `npx patchright@1.49.1 install chromium` — prevents supply chain attacks from unpinned npm resolution (SEC-001)
- **[DEEPENED]** After `npx patchright install`, verify the Chromium binary actually exists on disk — do not trust exit code alone (EC-008)
- The init flow needs: (1) check Node.js is available, (2) extract embedded worker source to `~/.dataward/worker/`, (3) run `npm ci --production` in the worker dir, (4) run `npx patchright@<pinned> install chromium`, (5) verify the Chromium binary exists
- **[DEEPENED]** Use `npm ci` instead of `npm install` for deterministic installs from lockfile (SEC-002)
- Use reqwest for streaming downloads with progress feedback to stderr
- **[DEEPENED]** SHA-256 must use streaming digest (BufReader chunks) — never load entire file into memory (PERF-002)
- Apply atomic file operations pattern from learnings: download to `.tmp` **in same directory as target** (same mount point guarantees atomic rename) (PERF-006), verify checksum, atomic rename
- Apply path traversal defense from learnings: validate all extracted paths stay within `~/.dataward/`
- **[DEEPENED]** Reject symlinks and hardlinks in tarball entirely (EC-014)
- **[DEEPENED]** Use `scopeguard` or Drop guard to clean up `.tmp` on any early exit/panic (EC-003)

### Worker Source Embedding (Step 31) [DEEPENED — REVISED]

**Original:** build.rs embeds worker/dist/ + node_modules/ + package.json as tarball via `include_bytes!`

**Revised (consensus from 4 review agents):** Embedding node_modules (50-200MB) in the binary is problematic:
- Bloats binary by 50-200MB (PERF-001)
- Every running instance maps the blob into memory (PERF-001)
- Couples Rust build to npm ecosystem — `build.rs` requires Node.js (ARCH-002)
- Makes worker independently non-patchable (SIMP-001)

**New approach:** Embed only worker source (worker/dist/ + package.json + package-lock.json) — this is <1MB compressed. Run `npm ci --production` at init time to install dependencies. This:
- Keeps binary small (<20MB total)
- Decouples Rust and Node.js builds
- Lets users patch worker JS without rebuilding Rust
- Lockfile guarantees deterministic dependency resolution

**Build script (`build.rs`):** Compiles TypeScript (`npm run build` in worker/), creates compressed tarball of `worker/dist/` + `worker/package.json` + `worker/package-lock.json`. Embedded via `include_bytes!`. No node_modules.

**[DEEPENED]** Version sentinel: embed a content hash of the tarball alongside it. On init, write `.worker-version` file after successful extraction. On subsequent runs, compare embedded hash vs sentinel — re-extract if they differ (ARCH-009, EC-004, PERF-005).

**[DEEPENED]** Extraction lock: acquire exclusive file lock (`data_dir/.init-lock`) during extraction to prevent concurrent init corruption (EC-005, ARCH-004).

- The `find_worker_script()` function (`subprocess.rs:264`) already searches relative to data_dir — needs a new search path at `data_dir/worker/dist/worker.js`
- **[DEEPENED]** Define explicit precedence: (1) `DATAWARD_WORKER_PATH` env override, (2) adjacent `worker/dist/worker.js` (development), (3) `data_dir/worker/dist/worker.js` (production). Log which path selected at startup (ARCH-005).

### Playbooks (Step 30)

- Write YAML playbooks following the existing schema in `broker_registry.rs`
- **[DEEPENED] Reduced initial scope from 10 to 3-5 representative playbooks** — validate the format and execution pipeline before scaling to all 10. Avoids rewriting if structural issues emerge (SIMP-007).
  - Phase 5a: 2-3 basic-form brokers (TruePeopleSearch, Radaris, FastPeopleSearch)
  - Phase 5b (follow-up): remaining basic-form + CAPTCHA-tier + manual-only
- Playbooks go in `playbooks/official/` — **[DEEPENED] extracted separately from worker** to `data_dir/playbooks/official/`, not embedded in worker tarball. Separates "what to automate" from "automation runtime" (ARCH-007).
- Each playbook needs: broker metadata, required_fields, steps with real selectors, allowed_domains
- **Important:** Selectors require research against live broker pages. Playbooks will be written with best-available selectors and marked with `# TODO: verify selectors` where uncertain
- **[DEEPENED]** Add `last_verified_date` field to playbook YAML metadata for staleness tracking (FLOW-013)
- **[DEEPENED]** Add `dataward playbook validate <file>` CLI subcommand — runs broker_registry validation on a single file and reports errors (FLOW-004)
- **[DEEPENED]** After loading all playbooks, assert count > 0. If zero valid playbooks, warn prominently at startup: "No valid playbooks found — check playbook directory" (EC-013, FLOW-007)

### Release Pipeline (Step 31)

- GitHub Actions workflow (`.github/workflows/release.yml`)
- Trigger: tag push (`v*`)
- **[DEEPENED] Start with single target: `x86_64-unknown-linux-gnu`** — validate the pipeline works before expanding. Add macOS targets as follow-up (SIMP-005).
- Steps: checkout → install Node.js → build worker → create tarball → build Rust → **verify tarball non-empty (FLOW-009)** → create GitHub release with artifacts
- **[DEEPENED]** Publish `SHA256SUMS` file alongside release binaries (FLOW-010)
- **[DEEPENED]** Verify tagged commit is on main branch before building (SEC-009)
- **[DEEPENED]** Add `aarch64-unknown-linux-gnu` to matrix (ARCH-010 — servers/Raspberry Pi)

### ~~Docker (Step 32)~~ [DEEPENED — DEFERRED]

~~Multi-stage build: Node.js stage builds worker, Rust stage builds binary, runtime stage has Node.js + Chromium deps~~

**Deferred.** Rationale:
- No demonstrated user need for containerized deployment (SIMP-002)
- Chromium-in-Docker requires `--no-sandbox` or `SYS_ADMIN` capability, adding security complexity (FLOW-003)
- Docker port binding defaults to 0.0.0.0, bypassing localhost-only assumption (SEC-007)
- UID/GID mismatch on volume mounts is a common pain point (FLOW-015)
- Adds ongoing maintenance surface to CI

**Revisit when:** a user requests Docker support, or the project reaches a maturity level where containerized deployment is expected.

### ~~Contributor Guide (Step 33)~~ [DEEPENED — DEFERRED]

~~CONTRIBUTING.md section on playbook authoring~~

**Deferred.** Rationale: no external contributors exist yet. Writing contributor docs for conventions that haven't stabilized creates maintenance burden with zero current payoff (SIMP-004). Instead:
- Add `dataward playbook validate` command (covers the contributor's primary need)
- Write CONTRIBUTING.md when the first external contributor appears or the project is publicly announced

## Implementation Steps [DEEPENED — REVISED]

| # | Step | Files | Size |
|---|------|-------|------|
| 1 | Add `src/download.rs` — streaming SHA-256 verification, progress output, atomic writes with scopeguard cleanup | `src/download.rs` | M |
| 2 | Add `src/worker_setup.rs` — tarball extraction with path traversal defense, sentinel versioning, init lock, Node.js detection, Patchright install + verify | `src/worker_setup.rs` | L |
| 3 | Add `build.rs` — compile worker TypeScript, create compressed tarball of dist + package.json + lockfile (NO node_modules), embed via include_bytes! | `build.rs`, `Cargo.toml` | M |
| 4 | Update `src/init.rs` — integrate worker_setup between config write and playbook loading | `src/init.rs` | M |
| 5 | Update `src/subprocess.rs` — explicit 3-tier path precedence for find_worker_script, log selected path | `src/subprocess.rs` | S |
| 6 | Add `dataward playbook validate` CLI subcommand | `src/main.rs`, `src/broker_registry.rs` | S |
| 7 | Write 3 basic-form broker playbooks (TruePeopleSearch, Radaris, FastPeopleSearch) with last_verified_date | `playbooks/official/*.yaml` | M |
| 8 | Create GitHub Actions release workflow (x86_64-linux initially, with SHA256SUMS) | `.github/workflows/release.yml` | M |
| 9 | Add unit + integration tests for download, extraction, path traversal, sentinel, lock | `src/download.rs`, `src/worker_setup.rs` (tests) | M |

## Affected Files

### New files

- `src/download.rs` — streaming download + SHA-256 verification module
- `src/worker_setup.rs` — tarball extraction, Node.js detection, Patchright install, sentinel versioning
- `build.rs` — build script for worker source tarball (no node_modules)
- `playbooks/official/*.yaml` — 3 broker playbooks (initial batch)
- `.github/workflows/release.yml` — release pipeline

### Modified files

- `Cargo.toml` — add `flate2`, `tar` dependencies; configure build script
- `src/main.rs` — add `playbook validate` subcommand, wire up worker_setup
- `src/init.rs` — integrate worker setup step
- `src/subprocess.rs` — explicit 3-tier path precedence for find_worker_script
- `src/broker_registry.rs` — expose validation for single-file CLI command

## Spec-Flow Analysis [DEEPENED]

### Flow 1: `dataward init` (new install)

1. Create data dir → 2. Passphrase → 3. Create DB → 4. Collect PII → 5. SMTP config → 6. Auth token → 7. Write config → 8. **Acquire init lock** → 9. **Check Node.js (version + path)** → 10. **Extract worker source tarball** → 11. **Run `npm ci --production`** → 12. **Run `npx patchright@<pinned> install chromium`** → 13. **Verify Chromium binary exists** → 14. **Write `.worker-version` sentinel** → 15. **Release init lock** → 16. Create playbook dirs → 17. **Extract official playbooks** → 18. Load & sync playbooks → 19. Done

| State | Handling |
|-------|----------|
| Happy path | All steps succeed, sentinel written, playbooks loaded |
| Node.js missing | **[DEEPENED]** Clear error: "Node.js >= 18 required. Install from https://nodejs.org" with platform-specific instructions. Abort before any extraction. |
| Node.js wrong version | **[DEEPENED]** Check `node --version` >= 18. Error with current vs required version. |
| Network failure (npm ci) | Retry with backoff (3 attempts, 5s/15s/30s), then: "Network error during dependency install. Check connection and retry `dataward init`." |
| Network failure (Chromium) | **[DEEPENED]** Same retry pattern. On final failure: "Chromium download failed. Manual install: `cd ~/.dataward/worker && npx patchright@1.49.1 install chromium`" (FLOW-006) |
| Checksum mismatch | Abort with "tampered download" warning, delete artifact |
| Disk full | **[DEEPENED]** Clean up `.tmp` via scopeguard. Report remaining space if available via `statvfs`. Suggest minimum required space (~200MB for Chromium) (EC-010). |
| Re-init after partial | **[DEEPENED]** Check sentinel file. Absent = re-extract. Present but version mismatch = re-extract. Present and matching = skip extraction (PERF-005). |
| Concurrent init | **[DEEPENED]** Second process hits lock file, exits with "Init already in progress" (EC-005). |
| Corrupt embedded tarball | **[DEEPENED]** SHA-256 of embedded bytes fails pre-extraction check. Fatal error — binary is corrupt, re-download (FLOW-005). |
| npx exits 0 but Chromium missing | **[DEEPENED]** Post-install binary check catches this. Error: "Patchright reported success but Chromium binary not found at <path>" (EC-008). |

### Flow 2: `dataward run` (with playbooks)

| State | Handling |
|-------|----------|
| Zero valid playbooks | **[DEEPENED]** Warn prominently: "No valid playbooks found in <dir>. Add playbooks and restart." Do not silently run with empty set (FLOW-007). |
| Worker script not found | **[DEEPENED]** Error: "Worker not installed. Run `dataward init` to set up." Log which paths were checked (ARCH-005). |
| Stale playbook (selector changed) | **[DEEPENED]** Worker reports step failure with step_index. Dashboard shows failed step. `last_verified_date` in playbook metadata helps triage (FLOW-013). |

### Flow 3: Release build (CI)

1. Tag push triggers → 2. **Verify tag is on main** → 3. Install Node.js → 4. Build worker (`npm ci && npm run build`) → 5. Create tarball → 6. **Verify tarball non-empty** → 7. Build Rust → 8. **Generate SHA256SUMS** → 9. Upload artifacts + SHA256SUMS → 10. Create GitHub release

### Flow 4: Playbook validation (contributor)

1. Write YAML file → 2. Run `dataward playbook validate broker.yaml` → 3. See pass/fail with specific field-level errors → 4. Fix and re-validate → 5. Submit PR

## Acceptance Criteria [DEEPENED]

- [ ] `dataward init` extracts embedded worker source and runs `npm ci --production`
- [ ] `dataward init` installs Patchright + Chromium via pinned version
- [ ] `dataward init` verifies Chromium binary exists after install
- [ ] Download failure produces clear error with **specific manual install command** (not just "manual instructions")
- [ ] Node.js absence detected early with actionable error message including version requirement
- [ ] SHA-256 checksum verification on worker tarball extraction (streaming digest, not in-memory)
- [ ] Path traversal defense rejects `../` paths and symlinks in tarball
- [ ] `.worker-version` sentinel written after successful extraction
- [ ] Concurrent init attempts handled via lock file
- [ ] `.tmp` artifacts cleaned up on failure via scopeguard
- [ ] At least 3 official broker playbooks pass schema validation
- [ ] `dataward playbook validate <file>` CLI command works
- [ ] `find_worker_script` uses explicit 3-tier precedence and logs selected path
- [ ] Release pipeline produces x86_64-linux binary with SHA256SUMS
- [ ] All new code has unit tests
- [ ] Zero valid playbooks at startup produces a warning (not silent no-op)

## Security Considerations [DEEPENED]

- Worker source tarball checksum embedded at compile time — no MITM on extraction
- **[DEEPENED]** Patchright version pinned (`@1.49.1`) to prevent supply chain attacks from unpinned npm resolution (SEC-001)
- **[DEEPENED]** `npm ci` (not `npm install`) ensures deterministic installs from lockfile (SEC-002)
- **[DEEPENED]** Tarball extraction validates every path: canonicalize and assert `starts_with(target_dir)`. Reject symlinks and hardlinks entirely (SEC-003, EC-002, EC-014)
- **[DEEPENED]** SHA-256 comparison should use constant-time comparison to prevent timing attacks (SEC-014, learnings: constant-time-comparison)
- Community playbook checksums (`.checksums` file) verify integrity
- Playbook validation (existing `broker_registry.rs`) rejects malicious URLs, enforces domain allowlists
- **[DEEPENED]** serde_yaml with `deny_unknown_fields` already used — protects against YAML deserialization attacks (SEC-006 — already mitigated)
- Downloaded Chromium binary permissions restricted (0700)
- **[DEEPENED]** Node.js prerequisite is a conscious architectural decision, documented as such. Version >= 18 required (ARCH-001)
- **[DEEPENED]** GitHub Actions release: verify tagged commit is on main before building; publish SHA256SUMS (SEC-009, FLOW-010)

## Risks [DEEPENED]

| Risk | Severity | Mitigation |
|------|----------|------------|
| Broker selectors change frequently | HIGH | `last_verified_date` in playbook metadata; start with 3 playbooks to validate before scaling |
| Patchright install mechanism changes | MEDIUM | Abstract behind `install_browser()` function, easy to swap; pin version |
| **[DEEPENED]** npm ci requires network at init time | MEDIUM | Clear error message with retry. Offline mode deferred — most users have internet during setup. |
| Node.js not installed on user machine | MEDIUM | Documented prerequisite. Clear error with version requirement and install link. Check early in init. |
| **[DEEPENED]** Patchright npm package compromised | LOW | Version pinned. Lockfile integrity verified by npm ci. Build uses npm ci not npm install. |
| Cross-compilation issues (SQLCipher) | LOW | rusqlite uses bundled-sqlcipher (pure C, no system deps). lettre uses rustls (pure Rust). No OpenSSL needed. |

## Test Strategy [DEEPENED]

- Unit tests: `download.rs` — streaming checksum verification (correct hash, wrong hash, truncated file, empty file)
- Unit tests: `worker_setup.rs` — path traversal defense (reject `../`, reject symlinks, reject absolute paths)
- Unit tests: `worker_setup.rs` — sentinel versioning (write, read, compare, re-extract on mismatch)
- Unit tests: `worker_setup.rs` — scopeguard cleanup (simulate failure mid-extraction, verify .tmp removed)
- Unit tests: `worker_setup.rs` — init lock (acquire, release, detect held lock)
- Integration tests: `find_worker_script` with explicit 3-tier precedence
- Integration tests: `dataward playbook validate` CLI command (valid file, invalid file, missing file)
- Playbook validation: all shipped playbooks pass `broker_registry::load_playbooks()`
- **[DEEPENED]** Test with non-ASCII data_dir path (spaces, unicode) to verify PathBuf handling (EC-009)

## Past Learnings Applied

- **Atomic file operations** → download to `.tmp` in same directory, verify, rename (from `atomic-file-ops-crash-recovery`)
- **Path traversal defense** → canonicalize + `starts_with(base + sep)` on every extracted entry (from `path-traversal-defense-patterns`)
- **setTimeout overflow** → clamp playbook timeouts in worker (from `settimeout-32bit-overflow-node`)
- **[DEEPENED]** Constant-time comparison → SHA-256 checksum comparison uses `subtle::ConstantTimeEq` (from `constant-time-comparison-length-leak`)

## Alternatives Considered

### Embed Node.js in binary (rejected)
Could bundle a Node.js binary to eliminate the Node.js prerequisite. Rejected because it adds 40-80MB to binary size and complicates cross-compilation. Node.js is widely installed; requiring it is reasonable. **[DEEPENED]** This is a conscious decision — Node.js >= 18 is documented as a prerequisite (ARCH-001).

### Embed node_modules in binary (rejected) [DEEPENED]
Original plan embedded worker/dist + node_modules + package.json (50-200MB) via include_bytes!. Rejected after review: bloats binary, inflates RSS, couples Rust build to npm, makes worker non-patchable. New approach: embed only source (<1MB), run `npm ci` at init time. Four review agents flagged this independently (ARCH-002, SIMP-001, PERF-001, PERF-004).

### Download worker at runtime instead of embedding (deferred)
Could download the worker tarball from GitHub releases instead of embedding in the binary. This reduces binary size further but adds a network dependency on first run and requires hosting infrastructure. Deferred — current approach (embed source, npm ci at init) is a good middle ground.

### Use playwright instead of patchright (rejected)
Standard Playwright lacks anti-detection features. Patchright is a maintained fork specifically for stealth browser automation. The brainstorm decision (Approach 2) chose Patchright for this reason.

### Docker image (deferred) [DEEPENED]
Deferred until user demand exists. Chromium-in-Docker requires sandbox flag workarounds, port binding defaults to 0.0.0.0, and UID/GID mapping on volumes is a common pain point. Not worth the maintenance burden at this stage (SIMP-002, SEC-007, FLOW-003, FLOW-015).

---

## Enhancement Summary [DEEPENED]

**Research agents:** 3 (codebase, learnings, best-practices)
**Review agents:** 6 (architecture, simplicity, security, performance, edge-case, spec-flow)
**Total findings:** 65+ across all agents

### Key Changes from Deepening

| Change | Source | Impact |
|--------|--------|--------|
| Don't embed node_modules — embed source only, npm ci at init | ARCH-002, SIMP-001, PERF-001, PERF-004 | Binary drops from ~200MB to <20MB |
| Pin Patchright version in npx call | SEC-001 | Supply chain defense |
| Use npm ci instead of npm install | SEC-002 | Deterministic, auditable installs |
| Add sentinel file for extraction versioning | ARCH-009, EC-004, PERF-005 | Reliable upgrade detection |
| Add init lock file | EC-005, ARCH-004 | Prevent concurrent init corruption |
| Add scopeguard for .tmp cleanup | EC-003 | No orphaned files on failure |
| Verify Chromium binary after npx install | EC-008 | Don't trust exit code alone |
| Reject symlinks in tarball | EC-014, SEC-003 | Path traversal defense |
| Defer Docker, contributor guide | SIMP-002, SIMP-004 | Scope reduction — ship faster |
| Reduce initial playbooks from 10 to 3 | SIMP-007 | Validate format before scaling |
| Start CI with 1 target, not 3 | SIMP-005 | Validate pipeline before expanding |
| Add `dataward playbook validate` command | FLOW-004 | Contributor self-validation |
| Add SHA256SUMS to releases | FLOW-010 | Binary integrity verification |
| Stream SHA-256 digest | PERF-002 | Avoid 150MB heap allocation |
| Temp files in same directory as target | PERF-006 | Guarantee atomic rename |

### Deferred Items (Documented for Future Phases)
- Docker image (when user demand exists)
- Contributor guide (when first external contributor appears)
- Remaining 7 playbooks (after initial 3 validate successfully)
- macOS CI targets (after Linux pipeline validates)
- aarch64-linux CI target (after x86_64 validates)
- Worker subprocess sandboxing beyond env_clear (SEC-004 — significant scope, separate issue)
- Community playbook cryptographic signatures (SEC-005 — when community tier is active)
