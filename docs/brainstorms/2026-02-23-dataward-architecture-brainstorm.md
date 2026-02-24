---
title: "Dataward System Architecture"
date: 2026-02-23
status: decided
chosen_approach: "Rust + Patchright Hybrid"
tags: [architecture, rust, patchright, browser-automation, data-brokers, privacy]
related_solutions: []
feeds_into: "docs/plans/2026-02-23-standard-dataward-architecture-plan.md"
---

# Dataward Architecture Brainstorm

## Problem Space

### Core Problem

Build an open-source, locally-run daemon that automatically opts users out of 750+ data brokers to minimize their digital footprint. Must handle diverse opt-out mechanisms (web forms, email, APIs), run continuously with re-checks, and be maintainable by a community.

### Hard Constraints

- Runs locally (no cloud dependency, user controls their PII)
- Open source
- Must handle 3 opt-out channels: web forms, email, API/DROP
- PII encrypted at rest (AES-256-GCM, user-derived key via Argon2id)
- Must handle CAPTCHAs (at least partially automated)
- Community-contributable broker definitions
- Must support recurring re-checks (brokers re-list within 30-180 days)

### Soft Preferences

- "Best technology, not easiest" — optimize for correctness, performance, longevity
- Single-binary distribution preferred
- Minimal external dependencies at runtime

### Context

- Greenfield project, no existing code
- Commercial services (DeleteMe, Optery) validate the approach at $100-250/year
- California DROP platform (Aug 2026) will cover registered CA brokers via single API
- Patchright (Playwright fork) solves anti-detection for browser automation
- No mature open-source competitor exists

---

## Approaches

### Approach 1: Rust Monolith with Embedded CDP [REJECTED]

Single Rust binary — daemon, scheduler, state, and browser automation via CDP (`chromiumoxide`). Email via `lettre`, HTTP via `reqwest`, YAML via `serde`.

| Field | Value |
|-------|-------|
| **Pros** | Single binary, zero runtime deps, maximum memory efficiency |
| **Cons** | Rust CDP crates lag Playwright; anti-detection is DIY; smaller contributor pool; CAPTCHA pipeline needs Rust bindings |
| **Complexity** | High |
| **Risk** | High — immature browser automation ecosystem |
| **Effort** | 3-4 months to MVP |

### Approach 2: Rust Core + Patchright Workers (Hybrid) [CHOSEN]

Rust daemon handles scheduling, state (SQLite), CLI, embedded web dashboard, email opt-outs, and API calls. Browser automation delegated to Patchright (TypeScript) worker scripts invoked as subprocesses — one invocation per opt-out task. Broker playbooks are YAML files interpreted by a thin TypeScript runner that drives Patchright.

| Field | Value |
|-------|-------|
| **Pros** | Best tool for each job; clean failure isolation; Patchright solves anti-detection out of box; YAML playbooks accessible to wide contributor base; whisper.cpp Rust bindings for CAPTCHA |
| **Cons** | Two-language stack; subprocess coordination layer; distribution requires auto-downloading Patchright runtime on first run; contributors need awareness of both (though most touch YAML only) |
| **Complexity** | Medium-High |
| **Risk** | Medium — both ecosystems mature, integration boundary well-understood |
| **Effort** | 2-3 months to MVP |

#### Subprocess Protocol (Rust ↔ Patchright)

**Invocation:** Rust daemon spawns `node worker.js` and pipes the task payload as JSON via stdin (avoids shell escaping issues and OS arg length limits). One process per opt-out task (not a long-lived pool) — simplifies failure isolation and resource cleanup. Note: 750 brokers means 750 process spawns at ~2-5s each for Node + Chromium startup. This is acceptable for a background daemon (full run completes in hours regardless due to rate limiting and human-like delays). A worker pool with process reuse is a future optimization if startup overhead proves problematic.

**Input contract (Rust → Worker):**
```json
{
  "task_id": "uuid",
  "broker_id": "spokeo",
  "playbook_path": "playbooks/spokeo.yaml",
  "user_data": { "name": "...", "email": "...", "address": "..." },
  "timeout_ms": 120000,
  "captcha_strategy": "stealth_then_whisper"
}
```

**Output contract (Worker → Rust):**
```json
{
  "task_id": "uuid",
  "status": "success | failure | captcha_blocked | timeout",
  "proof": { "screenshot_path": "...", "confirmation_id": "..." },
  "error": { "code": "...", "message": "...", "retryable": true },
  "duration_ms": 8500
}
```

#### Playbook Schema (Broker Definitions)

YAML-based declarative playbooks define per-broker opt-out flows. Inspired by Privotron's schema with additions for verification and conditional logic.

**Core actions:** `navigate`, `fill`, `click`, `select`, `wait`, `screenshot`, `assert_text`, `if_exists`

**Example playbook (`playbooks/spokeo.yaml`):**
```yaml
broker:
  id: spokeo
  name: Spokeo
  url: https://www.spokeo.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form

required_fields: [first_name, last_name, email]

steps:
  - navigate: "https://www.spokeo.com/optout"
  - fill: { selector: "#first_name", field: "first_name" }
  - fill: { selector: "#last_name", field: "last_name" }
  - fill: { selector: "#email", field: "email" }
  - click: { selector: "#submit-btn" }
  - wait: { seconds: 3 }
  - if_exists:
      selector: ".captcha-container"
      then: { action: "captcha", type: "recaptcha_v2" }
  - assert_text: { selector: ".confirmation", contains: "request received" }
  - screenshot: { name: "confirmation" }
```

**Conditional flows** (`if_exists`) allow playbooks to handle variable page states (CAPTCHA shown/not shown, multiple result pages, verification modals). This keeps playbooks declarative while supporting the branching reality of broker opt-out flows.

**Failure handling:**
- Worker process killed after `timeout_ms` — Rust daemon records as timeout, schedules retry with backoff
- Browser crash → non-zero exit code → daemon records failure, retries
- Unsolvable CAPTCHA → worker returns `captcha_blocked` → daemon queues for manual resolution via web dashboard

#### Distribution Strategy

**Primary:** Single Rust binary that auto-downloads Patchright + Chromium on first run (similar to `playwright install`). The TypeScript worker source and playbook directory are bundled as a compressed archive within the binary, extracted to `~/.dataward/` on `dataward init`. User runs one command to set up everything.

**Secondary:** Docker image with everything pre-bundled for users who prefer containers.

**Tertiary:** Package manager formulae (Homebrew, AUR) for native OS integration.

### Approach 3: TypeScript Monolith via Bun

Entire system in TypeScript, compiled to single binary via `bun build --compile`. Patchright for browser automation, `better-sqlite3` for state, built-in Bun HTTP server for dashboard, `nodemailer` for email. Broker playbooks in YAML.

| Field | Value |
|-------|-------|
| **Pros** | Single language; lowest contributor barrier; Patchright first-class; Bun compiles to single binary; fastest MVP path |
| **Cons** | Bun --compile is new (edge cases with native modules); V8 memory overhead (50-150MB); no memory safety; GC pauses in daemon context |
| **Complexity** | Medium |
| **Risk** | Medium — Bun compilation maturity is main unknown |
| **Effort** | 1.5-2 months to MVP |

---

## Comparison Matrix

| Criteria | Rust Monolith | Rust + Patchright | TS/Bun Monolith |
|---|---|---|---|
| Complexity | High | Medium-High | Medium |
| Risk | High | Medium | Medium |
| Effort to MVP | 3-4 months | 2-3 months | 1.5-2 months |
| Daemon stability | Excellent | Excellent | Good |
| Browser automation | Poor | Excellent | Excellent |
| Anti-detection | DIY (risky) | Battle-tested | Battle-tested |
| Distribution | Single binary | Binary + auto-download | Single binary (Bun) |
| Memory efficiency | Excellent (5-10MB) | Good (5MB + worker) | Fair (50-150MB) |
| Community contribution | Hard | Medium | Easy |
| Long-term stability | Excellent | Excellent | Good |
| CAPTCHA pipeline | Hard | Good | Good |
| "Best tech" alignment | Partial | Yes | Partial |

---

## Decision

**Chosen: Approach 2 — Rust + Patchright Hybrid**

**Rationale:** Only approach that doesn't compromise on either daemon runtime or browser automation ecosystem. The two-language cost is real but bounded: Rust owns the daemon, Patchright owns the browser, YAML playbooks are what contributors actually touch.

### Rejected Alternatives

- **Rust Monolith:** Browser automation ecosystem too immature. Would spend months rebuilding what Patchright gives for free. High risk of brittle, hard-to-maintain anti-detection code.
- **TypeScript/Bun Monolith:** Pragmatic but not "best tech." Memory overhead and GC pauses are real concerns for a daemon running 24/7. Bun compilation maturity is uncertain for native modules.

---

## Key Open Questions

These must be resolved during planning — they represent the hardest unsolved problems:

1. **CAPTCHA viability** — Google has been restricting reCAPTCHA audio challenges, which undermines the Whisper-based local solving pipeline. Need to prototype against current reCAPTCHA v2 to validate. Fallback plan: optional integration with external CAPTCHA-solving APIs (2Captcha, CapSolver) and a manual-solve queue in the web dashboard.

2. **Playbook maintenance burden** — Data brokers change their opt-out forms frequently. Commercial services employ dedicated teams for this. An open-source project depends on community contributions. Mitigation strategies to evaluate: visual regression detection (screenshot diff to detect broken playbooks), structured error reporting that identifies which playbook step failed, and a community contribution workflow that's as frictionless as possible.

3. **Email sender identity** — Opt-out emails need a "from" address. Options: (a) user provides their own SMTP credentials (exposes their real email), (b) daemon generates disposable email addresses via a self-hosted service, (c) user registers a dedicated opt-out email. Each has privacy and deliverability tradeoffs.

4. **Broker deduplication** — Many people-search sites share backend infrastructure (e.g., PeopleConnect owns multiple brands). Opting out of one may cover others. Need to research and map these relationships to avoid redundant opt-outs and accurately track coverage.

5. **DROP API integration** — California's DROP platform launches Aug 2026 with mandatory broker participation. The technical API spec is not yet public. This could eventually replace individual browser automation for CA-registered brokers but timeline and API design are unknown.

6. **Web dashboard scope** — Is the embedded web UI read-only monitoring (status, history, logs) or interactive (manual CAPTCHA solving queue, trigger ad-hoc runs, edit configuration)? Interactive is more useful but increases attack surface on localhost and development effort.

7. **Patchright dependency risk** — Patchright is maintained by a small team (Vinyzu + Kaliiiiiiiiii). If the project goes unmaintained, the fallback is vanilla Playwright with `playwright-extra` stealth plugin or `rebrowser-patches`. The worker layer should be designed so swapping the automation library requires changing only the browser initialization code, not every playbook.
