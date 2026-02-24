---
type: standard
title: "Phase 2: TypeScript Patchright Worker Subprocess"
date: 2026-02-24
status: in_progress
security_sensitive: false
priority: high
github_issue: 2
parent_plan: "docs/plans/1-2026-02-23-comprehensive-dataward-architecture-plan.md"
---

# Plan: Phase 2 — TypeScript Patchright Worker Subprocess

## Problem

Dataward needs a browser automation engine to execute opt-out playbooks against data broker websites. The Rust daemon handles scheduling, state management, and encryption, but cannot drive a real browser. A subprocess worker is needed that launches Chromium via Patchright (anti-detection Playwright fork), accepts tasks over a JSON-lines protocol, and executes the 6 MVP action types in isolated browser contexts.

## Goals

- Long-lived worker process that launches Chromium once and reuses it across tasks
- Fresh browser context per task for cookie/state isolation (~50MB vs ~500MB for new instance)
- JSON-lines IPC protocol over stdin/stdout for Rust <-> TypeScript communication
- All 6 MVP action types functional: navigate, fill, click, select, wait, screenshot
- Domain allowlist enforcement — block navigation to non-allowed domains
- Categorized error codes matching the Rust-side schema
- Graceful shutdown on command

## Solution

Create a TypeScript project under `worker/` that uses Patchright (drop-in Playwright replacement with anti-detection patches). The worker is a single long-lived Node.js process:

1. **Startup**: Launch Chromium via `patchright.chromium.launch()`, begin reading stdin
2. **Task handling**: Parse each JSON line from stdin, create a fresh `BrowserContext`, load the playbook YAML, execute steps sequentially via an interpreter, capture proof screenshots, destroy context
3. **Result reporting**: Write a JSON result line to stdout for each completed task
4. **Shutdown**: On `{"command": "shutdown"}`, close browser and exit cleanly

## Technical Approach

### Architecture

```
Rust Daemon (Phase 3)          TypeScript Worker (Phase 2)
+-----------------+            +----------------------+
| stdin --JSON-->  |---pipe--->| readline             |
|                  |            |   |                  |
|                  |            | TaskRouter            |
|                  |            |   |                  |
|                  |            | PlaybookInterpreter   |
|                  |            |   |                  |
|  <--JSON-- stdout|<--pipe----|BrowserContext(actions) |
+-----------------+            +----------------------+
```

### JSON-Lines Protocol

**Input (stdin, one JSON per line):**
```json
{"task_id":"uuid","broker_id":"spokeo","playbook_path":"playbooks/official/spokeo.yaml","user_data":{"first_name":"...","email":"..."},"timeout_ms":120000,"proof_dir":"proofs/spokeo/","allowed_domains":["spokeo.com","www.spokeo.com"]}
```

**Shutdown command:**
```json
{"command":"shutdown"}
```

**Output (stdout, one JSON per line):**
```json
{"task_id":"uuid","status":"success","proof":{"screenshot_path":"proofs/spokeo/2026-02-24-confirmation.png","confirmation_text":"Your request has been received"},"duration_ms":8500}
```

**Status values:** `success`, `failure`, `captcha_blocked`, `timeout`, `playbook_error`, `domain_violation`

### Domain Enforcement

Use Patchright's `page.route('**/*', handler)` to intercept all requests. For `navigate` actions, parse the target URL and verify the hostname matches one of the task's `allowed_domains`. Block non-matching navigations immediately with status `domain_violation`. Also intercept page-level navigations triggered by JavaScript redirects.

### Action Implementation

| Action | Patchright API | Notes |
|--------|---------------|-------|
| `navigate` | `page.goto(url, {timeout, waitUntil: 'networkidle'})` | Domain check before execution |
| `fill` | `page.fill(selector, value)` | Value from `user_data[field]` |
| `click` | `page.click(selector)` | Standard click with auto-wait |
| `select` | `page.selectOption(selector, value)` | Dropdown selection |
| `wait` | `page.waitForTimeout(seconds * 1000)` | Max 30s enforced by Rust validation |
| `screenshot` | `page.screenshot({path, fullPage: true})` | Saved to `proof_dir/{name}.png` |

### Error Categorization

Map Playwright errors to the Rust-side error_code enum:

| Condition | Error Code | Retryable |
|-----------|-----------|-----------|
| `page.waitForSelector` times out | `selector_not_found` | Yes |
| Page DOM doesn't match expected structure | `page_structure_changed` | No |
| Navigate URL not in allowed_domains | `domain_violation` | No |
| Unexpected redirect to non-allowed domain | `unexpected_navigation` | No |
| Task exceeds timeout_ms | `timeout` | Yes |
| CAPTCHA element detected | `captcha_blocked` | No |

### Playbook Loading

The worker reads YAML playbooks directly (using `js-yaml`). The Rust side already validates playbooks at load time, so the worker can trust the structure. However, the worker still validates `allowed_domains` at runtime since the playbook file could be modified between Rust validation and worker execution.

### stdout Discipline

All diagnostic output (logs, errors) goes to **stderr** via `console.error()`. Only JSON result lines go to stdout via `process.stdout.write(JSON.stringify(result) + '\n')`. This is critical — any non-JSON stdout corrupts the IPC protocol.

## Implementation Steps

1. **Initialize TypeScript project** — Create `worker/` directory with `package.json` (patchright, js-yaml, typescript, vitest), `tsconfig.json` (strict mode, ES2022 target, NodeNext modules)

2. **Define types** — `worker/src/types.ts`: TaskInput, TaskResult, PlaybookDefinition, PlaybookStep (matching Rust-side schema), ErrorCode enum, StatusCode enum

3. **Implement action handlers** — `worker/src/actions.ts`: Individual functions for each of the 6 action types. Each accepts a Patchright `Page` and action params, returns void or throws a categorized error.

4. **Implement domain enforcer** — `worker/src/domain.ts`: Sets up `page.route()` interception, validates navigation URLs against allowed_domains list, blocks violations.

5. **Implement playbook interpreter** — `worker/src/interpreter.ts`: Loads YAML playbook, iterates steps, calls action handlers, captures screenshots to proof_dir, handles per-step errors with step index tracking.

6. **Implement worker main loop** — `worker/src/worker.ts`: Launches Chromium, reads stdin via readline, routes tasks to interpreter with fresh browser context, writes results to stdout, handles shutdown command.

7. **Add comprehensive tests** — `worker/src/tests/`: Test each action type (mock page), domain enforcement, error categorization, multi-task session lifecycle, shutdown behavior.

8. **Build configuration** — Add build script to compile TypeScript to JavaScript, configure for Rust daemon to spawn `node worker/dist/worker.js`.

## Affected Files

### New Files (worker/ directory)
- `worker/package.json` — Dependencies: patchright, js-yaml, typescript, vitest
- `worker/tsconfig.json` — Strict TypeScript config
- `worker/src/types.ts` — Shared type definitions matching Rust schema
- `worker/src/actions.ts` — 6 MVP action handler functions
- `worker/src/domain.ts` — Domain allowlist enforcement via route interception
- `worker/src/interpreter.ts` — Playbook step executor with error categorization
- `worker/src/worker.ts` — Main entry: Chromium lifecycle, JSON-lines IPC, shutdown
- `worker/src/tests/actions.test.ts` — Action handler unit tests
- `worker/src/tests/domain.test.ts` — Domain enforcement tests
- `worker/src/tests/interpreter.test.ts` — Playbook execution tests
- `worker/src/tests/worker.test.ts` — Integration: multi-task, shutdown, error flows

### Modified Files
- `.gitignore` — Add `worker/node_modules/`, `worker/dist/`

## Acceptance Criteria

- [ ] Worker launches Chromium once, accepts multiple tasks over stdin
- [ ] Fresh browser context created per task, destroyed after completion
- [ ] All 6 action types functional: navigate, fill, click, select, wait, screenshot
- [ ] Domain allowlist enforced — navigate to non-allowed domain returns `domain_violation`
- [ ] Error codes categorized with step index
- [ ] Graceful shutdown on `{"command": "shutdown"}`
- [ ] Worker tests: each action type, domain enforcement, error categorization, multi-task sessions
- [ ] All diagnostic output to stderr, only JSON results to stdout
- [ ] TypeScript strict mode with no type errors
- [ ] Build produces runnable `worker/dist/worker.js`

## Test Strategy

**Unit tests (actions.test.ts):**
- `navigate`: valid URL succeeds, non-allowed domain returns domain_violation, non-HTTPS blocked
- `fill`: fills selector with value from user_data, missing selector throws selector_not_found
- `click`: clicks selector, missing selector throws selector_not_found
- `select`: selects option by value, missing selector throws
- `wait`: waits specified seconds (verify with timing), max 30s
- `screenshot`: captures to proof_dir with correct filename

**Domain enforcement tests (domain.test.ts):**
- Allowed domain passes through
- Non-allowed domain blocked with domain_violation
- Subdomain handling: `www.spokeo.com` allowed when `spokeo.com` in list (exact match only, not suffix)
- JavaScript redirect to non-allowed domain caught

**Interpreter tests (interpreter.test.ts):**
- Full playbook executes all steps in order
- Step failure returns error with step_index
- on_error: "retry" retries failed step (up to max_retries)
- on_error: "skip" continues to next step
- on_error: "fail" aborts playbook immediately
- Timeout_ms kills execution and returns timeout status

**Integration tests (worker.test.ts):**
- Send task via stdin, receive result via stdout
- Multiple sequential tasks reuse same Chromium instance
- Shutdown command closes browser and exits process
- Malformed JSON input produces error result, doesn't crash worker
- Task timeout produces timeout result with correct task_id

## Security Review

- [ ] No hardcoded secrets — worker receives only filtered user_data
- [ ] Domain allowlist enforced at worker level (defense-in-depth, Rust also validates)
- [ ] stdout discipline — no PII leaks to stdout (only structured JSON results)
- [ ] stderr used for diagnostics — may contain URLs but no user_data values
- [ ] Environment isolation — worker does not read env vars for secrets
- [ ] Proof screenshots contain PII (user data visible on screen) — Rust encrypts them after worker produces them
- [ ] No user_data logged to stderr in plaintext

## Past Learnings Applied

- (None found — docs/solutions/ doesn't exist yet. This is the first TypeScript component.)

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Patchright API diverges from Playwright | Low | Medium | Pin patchright version; API is currently identical to Playwright |
| Chromium memory leak on long sessions | Medium | Medium | Monitor RSS; if > 2GB, recycle browser (close + relaunch) |
| Broker sites detect automation despite Patchright | Medium | High | Patchright patches navigator.webdriver and CDP detection; add realistic viewport/user-agent; accept some sites may still block |
| JSON-lines parsing error corrupts IPC stream | Low | High | Wrap every stdin parse in try/catch; never let exceptions reach stdout; validate JSON before writing |
| Test flakiness with real browser | Medium | Low | Use mocked Page objects for unit tests; real browser only for integration tests with controlled test server |

## Spec-Flow Analysis

### Primary Flow: Execute Opt-Out Task
1. Worker receives JSON task on stdin -> Success: parse task | Error: malformed JSON -> write error result, continue reading
2. Create fresh BrowserContext -> Success: context ready | Error: browser crashed -> restart Chromium, report failure
3. Load playbook YAML from playbook_path -> Success: steps parsed | Error: file not found / invalid -> report playbook_error
4. Set up domain enforcement route handler -> Success: interception active
5. Execute each step sequentially -> Success: step complete | Error: per error_code table above -> categorize, include step_index
6. Capture proof screenshot -> Success: saved to proof_dir | Error: screenshot failed -> set proof_missing flag, still report success if opt-out completed
7. Destroy browser context -> Success: cleanup complete
8. Write JSON result to stdout -> Success: result delivered

### Alternative Flow: Shutdown
1. Worker receives `{"command": "shutdown"}` -> close browser -> exit(0)

### Alternative Flow: Task Timeout
1. timeout_ms timer fires -> abort current page actions -> destroy context -> report timeout status

### Edge States
- **Browser crash mid-task:** Detect with `browser.on('disconnected')`, restart Chromium, report failure for current task, resume reading stdin
- **stdin EOF (daemon crashed):** Close browser, exit(0) — daemon handles orphaned task reset on restart
- **Empty playbook (0 steps):** Report success immediately (nothing to do)
- **user_data missing a required field:** Report playbook_error (field reference can't resolve)
