# Phase 7.0.5 — Worker Capability Investigation

**Date:** 2026-04-08
**Issue:** [#13](https://github.com/CyngeX/dataward/issues/13)
**Plan reference:** `docs/plans/013-2026-04-08-comprehensive-breach-minimization-purge-plan.md` §J.5, §O
**Status:** Complete — decision locked

## Purpose

Phase 7.3 of the breach-minimization purge plan proposes 15–20 platform deletion playbooks (financial, health, dating, shopping, old forums). Those sites typically require authenticated sessions and 2FA. The existing Patchright worker was built for public people-search opt-out forms. §J.5 of the plan flagged this as an unverified assumption (ASSUMP-B) and made Phase 7.3 blocked on answering three capability questions.

This doc answers them with file:line evidence and locks Phase 7.3 scope against reality.

## Q1 — Does the worker support cookie/session persistence between playbook steps?

**No.** Each task runs in a disposable browser context that is destroyed on task completion.

Evidence:

- `worker/src/worker.ts:119-125` — every task builds a fresh `BrowserContext` with only `viewport` and `userAgent` options. No `storage_state` argument, no reuse of a prior context.
- `worker/src/worker.ts:171-178` — the `finally` block unconditionally calls `context.close()`, destroying all cookies, localStorage, sessionStorage, and in-memory DOM state at the end of every task.
- `worker/src/types.ts:20-29` — the `TaskInput` IPC contract has no `storage_state`, `cookie_jar`, `session_token`, or any persistence field. There is no channel for the Rust daemon to hand the worker a pre-built session, and no field in the task result for the worker to return one.
- `src/subprocess.rs` `WorkerTaskInput` struct — mirrors `TaskInput`; no session fields on the Rust side either.

There is no multi-task session context. Each playbook invocation starts from a cold browser.

## Q2 — Is there any 2FA-handling primitive (TOTP prompt, SMS wait, passkey, `wait_for_user_input`)?

**No.** The worker has no runtime user-input mechanism of any kind.

Evidence:

- `worker/src/types.ts:92-98` — `PlaybookStep` is a closed union of exactly six variants: `navigate | fill | click | select | wait | screenshot`. No `manual_step`, `pause`, `wait_user`, `prompt_user`, `totp_prompt`, `sms_code`, or similar.
- `worker/src/interpreter.ts` — the action dispatch table is a fixed 6-entry map; unknown step types are rejected at interpretation time.
- `worker/src/actions.ts` `executeWait()` — a plain `page.waitForTimeout(seconds * 1000)`. No polling, no user I/O, no stdin read.
- `worker/src/worker.ts:1-6` — stdin is consumed by a `readline` interface that reads task-dispatch JSON lines. There is no side-channel for a runtime "enter your 2FA code" prompt, and no mechanism to pause mid-playbook and resume on user input.
- `src/broker_registry.rs` — the Rust-side `PlaybookStep` enum mirrors the TS union (Navigate, Fill, Click, Select, Wait, Screenshot). Zero interactive variants.

The worker is fire-and-forget by design. There is no pause/resume and no way for a step to ask the human for anything.

## Q3 — Does the playbook YAML schema have any user-interactive wait states?

**No.** The YAML schema is locked to the same six non-interactive step types, and `deny_unknown_fields` makes it impossible to slip in a seventh.

Evidence:

- `src/broker_registry.rs` — `RawPlaybook` and `RawStep` are both annotated with `#[serde(deny_unknown_fields)]`. A playbook containing any step type other than the six declared keys fails deserialization.
- `worker/src/types.ts:83-85` — `WaitParams` is `{ seconds: number }`. The only "wait" is a time-based sleep.
- `docs/plans/013-*.md` lines 146-162 — the Phase 7 schema extension for platform playbooks adds `source_type`, `category`, `sensitivity_default`, and `manual_instructions` at the **top level** of the playbook, not as a new step type. `manual_instructions` is static documentation text surfaced in the dashboard for the user to read — it is not a runtime pause step.

Note: `manual_only` is a *delivery channel* attribute (broker-level), not a playbook step type. It means "the orchestrator should not attempt this automatically; show instructions to the user instead."

### Complete list of currently supported step types

1. `navigate: <url>` — load a URL (domain-validated against `allowed_domains`)
2. `fill: { selector, field }` — fill a form field from `user_data[field]`
3. `click: { selector }` — click an element
4. `select: { selector, value }` — select a dropdown option
5. `wait: { seconds }` — sleep (max 30s, validated)
6. `screenshot: { name }` — capture a proof screenshot

No conditionals, no branching, no loops, no user prompts, no session save/load.

## Verdict

**Phase 7.3 must be scoped down.** The worker in its current form cannot automate end-to-end deletion for any platform that requires login + 2FA + session persistence. That rules out the majority of the originally-imagined Phase 7.3 targets (banks, health portals, dating, shopping accounts behind logins).

### What the worker CAN automate end-to-end

- One-shot public opt-out forms (the current people-search broker pattern).
- Simple unauthenticated deletion requests — for example, a public "request deletion" form that only needs name/email and emits a confirmation email the service handles server-side.
- Short authenticated flows **only if** the entire login → action → confirmation sequence fits inside one playbook with no 2FA and no email-link verification. In practice this is rare enough to ignore as a design target.

### What the worker CANNOT automate (with the current architecture)

- Any site that requires 2FA (TOTP, SMS, passkey, security questions).
- Any site that requires clicking an email verification link mid-flow.
- Anything that needs session reuse across runs (e.g. login once, delete later).
- Password-change flows that require the old password at runtime.
- Phone / ID-photo identity verification.

## Decision — locked Phase 7.3 scope

**Phase 7.3 ships as "scaffold + 3 reference playbooks," not "15–20 platforms."**

Concretely:

1. **Schema extension (scaffold) — ship it.** Add `source_type`, `category`, `sensitivity_default`, and `manual_instructions` to the playbook YAML schema, with `deny_unknown_fields` preserved. This lets platform playbooks coexist with broker playbooks without touching the step interpreter.

2. **3 reference playbooks — pick from no-auth-required deletion endpoints only.** Candidates: Mozilla / Firefox Account deletion form, legacy forum deletion pages, any public "delete my data" form that does not sit behind a login. The exact three are a Phase 7.3 authoring decision; the constraint is "no login, no 2FA, no email-link dance."

3. **Everything else (banks, health, dating, shopping behind logins) → `manual_only`.** They appear in the dashboard triage queue as platform_accounts with `manual_instructions` rendered as step-by-step guidance for the user to execute by hand. The orchestrator marks them complete when the user confirms. This is consistent with §J.1/J.2 which already force financial/health to `manual_only` for lockout and ToS reasons.

4. **No new worker primitives in Phase 7.** `wait_for_user_input`, TOTP handling, session persistence, email-link polling, and any dashboard↔worker side-channel for runtime prompts are **explicitly deferred**. They are a self-contained workstream (schema change + subprocess protocol change + dashboard integration) and belong in a future phase if and when the manual-only path proves insufficient.

5. **Phase 7.3 acceptance criteria should read:**
   - [ ] Playbook YAML schema extended with platform fields (scaffold)
   - [ ] 3 reference playbooks shipped, all targeting no-auth public endpoints
   - [ ] `manual_only` platform_accounts render `manual_instructions` in the dashboard
   - [ ] No new runtime step types added to the worker

## Blast-radius check

The reduced scope does not weaken Phase 7's overall goal (shrink the data footprint before the inevitable breach). It shifts most platform deletions from "automated" to "user-guided manual with instructions," which is how commercial tools like Incogni already treat financial/health anyway. The dashboard still enumerates every account the user has forgotten about — that's the actual differentiator — and the user still gets a single surface to triage them from. Automation was always a means, not the goal.
