---
module: Worker
date: 2026-02-24
problem_type: security_issue
component: service
symptoms:
  - "Path traversal check using includes('..') on resolved path is dead code"
  - "startsWith(basePath) allows sibling directories with shared prefix"
  - "path.resolve() normalizes away '..' segments before check runs"
root_cause: logic_error
resolution_type: code_fix
severity: high
tags: [path-traversal, security, nodejs, path-resolve, defense-in-depth, startswith]
language: typescript
issue_ref: "#2"
---

# Troubleshooting: Node.js Path Traversal Defense — Three Gotchas

## Problem
Three separate path traversal defense patterns were implemented incorrectly, each caught by fresh-eyes review. All three are common mistakes when validating filesystem paths in Node.js.

## Environment
- Module: Worker subprocess (TypeScript/Node.js)
- Language/Framework: TypeScript / Node.js path module
- Affected Component: Playbook loader, proof directory validation, screenshot path guard
- Date: 2026-02-24

## Symptoms
- `path.resolve()` then checking for `..` segments never fires (dead code)
- `startsWith("/tmp/proof")` passes for `/tmp/proof-evil/x.png` (sibling bypass)
- `includes("..")` blocks legitimate paths like `/data/..hidden/file.yaml` (false positive)

## What Didn't Work

**Attempted Solution 1:** Check resolved path for `..` segments
```typescript
// BROKEN: path.resolve normalizes away ".." BEFORE the check
const resolved = path.resolve(userInput);
if (resolved.split(path.sep).includes("..")) { throw; } // Never fires!
```
- **Why it failed:** `path.resolve("../../etc/passwd")` returns `/etc/passwd` — the `..` is already gone. The check is dead code.

**Attempted Solution 2:** Check raw input with `includes("..")`
```typescript
// PARTIALLY BROKEN: false positives on legitimate paths
if (userInput.includes("..")) { throw; }
```
- **Why it failed:** Blocks legitimate paths containing `..` in directory names (e.g., `/data/..hidden/file`). Too broad — matches substring, not path component.

## Solution

**Three patterns, each for a different scenario:**

**Pattern 1: Check raw input using path component analysis (defense-in-depth)**
```typescript
// CORRECT: Normalize first (handles separators), then check for ".." as a PATH COMPONENT
if (path.normalize(userInput).split(path.sep).includes("..")) {
  throw new Error("Path traversal detected");
}
```
Use when: The caller is trusted (e.g., Rust daemon) but you want defense-in-depth. This catches `../../etc/passwd` without false-positiving on `..hidden`.

**Pattern 2: Resolve + startsWith with trailing separator (containment check)**
```typescript
// CORRECT: Append path.sep to prevent sibling directory bypass
const resolvedBase = path.resolve(baseDir);
const resolvedTarget = path.resolve(targetPath);
if (!resolvedTarget.startsWith(resolvedBase + path.sep)) {
  throw new Error("Path escapes base directory");
}
```
Use when: You know the expected base directory and want to ensure the target stays within it. The `+ path.sep` is critical — without it, `/tmp/proof-evil/x` passes when base is `/tmp/proof`.

**Pattern 3: Both (belt and suspenders)**
```typescript
// Defense-in-depth: catch traversal in raw input
if (path.normalize(input).split(path.sep).includes("..")) { throw; }
// Then verify resolved path is within expected base
const resolved = path.resolve(input);
if (!resolved.startsWith(path.resolve(BASE_DIR) + path.sep)) { throw; }
```

## Why This Works

1. **ROOT CAUSE:** `path.resolve()` normalizes `..` segments as part of resolution. Checking AFTER resolve is checking a path that no longer contains the thing you're looking for. Checking BEFORE resolve (on the raw or normalized input) catches the traversal attempt before it's hidden.
2. **`startsWith` without separator** compares string prefixes, not path prefixes. `/tmp/proof` is a string prefix of `/tmp/proof-evil/`, but `/tmp/proof/` is NOT a prefix of `/tmp/proof-evil/`.
3. **`includes("..")` vs `split(path.sep).includes("..")`** — the former is substring matching (matches `..hidden`), the latter checks for `..` as an actual path component.

## Prevention

- Never check for `..` on a path AFTER `path.resolve()` — it will always be normalized away
- Always append `path.sep` when using `startsWith` for path containment checks
- Use `path.normalize().split(path.sep).includes("..")` instead of `includes("..")` for path component checking
- When possible, use both raw input check AND resolved path containment (belt and suspenders)
- Fresh-eyes security review catches these — AI-generated path validation code is systematically wrong about `resolve` behavior
