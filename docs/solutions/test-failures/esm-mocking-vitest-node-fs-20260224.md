---
module: Worker
date: 2026-02-24
problem_type: test_failure
component: testing
symptoms:
  - "Cannot spy on export 'mkdirSync'. Module namespace is not configurable in ESM"
  - "Cannot access mockReadFileSync before initialization"
  - "vi.spyOn(fs, 'readFileSync') fails in ESM"
root_cause: dependency_issue
resolution_type: test_fix
severity: medium
tags: [vitest, esm, mocking, node-fs, vi-mock, vi-hoisted, vi-spyon]
language: typescript
issue_ref: "#2"
---

# Troubleshooting: vi.spyOn Fails on node:fs ESM Exports in Vitest

## Problem
`vi.spyOn(fs, 'readFileSync')` throws "Cannot spy on export. Module namespace is not configurable" when testing ESM modules that import from `node:fs`. The standard Vitest mocking approach doesn't work with Node.js built-in ESM exports.

## Environment
- Module: Worker subprocess tests
- Language/Framework: TypeScript / Vitest 3.x
- Affected Component: Tests for modules that use node:fs
- Date: 2026-02-24

## Symptoms
- `vi.spyOn(fs, 'readFileSync')` throws at test setup
- Error: "Cannot spy on export 'mkdirSync'. Module namespace is not configurable in ESM"
- Tests that worked with CommonJS fail after migrating to ESM

## What Didn't Work

**Attempted Solution 1:** `vi.spyOn` on imported fs module
```typescript
import * as fs from "node:fs";
vi.spyOn(fs, "readFileSync").mockReturnValue("content");
// THROWS: Cannot spy on export
```
- **Why it failed:** ESM module namespaces are frozen/non-configurable. `vi.spyOn` needs to modify the export, which ESM prevents.

**Attempted Solution 2:** `vi.mock` with inline factory variables
```typescript
const mockReadFileSync = vi.fn();
vi.mock("node:fs", () => ({ readFileSync: mockReadFileSync }));
// THROWS: Cannot access 'mockReadFileSync' before initialization
```
- **Why it failed:** `vi.mock` is hoisted to the top of the file (before any variable declarations). The factory function runs before `const mockReadFileSync` is declared.

## Solution

Use `vi.hoisted()` to declare mock functions in a hoisting-safe scope, then reference them in `vi.mock`:

```typescript
// Step 1: Declare mocks inside vi.hoisted — these are hoisted ALONGSIDE vi.mock
const { mockReadFileSync, mockMkdirSync } = vi.hoisted(() => ({
  mockReadFileSync: vi.fn(),
  mockMkdirSync: vi.fn(),
}));

// Step 2: vi.mock with the hoisted references
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,              // Keep unmocked exports
    readFileSync: mockReadFileSync,
    mkdirSync: mockMkdirSync,
  };
});

// Step 3: Import the module under test AFTER vi.mock
import { loadPlaybook } from "../interpreter.js";
```

**Key details:**
- `vi.hoisted()` returns values that exist at hoist-time, so `vi.mock` can reference them
- `importOriginal` preserves real implementations for unmocked exports
- Import the module under test AFTER `vi.mock` declarations (Vitest auto-hoists, but the import order communicates intent)

## Why This Works

1. **ROOT CAUSE:** ESM module namespaces (`import * as fs`) are sealed by the spec. Unlike CommonJS, their properties cannot be reassigned or spied on. Vitest's `vi.mock` replaces the entire module at the loader level — before the import resolves — which is the only way to intercept ESM imports.
2. **`vi.hoisted`** creates a scope that is hoisted alongside `vi.mock`, solving the temporal dead zone problem where factory functions run before variable declarations.
3. **`importOriginal`** lets you spread the real module and override only specific exports, avoiding the need to mock every function.

## Prevention

- For ESM projects, always use `vi.mock()` + `vi.hoisted()` instead of `vi.spyOn` for Node.js built-in modules
- Keep mock variable declarations inside `vi.hoisted()` — never declare them with `const`/`let` at module scope and reference them in `vi.mock` factories
- If you only need to mock one function, consider a simpler pattern: `vi.mock("node:fs", () => ({ readFileSync: vi.fn() }))`
