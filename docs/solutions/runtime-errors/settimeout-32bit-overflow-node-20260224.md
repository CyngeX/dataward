---
module: Worker
date: 2026-02-24
problem_type: runtime_error
component: service
symptoms:
  - "setTimeout fires immediately instead of after specified delay"
  - "Timeout callback runs with 0ms delay for large timeout values"
  - "Task times out instantly when timeout_ms exceeds 2^31"
root_cause: type_error
resolution_type: code_fix
severity: high
tags: [settimeout, 32-bit, overflow, nodejs, timer, integer-overflow, timeout]
language: typescript
issue_ref: "#2"
---

# Troubleshooting: setTimeout Fires Immediately for Values > 2^31-1

## Problem
`setTimeout(fn, delay)` fires the callback immediately (with ~0ms delay) when `delay` exceeds 2,147,483,647 (2^31 - 1). This is because Node.js internally stores the delay as a 32-bit signed integer, and values beyond this overflow to negative, which Node.js treats as 0.

## Environment
- Module: Worker subprocess (TypeScript/Node.js)
- Language/Framework: TypeScript / Node.js timers
- Affected Component: Task timeout wrapper (`withTimeout`)
- Date: 2026-02-24

## Symptoms
- Tasks with very large `timeout_ms` values time out instantly
- `setTimeout` callback fires with negligible delay
- No error is thrown — the timer just fires at the wrong time

## What Didn't Work

**Attempted Solution 1:** Pass the value directly to setTimeout
```typescript
// BROKEN: overflows for values > 2^31-1
setTimeout(() => { reject(new Error("timeout")); }, timeoutMs);
```
- **Why it failed:** Node.js clamps the delay to a 32-bit signed integer internally. Values above 2,147,483,647 overflow and fire immediately.

## Solution

Clamp the timeout value to the 32-bit signed integer maximum before passing to `setTimeout`:

```typescript
function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  taskId: string,
  onTimeout?: () => void,
): Promise<T> {
  if (timeoutMs <= 0) return promise;

  // Clamp to 32-bit signed max to prevent setTimeout overflow (fires immediately)
  const safeTimeout = Math.min(timeoutMs, 2_147_483_647);

  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout?.();
      reject(new WorkerError("timeout", `Task exceeded timeout`, true));
    }, safeTimeout);

    promise
      .then((val) => { clearTimeout(timer); resolve(val); })
      .catch((err) => { clearTimeout(timer); reject(err); });
  });
}
```

## Why This Works

1. **ROOT CAUSE:** Node.js uses `libuv` timers internally, which store delays as unsigned 32-bit integers. The Node.js API accepts a number but clamps it: values > 2^31-1 are treated as 1 (effectively immediate). This is documented but easy to miss.
2. **Clamping to 2^31-1** (~24.8 days) is the maximum safe delay. For most applications, this is far beyond any reasonable timeout. If a caller passes a larger value, they get the maximum timeout instead of an instant one.

## Prevention

- Always clamp `setTimeout` and `setInterval` delays to `2_147_483_647` when accepting external input
- This applies to any Node.js code that accepts timeout values from untrusted or external sources
- Consider adding a comment explaining the clamp — it's a non-obvious platform limitation
- Test with values at and above the boundary (e.g., `2_147_483_648`)
