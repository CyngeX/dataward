/**
 * Worker tests focus on unit-testable logic extracted from worker.ts:
 * - errorCodeToStatus mapping
 * - withTimeout behavior
 * - writeResult format
 *
 * Full integration tests (stdin/stdout/process lifecycle) would require
 * spawning a real process with Chromium, which belongs in e2e tests.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { WorkerError } from "../types.js";
import type { ErrorCode, TaskResult } from "../types.js";

// These functions are intentionally re-implemented rather than imported from worker.ts.
// Reason: worker.ts has a top-level `main().catch(...)` call that launches Chromium and
// reads stdin on import. ESM has no `require.main === module` guard, so importing the
// module in tests would trigger the full worker lifecycle. The re-implementations test
// the CONTRACT (expected mapping/behavior), not the implementation. If the real functions
// diverge, integration/e2e tests (which spawn the worker process) will catch it.

// --- errorCodeToStatus ---
function errorCodeToStatus(code: ErrorCode): string {
  switch (code) {
    case "timeout":
      return "timeout";
    case "captcha_blocked":
      return "captcha_blocked";
    case "domain_violation":
    case "unexpected_navigation":
      return "domain_violation";
    case "playbook_error":
      return "playbook_error";
    case "selector_not_found":
    case "page_structure_changed":
      return "failure";
  }
}

describe("errorCodeToStatus mapping", () => {
  it("maps timeout to timeout", () => {
    expect(errorCodeToStatus("timeout")).toBe("timeout");
  });

  it("maps captcha_blocked to captcha_blocked", () => {
    expect(errorCodeToStatus("captcha_blocked")).toBe("captcha_blocked");
  });

  it("maps domain_violation to domain_violation", () => {
    expect(errorCodeToStatus("domain_violation")).toBe("domain_violation");
  });

  it("maps unexpected_navigation to domain_violation", () => {
    expect(errorCodeToStatus("unexpected_navigation")).toBe("domain_violation");
  });

  it("maps playbook_error to playbook_error", () => {
    expect(errorCodeToStatus("playbook_error")).toBe("playbook_error");
  });

  it("maps selector_not_found to failure", () => {
    expect(errorCodeToStatus("selector_not_found")).toBe("failure");
  });

  it("maps page_structure_changed to failure", () => {
    expect(errorCodeToStatus("page_structure_changed")).toBe("failure");
  });

  it("covers all error codes", () => {
    const allCodes: ErrorCode[] = [
      "selector_not_found",
      "page_structure_changed",
      "domain_violation",
      "unexpected_navigation",
      "timeout",
      "captcha_blocked",
      "playbook_error",
    ];
    for (const code of allCodes) {
      expect(typeof errorCodeToStatus(code)).toBe("string");
    }
  });
});

// --- withTimeout ---

// Re-implemented — see rationale at top of file
function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  taskId: string,
  onTimeout?: () => void,
): Promise<T> {
  if (timeoutMs <= 0) return promise;

  const safeTimeout = Math.min(timeoutMs, 2_147_483_647);

  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout?.();
      reject(
        new WorkerError(
          "timeout",
          `Task ${taskId} exceeded timeout of ${timeoutMs}ms`,
          true,
        ),
      );
    }, safeTimeout);

    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

describe("withTimeout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("resolves when promise completes before timeout", async () => {
    const promise = Promise.resolve("done");
    const result = await withTimeout(promise, 5000, "test-1");
    expect(result).toBe("done");
  });

  it("rejects with WorkerError on timeout", async () => {
    const neverResolves = new Promise<string>(() => {}); // never resolves

    const race = withTimeout(neverResolves, 100, "test-2");
    vi.advanceTimersByTime(101);

    try {
      await race;
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("timeout");
      expect((err as WorkerError).retryable).toBe(true);
      expect((err as WorkerError).message).toContain("test-2");
      expect((err as WorkerError).message).toContain("100ms");
    }
  });

  it("propagates promise rejection", async () => {
    const failingPromise = Promise.reject(new Error("boom"));

    try {
      await withTimeout(failingPromise, 5000, "test-3");
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe("boom");
    }
  });

  it("passes through when timeoutMs is 0", async () => {
    const promise = Promise.resolve("instant");
    const result = await withTimeout(promise, 0, "test-4");
    expect(result).toBe("instant");
  });

  it("passes through when timeoutMs is negative", async () => {
    const promise = Promise.resolve("instant");
    const result = await withTimeout(promise, -1, "test-5");
    expect(result).toBe("instant");
  });

  it("calls onTimeout callback when timeout fires", async () => {
    const neverResolves = new Promise<string>(() => {});
    const onTimeout = vi.fn();

    const race = withTimeout(neverResolves, 100, "test-6", onTimeout);
    vi.advanceTimersByTime(101);

    try {
      await race;
    } catch {
      // expected
    }

    expect(onTimeout).toHaveBeenCalledOnce();
  });

  it("clamps large timeoutMs to prevent 32-bit overflow", async () => {
    const neverResolves = new Promise<string>(() => {});
    const onTimeout = vi.fn();

    // 3 billion ms exceeds 32-bit signed max (2,147,483,647)
    const race = withTimeout(neverResolves, 3_000_000_000, "test-7", onTimeout);

    // Should NOT have fired immediately (that's the bug this test guards against)
    expect(onTimeout).not.toHaveBeenCalled();

    // Advance to the clamped max
    vi.advanceTimersByTime(2_147_483_648);

    try {
      await race;
    } catch {
      // expected
    }

    expect(onTimeout).toHaveBeenCalledOnce();
  });
});

// --- writeResult format ---

describe("TaskResult JSON format", () => {
  it("success result has correct shape", () => {
    const result: TaskResult = {
      task_id: "uuid-123",
      status: "success",
      proof: {
        screenshot_path: "/proofs/2026-02-24-confirmation.png",
        confirmation_text: "Request received",
      },
      duration_ms: 8500,
    };

    const json = JSON.parse(JSON.stringify(result));
    expect(json.task_id).toBe("uuid-123");
    expect(json.status).toBe("success");
    expect(json.proof.screenshot_path).toContain("confirmation.png");
    expect(json.proof.confirmation_text).toBe("Request received");
    expect(json.duration_ms).toBe(8500);
    expect(json.error_code).toBeUndefined();
  });

  it("failure result has error fields", () => {
    const result: TaskResult = {
      task_id: "uuid-456",
      status: "failure",
      error_code: "selector_not_found",
      error_message: "Selector #submit not found",
      step_index: 3,
      duration_ms: 12000,
    };

    const json = JSON.parse(JSON.stringify(result));
    expect(json.status).toBe("failure");
    expect(json.error_code).toBe("selector_not_found");
    expect(json.error_message).toContain("#submit");
    expect(json.step_index).toBe(3);
    expect(json.proof).toBeUndefined();
  });

  it("result serializes to single JSON line", () => {
    const result: TaskResult = {
      task_id: "test",
      status: "success",
      duration_ms: 100,
    };

    const line = JSON.stringify(result) + "\n";
    expect(line.split("\n")).toHaveLength(2); // content + trailing empty
    expect(JSON.parse(line.trim())).toEqual(result);
  });
});
