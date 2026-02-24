import { describe, it, expect } from "vitest";
import {
  WorkerError,
  isShutdownCommand,
  isTaskInput,
} from "../types.js";

describe("WorkerError", () => {
  it("creates error with code and message", () => {
    const err = new WorkerError("timeout", "Timed out");
    expect(err.code).toBe("timeout");
    expect(err.message).toBe("Timed out");
    expect(err.retryable).toBe(false); // default
    expect(err.stepIndex).toBeUndefined();
    expect(err.name).toBe("WorkerError");
    expect(err).toBeInstanceOf(Error);
  });

  it("creates retryable error", () => {
    const err = new WorkerError("selector_not_found", "Not found", true);
    expect(err.retryable).toBe(true);
  });

  it("creates error with step index", () => {
    const err = new WorkerError("timeout", "Timed out", true, 5);
    expect(err.stepIndex).toBe(5);
  });

  it("allows stepIndex to be mutated", () => {
    const err = new WorkerError("timeout", "Timed out", true);
    expect(err.stepIndex).toBeUndefined();
    err.stepIndex = 3;
    expect(err.stepIndex).toBe(3);
  });
});

describe("isShutdownCommand", () => {
  it("returns true for valid shutdown command", () => {
    expect(isShutdownCommand({ command: "shutdown" })).toBe(true);
  });

  it("returns false for non-shutdown command", () => {
    expect(isShutdownCommand({ command: "restart" })).toBe(false);
  });

  it("returns false for task input", () => {
    expect(
      isShutdownCommand({
        task_id: "123",
        broker_id: "test",
        playbook_path: "/test.yaml",
      }),
    ).toBe(false);
  });

  it("returns false for null", () => {
    expect(isShutdownCommand(null)).toBe(false);
  });

  it("returns false for non-object", () => {
    expect(isShutdownCommand("shutdown")).toBe(false);
    expect(isShutdownCommand(42)).toBe(false);
    expect(isShutdownCommand(undefined)).toBe(false);
  });
});

describe("isTaskInput", () => {
  it("returns true for valid task input", () => {
    expect(
      isTaskInput({
        task_id: "uuid-123",
        broker_id: "spokeo",
        playbook_path: "/playbooks/spokeo.yaml",
        user_data: { email: "test@example.com" },
        timeout_ms: 60000,
        proof_dir: "/proofs",
        allowed_domains: ["spokeo.com"],
      }),
    ).toBe(true);
  });

  it("returns false with only partial required fields", () => {
    expect(
      isTaskInput({
        task_id: "123",
        broker_id: "test",
        playbook_path: "/test.yaml",
      }),
    ).toBe(false);
  });

  it("returns false for shutdown command", () => {
    expect(isTaskInput({ command: "shutdown" })).toBe(false);
  });

  it("returns false for null", () => {
    expect(isTaskInput(null)).toBe(false);
  });

  it("returns false for non-object", () => {
    expect(isTaskInput("task")).toBe(false);
  });

  it("returns false for missing required fields", () => {
    expect(isTaskInput({ task_id: "123" })).toBe(false);
    expect(isTaskInput({ task_id: "123", broker_id: "test" })).toBe(false);
  });

  it("returns false for NaN timeout_ms", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: "a@b.com" },
        timeout_ms: NaN,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(false);
  });

  it("returns false for Infinity timeout_ms", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: "a@b.com" },
        timeout_ms: Infinity,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(false);
  });

  it("returns false for negative timeout_ms", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: "a@b.com" },
        timeout_ms: -1,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(false);
  });

  it("returns false for zero timeout_ms", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: "a@b.com" },
        timeout_ms: 0,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(false);
  });

  it("returns false for non-string elements in allowed_domains", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: "a@b.com" },
        timeout_ms: 60000,
        proof_dir: "/proofs",
        allowed_domains: ["example.com", 42],
      }),
    ).toBe(false);
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: "a@b.com" },
        timeout_ms: 60000,
        proof_dir: "/proofs",
        allowed_domains: [null],
      }),
    ).toBe(false);
  });

  it("returns false for non-string values in user_data", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: 42 },
        timeout_ms: 60000,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(false);
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: { email: null },
        timeout_ms: 60000,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(false);
  });

  it("returns true for empty user_data object", () => {
    expect(
      isTaskInput({
        task_id: "1",
        broker_id: "b",
        playbook_path: "/p.yaml",
        user_data: {},
        timeout_ms: 60000,
        proof_dir: "/proofs",
        allowed_domains: ["example.com"],
      }),
    ).toBe(true);
  });
});
