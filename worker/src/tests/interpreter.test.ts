import { describe, it, expect, vi, beforeEach } from "vitest";
import { WorkerError } from "../types.js";
import type { TaskInput, PlaybookDefinition } from "../types.js";
import * as yaml from "js-yaml";

// Mock node:fs for ESM compatibility — vi.hoisted ensures fns exist before vi.mock hoists
const { mockReadFileSync, mockMkdirSync } = vi.hoisted(() => ({
  mockReadFileSync: vi.fn(),
  mockMkdirSync: vi.fn(),
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    readFileSync: mockReadFileSync,
    mkdirSync: mockMkdirSync,
  };
});

import { loadPlaybook, interpretPlaybook } from "../interpreter.js";

// --- Mock domain.ts ---
vi.mock("../domain.js", () => ({
  setupDomainEnforcement: vi.fn(() => ({
    getViolation: vi.fn(() => null),
    clearViolation: vi.fn(),
  })),
}));

// --- Mock actions.ts ---
vi.mock("../actions.js", () => ({
  executeNavigate: vi.fn().mockResolvedValue(undefined),
  executeFill: vi.fn().mockResolvedValue(undefined),
  executeClick: vi.fn().mockResolvedValue(undefined),
  executeSelect: vi.fn().mockResolvedValue(undefined),
  executeWait: vi.fn().mockResolvedValue(undefined),
  executeScreenshot: vi.fn().mockResolvedValue("/tmp/proofs/2026-02-24-proof.png"),
}));

import {
  executeNavigate,
  executeFill,
  executeClick,
  executeSelect,
  executeWait,
  executeScreenshot,
} from "../actions.js";

// --- Mock helpers ---

function mockPage(overrides: Record<string, unknown> = {}) {
  return {
    textContent: vi.fn().mockResolvedValue("Confirmation: your opt-out request was received."),
    ...overrides,
  } as any;
}

function makeTask(overrides: Partial<TaskInput> = {}): TaskInput {
  return {
    task_id: "test-task-1",
    broker_id: "spokeo",
    playbook_path: "/tmp/test-playbook.yaml",
    user_data: { email: "test@example.com", first_name: "John" },
    timeout_ms: 60000,
    proof_dir: "/tmp/proofs",
    allowed_domains: ["spokeo.com"],
    ...overrides,
  };
}

function makePlaybook(overrides: Partial<PlaybookDefinition> = {}): PlaybookDefinition {
  return {
    broker: {
      id: "spokeo",
      name: "Spokeo",
      url: "https://spokeo.com",
      category: "people-search",
      recheck_days: 90,
      opt_out_channel: "web_form",
      allowed_domains: ["spokeo.com"],
    },
    required_fields: ["email"],
    steps: [
      { navigate: "https://spokeo.com/optout" },
      { fill: { selector: "#email", field: "email" } },
      { click: { selector: "#submit" } },
      { screenshot: { name: "confirmation" } },
    ],
    on_error: "retry",
    max_retries: 3,
    ...overrides,
  };
}

// --- loadPlaybook ---

describe("loadPlaybook", () => {
  it("loads and parses a valid playbook YAML", () => {
    const playbookContent = yaml.dump({
      broker: {
        id: "spokeo",
        name: "Spokeo",
        url: "https://spokeo.com",
        category: "people-search",
        recheck_days: 90,
        opt_out_channel: "web_form",
        allowed_domains: ["spokeo.com"],
      },
      required_fields: ["email"],
      steps: [{ navigate: "https://spokeo.com/optout" }],
    });

    mockReadFileSync.mockReturnValue(playbookContent);

    const result = loadPlaybook("/tmp/test.yaml");

    expect(result.broker.id).toBe("spokeo");
    expect(result.steps).toHaveLength(1);
    expect(result.on_error).toBe("retry"); // default
    expect(result.max_retries).toBe(3); // default
    expect(result.required_fields).toEqual(["email"]);
  });

  it("throws playbook_error for missing file", () => {
    mockReadFileSync.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    expect(() => loadPlaybook("/nonexistent.yaml")).toThrow(WorkerError);
    try {
      loadPlaybook("/nonexistent.yaml");
    } catch (err) {
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("not found");
    }
  });

  it("throws playbook_error for invalid YAML", () => {
    mockReadFileSync.mockReturnValue("{{invalid yaml]]");

    expect(() => loadPlaybook("/bad.yaml")).toThrow(WorkerError);
    try {
      loadPlaybook("/bad.yaml");
    } catch (err) {
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("Invalid YAML");
    }
  });

  it("throws playbook_error for missing required fields", () => {
    mockReadFileSync.mockReturnValue(
      yaml.dump({ something: "else" }),
    );

    expect(() => loadPlaybook("/incomplete.yaml")).toThrow(WorkerError);
    try {
      loadPlaybook("/incomplete.yaml");
    } catch (err) {
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("missing required fields");
    }
  });

  it("applies defaults for optional fields", () => {
    const playbookContent = yaml.dump({
      broker: {
        id: "test",
        name: "Test",
        url: "https://test.com",
        category: "test",
        recheck_days: 30,
        opt_out_channel: "web_form",
        allowed_domains: ["test.com"],
      },
      steps: [{ navigate: "https://test.com" }],
    });

    mockReadFileSync.mockReturnValue(playbookContent);

    const result = loadPlaybook("/test.yaml");
    expect(result.required_fields).toEqual([]);
    expect(result.on_error).toBe("retry");
    expect(result.max_retries).toBe(3);
  });

  it("throws playbook_error for step with invalid action value type", () => {
    const playbookContent = yaml.dump({
      broker: {
        id: "test",
        name: "Test",
        url: "https://test.com",
        category: "test",
        recheck_days: 30,
        opt_out_channel: "web_form",
        allowed_domains: ["test.com"],
      },
      steps: [{ navigate: 123 }],
    });

    mockReadFileSync.mockReturnValue(playbookContent);

    expect(() => loadPlaybook("/test.yaml")).toThrow(WorkerError);
    try {
      loadPlaybook("/test.yaml");
    } catch (err) {
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("navigate must be a string");
    }
  });

  it("throws playbook_error for step with no recognized action key", () => {
    const playbookContent = yaml.dump({
      broker: {
        id: "test",
        name: "Test",
        url: "https://test.com",
        category: "test",
        recheck_days: 30,
        opt_out_channel: "web_form",
        allowed_domains: ["test.com"],
      },
      steps: [{ unknown_action: "value" }],
    });

    mockReadFileSync.mockReturnValue(playbookContent);

    expect(() => loadPlaybook("/test.yaml")).toThrow(WorkerError);
    try {
      loadPlaybook("/test.yaml");
    } catch (err) {
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("exactly one action key");
    }
  });
});

// --- interpretPlaybook ---

describe("interpretPlaybook", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("executes all steps in order", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook();

    const result = await interpretPlaybook(page, task, playbook);

    expect(executeNavigate).toHaveBeenCalledTimes(1);
    expect(executeFill).toHaveBeenCalledTimes(1);
    expect(executeClick).toHaveBeenCalledTimes(1);
    expect(executeScreenshot).toHaveBeenCalledTimes(1);
    expect(result.proof.screenshot_path).toBe("/tmp/proofs/2026-02-24-proof.png");
  });

  it("captures confirmation text from final page", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook();

    const result = await interpretPlaybook(page, task, playbook);

    expect(result.proof.confirmation_text).toBe(
      "Confirmation: your opt-out request was received.",
    );
  });

  it("truncates confirmation text to 500 chars", async () => {
    const longText = "A".repeat(600);
    const page = mockPage({
      textContent: vi.fn().mockResolvedValue(longText),
    });
    const task = makeTask();
    const playbook = makePlaybook();

    const result = await interpretPlaybook(page, task, playbook);

    expect(result.proof.confirmation_text.length).toBe(500);
  });

  it("returns empty confirmation_text if page.textContent fails", async () => {
    const page = mockPage({
      textContent: vi.fn().mockRejectedValue(new Error("Page navigated")),
    });
    const task = makeTask();
    const playbook = makePlaybook();

    const result = await interpretPlaybook(page, task, playbook);

    expect(result.proof.confirmation_text).toBe("");
  });

  it("propagates WorkerError with step index on failure (on_error: fail)", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      on_error: "fail",
    });

    vi.mocked(executeClick).mockRejectedValueOnce(
      new WorkerError("selector_not_found", "Not found", true),
    );

    try {
      await interpretPlaybook(page, task, playbook);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("selector_not_found");
      expect((err as WorkerError).stepIndex).toBe(2); // click is step index 2
    }
  });

  it("skips failed step with on_error: skip", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      on_error: "skip",
    });

    vi.mocked(executeClick).mockRejectedValueOnce(
      new WorkerError("selector_not_found", "Not found", true),
    );

    // Should not throw — the click step is skipped
    const result = await interpretPlaybook(page, task, playbook);

    expect(executeNavigate).toHaveBeenCalledTimes(1);
    expect(executeFill).toHaveBeenCalledTimes(1);
    expect(executeClick).toHaveBeenCalledTimes(1); // attempted once
    expect(executeScreenshot).toHaveBeenCalledTimes(1); // still executed
    expect(result.proof.screenshot_path).toBe("/tmp/proofs/2026-02-24-proof.png");
  });

  it("retries failed step with on_error: retry", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      on_error: "retry",
      max_retries: 2,
    });

    vi.mocked(executeClick)
      .mockRejectedValueOnce(
        new WorkerError("selector_not_found", "Not found", true),
      )
      .mockRejectedValueOnce(
        new WorkerError("selector_not_found", "Not found", true),
      )
      .mockResolvedValueOnce(undefined); // succeeds on retry 2

    const result = await interpretPlaybook(page, task, playbook);

    // Original call + 2 retries = 3 calls
    expect(executeClick).toHaveBeenCalledTimes(3);
    expect(result.proof.screenshot_path).toBe("/tmp/proofs/2026-02-24-proof.png");
  });

  it("propagates error after all retries exhausted", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      on_error: "retry",
      max_retries: 2,
    });

    vi.mocked(executeClick).mockRejectedValue(
      new WorkerError("selector_not_found", "Not found", true),
    );

    try {
      await interpretPlaybook(page, task, playbook);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("selector_not_found");
    }

    // Original call + 2 retries = 3
    expect(executeClick).toHaveBeenCalledTimes(3);
  });

  it("does not retry non-retryable errors even with on_error: retry", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      on_error: "retry",
      max_retries: 3,
    });

    vi.mocked(executeClick).mockRejectedValueOnce(
      new WorkerError("page_structure_changed", "Structure changed", false),
    );

    try {
      await interpretPlaybook(page, task, playbook);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("page_structure_changed");
    }

    // Only the original call, no retries
    expect(executeClick).toHaveBeenCalledTimes(1);
  });

  it("throws playbook_error for unknown step types", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      on_error: "fail",
      steps: [{ unknown_action: "something" } as any],
    });

    try {
      await interpretPlaybook(page, task, playbook);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("Unknown step type");
    }
  });

  it("handles wait steps", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      steps: [{ wait: { seconds: 2 } }],
    });

    await interpretPlaybook(page, task, playbook);
    expect(executeWait).toHaveBeenCalledTimes(1);
  });

  it("handles select steps", async () => {
    const page = mockPage();
    const task = makeTask();
    const playbook = makePlaybook({
      steps: [{ select: { selector: "#state", value: "CA" } }],
    });

    await interpretPlaybook(page, task, playbook);
    expect(executeSelect).toHaveBeenCalledTimes(1);
  });
});
