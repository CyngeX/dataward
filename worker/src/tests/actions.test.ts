import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  executeNavigate,
  executeFill,
  executeClick,
  executeSelect,
  executeWait,
  executeScreenshot,
} from "../actions.js";
import { WorkerError } from "../types.js";

// Mock node:fs for ESM compatibility
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    mkdirSync: vi.fn(),
  };
});

import * as fs from "node:fs";

// --- Mock helpers ---

function mockPage(overrides: Record<string, unknown> = {}) {
  return {
    goto: vi.fn().mockResolvedValue(undefined),
    fill: vi.fn().mockResolvedValue(undefined),
    click: vi.fn().mockResolvedValue(undefined),
    selectOption: vi.fn().mockResolvedValue(undefined),
    waitForTimeout: vi.fn().mockResolvedValue(undefined),
    screenshot: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as any;
}

function timeoutError(msg = "Timeout 30000ms exceeded"): Error {
  const err = new Error(msg);
  err.name = "TimeoutError";
  return err;
}

// --- executeNavigate ---

describe("executeNavigate", () => {
  it("navigates to an allowed domain", async () => {
    const page = mockPage();
    await executeNavigate(page, "https://spokeo.com/optout", ["spokeo.com"]);
    expect(page.goto).toHaveBeenCalledWith("https://spokeo.com/optout", {
      timeout: 30_000,
      waitUntil: "networkidle",
    });
  });

  it("throws domain_violation for non-allowed domain", async () => {
    const page = mockPage();

    try {
      await executeNavigate(page, "https://evil.com/phish", ["spokeo.com"]);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("domain_violation");
      expect((err as WorkerError).retryable).toBe(false);
    }

    expect(page.goto).not.toHaveBeenCalled();
  });

  it("throws timeout error as retryable", async () => {
    const page = mockPage({
      goto: vi.fn().mockRejectedValue(timeoutError()),
    });

    try {
      await executeNavigate(page, "https://spokeo.com/optout", ["spokeo.com"]);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("timeout");
      expect((err as WorkerError).retryable).toBe(true);
    }
  });

  it("throws page_structure_changed for non-timeout errors", async () => {
    const page = mockPage({
      goto: vi.fn().mockRejectedValue(new Error("net::ERR_CONNECTION_REFUSED")),
    });

    try {
      await executeNavigate(page, "https://spokeo.com/optout", ["spokeo.com"]);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("page_structure_changed");
      expect((err as WorkerError).retryable).toBe(false);
    }
  });
});

// --- executeFill ---

describe("executeFill", () => {
  it("fills selector with value from user_data", async () => {
    const page = mockPage();
    await executeFill(
      page,
      { selector: "#email", field: "email" },
      { email: "test@example.com" },
    );
    expect(page.fill).toHaveBeenCalledWith("#email", "test@example.com", {
      timeout: 30_000,
    });
  });

  it("throws playbook_error for missing field in user_data", async () => {
    const page = mockPage();
    try {
      await executeFill(
        page,
        { selector: "#email", field: "email" },
        { first_name: "John" },
      );
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("playbook_error");
      expect((err as WorkerError).message).toContain("email");
    }
  });

  it("throws selector_not_found on timeout", async () => {
    const page = mockPage({
      fill: vi.fn().mockRejectedValue(timeoutError()),
    });
    try {
      await executeFill(
        page,
        { selector: "#missing", field: "email" },
        { email: "test@example.com" },
      );
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("selector_not_found");
      expect((err as WorkerError).retryable).toBe(true);
    }
  });
});

// --- executeClick ---

describe("executeClick", () => {
  it("clicks the specified selector", async () => {
    const page = mockPage();
    await executeClick(page, { selector: "#submit" });
    expect(page.click).toHaveBeenCalledWith("#submit", { timeout: 30_000 });
  });

  it("throws selector_not_found on timeout", async () => {
    const page = mockPage({
      click: vi.fn().mockRejectedValue(timeoutError()),
    });
    try {
      await executeClick(page, { selector: "#missing" });
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("selector_not_found");
    }
  });

  it("throws page_structure_changed on non-timeout error", async () => {
    const page = mockPage({
      click: vi.fn().mockRejectedValue(new Error("Element is not visible")),
    });
    try {
      await executeClick(page, { selector: "#hidden" });
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("page_structure_changed");
    }
  });
});

// --- executeSelect ---

describe("executeSelect", () => {
  it("selects an option by value", async () => {
    const page = mockPage();
    await executeSelect(page, { selector: "#state", value: "CA" });
    expect(page.selectOption).toHaveBeenCalledWith("#state", "CA", {
      timeout: 30_000,
    });
  });

  it("throws selector_not_found on timeout", async () => {
    const page = mockPage({
      selectOption: vi.fn().mockRejectedValue(timeoutError()),
    });
    try {
      await executeSelect(page, { selector: "#missing", value: "CA" });
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("selector_not_found");
    }
  });
});

// --- executeWait ---

describe("executeWait", () => {
  it("waits for specified seconds", async () => {
    const page = mockPage();
    await executeWait(page, { seconds: 2 });
    expect(page.waitForTimeout).toHaveBeenCalledWith(2000);
  });

  it("caps wait at 30 seconds", async () => {
    const page = mockPage();
    await executeWait(page, { seconds: 60 });
    expect(page.waitForTimeout).toHaveBeenCalledWith(30_000);
  });

  it("handles zero seconds", async () => {
    const page = mockPage();
    await executeWait(page, { seconds: 0 });
    expect(page.waitForTimeout).toHaveBeenCalledWith(0);
  });
});

// --- executeScreenshot ---

describe("executeScreenshot", () => {
  it("captures screenshot to proof directory", async () => {
    const page = mockPage();
    const proofDir = "/tmp/proofs/spokeo";

    const result = await executeScreenshot(
      page,
      { name: "confirmation" },
      proofDir,
    );

    expect(fs.mkdirSync).toHaveBeenCalledWith(proofDir, { recursive: true });
    expect(page.screenshot).toHaveBeenCalledWith(
      expect.objectContaining({
        fullPage: true,
        timeout: 30_000,
      }),
    );
    // Result should be a path containing the name
    expect(result).toContain("confirmation.png");
    expect(result).toContain(proofDir);
  });

  it("includes date prefix in filename", async () => {
    const page = mockPage();
    const result = await executeScreenshot(
      page,
      { name: "test" },
      "/tmp/proofs",
    );
    // Should contain ISO date prefix like 2026-02-24
    expect(result).toMatch(/\d{4}-\d{2}-\d{2}-test\.png$/);
  });

  it("throws on screenshot failure", async () => {
    const page = mockPage({
      screenshot: vi.fn().mockRejectedValue(new Error("Page crashed")),
    });
    try {
      await executeScreenshot(page, { name: "test" }, "/tmp/proofs");
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerError);
      expect((err as WorkerError).code).toBe("page_structure_changed");
    }
  });
});
