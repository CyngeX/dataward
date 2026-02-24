import type { Page } from "patchright";
import type {
  FillParams,
  ClickParams,
  SelectParams,
  WaitParams,
  ScreenshotParams,
} from "./types.js";
import { WorkerError } from "./types.js";
import * as path from "node:path";
import * as fs from "node:fs";

const ACTION_TIMEOUT_MS = 30_000;

/**
 * Navigate to a URL. Domain enforcement is handled externally via page.route()
 * but we also pre-check here as defense-in-depth.
 */
export async function executeNavigate(
  page: Page,
  url: string,
  allowedDomains: string[],
): Promise<void> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new WorkerError(
      "domain_violation",
      `Navigation blocked: unsupported protocol ${parsed.protocol}`,
      false,
    );
  }
  if (!allowedDomains.includes(parsed.hostname)) {
    throw new WorkerError(
      "domain_violation",
      `Navigation blocked: ${parsed.hostname} not in allowed domains [${allowedDomains.join(", ")}]`,
      false,
    );
  }

  try {
    await page.goto(url, {
      timeout: ACTION_TIMEOUT_MS,
      waitUntil: "networkidle",
    });
  } catch (err) {
    if (isTimeoutError(err)) {
      throw new WorkerError(
        "timeout",
        `Navigation to ${url} timed out`,
        true,
      );
    }
    throw new WorkerError(
      "page_structure_changed",
      `Navigation to ${url} failed: ${errorMessage(err)}`,
      false,
    );
  }
}

/** Fill a form field with a value from user_data. */
export async function executeFill(
  page: Page,
  params: FillParams,
  userData: Record<string, string>,
): Promise<void> {
  const value = userData[params.field];
  if (value === undefined) {
    throw new WorkerError(
      "playbook_error",
      `Field "${params.field}" not found in user_data`,
      false,
    );
  }

  try {
    await page.fill(params.selector, value, { timeout: ACTION_TIMEOUT_MS });
  } catch (err) {
    if (isTimeoutError(err)) {
      throw new WorkerError(
        "selector_not_found",
        `Selector "${params.selector}" not found for fill`,
        true,
      );
    }
    throw new WorkerError(
      "page_structure_changed",
      `Fill failed on "${params.selector}": ${errorMessage(err)}`,
      false,
    );
  }
}

/** Click an element. */
export async function executeClick(
  page: Page,
  params: ClickParams,
): Promise<void> {
  try {
    await page.click(params.selector, { timeout: ACTION_TIMEOUT_MS });
  } catch (err) {
    if (isTimeoutError(err)) {
      throw new WorkerError(
        "selector_not_found",
        `Selector "${params.selector}" not found for click`,
        true,
      );
    }
    throw new WorkerError(
      "page_structure_changed",
      `Click failed on "${params.selector}": ${errorMessage(err)}`,
      false,
    );
  }
}

/** Select an option from a dropdown. */
export async function executeSelect(
  page: Page,
  params: SelectParams,
): Promise<void> {
  try {
    await page.selectOption(params.selector, params.value, {
      timeout: ACTION_TIMEOUT_MS,
    });
  } catch (err) {
    if (isTimeoutError(err)) {
      throw new WorkerError(
        "selector_not_found",
        `Selector "${params.selector}" not found for select`,
        true,
      );
    }
    throw new WorkerError(
      "page_structure_changed",
      `Select failed on "${params.selector}": ${errorMessage(err)}`,
      false,
    );
  }
}

/** Wait for a specified duration. Max 30s enforced by Rust validation. */
export async function executeWait(
  page: Page,
  params: WaitParams,
): Promise<void> {
  if (!Number.isFinite(params.seconds) || params.seconds < 0) {
    throw new WorkerError("playbook_error", `Invalid wait duration: ${params.seconds}`, false);
  }
  const maxMs = 30_000;
  const requestedMs = params.seconds * 1000;
  if (requestedMs > maxMs) {
    console.error(
      `[worker] Wait duration clamped: ${params.seconds}s requested, 30s applied`,
    );
  }
  await page.waitForTimeout(Math.min(requestedMs, maxMs));
}

/** Capture a screenshot to the proof directory. */
export async function executeScreenshot(
  page: Page,
  params: ScreenshotParams,
  proofDir: string,
): Promise<string> {
  fs.mkdirSync(proofDir, { recursive: true });

  const date = new Date().toISOString().split("T")[0];
  const safeName = params.name.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 200);
  const filename = `${date}-${safeName}.png`;
  const screenshotPath = path.join(proofDir, filename);
  // Defense-in-depth: verify path stays within proofDir
  const resolvedProof = path.resolve(proofDir);
  const resolvedScreenshot = path.resolve(screenshotPath);
  if (!resolvedScreenshot.startsWith(resolvedProof + path.sep)) {
    throw new WorkerError("playbook_error", `Screenshot path escapes proof directory: ${params.name}`, false);
  }

  try {
    await page.screenshot({
      path: screenshotPath,
      fullPage: true,
      timeout: ACTION_TIMEOUT_MS,
    });
  } catch (err) {
    throw new WorkerError(
      "page_structure_changed",
      `Screenshot failed: ${errorMessage(err)}`,
      false,
    );
  }

  return screenshotPath;
}

function isTimeoutError(err: unknown): boolean {
  return err instanceof Error && err.name === "TimeoutError";
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
