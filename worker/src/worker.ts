import { chromium, type Browser, type BrowserContext } from "patchright";
import * as readline from "node:readline";
import * as path from "node:path";
import type { TaskInput, TaskResult, StatusCode, ErrorCode } from "./types.js";
import { WorkerError, isShutdownCommand, isTaskInput } from "./types.js";
import { loadPlaybook, interpretPlaybook } from "./interpreter.js";

/** Track in-flight task ID for disconnect handler. */
let currentTaskId: string | null = null;
let currentTaskStart = 0;

/**
 * Main worker entry point. Launches Chromium once, then reads JSON-lines
 * from stdin. Each task gets a fresh BrowserContext for isolation.
 * Results are written as JSON-lines to stdout.
 * All diagnostics go to stderr via console.error().
 */
async function main(): Promise<void> {
  let browser: Browser;

  try {
    browser = await chromium.launch({
      headless: true,
      timeout: 30_000,
    });
  } catch (err) {
    console.error(
      `[worker] Failed to launch Chromium: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }

  console.error("[worker] Chromium launched, ready for tasks");

  // Handle browser crash — write failure for in-flight task, then exit so Rust daemon can respawn
  browser.on("disconnected", () => {
    console.error("[worker] Browser disconnected unexpectedly");
    if (currentTaskId) {
      writeResult({
        task_id: currentTaskId,
        status: "failure",
        error_code: "playbook_error",
        error_message: "Browser disconnected unexpectedly",
        duration_ms: Date.now() - currentTaskStart,
      });
    }
    process.exit(2);
  });

  const rl = readline.createInterface({
    input: process.stdin,
    terminal: false,
  });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed === "") continue;

    let msg: unknown;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      console.error(`[worker] Malformed JSON input (${trimmed.length} bytes)`);
      continue;
    }

    if (isShutdownCommand(msg)) {
      console.error("[worker] Shutdown command received");
      break;
    }

    if (!isTaskInput(msg)) {
      console.error("[worker] Unknown message type, ignoring");
      continue;
    }

    const task = msg as TaskInput;
    await handleTask(browser, task);
  }

  // Clean shutdown
  console.error("[worker] Closing browser");
  const SHUTDOWN_TIMEOUT_MS = 5_000;
  try {
    await Promise.race([
      browser.close(),
      new Promise<void>((_, reject) =>
        setTimeout(() => reject(new Error("Browser close timed out")), SHUTDOWN_TIMEOUT_MS)
      ),
    ]);
  } catch {
    console.error("[worker] Browser close timed out, forcing exit");
  }
  console.error("[worker] Exited cleanly");
}

/**
 * Handle a single task: create context, run playbook, write result, destroy context.
 */
async function handleTask(browser: Browser, task: TaskInput): Promise<void> {
  const startTime = Date.now();
  currentTaskId = task.task_id;
  currentTaskStart = startTime;
  let context: BrowserContext | null = null;

  // Defense-in-depth: check for ".." path components before resolving.
  if (path.normalize(task.proof_dir).split(path.sep).includes("..")) {
    writeResult({
      task_id: task.task_id,
      status: "playbook_error",
      error_code: "playbook_error",
      error_message: "Invalid proof_dir: path traversal detected",
      duration_ms: Date.now() - startTime,
    });
    currentTaskId = null;
    return;
  }

  try {
    context = await browser.newContext({
      // Reasonable viewport for opt-out forms
      viewport: { width: 1280, height: 720 },
      // Mimic a common user-agent (Patchright patches fingerprint leaks)
      userAgent: undefined, // Let Patchright use its default anti-detection UA
    });

    const page = await context.newPage();

    const playbook = loadPlaybook(task.playbook_path);

    // Race playbook execution against task timeout.
    // On timeout, close context immediately to abort in-flight browser operations.
    const result = await withTimeout(
      interpretPlaybook(page, task, playbook),
      task.timeout_ms,
      task.task_id,
      () => {
        context?.close().catch(() => {});
      },
    );

    writeResult({
      task_id: task.task_id,
      status: "success",
      proof: result.proof,
      duration_ms: Date.now() - startTime,
    });
    currentTaskId = null;
  } catch (err) {
    const duration_ms = Date.now() - startTime;

    if (err instanceof WorkerError) {
      writeResult({
        task_id: task.task_id,
        status: errorCodeToStatus(err.code),
        error_code: err.code,
        error_message: err.message,
        step_index: err.stepIndex,
        duration_ms,
      });
    } else {
      writeResult({
        task_id: task.task_id,
        status: "failure",
        error_code: "playbook_error",
        error_message: err instanceof Error ? err.message : String(err),
        duration_ms,
      });
    }
    currentTaskId = null;
  } finally {
    if (context) {
      try {
        await context.close();
      } catch {
        // Context may already be closed if browser crashed or timeout
      }
    }
  }
}

/**
 * Map an error code to a status code for the result.
 */
function errorCodeToStatus(code: ErrorCode): StatusCode {
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

/**
 * Write a task result as a JSON line to stdout.
 * This is the ONLY place we write to stdout — all other output goes to stderr.
 */
function writeResult(result: TaskResult): void {
  process.stdout.write(JSON.stringify(result) + "\n");
}

/**
 * Race a promise against a timeout. Throws WorkerError with code "timeout"
 * if the timeout fires first. Optional onTimeout callback for cleanup
 * (e.g. closing browser context to abort in-flight operations).
 */
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

// --- Entry point ---
main().catch((err) => {
  console.error(`[worker] Fatal error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
