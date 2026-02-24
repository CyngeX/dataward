import type { Page } from "patchright";
import * as fs from "node:fs";
import * as path from "node:path";
import * as yaml from "js-yaml";
import type {
  PlaybookDefinition,
  PlaybookStep,
  FillParams,
  ClickParams,
  SelectParams,
  WaitParams,
  ScreenshotParams,
  TaskInput,
  ProofInfo,
} from "./types.js";
import { WorkerError } from "./types.js";
import {
  executeNavigate,
  executeFill,
  executeClick,
  executeSelect,
  executeWait,
  executeScreenshot,
} from "./actions.js";
import { setupDomainEnforcement } from "./domain.js";

/** Result of interpreting a playbook. */
export interface InterpretResult {
  proof: ProofInfo;
}

/**
 * Load a playbook YAML file and parse it into a PlaybookDefinition.
 * The Rust side already validates at load time, but we still parse defensively.
 */
export function loadPlaybook(playbookPath: string): PlaybookDefinition {
  // Defense-in-depth: check for ".." path components before resolving.
  // Uses path.normalize to handle separators, then checks for ".." segments.
  if (path.normalize(playbookPath).split(path.sep).includes("..")) {
    throw new WorkerError(
      "playbook_error",
      `Path traversal detected in playbook path`,
      false,
    );
  }
  const resolved = path.resolve(playbookPath);

  let content: string;
  try {
    content = fs.readFileSync(resolved, "utf-8");
  } catch {
    throw new WorkerError(
      "playbook_error",
      `Playbook file not found: ${playbookPath}`,
      false,
    );
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(content);
  } catch {
    throw new WorkerError(
      "playbook_error",
      `Invalid YAML in playbook: ${playbookPath}`,
      false,
    );
  }

  const doc = parsed as PlaybookDefinition;
  if (!doc || !doc.broker || !Array.isArray(doc.steps)) {
    throw new WorkerError(
      "playbook_error",
      `Playbook missing required fields (broker, steps): ${playbookPath}`,
      false,
    );
  }

  // Validate each step has exactly one recognized action key with correct value type
  const actionTypes: Record<string, string> = {
    navigate: "string",
    fill: "object",
    click: "object",
    select: "object",
    wait: "object",
    screenshot: "object",
  };
  for (let i = 0; i < doc.steps.length; i++) {
    const step = doc.steps[i] as Record<string, unknown>;
    const keys = Object.keys(step).filter((k) => k in actionTypes);
    if (keys.length !== 1) {
      throw new WorkerError(
        "playbook_error",
        `Step ${i} must have exactly one action key, found: ${JSON.stringify(Object.keys(step))}`,
        false,
      );
    }
    const action = keys[0];
    const value = step[action];
    const expectedType = actionTypes[action];
    if (typeof value !== expectedType || (expectedType === "object" && value === null)) {
      throw new WorkerError(
        "playbook_error",
        `Step ${i}: ${action} must be a ${expectedType}`,
        false,
      );
    }
  }

  return {
    broker: doc.broker,
    required_fields: doc.required_fields ?? [],
    steps: doc.steps,
    on_error: doc.on_error ?? "retry",
    max_retries: doc.max_retries ?? 3,
  };
}

/**
 * Execute a playbook against a page. Iterates through steps, handles
 * errors based on on_error strategy, collects proof screenshots.
 */
export async function interpretPlaybook(
  page: Page,
  task: TaskInput,
  playbook: PlaybookDefinition,
): Promise<InterpretResult> {
  const enforcer = await setupDomainEnforcement(page, task.allowed_domains);

  let lastScreenshotPath: string | null = null;
  let confirmationText = "";

  for (let i = 0; i < playbook.steps.length; i++) {
    const step = playbook.steps[i];
    enforcer.clearViolation();

    try {
      const result = await executeStep(
        page,
        step,
        i,
        task,
        playbook,
        enforcer,
      );

      if (result?.screenshotPath) {
        lastScreenshotPath = result.screenshotPath;
      }
    } catch (err) {
      // Check if domain enforcer caught a violation during the step
      const violation = enforcer.getViolation();
      if (violation) {
        violation.stepIndex = i;
        throw violation;
      }

      if (err instanceof WorkerError) {
        err.stepIndex = i;
        const handled = await handleStepError(
          err,
          page,
          step,
          i,
          task,
          playbook,
          enforcer,
        );
        if (!handled) throw err;
      } else {
        throw new WorkerError(
          "playbook_error",
          `Unexpected error at step ${i}: ${err instanceof Error ? err.message : String(err)}`,
          false,
          i,
        );
      }
    }
  }

  // Try to extract confirmation text from the final page
  try {
    confirmationText = await page.textContent("body", { timeout: 5000 }) ?? "";
    // Truncate to first 500 chars
    if (confirmationText.length > 500) {
      confirmationText = confirmationText.substring(0, 500);
    }
  } catch {
    // Non-fatal: page may have navigated away
  }

  return {
    proof: {
      screenshot_path: lastScreenshotPath,
      confirmation_text: confirmationText.trim(),
    },
  };
}

interface StepResult {
  screenshotPath?: string;
}

/** Execute a single playbook step. */
async function executeStep(
  page: Page,
  step: PlaybookStep,
  stepIndex: number,
  task: TaskInput,
  playbook: PlaybookDefinition,
  enforcer: { getViolation(): WorkerError | null },
): Promise<StepResult | void> {
  if ("navigate" in step) {
    await executeNavigate(page, step.navigate, task.allowed_domains);
    // Check for domain violation from JS redirect after navigation
    const violation = enforcer.getViolation();
    if (violation) {
      violation.stepIndex = stepIndex;
      throw violation;
    }
  } else if ("fill" in step) {
    await executeFill(page, step.fill as FillParams, task.user_data);
  } else if ("click" in step) {
    await executeClick(page, step.click as ClickParams);
  } else if ("select" in step) {
    await executeSelect(page, step.select as SelectParams);
  } else if ("wait" in step) {
    await executeWait(page, step.wait as WaitParams);
  } else if ("screenshot" in step) {
    const screenshotPath = await executeScreenshot(
      page,
      step.screenshot as ScreenshotParams,
      task.proof_dir,
    );
    return { screenshotPath };
  } else {
    throw new WorkerError(
      "playbook_error",
      `Unknown step type at index ${stepIndex}`,
      false,
      stepIndex,
    );
  }
}

/**
 * Handle a step error based on the playbook's on_error strategy.
 * Returns true if the error was handled (retried or skipped), false if it should propagate.
 */
async function handleStepError(
  err: WorkerError,
  page: Page,
  step: PlaybookStep,
  stepIndex: number,
  task: TaskInput,
  playbook: PlaybookDefinition,
  enforcer: { getViolation(): WorkerError | null },
): Promise<boolean> {
  const strategy = playbook.on_error;

  if (strategy === "fail") {
    return false;
  }

  if (strategy === "skip") {
    console.error(
      `[worker] Skipping step ${stepIndex} after error: ${err.message}`,
    );
    return true;
  }

  if (strategy === "retry" && err.retryable) {
    for (let attempt = 1; attempt <= playbook.max_retries; attempt++) {
      console.error(
        `[worker] Retrying step ${stepIndex} (attempt ${attempt}/${playbook.max_retries})`,
      );
      await new Promise<void>((r) => setTimeout(r, 1000 * attempt));
      try {
        await executeStep(page, step, stepIndex, task, playbook, enforcer);
        return true; // Retry succeeded
      } catch (retryErr) {
        console.error(
          `[worker] Retry attempt ${attempt}/${playbook.max_retries} failed at step ${stepIndex}: ${retryErr instanceof Error ? retryErr.message : String(retryErr)}`,
        );
      }
    }
    // All retries exhausted
    return false;
  }

  // Non-retryable error with retry strategy: propagate
  return false;
}
