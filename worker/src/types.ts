/** Error codes matching Rust-side error_code enum in db.rs */
export type ErrorCode =
  | "selector_not_found"
  | "page_structure_changed"
  | "domain_violation"
  | "unexpected_navigation"
  | "timeout"
  | "captcha_blocked"
  | "playbook_error";

/** Result status values matching Rust-side schema */
export type StatusCode =
  | "success"
  | "failure"
  | "captcha_blocked"
  | "timeout"
  | "playbook_error"
  | "domain_violation";

/** Task input received from Rust daemon via stdin JSON-lines */
export interface TaskInput {
  task_id: string;
  broker_id: string;
  playbook_path: string;
  user_data: Record<string, string>;
  timeout_ms: number;
  proof_dir: string;
  allowed_domains: string[];
}

/** Shutdown command from Rust daemon */
export interface ShutdownCommand {
  command: "shutdown";
}

/** Union type for all possible stdin messages */
export type StdinMessage = TaskInput | ShutdownCommand;

/** Proof information included in successful results */
export interface ProofInfo {
  screenshot_path: string | null;
  confirmation_text: string;
}

/** Task result written to stdout JSON-lines */
export interface TaskResult {
  task_id: string;
  status: StatusCode;
  proof?: ProofInfo;
  error_code?: ErrorCode;
  error_message?: string;
  step_index?: number;
  duration_ms: number;
}

// --- Playbook types matching Rust-side broker_registry.rs ---

export interface BrokerDefinition {
  id: string;
  name: string;
  url: string;
  category: string;
  recheck_days: number;
  opt_out_channel: string;
  parent_company?: string;
  allowed_domains: string[];
}

export interface FillParams {
  selector: string;
  field: string;
}

export interface ClickParams {
  selector: string;
}

export interface SelectParams {
  selector: string;
  value: string;
}

export interface WaitParams {
  seconds: number;
}

export interface ScreenshotParams {
  name: string;
}

/** A single playbook step — exactly one action key per object */
export type PlaybookStep =
  | { navigate: string }
  | { fill: FillParams }
  | { click: ClickParams }
  | { select: SelectParams }
  | { wait: WaitParams }
  | { screenshot: ScreenshotParams };

/** On-error strategy for playbook execution */
export type OnErrorStrategy = "retry" | "skip" | "fail";

/** Full playbook definition loaded from YAML */
export interface PlaybookDefinition {
  broker: BrokerDefinition;
  required_fields: string[];
  steps: PlaybookStep[];
  on_error: OnErrorStrategy;
  max_retries: number;
}

/** Structured error thrown by action handlers */
export class WorkerError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly retryable: boolean = false,
    public stepIndex?: number,
  ) {
    super(message);
    this.name = "WorkerError";
  }
}

/** Type guard: is this a shutdown command? */
export function isShutdownCommand(msg: unknown): msg is ShutdownCommand {
  return (
    typeof msg === "object" &&
    msg !== null &&
    "command" in msg &&
    (msg as ShutdownCommand).command === "shutdown"
  );
}

/**
 * Type guard: is this a task input?
 *
 * Validates all 7 required fields of TaskInput:
 * - task_id, broker_id, playbook_path, proof_dir must be strings
 * - timeout_ms must be a finite positive number
 * - user_data must be a non-null, non-array object with string values
 * - allowed_domains must be an array of strings
 */
export function isTaskInput(msg: unknown): msg is TaskInput {
  if (typeof msg !== "object" || msg === null) return false;
  const m = msg as Record<string, unknown>;
  return (
    typeof m["task_id"] === "string" &&
    typeof m["broker_id"] === "string" &&
    typeof m["playbook_path"] === "string" &&
    typeof m["proof_dir"] === "string" &&
    typeof m["timeout_ms"] === "number" &&
    Number.isFinite(m["timeout_ms"]) &&
    (m["timeout_ms"] as number) > 0 &&
    typeof m["user_data"] === "object" &&
    m["user_data"] !== null &&
    !Array.isArray(m["user_data"]) &&
    Object.values(m["user_data"] as Record<string, unknown>).every(
      (v) => typeof v === "string",
    ) &&
    Array.isArray(m["allowed_domains"]) &&
    (m["allowed_domains"] as unknown[]).every((el) => typeof el === "string")
  );
}
