use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

/// Maximum line length from worker stdout (1MB). Lines exceeding this are truncated.
const MAX_LINE_LENGTH: usize = 1_048_576;

/// Task input sent to the worker subprocess via stdin JSON-lines.
#[derive(Debug, serde::Serialize)]
pub struct WorkerTaskInput {
    pub task_id: String,
    pub broker_id: String,
    pub playbook_path: String,
    pub user_data: HashMap<String, String>,
    pub timeout_ms: u64,
    pub proof_dir: String,
    pub allowed_domains: Vec<String>,
}

/// Task result received from the worker subprocess via stdout JSON-lines.
#[derive(Debug, serde::Deserialize)]
pub struct WorkerTaskResult {
    pub task_id: String,
    pub status: String,
    pub proof: Option<WorkerProofInfo>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub step_index: Option<i32>,
    pub duration_ms: i64,
}

/// Proof information from a successful worker task.
#[derive(Debug, serde::Deserialize)]
pub struct WorkerProofInfo {
    pub screenshot_path: Option<String>,
    pub confirmation_text: String,
}

/// Manages a long-lived worker subprocess.
///
/// The subprocess runs `node worker/dist/worker.js` with an isolated HOME
/// directory and cleared environment. Communication is via JSON-lines on
/// stdin (tasks) and stdout (results). All diagnostics go to stderr.
pub struct SubprocessManager {
    child: Child,
    /// BufReader over the child's stdout, with max line length.
    stdout_reader: BufReader<tokio::process::ChildStdout>,
    /// Writer to child's stdin.
    stdin: tokio::process::ChildStdin,
    /// Path to the worker script.
    worker_script: PathBuf,
    /// Isolated HOME directory for the worker.
    worker_home: PathBuf,
}

impl SubprocessManager {
    /// Launches the worker subprocess.
    ///
    /// The worker runs with:
    /// - Cleared environment (env_clear)
    /// - HOME set to an isolated temp directory
    /// - PATH preserved for node/npx lookup
    /// - Stdin/stdout piped for JSON-lines IPC
    /// - Stderr inherited for diagnostics
    pub async fn spawn(data_dir: &Path) -> Result<Self> {
        let worker_script = find_worker_script(data_dir)?;
        let worker_home = data_dir.join("worker_home");
        std::fs::create_dir_all(&worker_home)
            .context("Failed to create worker HOME directory")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&worker_home, std::fs::Permissions::from_mode(0o700))?;
        }

        // Preserve PATH for node binary lookup
        let path_env = std::env::var("PATH").unwrap_or_default();

        let mut child = Command::new("node")
            .arg(&worker_script)
            .env_clear()
            .env("HOME", &worker_home)
            .env("PATH", &path_env)
            // Prevent Node from using the parent's npmrc/config
            .env("NODE_ENV", "production")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn worker: node {}", worker_script.display()))?;

        let stdin = child.stdin.take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture worker stdin"))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| anyhow::anyhow!("Failed to capture worker stdout"))?;

        let stdout_reader = BufReader::new(stdout);

        tracing::info!(
            pid = child.id().unwrap_or(0),
            script = %worker_script.display(),
            "Worker subprocess spawned"
        );

        Ok(Self {
            child,
            stdout_reader,
            stdin,
            worker_script,
            worker_home,
        })
    }

    /// Sends a task to the worker and waits for the result.
    ///
    /// Uses `select!` to race between:
    /// - Worker stdout line (result)
    /// - Cancellation token (graceful shutdown)
    /// - Process exit (crash)
    pub async fn execute_task(
        &mut self,
        input: &WorkerTaskInput,
        cancel: &CancellationToken,
    ) -> Result<WorkerTaskResult> {
        // Serialize task as JSON line
        let mut json = serde_json::to_string(input)
            .context("Failed to serialize worker task input")?;
        json.push('\n');

        // Send to worker stdin
        self.stdin.write_all(json.as_bytes()).await
            .context("Failed to write to worker stdin")?;
        self.stdin.flush().await
            .context("Failed to flush worker stdin")?;

        // Wait for result line from stdout
        loop {
            tokio::select! {
                result = Self::read_bounded_line(&mut self.stdout_reader) => {
                    let line = result?;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let result: WorkerTaskResult = serde_json::from_str(trimmed)
                        .with_context(|| format!(
                            "Failed to parse worker result ({} bytes)",
                            trimmed.len()
                        ))?;
                    return Ok(result);
                }
                _ = cancel.cancelled() => {
                    tracing::info!("Shutdown requested during task execution");
                    anyhow::bail!("Shutdown requested");
                }
            }
        }
    }

    /// Reads a single line from stdout, bounded to MAX_LINE_LENGTH bytes (CONS-R3-002).
    ///
    /// Unlike `read_line` which allocates unboundedly until '\n', this reads
    /// via `fill_buf` + `consume` to cap memory usage. If the line exceeds the
    /// limit, the excess is discarded until the next newline.
    async fn read_bounded_line(
        reader: &mut BufReader<tokio::process::ChildStdout>,
    ) -> Result<String> {
        use tokio::io::AsyncBufReadExt;

        let mut buf = Vec::with_capacity(8192);
        loop {
            let available = reader.fill_buf().await
                .context("Failed to read from worker stdout")?;

            if available.is_empty() {
                if buf.is_empty() {
                    anyhow::bail!("Worker process exited unexpectedly (EOF on stdout)");
                }
                break; // EOF with partial line — return what we have
            }

            // Find newline in available data
            let newline_pos = available.iter().position(|&b| b == b'\n');
            let chunk_end = newline_pos.map(|p| p + 1).unwrap_or(available.len());

            // Only copy up to remaining capacity
            let remaining_cap = MAX_LINE_LENGTH.saturating_sub(buf.len());
            let to_copy = chunk_end.min(remaining_cap);
            buf.extend_from_slice(&available[..to_copy]);
            reader.consume(chunk_end);

            if newline_pos.is_some() {
                break; // Found newline — line complete
            }

            if buf.len() >= MAX_LINE_LENGTH {
                tracing::warn!(bytes = buf.len(), "Worker output exceeds {}B, truncating", MAX_LINE_LENGTH);
                // CONS-R4-003: Discard remaining bytes until newline or EOF.
                // Propagate IO errors instead of swallowing them.
                loop {
                    let rest = reader.fill_buf().await
                        .context("IO error while discarding oversized worker output")?;
                    if rest.is_empty() { break; }
                    let end = rest.iter().position(|&b| b == b'\n')
                        .map(|p| p + 1)
                        .unwrap_or(rest.len());
                    let found_nl = end > 0 && rest[end - 1] == b'\n';
                    reader.consume(end);
                    if found_nl { break; }
                }
                break;
            }
        }

        Ok(String::from_utf8_lossy(&buf).to_string())
    }

    /// Sends a graceful shutdown command to the worker.
    pub async fn shutdown(&mut self) -> Result<()> {
        let shutdown_cmd = r#"{"command":"shutdown"}"#.to_string() + "\n";
        match self.stdin.write_all(shutdown_cmd.as_bytes()).await {
            Ok(_) => {
                let _ = self.stdin.flush().await;
                tracing::info!("Sent shutdown command to worker");
            }
            Err(e) => {
                tracing::warn!("Failed to send shutdown command: {}. Worker may have already exited.", e);
            }
        }

        // Wait for process to exit with timeout
        let timeout = tokio::time::Duration::from_secs(10);
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(status)) => {
                tracing::info!(?status, "Worker exited");
            }
            Ok(Err(e)) => {
                tracing::warn!("Error waiting for worker: {}", e);
            }
            Err(_) => {
                tracing::warn!("Worker did not exit within 10s, killing");
                let _ = self.child.kill().await;
            }
        }

        Ok(())
    }

    /// Returns the worker process ID, if still running.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
}

/// Finds the worker script path using explicit 3-tier precedence.
///
/// Search order:
/// 1. `DATAWARD_WORKER_PATH` env var (explicit override)
/// 2. Adjacent to executable / project root (development)
/// 3. `data_dir/worker/dist/worker.js` (production — extracted by `dataward init`)
fn find_worker_script(data_dir: &Path) -> Result<PathBuf> {
    // Tier 1: Explicit env var override
    if let Ok(env_path) = std::env::var("DATAWARD_WORKER_PATH") {
        let path = PathBuf::from(&env_path);
        if path.exists() {
            if !env_path.ends_with("worker.js") {
                tracing::warn!(
                    path = %env_path,
                    "DATAWARD_WORKER_PATH does not end with 'worker.js' — ensure it points to the correct script"
                );
            }
            tracing::info!(path = %path.display(), tier = "env-override", "Worker script found");
            return Ok(path);
        }
        tracing::warn!(
            path = %env_path,
            "DATAWARD_WORKER_PATH set but file not found, falling through to other tiers"
        );
    }

    // Tier 2: Adjacent to executable (development builds)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // Direct sibling, one level up, two levels up (target/debug → project root)
            for ancestor in [Some(exe_dir), exe_dir.parent(), exe_dir.parent().and_then(|p| p.parent())] {
                if let Some(dir) = ancestor {
                    let script = dir.join("worker/dist/worker.js");
                    if script.exists() {
                        tracing::info!(path = %script.display(), tier = "development", "Worker script found");
                        return Ok(script);
                    }
                }
            }
        }
    }

    // Also check CWD for development convenience
    let cwd_script = PathBuf::from("worker/dist/worker.js");
    if cwd_script.exists() {
        tracing::info!(path = %cwd_script.display(), tier = "development-cwd", "Worker script found");
        return Ok(cwd_script);
    }

    // Tier 3: Production path (extracted by dataward init)
    let data_script = data_dir.join("worker/dist/worker.js");
    if data_script.exists() {
        tracing::info!(path = %data_script.display(), tier = "production", "Worker script found");
        return Ok(data_script);
    }

    anyhow::bail!(
        "Worker script not found. Run `dataward init` to set up the worker runtime.\n\
         Checked locations:\n\
         - DATAWARD_WORKER_PATH env var (not set or file missing)\n\
         - Adjacent to binary (development builds)\n\
         - {} (production)",
        data_script.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_task_input_serializes() {
        let input = WorkerTaskInput {
            task_id: "123".to_string(),
            broker_id: "spokeo".to_string(),
            playbook_path: "/playbooks/official/spokeo.yaml".to_string(),
            user_data: HashMap::from([
                ("first_name".to_string(), "John".to_string()),
                ("email".to_string(), "john@example.com".to_string()),
            ]),
            timeout_ms: 120_000,
            proof_dir: "/proofs/".to_string(),
            allowed_domains: vec!["spokeo.com".to_string(), "www.spokeo.com".to_string()],
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"task_id\":\"123\""));
        assert!(json.contains("\"broker_id\":\"spokeo\""));
        assert!(json.contains("\"timeout_ms\":120000"));
        // Should be a single line (no internal newlines)
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_worker_task_result_deserializes_success() {
        let json = r#"{"task_id":"123","status":"success","proof":{"screenshot_path":"/proofs/test.png","confirmation_text":"Request received"},"duration_ms":5000}"#;
        let result: WorkerTaskResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.task_id, "123");
        assert_eq!(result.status, "success");
        assert!(result.proof.is_some());
        assert_eq!(result.proof.as_ref().unwrap().confirmation_text, "Request received");
        assert_eq!(result.duration_ms, 5000);
        assert!(result.error_code.is_none());
    }

    #[test]
    fn test_worker_task_result_deserializes_failure() {
        let json = r##"{"task_id":"456","status":"failure","error_code":"selector_not_found","error_message":"#submit not found","step_index":3,"duration_ms":12000}"##;
        let result: WorkerTaskResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.task_id, "456");
        assert_eq!(result.status, "failure");
        assert_eq!(result.error_code.as_deref(), Some("selector_not_found"));
        assert_eq!(result.error_message.as_deref(), Some("#submit not found"));
        assert_eq!(result.step_index, Some(3));
        assert!(result.proof.is_none());
    }

    #[test]
    fn test_worker_task_result_deserializes_timeout() {
        let json = r#"{"task_id":"789","status":"timeout","error_code":"timeout","error_message":"Task exceeded 120000ms","duration_ms":120001}"#;
        let result: WorkerTaskResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.status, "timeout");
        assert_eq!(result.error_code.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_find_worker_script_finds_cwd_or_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_worker_script(dir.path());
        // If worker/dist/worker.js exists in CWD (dev environment), it's found.
        // If not (CI), it returns an error.
        if let Err(e) = &result {
            assert!(e.to_string().contains("Worker script not found"));
        } else {
            let path = result.unwrap();
            assert!(path.to_str().unwrap().contains("worker.js"));
        }
    }

    #[test]
    fn test_shutdown_command_format() {
        let cmd = r#"{"command":"shutdown"}"#;
        let parsed: serde_json::Value = serde_json::from_str(cmd).unwrap();
        assert_eq!(parsed["command"], "shutdown");
    }
}
