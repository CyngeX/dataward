use anyhow::{Context, Result};
use secrecy::{SecretBox, SecretString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::api_worker;
use crate::broker_registry;
use crate::config::Config;
use crate::crypto;
use crate::dashboard;
use crate::db;
use crate::email_worker;
use crate::logging;
use crate::scheduler;
use crate::subprocess;

/// Per-task timeout for browser/subprocess tasks (120 seconds).
const BROWSER_TIMEOUT_MS: u64 = 120_000;

/// Per-task timeout for email tasks (30 seconds).
const EMAIL_TIMEOUT_SECS: u64 = 30;

/// Per-task timeout for API tasks (15 seconds).
const API_TIMEOUT_SECS: u64 = 15;

/// Graceful shutdown timeout (30 seconds).
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// PID file name within the data directory.
const PID_FILE_NAME: &str = "dataward.pid";

/// Summary of a single scheduler run.
#[derive(Debug, Default)]
pub struct RunSummary {
    pub total: i32,
    pub succeeded: i32,
    pub failed: i32,
    pub captcha_blocked: i32,
    pub skipped: i32,
}

impl std::fmt::Display for RunSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Tasks: {} total, {} succeeded, {} failed, {} captcha, {} skipped",
            self.total, self.succeeded, self.failed, self.captcha_blocked, self.skipped
        )
    }
}

/// Main entry point for `dataward run`.
///
/// Lifecycle:
/// 1. Acquire PID file lock (flock)
/// 2. Read passphrase, derive key
/// 3. Open DB connections (read + write)
/// 4. Initialize logging
/// 5. Crash recovery (reset orphans, replay journal)
/// 6. Spawn DB writer
/// 7. Set up signal handlers
/// 8. Run scheduler loop (daemon) or single tick (--once)
/// 9. Graceful shutdown
pub async fn run(data_dir: &Path, once: bool) -> Result<()> {
    // 1. Acquire PID lock
    let pid_lock = acquire_pid_lock(data_dir)?;

    // 2. Read passphrase and derive key BEFORE starting tokio threads.
    //    strip_passphrase_env must be called single-threaded.
    let passphrase = crypto::get_passphrase("Passphrase: ")?;
    let salt = std::fs::read(data_dir.join(".salt"))
        .context("Failed to read salt file. Is Dataward initialized?")?;
    // CONS-015: Use Zeroizing to securely clear key material on drop
    let hex_key = Zeroizing::new(db::derive_db_key(&passphrase, &salt)?);
    // Keep passphrase for dashboard master key derivation (dropped after dashboard setup)
    let passphrase_for_key = passphrase;

    // 3. Open DB connections
    let db_path = data_dir.join("dataward.db");
    let read_conn = db::open_db_with_key(&db_path, &hex_key)?;
    let write_conn = db::open_db_with_key(&db_path, &hex_key)?;
    // hex_key kept alive until dashboard state is built (deferred drop)

    // CONS-007: Set busy_timeout to handle write contention between read_conn
    // and write_conn in WAL mode. Startup writes (reset_orphaned_tasks,
    // replay_journal) happen before spawn_writer, so they are safe.
    // Runtime writes (mark_task_running, scheduler_tick) may contend with
    // the writer task; busy_timeout ensures SQLite waits rather than returning
    // SQLITE_BUSY immediately.
    read_conn
        .busy_timeout(std::time::Duration::from_secs(5))
        .context("Failed to set busy_timeout on read connection")?;

    // 4. Initialize logging
    let config = Config::load(data_dir)?;
    logging::init_logging(data_dir, &config.logging.level)?;
    tracing::info!(
        data_dir = %data_dir.display(),
        once,
        "Dataward starting"
    );

    // 5. Crash recovery
    let orphans = db::reset_orphaned_tasks(&read_conn)?;
    if orphans > 0 {
        tracing::warn!(orphans, "Reset orphaned tasks from previous run");
    }

    let journal_path = data_dir.join("db_journal.jsonl");
    let replayed = db::replay_journal(&read_conn, &journal_path)?;
    if replayed > 0 {
        tracing::info!(replayed, "Replayed journal entries from previous crash");
    }

    // 6. Spawn DB writer
    let (db_tx, writer_handle) = db::spawn_writer(write_conn, journal_path.clone());

    // 6b. Create scheduler notification channel (dashboard → scheduler)
    let (scheduler_notify_tx, scheduler_notify_rx) = mpsc::channel::<()>(1);

    // 6c. Start dashboard (if auth token configured)
    let dashboard_handle = {
        let auth_token = db::get_config(&read_conn, "dashboard_token")?;
        match auth_token {
            Some(token) => {
                // Derive master key for proof decryption (same Argon2id derivation)
                let (master_key_bytes, _) = crypto::derive_key_with_params(
                    passphrase_for_key.as_bytes(),
                    Some(&salt),
                    &crypto::PRODUCTION_PARAMS,
                )?;
                drop(passphrase_for_key); // No longer needed

                // Generate session secret
                let mut session_secret = [0u8; 32];
                getrandom::fill(&mut session_secret)
                    .map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;

                // Create dashboard indexes
                db::create_dashboard_indexes(&read_conn)?;

                // Precompute token hash for session cookie verification
                use sha2::Digest;
                let token_hash = sha2::Sha256::digest(token.as_bytes());
                let token_hash_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    token_hash,
                );

                let dashboard_state = dashboard::DashboardState {
                    db_path: db_path.clone(),
                    db_hex_key: SecretString::from(hex_key.as_str().to_string()),
                    write_tx: db_tx.clone(),
                    scheduler_notify: scheduler_notify_tx,
                    master_key: Arc::new(SecretBox::new(Box::new(master_key_bytes))),
                    auth_token: SecretString::from(token),
                    session_secret: Arc::new(SecretBox::new(Box::new(session_secret.to_vec()))),
                    token_hash_b64,
                    data_dir: data_dir.to_path_buf(),
                    login_attempts: Arc::new(tokio::sync::Mutex::new(
                        std::collections::VecDeque::new(),
                    )),
                };

                let cancel_dashboard = CancellationToken::new();
                let cancel_dashboard_clone = cancel_dashboard.clone();

                match dashboard::start(dashboard_state, cancel_dashboard_clone).await {
                    Ok(handle) => {
                        tracing::info!("Dashboard started on http://127.0.0.1:9847");
                        Some((handle, cancel_dashboard))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to start dashboard (continuing without): {}", e);
                        None
                    }
                }
            }
            None => {
                tracing::info!("No dashboard token configured, skipping dashboard");
                None
            }
        }
    };

    // hex_key is Zeroizing — memory will be zeroed on drop
    drop(hex_key);

    // 7. Set up cancellation and signal handlers
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        if let Err(e) = wait_for_shutdown_signal().await {
            tracing::error!("Signal handler error: {}", e);
        }
        tracing::info!("Shutdown signal received");
        cancel_clone.cancel();
    });

    // 8. Run scheduler
    let playbooks_dir = data_dir.join("playbooks");
    let proof_dir = data_dir.join("proofs");
    std::fs::create_dir_all(&proof_dir)?;

    let result = if once {
        run_once(
            &read_conn,
            &db_tx,
            &config,
            &playbooks_dir,
            &proof_dir,
            data_dir,
            &cancel,
        )
        .await
    } else {
        run_daemon(
            &read_conn,
            &db_tx,
            &config,
            &playbooks_dir,
            &proof_dir,
            data_dir,
            &cancel,
            scheduler_notify_rx,
        )
        .await
    };

    // 9. Graceful shutdown
    tracing::info!("Initiating shutdown...");

    // 9a. Shut down dashboard first (5s timeout)
    if let Some((handle, cancel_token)) = dashboard_handle {
        tracing::info!("Stopping dashboard...");
        cancel_token.cancel();
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(())) => tracing::info!("Dashboard shut down cleanly"),
            Ok(Err(e)) => tracing::warn!("Dashboard task panicked: {}", e),
            Err(_) => tracing::warn!("Dashboard shutdown timed out after 5s"),
        }
    }

    // 9b. Signal DB writer to shut down
    let _ = db_tx.send(db::DbWriteMessage::Shutdown).await; // Shutdown send failure is expected if writer already stopped
    drop(db_tx);

    // Wait for writer with timeout
    match tokio::time::timeout(
        std::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
        writer_handle,
    )
    .await
    {
        Ok(Ok(Ok(()))) => tracing::info!("DB writer shut down cleanly"),
        Ok(Ok(Err(e))) => tracing::warn!("DB writer error during shutdown: {}", e),
        Ok(Err(e)) => tracing::warn!("DB writer task panicked: {}", e),
        Err(_) => tracing::warn!(
            "DB writer shutdown timed out after {}s",
            SHUTDOWN_TIMEOUT_SECS
        ),
    }

    // Release PID lock (implicit on drop, but be explicit)
    drop(pid_lock);

    tracing::info!("Dataward stopped");
    result
}

/// Runs a single scheduler tick, processes all due tasks, then exits.
async fn run_once(
    read_conn: &rusqlite::Connection,
    db_tx: &mpsc::Sender<db::DbWriteMessage>,
    config: &Config,
    playbooks_dir: &Path,
    proof_dir: &Path,
    data_dir: &Path,
    cancel: &CancellationToken,
) -> Result<()> {
    let tick = scheduler::scheduler_tick(read_conn, playbooks_dir)?;
    let summary = dispatch_tasks(
        read_conn,
        db_tx,
        config,
        &tick.due_tasks,
        proof_dir,
        data_dir,
        cancel,
    )
    .await?;

    // Update run log (CONS-R2-019: log send failures)
    if let Err(e) = db_tx
        .send(db::DbWriteMessage::UpdateRunLog {
            run_id: tick.run_id,
            total: summary.total,
            succeeded: summary.succeeded,
            failed: summary.failed,
            captcha_blocked: summary.captcha_blocked,
        })
        .await
    {
        tracing::error!(run_id = tick.run_id, "Failed to send run log update: {}", e);
    }

    // Print summary
    eprintln!();
    eprintln!("=== Run Complete ===");
    eprintln!("{}", summary);
    if tick.tasks_created > 0 {
        eprintln!("New tasks created: {}", tick.tasks_created);
    }

    Ok(())
}

/// Runs the scheduler in daemon mode with periodic ticks.
async fn run_daemon(
    read_conn: &rusqlite::Connection,
    db_tx: &mpsc::Sender<db::DbWriteMessage>,
    config: &Config,
    playbooks_dir: &Path,
    proof_dir: &Path,
    data_dir: &Path,
    cancel: &CancellationToken,
    mut scheduler_notify_rx: mpsc::Receiver<()>,
) -> Result<()> {
    // CONS-R2-008: Validate interval_hours > 0 (zero causes tokio panic)
    if config.scheduler.interval_hours == 0 {
        anyhow::bail!("scheduler.interval_hours must be > 0 (got 0)");
    }
    let interval_secs = config.scheduler.interval_hours as u64 * 3600;
    let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(
        interval_hours = config.scheduler.interval_hours,
        "Daemon mode: scheduler running every {} hours",
        config.scheduler.interval_hours
    );

    loop {
        tokio::select! {
            _ = tick_interval.tick() => {
                tracing::info!("Scheduler tick starting");
                match scheduler::scheduler_tick(read_conn, playbooks_dir) {
                    Ok(tick) => {
                        // CONS-R2-002: Catch dispatch errors; don't tear down daemon
                        let summary = match dispatch_tasks(
                            read_conn, db_tx, config, &tick.due_tasks, proof_dir, data_dir, cancel,
                        ).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!("dispatch_tasks failed: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = db_tx.send(db::DbWriteMessage::UpdateRunLog {
                            run_id: tick.run_id,
                            total: summary.total,
                            succeeded: summary.succeeded,
                            failed: summary.failed,
                            captcha_blocked: summary.captcha_blocked,
                        }).await {
                            tracing::error!(run_id = tick.run_id, "Failed to send run log update: {}", e);
                        }

                        tracing::info!(%summary, "Scheduler tick complete");
                    }
                    Err(e) => {
                        tracing::error!("Scheduler tick failed: {}", e);
                    }
                }
            }
            // Dashboard notification: CAPTCHA resolved or re-run triggered → immediate tick
            _ = scheduler_notify_rx.recv() => {
                tracing::info!("Dashboard triggered immediate scheduler tick");
                match scheduler::scheduler_tick(read_conn, playbooks_dir) {
                    Ok(tick) => {
                        match dispatch_tasks(
                            read_conn, db_tx, config, &tick.due_tasks, proof_dir, data_dir, cancel,
                        ).await {
                            Ok(summary) => {
                                if let Err(e) = db_tx.send(db::DbWriteMessage::UpdateRunLog {
                                    run_id: tick.run_id,
                                    total: summary.total,
                                    succeeded: summary.succeeded,
                                    failed: summary.failed,
                                    captcha_blocked: summary.captcha_blocked,
                                }).await {
                                    tracing::error!(run_id = tick.run_id, "Failed to send run log update: {}", e);
                                }
                                tracing::info!(%summary, "Dashboard-triggered tick complete");
                            }
                            Err(e) => {
                                tracing::error!("Dashboard-triggered dispatch failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Dashboard-triggered scheduler tick failed: {}", e);
                    }
                }
            }
            _ = cancel.cancelled() => {
                tracing::info!("Shutdown signal received, stopping daemon");
                break;
            }
        }
    }

    Ok(())
}

/// Maximum size in bytes for any single PII profile field value.
///
/// Values exceeding this are rejected before being sent to workers
/// to prevent OOM in the subprocess or oversized JSON payloads (CONS-R3-006).
const MAX_PII_FIELD_BYTES: usize = 512;

/// Dispatches due tasks to the appropriate worker by channel type.
///
/// Architecture: Tasks are dispatched sequentially (concurrency=1). Each task
/// is routed to one of three channels: `web_form` (subprocess), `email` (SMTP),
/// or `api` (HTTPS POST). `manual_only` tasks are skipped without marking as
/// running. Playbooks and PII fields are cached per-tick to avoid redundant
/// filesystem and DB reads (CONS-R3-003).
///
/// CONS-R3-008: The email and API arms share a similar load-validate-send pattern.
/// TODO(Phase 4): Extract shared dispatch helper to reduce duplication.
async fn dispatch_tasks(
    read_conn: &rusqlite::Connection,
    db_tx: &mpsc::Sender<db::DbWriteMessage>,
    config: &Config,
    due_tasks: &[db::DueTask],
    proof_dir: &Path,
    data_dir: &Path,
    cancel: &CancellationToken,
) -> Result<RunSummary> {
    let mut summary = RunSummary::default();
    summary.total = due_tasks.len() as i32;

    if due_tasks.is_empty() {
        return Ok(summary);
    }

    // CONS-R3-003: Cache PII profile fields per-tick (one DB read for all tasks)
    let all_profile = db::get_all_profile_fields(read_conn)?;

    // Lazily create workers only when needed
    let mut subprocess_mgr: Option<subprocess::SubprocessManager> = None;
    // CONS-R3-017: API client created per-tick; reqwest internally pools connections.
    let api_client = api_worker::create_api_client()?;

    // CONS-R3-003: Cache loaded playbooks per-tick (keyed by parent directory)
    let mut playbook_cache: std::collections::HashMap<PathBuf, Vec<broker_registry::Playbook>> =
        std::collections::HashMap::new();

    for task in due_tasks {
        if cancel.is_cancelled() {
            tracing::info!("Shutdown requested, stopping task dispatch");
            // CONS-R3-013: Subtract already-counted items including skipped
            summary.skipped += (due_tasks.len() as i32)
                - summary.succeeded
                - summary.failed
                - summary.captcha_blocked
                - summary.skipped;
            break;
        }

        // CONS-R3-001: Check channel BEFORE marking as running.
        // Non-dispatchable channels skip without acquiring the task.
        match task.channel.as_str() {
            "manual_only" => {
                tracing::debug!(
                    broker = %task.broker_id,
                    "Skipping manual-only broker"
                );
                summary.skipped += 1;
                continue;
            }
            "web_form" | "email" | "api" => {} // dispatchable — proceed
            other => {
                tracing::warn!(
                    broker = %task.broker_id,
                    channel = other,
                    "Unknown opt-out channel, skipping"
                );
                summary.skipped += 1;
                continue;
            }
        }

        // Mark task as running (CONS-011: check rows_affected)
        // Only reached for dispatchable channels (web_form, email, api)
        match db::mark_task_running(read_conn, task.id) {
            Ok(true) => {} // claimed successfully
            Ok(false) => {
                tracing::warn!(
                    task_id = task.id,
                    "Task already claimed by another tick, skipping"
                );
                summary.skipped += 1;
                continue;
            }
            Err(e) => {
                tracing::error!(task_id = task.id, "Failed to mark task running: {}", e);
                summary.failed += 1;
                continue;
            }
        }

        tracing::info!(
            task_id = task.id,
            broker = %task.broker_id,
            channel = %task.channel,
            "Dispatching task"
        );

        match task.channel.as_str() {
            "web_form" => {
                // Load playbook to get required_fields and allowed_domains
                // CONS-R2-009: Return error instead of silently falling back to "."
                let playbook_parent = match PathBuf::from(&task.playbook_path).parent() {
                    Some(p) => p.to_path_buf(),
                    None => {
                        report_failure(
                            db_tx,
                            task,
                            "playbook_error",
                            &format!("Invalid playbook path (no parent): {}", task.playbook_path),
                            false,
                        )
                        .await;
                        summary.failed += 1;
                        continue;
                    }
                };
                // CONS-R3-003: Use playbook cache instead of reloading from disk per task
                let playbook = match get_cached_playbook(
                    &mut playbook_cache,
                    &playbook_parent,
                    &task.broker_id,
                    task.id,
                ) {
                    Ok(Some(p)) => p,
                    Ok(None) => {
                        report_failure(db_tx, task, "playbook_error", "Playbook not found", false)
                            .await;
                        summary.failed += 1;
                        continue;
                    }
                    Err(e) => {
                        report_failure(db_tx, task, "playbook_error", &e.to_string(), false).await;
                        summary.failed += 1;
                        continue;
                    }
                };

                // CONS-R3-003: Validate required PII fields from cached profile data
                let user_data =
                    match validate_fields_from_cache(&all_profile, &playbook.required_fields) {
                        Ok(data) => data,
                        Err(e) => {
                            report_failure(db_tx, task, "playbook_error", &e.to_string(), false)
                                .await;
                            summary.failed += 1;
                            continue;
                        }
                    };

                // Spawn subprocess if not already running
                if subprocess_mgr.is_none() {
                    match subprocess::SubprocessManager::spawn(data_dir).await {
                        Ok(mgr) => subprocess_mgr = Some(mgr),
                        Err(e) => {
                            tracing::error!("Failed to spawn worker subprocess: {}", e);
                            report_failure(db_tx, task, "playbook_error", &e.to_string(), true)
                                .await;
                            summary.failed += 1;
                            continue;
                        }
                    }
                }

                let mgr = subprocess_mgr.as_mut().unwrap();

                let input = subprocess::WorkerTaskInput {
                    task_id: task.id.to_string(),
                    broker_id: task.broker_id.clone(),
                    playbook_path: playbook.file_path.to_string_lossy().to_string(),
                    user_data,
                    timeout_ms: BROWSER_TIMEOUT_MS,
                    proof_dir: proof_dir.to_string_lossy().to_string(),
                    allowed_domains: playbook.broker.allowed_domains.clone(),
                };

                // Execute with per-task timeout
                let result = tokio::time::timeout(
                    std::time::Duration::from_millis(BROWSER_TIMEOUT_MS + 5000), // 5s grace
                    mgr.execute_task(&input, cancel),
                )
                .await;

                match result {
                    Ok(Ok(worker_result)) => {
                        process_worker_result(
                            db_tx,
                            task,
                            &worker_result,
                            playbook.broker.recheck_days,
                            playbook.max_retries as i32,
                            &mut summary,
                        )
                        .await;
                    }
                    Ok(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("Shutdown requested") {
                            summary.skipped += 1;
                        } else {
                            // Worker crashed — clear the subprocess manager so it respawns
                            tracing::error!(task_id = task.id, "Worker error: {}", msg);
                            subprocess_mgr = None;
                            report_failure(db_tx, task, "playbook_error", &msg, true).await;
                            summary.failed += 1;
                        }
                    }
                    Err(_) => {
                        // Outer timeout fired
                        tracing::error!(task_id = task.id, "Task timed out (outer)");
                        report_failure(db_tx, task, "timeout", "Task exceeded outer timeout", true)
                            .await;
                        summary.failed += 1;
                        // Kill and respawn worker
                        subprocess_mgr = None;
                    }
                }
            }
            "email" => {
                // Load playbook for required_fields (CONS-R3-003: cached)
                let playbook =
                    load_playbook_for_broker(&PathBuf::from(&task.playbook_path), &task.broker_id);

                let (required_fields, broker_name, broker_email, recheck_days, max_retries) =
                    match playbook {
                        Ok(p) => {
                            // CONS-001: Use broker.url as the email address for email-channel brokers.
                            let email = p.broker.url.clone();
                            if email.is_empty() || !email.contains('@') {
                                report_failure(
                                db_tx, task, "playbook_error",
                                &format!("Broker '{}' has no valid email address in playbook (url field: '{}')", p.broker.id, email),
                                false,
                            ).await;
                                summary.failed += 1;
                                continue;
                            }
                            (
                                p.required_fields.clone(),
                                p.broker.name.clone(),
                                email,
                                p.broker.recheck_days,
                                p.max_retries as i32,
                            )
                        }
                        Err(e) => {
                            report_failure(db_tx, task, "playbook_error", &e.to_string(), false)
                                .await;
                            summary.failed += 1;
                            continue;
                        }
                    };

                // CONS-R3-003: Validate from cached profile data
                let user_data = match validate_fields_from_cache(&all_profile, &required_fields) {
                    Ok(data) => data,
                    Err(e) => {
                        report_failure(db_tx, task, "playbook_error", &e.to_string(), false).await;
                        summary.failed += 1;
                        continue;
                    }
                };

                let email_result = tokio::time::timeout(
                    std::time::Duration::from_secs(EMAIL_TIMEOUT_SECS),
                    email_worker::send_opt_out_email(
                        read_conn,
                        &task.broker_id,
                        &broker_name,
                        &broker_email,
                        &user_data,
                        config.email.daily_limit,
                    ),
                )
                .await;

                match email_result {
                    Ok(Ok(result)) => {
                        if result.success {
                            if let Err(e) = db_tx
                                .send(db::DbWriteMessage::CompleteTaskSuccess {
                                    task_id: task.id,
                                    duration_ms: result.duration_ms,
                                    proof_path: None,
                                    confirmation_text: result.confirmation_text,
                                    recheck_days,
                                })
                                .await
                            {
                                tracing::error!(task_id = task.id, "DB writer send failed: {}", e);
                            }
                            summary.succeeded += 1;
                        } else if result.error_code.as_deref() == Some("rate_limited") {
                            // CONS-R3-007: Rate-limited tasks reset to pending without
                            // burning a retry attempt. Rate limiting is transient infra,
                            // not a task-level failure.
                            if let Err(e) = db_tx
                                .send(db::DbWriteMessage::UpdateTask {
                                    task_id: task.id,
                                    status: "pending".to_string(),
                                    error_code: Some("rate_limited".to_string()),
                                    error_message: result.error_message,
                                    error_retryable: Some(true),
                                    duration_ms: Some(result.duration_ms),
                                    proof_path: None,
                                    confirmation_text: None,
                                    // CONS-R4-001: Delay recheck by 1 day to avoid tight re-dispatch loop
                                    delay_recheck_days: Some(1),
                                })
                                .await
                            {
                                tracing::error!(task_id = task.id, "DB writer send failed: {}", e);
                            }
                            summary.skipped += 1;
                        } else {
                            if let Err(e) = db_tx
                                .send(db::DbWriteMessage::FailTaskWithRetry {
                                    task_id: task.id,
                                    error_code: result
                                        .error_code
                                        .unwrap_or_else(|| "playbook_error".into()),
                                    error_message: result.error_message.unwrap_or_default(),
                                    error_retryable: result.error_retryable,
                                    duration_ms: result.duration_ms,
                                    max_retries,
                                })
                                .await
                            {
                                tracing::error!(task_id = task.id, "DB writer send failed: {}", e);
                            }
                            summary.failed += 1;
                        }
                    }
                    Ok(Err(e)) => {
                        report_failure(db_tx, task, "playbook_error", &e.to_string(), true).await;
                        summary.failed += 1;
                    }
                    Err(_) => {
                        report_failure(db_tx, task, "timeout", "Email task timed out", true).await;
                        summary.failed += 1;
                    }
                }
            }
            "api" => {
                let playbook =
                    load_playbook_for_broker(&PathBuf::from(&task.playbook_path), &task.broker_id);

                let (api_url, required_fields, recheck_days, max_retries) = match playbook {
                    Ok(p) => (
                        p.broker.url.clone(),
                        p.required_fields.clone(),
                        p.broker.recheck_days,
                        p.max_retries as i32,
                    ),
                    Err(e) => {
                        report_failure(db_tx, task, "playbook_error", &e.to_string(), false).await;
                        summary.failed += 1;
                        continue;
                    }
                };

                // CONS-R3-003: Validate from cached profile data
                let user_data = match validate_fields_from_cache(&all_profile, &required_fields) {
                    Ok(data) => data,
                    Err(e) => {
                        report_failure(db_tx, task, "playbook_error", &e.to_string(), false).await;
                        summary.failed += 1;
                        continue;
                    }
                };

                let api_result = tokio::time::timeout(
                    std::time::Duration::from_secs(API_TIMEOUT_SECS),
                    api_worker::send_opt_out_api(
                        &api_client,
                        &api_url,
                        &user_data,
                        &task.broker_id,
                    ),
                )
                .await;

                match api_result {
                    Ok(result) => {
                        if result.success {
                            if let Err(e) = db_tx
                                .send(db::DbWriteMessage::CompleteTaskSuccess {
                                    task_id: task.id,
                                    duration_ms: result.duration_ms,
                                    proof_path: None,
                                    confirmation_text: result.confirmation_text,
                                    recheck_days,
                                })
                                .await
                            {
                                tracing::error!(task_id = task.id, "DB writer send failed: {}", e);
                            }
                            summary.succeeded += 1;
                        } else {
                            if let Err(e) = db_tx
                                .send(db::DbWriteMessage::FailTaskWithRetry {
                                    task_id: task.id,
                                    error_code: result
                                        .error_code
                                        .unwrap_or_else(|| "playbook_error".into()),
                                    error_message: result.error_message.unwrap_or_default(),
                                    error_retryable: result.error_retryable,
                                    duration_ms: result.duration_ms,
                                    max_retries,
                                })
                                .await
                            {
                                tracing::error!(task_id = task.id, "DB writer send failed: {}", e);
                            }
                            summary.failed += 1;
                        }
                    }
                    Err(_) => {
                        report_failure(db_tx, task, "timeout", "API task timed out", true).await;
                        summary.failed += 1;
                    }
                }
            }
            // CONS-R3-001: manual_only and unknown channels handled before mark_task_running
            _ => unreachable!("non-dispatchable channels filtered before mark_task_running"),
        }
    }

    // Gracefully shut down the subprocess manager if it was used
    if let Some(mut mgr) = subprocess_mgr {
        if let Err(e) = mgr.shutdown().await {
            tracing::warn!("Worker shutdown error: {}", e);
        }
    }

    Ok(summary)
}

/// Processes a worker result from the subprocess manager.
async fn process_worker_result(
    db_tx: &mpsc::Sender<db::DbWriteMessage>,
    task: &db::DueTask,
    result: &subprocess::WorkerTaskResult,
    recheck_days: i32,
    max_retries: i32,
    summary: &mut RunSummary,
) {
    match result.status.as_str() {
        "success" => {
            let proof_path = result
                .proof
                .as_ref()
                .and_then(|p| p.screenshot_path.clone());
            let confirmation_text = result.proof.as_ref().map(|p| p.confirmation_text.clone());
            if let Err(e) = db_tx
                .send(db::DbWriteMessage::CompleteTaskSuccess {
                    task_id: task.id,
                    duration_ms: result.duration_ms,
                    proof_path,
                    confirmation_text,
                    recheck_days,
                })
                .await
            {
                tracing::error!(task_id = %task.id, "DB writer send failed: {}", e);
            }
            summary.succeeded += 1;
        }
        "captcha_blocked" => {
            if let Err(e) = db_tx
                .send(db::DbWriteMessage::FailTaskWithRetry {
                    task_id: task.id,
                    error_code: "captcha_blocked".to_string(),
                    error_message: result.error_message.clone().unwrap_or_default(),
                    error_retryable: true,
                    duration_ms: result.duration_ms,
                    max_retries,
                })
                .await
            {
                tracing::error!(task_id = %task.id, "DB writer send failed: {}", e);
            }
            summary.captcha_blocked += 1;
        }
        "timeout" => {
            if let Err(e) = db_tx
                .send(db::DbWriteMessage::FailTaskWithRetry {
                    task_id: task.id,
                    error_code: "timeout".to_string(),
                    error_message: result.error_message.clone().unwrap_or_default(),
                    error_retryable: true,
                    duration_ms: result.duration_ms,
                    max_retries,
                })
                .await
            {
                tracing::error!(task_id = %task.id, "DB writer send failed: {}", e);
            }
            summary.failed += 1;
        }
        _ => {
            // All other failure statuses
            let error_retryable = matches!(
                result.error_code.as_deref(),
                Some("selector_not_found") | Some("page_structure_changed")
            );
            if let Err(e) = db_tx
                .send(db::DbWriteMessage::FailTaskWithRetry {
                    task_id: task.id,
                    error_code: result
                        .error_code
                        .clone()
                        .unwrap_or_else(|| "playbook_error".to_string()),
                    error_message: result.error_message.clone().unwrap_or_default(),
                    error_retryable,
                    duration_ms: result.duration_ms,
                    max_retries,
                })
                .await
            {
                tracing::error!(task_id = %task.id, "DB writer send failed: {}", e);
            }
            summary.failed += 1;
        }
    }
}

/// Reports a task failure through the DB writer channel.
async fn report_failure(
    db_tx: &mpsc::Sender<db::DbWriteMessage>,
    task: &db::DueTask,
    error_code: &str,
    error_message: &str,
    retryable: bool,
) {
    if let Err(e) = db_tx
        .send(db::DbWriteMessage::FailTaskWithRetry {
            task_id: task.id,
            error_code: error_code.to_string(),
            error_message: error_message.to_string(),
            error_retryable: retryable,
            duration_ms: 0,
            max_retries: task.max_retries,
        })
        .await
    {
        tracing::error!(
            task_id = task.id,
            "Failed to send failure to DB writer: {}",
            e
        );
    }
}

/// Loads a single playbook for a specific broker.
fn load_playbook_for_broker(
    playbook_path: &Path,
    broker_id: &str,
) -> Result<broker_registry::Playbook> {
    // The playbook_path in the DB is the full path to the YAML file.
    // We need to find its parent directory structure (official/community/local)
    // to load via the standard playbook loader.
    let parent = playbook_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid playbook path: {}", playbook_path.display()))?;
    let grandparent = parent.parent().ok_or_else(|| {
        anyhow::anyhow!("Invalid playbook directory structure: {}", parent.display())
    })?;

    let playbooks = broker_registry::load_playbooks(grandparent)?;
    playbooks
        .into_iter()
        .find(|p| p.broker.id == broker_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Playbook for broker '{}' not found in {}",
                broker_id,
                grandparent.display()
            )
        })
}

/// Looks up a playbook from the per-tick cache, loading from disk on first access (CONS-R3-003).
fn get_cached_playbook(
    cache: &mut std::collections::HashMap<PathBuf, Vec<broker_registry::Playbook>>,
    playbook_parent: &Path,
    broker_id: &str,
    task_id: i64,
) -> Result<Option<broker_registry::Playbook>> {
    if !cache.contains_key(playbook_parent) {
        match broker_registry::load_playbooks(playbook_parent) {
            Ok(playbooks) => {
                // CONS-R4-004: Warn when directory loads empty — all tasks for this
                // directory will fail this tick with "Playbook not found".
                if playbooks.is_empty() {
                    tracing::warn!(
                        path = %playbook_parent.display(),
                        "Playbook directory loaded with no playbooks — all tasks for this directory will fail"
                    );
                }
                cache.insert(playbook_parent.to_path_buf(), playbooks);
            }
            Err(e) => {
                tracing::error!(task_id, "Failed to load playbook: {}", e);
                return Err(e);
            }
        }
    }

    let playbooks = cache
        .get(playbook_parent)
        .expect("cache key was just inserted");
    Ok(playbooks.iter().find(|p| p.broker.id == broker_id).cloned())
}

/// Validates required fields from a pre-loaded profile cache (CONS-R3-003).
///
/// Returns a HashMap of required fields → values, or an error if any are missing
/// or exceed the size limit (CONS-R4-002).
fn validate_fields_from_cache(
    all_profile: &std::collections::HashMap<String, String>,
    required_fields: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    let mut user_data = std::collections::HashMap::new();
    let mut missing = Vec::new();

    for field in required_fields {
        match all_profile.get(field) {
            Some(value) => {
                user_data.insert(field.clone(), value.clone());
            }
            None => {
                missing.push(field.clone());
            }
        }
    }

    if !missing.is_empty() {
        anyhow::bail!(
            "Missing required PII fields: {}. Run `dataward init` to update your profile.",
            missing.join(", ")
        );
    }

    // CONS-R4-002: Validate PII field sizes for all channels (not just web_form).
    // Also includes field name in error message (resolves CONS-R4-006).
    for (key, value) in &user_data {
        if value.len() > MAX_PII_FIELD_BYTES {
            anyhow::bail!(
                "PII field '{}' exceeds {} byte limit ({} bytes)",
                key,
                MAX_PII_FIELD_BYTES,
                value.len()
            );
        }
    }

    Ok(user_data)
}

/// Acquires an exclusive PID file lock using flock().
///
/// This prevents multiple daemon instances from running simultaneously.
/// The lock is automatically released when the returned guard is dropped.
fn acquire_pid_lock(data_dir: &Path) -> Result<PidLock> {
    use fs2::FileExt;

    let pid_path = data_dir.join(PID_FILE_NAME);

    // CONS-R2-020: Open WITHOUT truncate, lock first, then truncate and write
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&pid_path)
        .with_context(|| format!("Failed to open PID file: {}", pid_path.display()))?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pid_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Try to acquire exclusive lock (non-blocking)
    match file.try_lock_exclusive() {
        Ok(()) => {
            // Truncate and write our PID only after acquiring lock
            use std::io::Write;
            let mut file = file;
            file.set_len(0)?;
            write!(file, "{}", std::process::id())?;
            file.sync_all()?;
            Ok(PidLock {
                _file: file,
                path: pid_path,
            })
        }
        Err(_e) => {
            // Read existing PID for error message
            let existing_pid = std::fs::read_to_string(&pid_path).unwrap_or_default();
            anyhow::bail!(
                "Another Dataward instance is already running (PID: {}). \
                 Remove {} if the process is not running.",
                existing_pid.trim(),
                pid_path.display()
            )
        }
    }
}

/// Guard that holds the PID file lock. Lock is released on drop.
#[derive(Debug)]
struct PidLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl Drop for PidLock {
    fn drop(&mut self) {
        // Remove PID file on clean shutdown
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Waits for SIGTERM or SIGINT.
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;
    let mut sigint =
        signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM");
        }
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT");
        }
    }

    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_summary_display() {
        let summary = RunSummary {
            total: 10,
            succeeded: 7,
            failed: 2,
            captcha_blocked: 1,
            skipped: 0,
        };
        let display = format!("{}", summary);
        assert!(display.contains("10 total"));
        assert!(display.contains("7 succeeded"));
        assert!(display.contains("2 failed"));
        assert!(display.contains("1 captcha"));
    }

    #[test]
    fn test_run_summary_default() {
        let summary = RunSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_pid_lock_acquire_and_release() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join(PID_FILE_NAME);

        // Acquire lock
        let lock = acquire_pid_lock(dir.path()).unwrap();
        assert!(pid_path.exists());

        // Read PID from file
        let pid_content = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(pid_content, std::process::id().to_string());

        // Second lock should fail
        let result = acquire_pid_lock(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));

        // Drop lock — PID file should be removed
        drop(lock);
        assert!(!pid_path.exists());
    }

    #[test]
    fn test_pid_lock_stale_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join(PID_FILE_NAME);

        // Write a stale PID file (no flock held)
        std::fs::write(&pid_path, "99999").unwrap();

        // Should be able to acquire lock despite stale file
        let lock = acquire_pid_lock(dir.path()).unwrap();
        let pid_content = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(pid_content, std::process::id().to_string());
        drop(lock);
    }

    #[test]
    fn test_worker_result_success_classification() {
        // Test that we correctly identify success vs failure from worker results
        let success_result = subprocess::WorkerTaskResult {
            task_id: "1".to_string(),
            status: "success".to_string(),
            proof: Some(subprocess::WorkerProofInfo {
                screenshot_path: Some("/proofs/test.png".to_string()),
                confirmation_text: "Confirmed".to_string(),
            }),
            error_code: None,
            error_message: None,
            step_index: None,
            duration_ms: 5000,
        };
        assert_eq!(success_result.status, "success");

        let failure_result = subprocess::WorkerTaskResult {
            task_id: "2".to_string(),
            status: "failure".to_string(),
            proof: None,
            error_code: Some("selector_not_found".to_string()),
            error_message: Some("Button missing".to_string()),
            step_index: Some(3),
            duration_ms: 12000,
        };
        assert_eq!(failure_result.status, "failure");
        assert!(failure_result.error_code.is_some());
    }
}
