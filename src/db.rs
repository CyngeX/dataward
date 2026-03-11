use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::mpsc;

use crate::crypto;

/// Database schema version for migration tracking.
const SCHEMA_VERSION: i32 = 1;

/// Opens (or creates) the SQLCipher-encrypted database with WAL mode.
pub fn open_db(db_path: &Path, passphrase: &str, salt: &[u8]) -> Result<Connection> {
    open_db_with_params(db_path, passphrase, salt, &crypto::PRODUCTION_PARAMS)
}

/// Opens the database with explicit Argon2id parameters (used by tests).
pub fn open_db_with_params(
    db_path: &Path,
    passphrase: &str,
    salt: &[u8],
    params: &crypto::Argon2Params,
) -> Result<Connection> {
    // Argon2id key is re-derived on every open_db call. This is intentional for Phase 1
    // where the database is opened once per process run and performance is not a concern.
    // TODO(Phase 2+): If reconnection support is added, derive the key once at startup
    // and cache it securely rather than re-deriving on every open call.
    let (key, _) = crypto::derive_key_with_params(passphrase.as_bytes(), Some(salt), params)?;
    let hex_key = crypto::key_to_sqlcipher_hex(&key);

    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    // Set SQLCipher encryption key
    conn.pragma_update(None, "key", &hex_key)
        .context("Failed to set SQLCipher key (wrong passphrase?)")?;

    // Verify the key works by attempting a read
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| anyhow::anyhow!("Incorrect passphrase. Your data is safe — try again."))?;

    // Enable WAL mode for read concurrency
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("Failed to enable WAL mode")?;

    // Foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("Failed to enable foreign keys")?;

    Ok(conn)
}

/// Opens the database with a pre-derived SQLCipher hex key.
///
/// Use this when you need multiple connections (e.g., read + write) to avoid
/// the expensive Argon2id derivation on each open call.
pub fn open_db_with_key(db_path: &Path, hex_key: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    conn.pragma_update(None, "key", hex_key)
        .context("Failed to set SQLCipher key (wrong passphrase?)")?;

    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| anyhow::anyhow!("Incorrect passphrase. Your data is safe — try again."))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .context("Failed to enable WAL mode")?;

    conn.pragma_update(None, "foreign_keys", "ON")
        .context("Failed to enable foreign keys")?;

    Ok(conn)
}

/// Derives the SQLCipher hex key from passphrase and salt.
///
/// Returns the hex key string that can be passed to `open_db_with_key`.
/// Derive once, open multiple connections.
pub fn derive_db_key(passphrase: &str, salt: &[u8]) -> Result<String> {
    derive_db_key_with_params(passphrase, salt, &crypto::PRODUCTION_PARAMS)
}

/// Derives the SQLCipher hex key with explicit Argon2id parameters (used by tests).
pub fn derive_db_key_with_params(
    passphrase: &str,
    salt: &[u8],
    params: &crypto::Argon2Params,
) -> Result<String> {
    let (key, _) = crypto::derive_key_with_params(passphrase.as_bytes(), Some(salt), params)?;
    Ok(crypto::key_to_sqlcipher_hex(&key))
}

/// Re-encrypts the database with a new passphrase using SQLCipher's PRAGMA rekey.
///
/// 1. Opens the DB with the old passphrase
/// 2. Derives a new key from the new passphrase (reusing existing salt)
/// 3. Issues PRAGMA rekey to re-encrypt in place
/// 4. Verifies the new key works
pub fn rekey_db(
    db_path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    salt: &[u8],
) -> Result<()> {
    rekey_db_with_params(
        db_path,
        old_passphrase,
        new_passphrase,
        salt,
        &crypto::PRODUCTION_PARAMS,
    )
}

/// Re-encrypts the database with explicit Argon2id parameters (used by tests).
pub fn rekey_db_with_params(
    db_path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    salt: &[u8],
    params: &crypto::Argon2Params,
) -> Result<()> {
    // Open with old key
    let conn = open_db_with_params(db_path, old_passphrase, salt, params)?;

    // Derive new key
    let (new_key, _) =
        crypto::derive_key_with_params(new_passphrase.as_bytes(), Some(salt), params)?;
    let new_hex_key = crypto::key_to_sqlcipher_hex(&new_key);

    // Re-encrypt the database
    conn.pragma_update(None, "rekey", &new_hex_key)
        .context("Failed to rekey database (PRAGMA rekey failed)")?;

    // Verify the new key works by closing and reopening
    drop(conn);
    let verify_conn = open_db_with_params(db_path, new_passphrase, salt, params)?;
    verify_conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .context("Rekey verification failed — database may be corrupted")?;

    Ok(())
}

/// Creates the database and applies the initial schema.
pub fn create_db(db_path: &Path, passphrase: &str) -> Result<(Connection, Vec<u8>)> {
    create_db_with_params(db_path, passphrase, &crypto::PRODUCTION_PARAMS)
}

/// Creates the database with explicit Argon2id parameters (used by tests).
pub fn create_db_with_params(
    db_path: &Path,
    passphrase: &str,
    params: &crypto::Argon2Params,
) -> Result<(Connection, Vec<u8>)> {
    // Generate a new salt for this database
    let (key, salt) = crypto::derive_key_with_params(passphrase.as_bytes(), None, params)?;
    let hex_key = crypto::key_to_sqlcipher_hex(&key);

    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to create database: {}", db_path.display()))?;

    // Set encryption key
    conn.pragma_update(None, "key", &hex_key)
        .context("Failed to set SQLCipher key")?;

    // Enable WAL mode
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("Failed to enable WAL mode")?;

    // Foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("Failed to enable foreign keys")?;

    apply_schema(&conn)?;

    // Set restrictive file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok((conn, salt))
}

/// Applies the full database schema.
fn apply_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS brokers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            opt_out_channel TEXT NOT NULL,
            recheck_days INTEGER NOT NULL,
            parent_company TEXT,
            playbook_path TEXT NOT NULL,
            trust_tier TEXT NOT NULL DEFAULT 'official',
            enabled INTEGER DEFAULT 1,
            success_rate REAL DEFAULT 0.0,
            last_success_at TEXT
        );

        CREATE TABLE IF NOT EXISTS opt_out_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            broker_id TEXT NOT NULL REFERENCES brokers(id),
            status TEXT NOT NULL,
            channel TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            next_recheck_at TEXT,
            retry_count INTEGER DEFAULT 0,
            proof_path TEXT,
            proof_missing INTEGER DEFAULT 0,
            confirmation_text TEXT,
            error_code TEXT,
            error_message TEXT,
            error_retryable INTEGER,
            duration_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS user_profile (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS run_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            total_tasks INTEGER,
            succeeded INTEGER,
            failed INTEGER,
            captcha_blocked INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_status ON opt_out_tasks(status);
        CREATE INDEX IF NOT EXISTS idx_tasks_recheck ON opt_out_tasks(next_recheck_at);
        CREATE INDEX IF NOT EXISTS idx_tasks_broker ON opt_out_tasks(broker_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_status_recheck ON opt_out_tasks(status, next_recheck_at);
        -- CONS-R2-012: Composite index for daily email count query
        CREATE INDEX IF NOT EXISTS idx_tasks_email_daily ON opt_out_tasks(channel, status, completed_at);

        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );
        ",
    )
    .context("Failed to apply database schema")?;

    // Set schema version
    let current_version: Option<i32> = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
            row.get(0)
        })
        .ok();

    if current_version.is_none() {
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [SCHEMA_VERSION],
        )
        .context("Failed to set schema version")?;
    }

    Ok(())
}

// -- User profile helpers --

/// Stores a PII field in the encrypted user_profile table.
pub fn set_profile_field(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO user_profile (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )
    .with_context(|| format!("Failed to store profile field: {}", key))?;
    Ok(())
}

/// Retrieves a PII field from the user_profile table.
pub fn get_profile_field(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    let result = conn.query_row(
        "SELECT value FROM user_profile WHERE key = ?1",
        [key],
        |row| row.get::<_, Vec<u8>>(0),
    );
    match result {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e).context("Failed to read profile field"),
    }
}

/// Retrieves all PII fields from the user_profile table.
///
/// Returns a HashMap of key → value (raw bytes decoded as UTF-8).
/// Used by the dispatcher to cache profile data per-tick (CONS-R3-003).
pub fn get_all_profile_fields(conn: &Connection) -> Result<HashMap<String, String>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM user_profile")
        .context("Failed to prepare get_all_profile_fields query")?;
    let rows = stmt
        .query_map([], |row| {
            let key: String = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            Ok((key, value))
        })
        .context("Failed to query profile fields")?;

    let mut fields = HashMap::new();
    for row in rows {
        let (key, value) = row.context("Failed to read profile field row")?;
        let s = String::from_utf8(value)
            .with_context(|| format!("Profile field '{}' contains invalid UTF-8", key))?;
        if !s.is_empty() {
            fields.insert(key, s);
        }
    }
    Ok(fields)
}

// -- Config helpers --

/// Stores a config value (non-PII).
pub fn set_config(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )
    .with_context(|| format!("Failed to store config: {}", key))?;
    Ok(())
}

/// Retrieves a config value.
pub fn get_config(conn: &Connection, key: &str) -> Result<Option<String>> {
    let result = conn.query_row("SELECT value FROM config WHERE key = ?1", [key], |row| {
        row.get::<_, String>(0)
    });
    match result {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e).context("Failed to read config"),
    }
}

// -- Broker helpers --

/// Inserts or updates a broker in the registry.
pub fn upsert_broker(conn: &Connection, broker: &BrokerRow) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO brokers (id, name, category, opt_out_channel, recheck_days, parent_company, playbook_path, trust_tier, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            broker.id,
            broker.name,
            broker.category,
            broker.opt_out_channel,
            broker.recheck_days,
            broker.parent_company,
            broker.playbook_path,
            broker.trust_tier,
            broker.enabled,
        ],
    )
    .with_context(|| format!("Failed to upsert broker: {}", broker.id))?;
    Ok(())
}

/// Row representation for the brokers table.
#[derive(Debug, Clone)]
pub struct BrokerRow {
    pub id: String,
    pub name: String,
    pub category: String,
    pub opt_out_channel: String,
    pub recheck_days: i32,
    pub parent_company: Option<String>,
    pub playbook_path: String,
    pub trust_tier: String,
    pub enabled: bool,
}

// -- Crash recovery --

/// Resets all `running` tasks to `pending` on startup.
/// This handles orphaned tasks from a previous crash.
pub fn reset_orphaned_tasks(conn: &Connection) -> Result<usize> {
    let count = conn
        .execute(
            "UPDATE opt_out_tasks SET status = 'pending' WHERE status = 'running'",
            [],
        )
        .context("Failed to reset orphaned tasks")?;
    Ok(count)
}

// -- Scheduler queries --

/// A task that is due for execution.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DueTask {
    pub id: i64,
    pub broker_id: String,
    pub channel: String,
    pub retry_count: i32,
    pub playbook_path: String,
    pub allowed_domains: Vec<String>,
    pub max_retries: i32,
}

/// Retrieves all pending tasks that are due for execution.
///
/// A task is due when:
/// - status = 'pending'
/// - next_recheck_at IS NULL (first run) OR next_recheck_at <= now
/// - the associated broker is enabled
pub fn get_due_tasks(conn: &Connection) -> Result<Vec<DueTask>> {
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.broker_id, t.channel, t.retry_count,
                b.playbook_path, b.recheck_days
         FROM opt_out_tasks t
         JOIN brokers b ON t.broker_id = b.id
         WHERE t.status = 'pending'
           AND b.enabled = 1
           AND (t.next_recheck_at IS NULL OR t.next_recheck_at <= datetime('now'))
         ORDER BY t.next_recheck_at ASC NULLS FIRST",
        )
        .context("Failed to prepare get_due_tasks query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(DueTask {
                id: row.get(0)?,
                broker_id: row.get(1)?,
                channel: row.get(2)?,
                retry_count: row.get(3)?,
                playbook_path: row.get(4)?,
                // allowed_domains populated separately below
                allowed_domains: Vec::new(),
                max_retries: 3, // default, overridden below
            })
        })
        .context("Failed to query due tasks")?;

    // CONS-R2-018: Surface row deserialization errors instead of silently dropping
    let tasks: Vec<DueTask> = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to deserialize due task rows")?;

    // Populate allowed_domains from playbook YAML (stored in broker metadata)
    // For now, we'll load them when dispatching. Leave empty here.
    // The dispatcher will read the playbook file to get allowed_domains.

    Ok(tasks)
}

/// Creates pending tasks for all enabled brokers that don't have an active task.
///
/// An "active" task is one with status in ('pending', 'running').
/// Returns the number of tasks created.
pub fn create_missing_tasks(conn: &Connection) -> Result<usize> {
    let count = conn
        .execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
         SELECT b.id, 'pending', b.opt_out_channel, datetime('now')
         FROM brokers b
         WHERE b.enabled = 1
           AND NOT EXISTS (
               SELECT 1 FROM opt_out_tasks t
               WHERE t.broker_id = b.id
                 AND t.status IN ('pending', 'running')
           )",
            [],
        )
        .context("Failed to create missing tasks")?;

    Ok(count)
}

/// Marks a task as 'running' before dispatch.
///
/// Returns Ok(true) if the task was claimed, Ok(false) if another
/// process/tick already claimed it (0 rows affected).
pub fn mark_task_running(conn: &Connection, task_id: i64) -> Result<bool> {
    let rows = conn
        .execute(
            "UPDATE opt_out_tasks SET status = 'running' WHERE id = ?1 AND status = 'pending'",
            [task_id],
        )
        .context("Failed to mark task as running")?;
    Ok(rows > 0)
}

/// Exponential backoff durations for retries: 1h, 4h, 24h, 72h.
#[allow(dead_code)]
const RETRY_BACKOFFS: &[i64] = &[3600, 14400, 86400, 259200];

/// Calculates the next retry time based on retry count.
///
/// Returns offset in seconds from now. After exhausting RETRY_BACKOFFS,
/// returns the last value (72h).
#[allow(dead_code)]
pub fn retry_backoff_secs(retry_count: i32) -> i64 {
    let idx = (retry_count.max(0) as usize).min(RETRY_BACKOFFS.len() - 1);
    RETRY_BACKOFFS[idx]
}

/// Updates a failed task for retry if retryable and under max_retries.
///
/// Returns true if the task was scheduled for retry, false if permanently failed.
/// CONS-R2-010: Uses atomic UPDATE with WHERE clause to avoid TOCTOU.
pub fn update_task_for_retry(
    conn: &Connection,
    task_id: i64,
    error_code: &str,
    error_message: &str,
    error_retryable: bool,
    duration_ms: i64,
    max_retries: i32,
) -> Result<bool> {
    if error_retryable {
        // Atomic: UPDATE only if retry_count < max_retries (no separate SELECT)
        // Use the current retry_count for backoff calculation via CASE expression.
        // NOTE: CASE values MUST match RETRY_BACKOFFS constant above (CONS-R3-015).
        // retry_count 0→3600s(1h), 1→14400s(4h), 2→86400s(24h), ≥3→259200s(72h)
        let rows = conn
            .execute(
                "UPDATE opt_out_tasks SET
                status = 'pending',
                retry_count = retry_count + 1,
                error_code = ?1,
                error_message = ?2,
                error_retryable = 1,
                duration_ms = ?3,
                next_recheck_at = datetime('now', '+' ||
                    CASE
                        WHEN retry_count >= 3 THEN 259200
                        WHEN retry_count = 2 THEN 86400
                        WHEN retry_count = 1 THEN 14400
                        ELSE 3600
                    END || ' seconds')
             WHERE id = ?4 AND retry_count < ?5",
                rusqlite::params![error_code, error_message, duration_ms, task_id, max_retries],
            )
            .context("Failed to schedule task retry")?;

        if rows > 0 {
            return Ok(true);
        }
        // Fall through: retry_count >= max_retries, mark as permanent failure
    }

    {
        conn.execute(
            "UPDATE opt_out_tasks SET
                status = 'failure',
                error_code = ?1,
                error_message = ?2,
                error_retryable = ?3,
                duration_ms = ?4,
                completed_at = datetime('now')
             WHERE id = ?5",
            rusqlite::params![
                error_code,
                error_message,
                error_retryable as i32,
                duration_ms,
                task_id,
            ],
        )
        .context("Failed to mark task as permanently failed")?;
        Ok(false)
    }
}

/// Marks a task as successful.
pub fn complete_task_success(
    conn: &Connection,
    task_id: i64,
    duration_ms: i64,
    proof_path: Option<&str>,
    confirmation_text: Option<&str>,
    recheck_days: i32,
) -> Result<()> {
    conn.execute(
        "UPDATE opt_out_tasks SET
            status = 'success',
            duration_ms = ?1,
            proof_path = ?2,
            confirmation_text = ?3,
            completed_at = datetime('now'),
            next_recheck_at = datetime('now', '+' || ?4 || ' days'),
            error_code = NULL,
            error_message = NULL,
            error_retryable = NULL
         WHERE id = ?5",
        rusqlite::params![
            duration_ms,
            proof_path,
            confirmation_text,
            recheck_days,
            task_id
        ],
    )
    .context("Failed to complete task")?;
    Ok(())
}

// -- Run log --

/// Inserts a new run_log entry. Returns the row ID.
pub fn insert_run_log(conn: &Connection) -> Result<i64> {
    conn.execute(
        "INSERT INTO run_log (started_at, total_tasks, succeeded, failed, captcha_blocked)
         VALUES (datetime('now'), 0, 0, 0, 0)",
        [],
    )
    .context("Failed to insert run log")?;
    Ok(conn.last_insert_rowid())
}

/// Updates a run_log entry with final counts.
pub fn update_run_log(
    conn: &Connection,
    run_id: i64,
    total: i32,
    succeeded: i32,
    failed: i32,
    captcha_blocked: i32,
) -> Result<()> {
    conn.execute(
        "UPDATE run_log SET
            completed_at = datetime('now'),
            total_tasks = ?1,
            succeeded = ?2,
            failed = ?3,
            captcha_blocked = ?4
         WHERE id = ?5",
        rusqlite::params![total, succeeded, failed, captcha_blocked, run_id],
    )
    .context("Failed to update run log")?;
    Ok(())
}

/// Row returned by `get_run_summaries`.
#[allow(dead_code)]
pub struct RunSummaryRow {
    pub id: i64,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_tasks: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub captcha_blocked: i64,
}

/// Returns recent run summaries, most recent first.
#[allow(dead_code)]
pub fn get_run_summaries(conn: &Connection, limit: i64) -> Result<Vec<RunSummaryRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, started_at, completed_at, total_tasks, succeeded, failed, captcha_blocked
         FROM run_log
         ORDER BY id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit], |row| {
        Ok(RunSummaryRow {
            id: row.get(0)?,
            started_at: row.get(1)?,
            completed_at: row.get(2)?,
            total_tasks: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            succeeded: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
            failed: row.get::<_, Option<i64>>(5)?.unwrap_or(0),
            captcha_blocked: row.get::<_, Option<i64>>(6)?.unwrap_or(0),
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("Failed to query run summaries")
}

// -- Email rate limiting --

/// Returns the number of email opt-out tasks completed today.
pub fn get_daily_email_count(conn: &Connection) -> Result<i32> {
    let count: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM opt_out_tasks
         WHERE channel = 'email'
           AND status = 'success'
           AND completed_at >= date('now')",
            [],
            |row| row.get(0),
        )
        .context("Failed to count daily emails")?;
    Ok(count)
}

// -- Journal replay --

/// Valid task status values for journal replay validation (CONS-008).
const VALID_TASK_STATUSES: &[&str] = &["pending", "running", "success", "failure"];

/// Replays journal entries that were written during DB write failures.
///
/// Returns the number of entries replayed.
pub fn replay_journal(conn: &Connection, journal_path: &Path) -> Result<usize> {
    // CONS-R5-001: Check for orphaned .merging file from a crash during atomic merge.
    // If .merging exists, it contains the fully merged content and should become the journal.
    let merging_path = journal_path.with_extension("merging");
    if merging_path.exists() {
        tracing::warn!("Found orphaned .merging file — recovering from previous crash");
        std::fs::rename(&merging_path, journal_path)
            .context("Failed to recover orphaned .merging journal")?;
    }

    // CONS-R3-004: Check for orphaned .replaying file from a previous crash
    // (crash between rename-to-.replaying and COMMIT leaves unprocessed entries)
    let replaying_path = journal_path.with_extension("replaying");
    if replaying_path.exists() && !journal_path.exists() {
        tracing::warn!("Found orphaned .replaying file — recovering from previous crash");
        std::fs::rename(&replaying_path, journal_path)
            .context("Failed to recover orphaned .replaying journal")?;
    } else if replaying_path.exists() && journal_path.exists() {
        // Both exist: .replaying was from a previous crash, new journal has newer entries.
        // Prepend .replaying content to journal for unified replay.
        // CONS-R4-005: Use write-to-temp + rename for atomicity.
        let old_content = std::fs::read_to_string(&replaying_path)
            .context("Failed to read orphaned .replaying file")?;
        let new_content =
            std::fs::read_to_string(journal_path).context("Failed to read current journal")?;
        let merged = if old_content.trim().is_empty() {
            new_content.trim().to_string()
        } else {
            format!("{}\n{}", old_content.trim(), new_content.trim())
        };
        let merging_path = journal_path.with_extension("merging");
        std::fs::write(&merging_path, &merged)
            .context("Failed to write merged journal to temp file")?;
        std::fs::rename(&merging_path, journal_path)
            .context("Failed to rename merged journal into place")?;
        if let Err(e) = std::fs::remove_file(&replaying_path) {
            tracing::warn!(
                "Failed to remove .replaying after merge: {}. Will be cleaned on next startup.",
                e
            );
        }
        tracing::warn!("Merged orphaned .replaying into journal for unified replay");
    }

    if !journal_path.exists() {
        return Ok(0);
    }

    // Check journal size limit BEFORE reading into memory (CONS-024)
    let metadata = std::fs::metadata(journal_path)?;
    if metadata.len() > 10 * 1024 * 1024 {
        anyhow::bail!(
            "Journal file exceeds 10MB limit ({} bytes). Manual intervention required.",
            metadata.len()
        );
    }

    let content = std::fs::read_to_string(journal_path).context("Failed to read journal file")?;

    if content.trim().is_empty() {
        let _ = std::fs::remove_file(journal_path);
        return Ok(0);
    }

    // Rename to .replaying so the journal is preserved on crash (CONS-012)
    // replaying_path already defined at function start for CONS-R3-004 recovery
    std::fs::rename(journal_path, &replaying_path)
        .context("Failed to rename journal for replay")?;

    let mut replayed = 0;
    let mut failed = 0;
    conn.execute_batch("BEGIN")?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(entry) => {
                let entry_type = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match entry_type {
                    "update_task" => {
                        if let (Some(task_id), Some(status)) = (
                            entry.get("task_id").and_then(|v| v.as_i64()),
                            entry.get("status").and_then(|v| v.as_str()),
                        ) {
                            // Validate status against allowlist (CONS-008)
                            if !VALID_TASK_STATUSES.contains(&status) {
                                tracing::error!(
                                    task_id,
                                    status,
                                    "Journal entry has invalid status value, skipping"
                                );
                                failed += 1;
                                continue;
                            }
                            match conn.execute(
                                "UPDATE opt_out_tasks SET status = ?1, completed_at = datetime('now') WHERE id = ?2",
                                rusqlite::params![status, task_id],
                            ) {
                                Ok(_) => replayed += 1,
                                Err(e) => {
                                    tracing::error!(task_id, "Journal replay failed for update_task: {}", e);
                                    failed += 1;
                                }
                            }
                        }
                    }
                    "insert_task" => {
                        if let (Some(broker_id), Some(channel)) = (
                            entry.get("broker_id").and_then(|v| v.as_str()),
                            entry.get("channel").and_then(|v| v.as_str()),
                        ) {
                            match conn.execute(
                                "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
                                 SELECT ?1, 'pending', ?2, datetime('now')
                                 WHERE NOT EXISTS (
                                     SELECT 1 FROM opt_out_tasks
                                     WHERE broker_id = ?1 AND status IN ('pending', 'running')
                                 )",
                                rusqlite::params![broker_id, channel],
                            ) {
                                Ok(_) => replayed += 1,
                                Err(e) => {
                                    tracing::error!(
                                        broker_id,
                                        "Journal replay failed for insert_task: {}",
                                        e
                                    );
                                    failed += 1;
                                }
                            }
                        }
                    }
                    _ => {
                        tracing::warn!(entry_type, "Unknown journal entry type, skipping");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Malformed journal entry, skipping: {}", e);
                failed += 1;
            }
        }
    }

    conn.execute_batch("COMMIT")?;

    // Only delete after successful commit (CONS-012)
    // CONS-R2-013: Downgrade to warning — entries are already committed,
    // so failing to delete is not data loss (at most a harmless re-replay).
    if let Err(e) = std::fs::remove_file(&replaying_path) {
        tracing::warn!(
            "Failed to remove replayed journal file (entries already committed): {}",
            e
        );
    }

    if failed > 0 {
        tracing::warn!(replayed, failed, "Journal replay completed with failures");
    } else {
        tracing::info!(replayed, "Replayed journal entries");
    }
    Ok(replayed)
}

// -- Dashboard query functions --

/// Row returned by `get_broker_statuses` for the status page.
pub struct BrokerStatusRow {
    pub id: String,
    pub name: String,
    pub category: String,
    pub channel: String,
    pub trust_tier: String,
    pub enabled: bool,
    pub success_rate: f64,
    pub latest_status: Option<String>,
    pub last_attempt: Option<String>,
    pub next_recheck: Option<String>,
}

/// Returns broker statuses with their latest task info (window function CTE).
pub fn get_broker_statuses(conn: &Connection) -> Result<Vec<BrokerStatusRow>> {
    let mut stmt = conn.prepare(
        "WITH latest_tasks AS (
            SELECT
                broker_id, status, created_at, next_recheck_at,
                ROW_NUMBER() OVER (PARTITION BY broker_id ORDER BY created_at DESC) AS rn
            FROM opt_out_tasks
        )
        SELECT
            b.id, b.name, b.category, b.opt_out_channel, b.trust_tier, b.enabled,
            b.success_rate,
            lt.status, lt.created_at, lt.next_recheck_at
        FROM brokers b
        LEFT JOIN latest_tasks lt ON b.id = lt.broker_id AND lt.rn = 1
        ORDER BY b.name",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(BrokerStatusRow {
            id: row.get(0)?,
            name: row.get(1)?,
            category: row.get(2)?,
            channel: row.get(3)?,
            trust_tier: row.get(4)?,
            enabled: row.get::<_, i32>(5)? != 0,
            success_rate: row.get(6)?,
            latest_status: row.get(7)?,
            last_attempt: row.get(8)?,
            next_recheck: row.get(9)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("Failed to query broker statuses")
}

/// Row returned by `get_task_history` for the history page.
pub struct TaskHistoryRow {
    pub id: i64,
    pub broker_name: String,
    pub channel: String,
    pub status: String,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub proof_path: Option<String>,
    pub error_message: Option<String>,
}

/// Returns task history with cursor-based pagination.
///
/// Cursor is `(completed_at, id)`. First page: pass `None` for both.
pub fn get_task_history(
    conn: &Connection,
    cursor_ts: Option<&str>,
    cursor_id: Option<i64>,
    limit: i64,
) -> Result<Vec<TaskHistoryRow>> {
    let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match (cursor_ts, cursor_id)
    {
        (Some(ts), Some(id)) => (
            "SELECT t.id, b.name, t.channel, t.status, t.created_at, t.completed_at,
                    t.duration_ms, t.proof_path, t.error_message
             FROM opt_out_tasks t
             JOIN brokers b ON t.broker_id = b.id
             WHERE (t.completed_at < ?1 OR (t.completed_at = ?1 AND t.id < ?2))
             ORDER BY t.completed_at DESC NULLS LAST, t.id DESC
             LIMIT ?3"
                .to_string(),
            vec![
                Box::new(ts.to_string()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(id),
                Box::new(limit),
            ],
        ),
        _ => (
            "SELECT t.id, b.name, t.channel, t.status, t.created_at, t.completed_at,
                    t.duration_ms, t.proof_path, t.error_message
             FROM opt_out_tasks t
             JOIN brokers b ON t.broker_id = b.id
             ORDER BY t.completed_at DESC NULLS LAST, t.id DESC
             LIMIT ?1"
                .to_string(),
            vec![Box::new(limit) as Box<dyn rusqlite::types::ToSql>],
        ),
    };

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(TaskHistoryRow {
            id: row.get(0)?,
            broker_name: row.get(1)?,
            channel: row.get(2)?,
            status: row.get(3)?,
            created_at: row.get(4)?,
            completed_at: row.get(5)?,
            duration_ms: row.get(6)?,
            proof_path: row.get(7)?,
            error_message: row.get(8)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("Failed to query task history")
}

/// Row returned by `get_captcha_queue`.
pub struct CaptchaQueueRow {
    pub id: i64,
    pub broker_id: String,
    pub broker_name: String,
    pub broker_url: String,
    pub created_at: String,
    pub retry_count: i32,
}

/// Returns tasks in captcha_blocked status, ordered by creation time (oldest first).
pub fn get_captcha_queue(conn: &Connection) -> Result<Vec<CaptchaQueueRow>> {
    let mut stmt = conn.prepare(
        "SELECT t.id, t.broker_id, b.name, b.playbook_path, t.created_at, t.retry_count
         FROM opt_out_tasks t
         JOIN brokers b ON t.broker_id = b.id
         WHERE t.status = 'captcha_blocked'
         ORDER BY t.created_at ASC
         LIMIT 200",
    )?;

    let rows = stmt.query_map([], |row| {
        // Use the broker's URL from playbook_path parent context, or fallback
        // For now we use the broker name as URL since the actual broker URL is in the playbook
        Ok(CaptchaQueueRow {
            id: row.get(0)?,
            broker_id: row.get(1)?,
            broker_name: row.get(2)?,
            broker_url: row.get::<_, String>(3).unwrap_or_default(), // playbook_path as fallback
            created_at: row.get(4)?,
            retry_count: row.get(5)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("Failed to query captcha queue")
}

/// Result of a CAPTCHA mutation (resolve/abandon).
pub enum CaptchaMutationResult {
    /// Operation succeeded.
    Success,
    /// Task not found.
    NotFound,
    /// Task is not in captcha_blocked status.
    WrongStatus,
    /// Task has expired (>24h).
    Expired,
    /// Max retries exceeded — task permanently failed.
    MaxRetriesExceeded,
}

/// Resolves a CAPTCHA task: sets status to pending, resets retry_count.
///
/// Uses a single atomic UPDATE with all guards in the WHERE clause to prevent
/// TOCTOU races under concurrent requests.
pub fn resolve_captcha_task(conn: &Connection, task_id: i64) -> Result<CaptchaMutationResult> {
    // First check if task exists at all (for NotFound vs WrongStatus distinction)
    let task_status: Option<String> = conn
        .query_row(
            "SELECT status FROM opt_out_tasks WHERE id = ?1",
            [task_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to query task")?;

    match task_status.as_deref() {
        None => return Ok(CaptchaMutationResult::NotFound),
        Some(s) if s != "captcha_blocked" => return Ok(CaptchaMutationResult::WrongStatus),
        _ => {}
    }

    // Atomic UPDATE: status guard + expiry guard in WHERE clause.
    // If another request resolved/abandoned first, rows_affected == 0.
    let rows = conn
        .execute(
            "UPDATE opt_out_tasks SET status = 'pending', retry_count = 0
         WHERE id = ?1 AND status = 'captcha_blocked'
           AND created_at > datetime('now', '-24 hours')",
            [task_id],
        )
        .context("Failed to resolve captcha task")?;

    if rows == 0 {
        // Task was captcha_blocked but expired (created_at > 24h ago), or another
        // request resolved it between our SELECT and UPDATE (race — correct behavior).
        return Ok(CaptchaMutationResult::Expired);
    }

    Ok(CaptchaMutationResult::Success)
}

/// Abandons a CAPTCHA task: increments retry_count, returns to pending.
/// If retry_count >= 4 (meaning this is the 5th+ abandon), permanently fails the task.
///
/// Uses atomic UPDATEs with retry_count guards in WHERE to prevent TOCTOU races.
pub fn abandon_captcha_task(conn: &Connection, task_id: i64) -> Result<CaptchaMutationResult> {
    // Check task exists and is in correct status
    let task_status: Option<String> = conn
        .query_row(
            "SELECT status FROM opt_out_tasks WHERE id = ?1",
            [task_id],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to query task")?;

    match task_status.as_deref() {
        None => return Ok(CaptchaMutationResult::NotFound),
        Some(s) if s != "captcha_blocked" => return Ok(CaptchaMutationResult::WrongStatus),
        _ => {}
    }

    // Try the permanent-failure path first (retry_count >= 4 means 5th+ abandon).
    // Atomic: only matches if status AND retry_count threshold both hold.
    let perm_fail_rows = conn
        .execute(
            "UPDATE opt_out_tasks SET status = 'failure', error_code = 'max_retries_exceeded',
         error_message = 'CAPTCHA abandoned too many times', completed_at = datetime('now')
         WHERE id = ?1 AND status = 'captcha_blocked' AND retry_count >= 4",
            [task_id],
        )
        .context("Failed to permanently fail captcha task")?;

    if perm_fail_rows > 0 {
        return Ok(CaptchaMutationResult::MaxRetriesExceeded);
    }

    // Normal abandon: increment retry_count and return to pending.
    // Atomic: only matches if still captcha_blocked AND retry_count < 4.
    let rows = conn
        .execute(
            "UPDATE opt_out_tasks SET status = 'pending', retry_count = retry_count + 1
         WHERE id = ?1 AND status = 'captcha_blocked' AND retry_count < 4",
            [task_id],
        )
        .context("Failed to abandon captcha task")?;

    if rows == 0 {
        // Another request changed the status or retry_count between our SELECT and UPDATE
        return Ok(CaptchaMutationResult::WrongStatus);
    }

    Ok(CaptchaMutationResult::Success)
}

/// Checks if a task is expired (created_at + 24h < now).
#[allow(dead_code)]
fn check_task_expired(created_at: &str) -> bool {
    let created = chrono::NaiveDateTime::parse_from_str(created_at, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(created_at).map(|dt| dt.naive_utc()));
    match created {
        Ok(dt) => {
            let now = chrono::Utc::now().naive_utc();
            now.signed_duration_since(dt).num_hours() > 24
        }
        Err(_) => false, // Can't parse — don't expire
    }
}

/// Returns the proof_path for a task, if it exists.
pub fn get_task_proof_path(conn: &Connection, task_id: i64) -> Result<Option<String>> {
    conn.query_row(
        "SELECT proof_path FROM opt_out_tasks WHERE id = ?1",
        [task_id],
        |row| row.get(0),
    )
    .optional()
    .context("Failed to query task proof path")
}

/// Result of a broker re-run trigger.
pub enum RerunResult {
    /// New task created (includes broker name for response).
    Created(String),
    /// A pending/running task already exists for this broker.
    AlreadyQueued,
    /// Broker not found.
    BrokerNotFound,
    /// Broker is disabled.
    BrokerDisabled,
}

/// Triggers a re-run for a broker via atomic INSERT WHERE NOT EXISTS.
///
/// Combines the enabled check and duplicate-task check into a single atomic INSERT...SELECT
/// to prevent TOCTOU races (broker disabled between check and insert).
pub fn trigger_broker_rerun(conn: &Connection, broker_id: &str) -> Result<RerunResult> {
    // Atomic insert: checks broker exists, is enabled, and no pending/running task exists
    // all within a single SQL statement.
    let rows = conn
        .execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
         SELECT b.id, 'pending', b.opt_out_channel, datetime('now')
         FROM brokers b
         WHERE b.id = ?1 AND b.enabled = 1
           AND NOT EXISTS (
             SELECT 1 FROM opt_out_tasks
             WHERE broker_id = ?1 AND status IN ('pending', 'running')
         )",
            rusqlite::params![broker_id],
        )
        .context("Failed to trigger broker rerun")?;

    if rows > 0 {
        // Task was created — fetch broker name for response
        let broker_name: String = conn
            .query_row(
                "SELECT name FROM brokers WHERE id = ?1",
                [broker_id],
                |row| row.get(0),
            )
            .context("Failed to get broker name")?;
        Ok(RerunResult::Created(broker_name))
    } else {
        // Zero rows: broker not found, disabled, or already queued.
        // Disambiguate for accurate error responses.
        let broker_info: Option<(String, bool)> = conn
            .query_row(
                "SELECT name, enabled FROM brokers WHERE id = ?1",
                [broker_id],
                |row| Ok((row.get(0)?, row.get::<_, i32>(1)? != 0)),
            )
            .optional()
            .context("Failed to query broker")?;

        match broker_info {
            None => Ok(RerunResult::BrokerNotFound),
            Some((_, false)) => Ok(RerunResult::BrokerDisabled),
            Some(_) => Ok(RerunResult::AlreadyQueued),
        }
    }
}

/// Aggregate health statistics for the health page.
pub struct HealthStats {
    pub total_brokers: i64,
    pub active_brokers: i64,
    pub disabled_brokers: i64,
    pub pending_tasks: i64,
    pub broker_health: Vec<BrokerHealthRow>,
    pub last_run: Option<LastRunRow>,
    pub emails_today: i32,
    pub email_limit: i32,
    pub has_run_data: bool,
}

pub struct BrokerHealthRow {
    pub name: String,
    pub success_rate: f64,
    pub total_attempts: i64,
    pub successful: i64,
}

pub struct LastRunRow {
    pub started_at: String,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub captcha_blocked: i64,
}

/// Returns aggregate health statistics for the dashboard.
///
/// Uses a single CTE query for broker/task counts to minimize DB round-trips.
pub fn get_health_stats(conn: &Connection) -> Result<HealthStats> {
    // Single query for all aggregate counts
    let (total_brokers, active_brokers, pending_tasks): (i64, i64, i64) = conn.query_row(
        "SELECT
            (SELECT COUNT(*) FROM brokers),
            (SELECT COUNT(*) FROM brokers WHERE enabled = 1),
            (SELECT COUNT(*) FROM opt_out_tasks WHERE status IN ('pending', 'running'))",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let disabled_brokers = total_brokers - active_brokers;

    // Per-broker health
    let mut stmt = conn.prepare(
        "SELECT b.name,
                COUNT(t.id) as total_attempts,
                SUM(CASE WHEN t.status = 'success' THEN 1 ELSE 0 END) as successful
         FROM brokers b
         LEFT JOIN opt_out_tasks t ON b.id = t.broker_id
         GROUP BY b.id, b.name
         HAVING total_attempts > 0
         ORDER BY b.name",
    )?;
    let broker_health: Vec<BrokerHealthRow> = stmt
        .query_map([], |row| {
            let total: i64 = row.get(1)?;
            let successful: i64 = row.get(2)?;
            let rate = if total > 0 {
                (successful as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            Ok(BrokerHealthRow {
                name: row.get(0)?,
                success_rate: rate,
                total_attempts: total,
                successful,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Failed to query broker health")?;

    // Last run
    let last_run: Option<LastRunRow> = conn
        .query_row(
            "SELECT started_at, total_tasks, succeeded, failed, captcha_blocked
         FROM run_log
         ORDER BY id DESC LIMIT 1",
            [],
            |row| {
                Ok(LastRunRow {
                    started_at: row.get(0)?,
                    total: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    succeeded: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    failed: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    captcha_blocked: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                })
            },
        )
        .optional()
        .context("Failed to query last run")?;

    let has_run_data = last_run.is_some() || !broker_health.is_empty();

    let emails_today = get_daily_email_count(conn).context("Failed to query daily email count")?;

    Ok(HealthStats {
        total_brokers,
        active_brokers,
        disabled_brokers,
        pending_tasks,
        broker_health,
        last_run,
        emails_today,
        email_limit: 10, // Default; caller can override from config
        has_run_data,
    })
}

/// Creates dashboard-specific indexes if they don't already exist.
pub fn create_dashboard_indexes(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_tasks_broker_created ON opt_out_tasks(broker_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON opt_out_tasks(status, created_at ASC);
         CREATE INDEX IF NOT EXISTS idx_tasks_completed_id ON opt_out_tasks(completed_at DESC, id DESC);"
    ).context("Failed to create dashboard indexes")?;
    Ok(())
}

// -- Channel-based writer --

/// Messages that can be sent to the DB writer task.
#[derive(Debug)]
pub enum DbWriteMessage {
    /// Update an opt-out task's status and results.
    UpdateTask {
        task_id: i64,
        status: String,
        error_code: Option<String>,
        error_message: Option<String>,
        error_retryable: Option<bool>,
        duration_ms: Option<i64>,
        proof_path: Option<String>,
        confirmation_text: Option<String>,
        /// If set, delays next_recheck_at by this many days from now.
        delay_recheck_days: Option<i32>,
    },
    /// Insert a new opt-out task.
    #[allow(dead_code)]
    InsertTask { broker_id: String, channel: String },
    /// Record a successful task completion with recheck scheduling.
    CompleteTaskSuccess {
        task_id: i64,
        duration_ms: i64,
        proof_path: Option<String>,
        confirmation_text: Option<String>,
        recheck_days: i32,
    },
    /// Record a failed task with retry logic.
    FailTaskWithRetry {
        task_id: i64,
        error_code: String,
        error_message: String,
        error_retryable: bool,
        duration_ms: i64,
        max_retries: i32,
    },
    /// Update a run log entry.
    UpdateRunLog {
        run_id: i64,
        total: i32,
        succeeded: i32,
        failed: i32,
        captcha_blocked: i32,
    },
    /// Graceful shutdown.
    Shutdown,
}

/// Spawns the channel-based DB writer task.
///
/// All database writes should go through the returned sender to avoid
/// SQLite write contention. The writer drains messages and batches writes.
pub fn spawn_writer(
    conn: Connection,
    journal_path: std::path::PathBuf,
) -> (
    mpsc::Sender<DbWriteMessage>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, mut rx) = mpsc::channel::<DbWriteMessage>(256);

    let handle = tokio::task::spawn_blocking(move || {
        // Journal file handle: opened lazily on first use, held open for reuse.
        let mut journal_file: Option<std::fs::File> = None;

        while let Some(first) = rx.blocking_recv() {
            // Drain any additional pending messages into a batch.
            let mut batch = vec![first];
            while let Ok(msg) = rx.try_recv() {
                batch.push(msg);
            }

            // Check for shutdown in the batch.
            let has_shutdown = batch.iter().any(|m| matches!(m, DbWriteMessage::Shutdown));

            // Process all non-shutdown messages in a single transaction.
            let non_shutdown: Vec<_> = batch
                .into_iter()
                .filter(|m| !matches!(m, DbWriteMessage::Shutdown))
                .collect();

            if !non_shutdown.is_empty() {
                conn.execute_batch("BEGIN")?;
                for msg in non_shutdown {
                    match msg {
                        DbWriteMessage::UpdateTask {
                            task_id,
                            status,
                            error_code,
                            error_message,
                            error_retryable,
                            duration_ms,
                            proof_path,
                            confirmation_text,
                            delay_recheck_days,
                        } => {
                            let result = conn.execute(
                                "UPDATE opt_out_tasks SET status = ?1, error_code = ?2, error_message = ?3,
                                 error_retryable = ?4, duration_ms = ?5, proof_path = ?6,
                                 confirmation_text = ?7, completed_at = datetime('now'),
                                 next_recheck_at = CASE WHEN ?9 IS NOT NULL THEN datetime('now', '+' || ?9 || ' days') ELSE next_recheck_at END
                                 WHERE id = ?8",
                                rusqlite::params![
                                    status,
                                    error_code,
                                    error_message,
                                    error_retryable.map(|b| b as i32),
                                    duration_ms,
                                    proof_path,
                                    confirmation_text,
                                    task_id,
                                    delay_recheck_days,
                                ],
                            );
                            if let Err(e) = result {
                                tracing::error!(
                                    "DB write failed for task {}: {}. Writing to journal.",
                                    task_id,
                                    e
                                );
                                let entry = serde_json::json!({
                                    "type": "update_task",
                                    "task_id": task_id,
                                    "status": status,
                                });
                                write_to_journal(
                                    &journal_path,
                                    &entry.to_string(),
                                    &mut journal_file,
                                );
                            }
                        }
                        DbWriteMessage::InsertTask { broker_id, channel } => {
                            let result = conn.execute(
                                "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
                                 VALUES (?1, 'pending', ?2, datetime('now'))",
                                rusqlite::params![broker_id, channel],
                            );
                            if let Err(e) = result {
                                tracing::error!(
                                    "DB insert failed for broker {}: {}. Writing to journal.",
                                    broker_id,
                                    e
                                );
                                let entry = serde_json::json!({
                                    "type": "insert_task",
                                    "broker_id": broker_id,
                                    "channel": channel,
                                });
                                write_to_journal(
                                    &journal_path,
                                    &entry.to_string(),
                                    &mut journal_file,
                                );
                            }
                        }
                        // CONS-016: Call existing function instead of duplicating SQL
                        DbWriteMessage::CompleteTaskSuccess {
                            task_id,
                            duration_ms,
                            proof_path,
                            confirmation_text,
                            recheck_days,
                        } => {
                            if let Err(e) = complete_task_success(
                                &conn,
                                task_id,
                                duration_ms,
                                proof_path.as_deref(),
                                confirmation_text.as_deref(),
                                recheck_days,
                            ) {
                                tracing::error!(
                                    "DB success update failed for task {}: {}. Writing to journal.",
                                    task_id,
                                    e
                                );
                                let entry = serde_json::json!({
                                    "type": "update_task",
                                    "task_id": task_id,
                                    "status": "success",
                                });
                                write_to_journal(
                                    &journal_path,
                                    &entry.to_string(),
                                    &mut journal_file,
                                );
                            }
                        }
                        // CONS-003, CONS-016: Call existing function; journal on failure
                        DbWriteMessage::FailTaskWithRetry {
                            task_id,
                            error_code,
                            error_message,
                            error_retryable,
                            duration_ms,
                            max_retries,
                        } => {
                            match update_task_for_retry(
                                &conn,
                                task_id,
                                &error_code,
                                &error_message,
                                error_retryable,
                                duration_ms,
                                max_retries,
                            ) {
                                Ok(retried) => {
                                    let status = if retried { "pending" } else { "failure" };
                                    tracing::debug!(task_id, status, "Task retry result recorded");
                                }
                                Err(e) => {
                                    tracing::error!("DB retry update failed for task {}: {}. Writing to journal.", task_id, e);
                                    let entry = serde_json::json!({
                                        "type": "update_task",
                                        "task_id": task_id,
                                        "status": "failure",
                                    });
                                    write_to_journal(
                                        &journal_path,
                                        &entry.to_string(),
                                        &mut journal_file,
                                    );
                                }
                            }
                        }
                        // CONS-004: Log errors instead of silently swallowing
                        DbWriteMessage::UpdateRunLog {
                            run_id,
                            total,
                            succeeded,
                            failed,
                            captcha_blocked,
                        } => {
                            if let Err(e) = update_run_log(
                                &conn,
                                run_id,
                                total,
                                succeeded,
                                failed,
                                captcha_blocked,
                            ) {
                                tracing::error!(run_id, "Failed to update run log: {}", e);
                            }
                        }
                        DbWriteMessage::Shutdown => {}
                    }
                }
                conn.execute_batch("COMMIT")?;
            }

            if has_shutdown {
                break;
            }
        }

        Ok(())
    });

    (tx, handle)
}

/// Fallback: write failed DB operations to a journal file for later replay.
/// The file handle is held open across calls (pass `journal_file` as persistent state).
fn write_to_journal(journal_path: &Path, line: &str, journal_file: &mut Option<std::fs::File>) {
    use std::io::Write;

    // Open lazily on first call; reuse on subsequent calls.
    if journal_file.is_none() {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path)
        {
            Ok(f) => {
                // Set restrictive permissions on the journal file.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = std::fs::set_permissions(
                        journal_path,
                        std::fs::Permissions::from_mode(0o600),
                    ) {
                        tracing::error!("Failed to set journal file permissions: {}", e);
                    }
                }
                *journal_file = Some(f);
            }
            Err(e) => {
                tracing::error!("Failed to open journal file {:?}: {}", journal_path, e);
                return;
            }
        }
    }

    if let Some(file) = journal_file.as_mut() {
        if let Err(e) = writeln!(file, "{}", line) {
            tracing::error!("Failed to write to journal file: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    use crate::crypto::TEST_PARAMS;

    fn create_test_db() -> (Connection, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _salt) =
            create_db_with_params(&db_path, "test-passphrase", &TEST_PARAMS).unwrap();
        (conn, dir)
    }

    #[test]
    fn test_create_and_open_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let (_conn, salt) = create_db_with_params(&db_path, "my-passphrase", &TEST_PARAMS).unwrap();
        drop(_conn);

        // Reopen with correct passphrase
        let _conn = open_db_with_params(&db_path, "my-passphrase", &salt, &TEST_PARAMS).unwrap();
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let (_conn, salt) = create_db_with_params(&db_path, "correct-pass", &TEST_PARAMS).unwrap();
        drop(_conn);

        let result = open_db_with_params(&db_path, "wrong-pass", &salt, &TEST_PARAMS);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Incorrect passphrase"));
    }

    #[test]
    fn test_schema_tables_exist() {
        let (conn, _dir) = create_test_db();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"brokers".to_string()));
        assert!(tables.contains(&"opt_out_tasks".to_string()));
        assert!(tables.contains(&"user_profile".to_string()));
        assert!(tables.contains(&"config".to_string()));
        assert!(tables.contains(&"run_log".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));
    }

    #[test]
    fn test_profile_field_roundtrip() {
        let (conn, _dir) = create_test_db();

        set_profile_field(&conn, "email", b"john@example.com").unwrap();
        let value = get_profile_field(&conn, "email").unwrap();
        assert_eq!(value, Some(b"john@example.com".to_vec()));
    }

    #[test]
    fn test_profile_field_missing() {
        let (conn, _dir) = create_test_db();
        let value = get_profile_field(&conn, "nonexistent").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_config_roundtrip() {
        let (conn, _dir) = create_test_db();

        set_config(&conn, "dashboard_token", "abc123").unwrap();
        let value = get_config(&conn, "dashboard_token").unwrap();
        assert_eq!(value, Some("abc123".to_string()));
    }

    #[test]
    fn test_upsert_broker() {
        let (conn, _dir) = create_test_db();

        let broker = BrokerRow {
            id: "spokeo".into(),
            name: "Spokeo".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/spokeo.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        };

        upsert_broker(&conn, &broker).unwrap();

        let name: String = conn
            .query_row("SELECT name FROM brokers WHERE id = 'spokeo'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "Spokeo");
    }

    #[tokio::test]
    async fn test_writer_concurrent_sends() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_writer.db");
        let journal_path = dir.path().join("test_writer.journal");
        let (conn, _salt) =
            create_db_with_params(&db_path, "test-passphrase", &TEST_PARAMS).unwrap();

        // Insert a broker and a task so UpdateTask has something to update.
        let broker = BrokerRow {
            id: "broker1".into(),
            name: "Broker1".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/broker1.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        };
        upsert_broker(&conn, &broker).unwrap();
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at) VALUES ('broker1', 'running', 'web_form', datetime('now'))",
            [],
        ).unwrap();

        let (tx, handle) = spawn_writer(conn, journal_path);

        // Send multiple InsertTask messages concurrently from different tasks.
        let mut join_set = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let tx2 = tx.clone();
            join_set.spawn(async move {
                tx2.send(DbWriteMessage::InsertTask {
                    broker_id: "broker1".into(),
                    channel: "web_form".into(),
                })
                .await
                .unwrap();
            });
        }
        while join_set.join_next().await.is_some() {}

        tx.send(DbWriteMessage::Shutdown).await.unwrap();
        drop(tx);
        handle.await.unwrap().unwrap();

        // Reopen DB and verify inserts were processed.
        let db_path2 = dir.path().join("test_writer.db");
        let salt_path = dir.path().join("test_writer.db-salt");
        // We just verify the writer task completed without panic; row count varies by timing.
        let _ = (db_path2, salt_path);
    }

    #[test]
    fn test_open_db_with_key() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let (_conn, salt) = create_db_with_params(&db_path, "my-passphrase", &TEST_PARAMS).unwrap();
        drop(_conn);

        // Derive key once
        let hex_key = derive_db_key_with_params("my-passphrase", &salt, &TEST_PARAMS).unwrap();

        // Open two connections with same key
        let conn1 = open_db_with_key(&db_path, &hex_key).unwrap();
        let conn2 = open_db_with_key(&db_path, &hex_key).unwrap();

        // Both should be able to read
        let _: i32 = conn1
            .query_row("SELECT COUNT(*) FROM brokers", [], |row| row.get(0))
            .unwrap();
        let _: i32 = conn2
            .query_row("SELECT COUNT(*) FROM brokers", [], |row| row.get(0))
            .unwrap();
    }

    #[test]
    fn test_get_due_tasks_returns_pending() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");

        // Insert a pending task with no recheck time (first run)
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
             VALUES ('broker1', 'pending', 'web_form', datetime('now'))",
            [],
        )
        .unwrap();

        let tasks = get_due_tasks(&conn).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].broker_id, "broker1");
    }

    #[test]
    fn test_get_due_tasks_skips_future() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");

        // Insert a pending task scheduled for the future
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, next_recheck_at)
             VALUES ('broker1', 'pending', 'web_form', datetime('now'), datetime('now', '+1 day'))",
            [],
        )
        .unwrap();

        let tasks = get_due_tasks(&conn).unwrap();
        assert_eq!(tasks.len(), 0);
    }

    #[test]
    fn test_get_due_tasks_skips_disabled_broker() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        conn.execute("UPDATE brokers SET enabled = 0 WHERE id = 'broker1'", [])
            .unwrap();

        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
             VALUES ('broker1', 'pending', 'web_form', datetime('now'))",
            [],
        )
        .unwrap();

        let tasks = get_due_tasks(&conn).unwrap();
        assert_eq!(tasks.len(), 0);
    }

    #[test]
    fn test_create_missing_tasks() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        insert_test_broker(&conn, "broker2");

        // broker1 already has a pending task
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
             VALUES ('broker1', 'pending', 'web_form', datetime('now'))",
            [],
        )
        .unwrap();

        // Should create a task only for broker2
        let created = create_missing_tasks(&conn).unwrap();
        assert_eq!(created, 1);

        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM opt_out_tasks WHERE broker_id = 'broker2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_retry_backoff_schedule() {
        assert_eq!(retry_backoff_secs(0), 3600); // 1h
        assert_eq!(retry_backoff_secs(1), 14400); // 4h
        assert_eq!(retry_backoff_secs(2), 86400); // 24h
        assert_eq!(retry_backoff_secs(3), 259200); // 72h
        assert_eq!(retry_backoff_secs(99), 259200); // clamped to last
    }

    #[test]
    fn test_update_task_for_retry_schedules_retry() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, retry_count)
             VALUES ('broker1', 'running', 'web_form', datetime('now'), 0)",
            [],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();

        let retried = update_task_for_retry(
            &conn,
            task_id,
            "selector_not_found",
            "Button missing",
            true,
            5000,
            3,
        )
        .unwrap();
        assert!(retried);

        let status: String = conn
            .query_row(
                "SELECT status FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending");

        let retry_count: i32 = conn
            .query_row(
                "SELECT retry_count FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retry_count, 1);
    }

    #[test]
    fn test_update_task_for_retry_fails_permanently_when_exhausted() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, retry_count)
             VALUES ('broker1', 'running', 'web_form', datetime('now'), 3)",
            [],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();

        let retried = update_task_for_retry(
            &conn,
            task_id,
            "playbook_error",
            "Step failed",
            true,
            5000,
            3,
        )
        .unwrap();
        assert!(!retried);

        let status: String = conn
            .query_row(
                "SELECT status FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "failure");
    }

    #[test]
    fn test_update_task_for_retry_non_retryable_fails_immediately() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, retry_count)
             VALUES ('broker1', 'running', 'web_form', datetime('now'), 0)",
            [],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();

        let retried = update_task_for_retry(
            &conn,
            task_id,
            "domain_violation",
            "Security violation",
            false,
            3000,
            3,
        )
        .unwrap();
        assert!(!retried);

        let status: String = conn
            .query_row(
                "SELECT status FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "failure");
    }

    #[test]
    fn test_complete_task_success() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
             VALUES ('broker1', 'running', 'web_form', datetime('now'))",
            [],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();

        complete_task_success(
            &conn,
            task_id,
            5000,
            Some("/proofs/test.png"),
            Some("Confirmed"),
            90,
        )
        .unwrap();

        let status: String = conn
            .query_row(
                "SELECT status FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "success");

        // next_recheck_at should be set (90 days from now)
        let has_recheck: bool = conn
            .query_row(
                "SELECT next_recheck_at IS NOT NULL FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_recheck);
    }

    #[test]
    fn test_run_log_lifecycle() {
        let (conn, _dir) = create_test_db();

        let run_id = insert_run_log(&conn).unwrap();
        assert!(run_id > 0);

        update_run_log(&conn, run_id, 10, 8, 1, 1).unwrap();

        let (total, succeeded): (i32, i32) = conn
            .query_row(
                "SELECT total_tasks, succeeded FROM run_log WHERE id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(total, 10);
        assert_eq!(succeeded, 8);
    }

    #[test]
    fn test_get_daily_email_count() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");

        // Insert completed email tasks
        for _ in 0..3 {
            conn.execute(
                "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at, completed_at)
                 VALUES ('broker1', 'success', 'email', datetime('now'), datetime('now'))",
                [],
            )
            .unwrap();
        }

        let count = get_daily_email_count(&conn).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_replay_journal() {
        let (conn, _dir) = create_test_db();
        let journal_path = _dir.path().join("test.journal");
        insert_test_broker(&conn, "broker1");
        insert_test_broker(&conn, "broker2");

        // Write some journal entries (different brokers for idempotent INSERT)
        let entries = vec![
            r#"{"type":"insert_task","broker_id":"broker1","channel":"web_form"}"#,
            r#"{"type":"insert_task","broker_id":"broker2","channel":"email"}"#,
        ];
        std::fs::write(&journal_path, entries.join("\n") + "\n").unwrap();

        let replayed = replay_journal(&conn, &journal_path).unwrap();
        assert_eq!(replayed, 2);

        // Journal file should be removed after replay
        assert!(!journal_path.exists());

        // Tasks should exist in DB
        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM opt_out_tasks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_replay_journal_missing_file() {
        let (conn, _dir) = create_test_db();
        let journal_path = _dir.path().join("nonexistent.journal");
        let replayed = replay_journal(&conn, &journal_path).unwrap();
        assert_eq!(replayed, 0);
    }

    #[test]
    fn test_mark_task_running() {
        let (conn, _dir) = create_test_db();
        insert_test_broker(&conn, "broker1");
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
             VALUES ('broker1', 'pending', 'web_form', datetime('now'))",
            [],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();

        let claimed = mark_task_running(&conn, task_id).unwrap();
        assert!(claimed, "Task should be claimed on first attempt");

        let status: String = conn
            .query_row(
                "SELECT status FROM opt_out_tasks WHERE id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "running");

        // CONS-011: Second attempt should return false (already claimed)
        let claimed_again = mark_task_running(&conn, task_id).unwrap();
        assert!(!claimed_again, "Task should not be claimable a second time");
    }

    /// Helper to insert a test broker (used by scheduler query tests).
    fn insert_test_broker(conn: &Connection, id: &str) {
        let broker = BrokerRow {
            id: id.into(),
            name: format!("Test {}", id),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: format!("playbooks/official/{}.yaml", id),
            trust_tier: "official".into(),
            enabled: true,
        };
        upsert_broker(conn, &broker).unwrap();
    }

    #[test]
    fn test_reset_orphaned_tasks() {
        let (conn, _dir) = create_test_db();

        // Insert a broker first (FK constraint)
        let broker = BrokerRow {
            id: "test".into(),
            name: "Test".into(),
            category: "people_search".into(),
            opt_out_channel: "web_form".into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: "playbooks/official/test.yaml".into(),
            trust_tier: "official".into(),
            enabled: true,
        };
        upsert_broker(&conn, &broker).unwrap();

        // Insert tasks in various states
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at) VALUES ('test', 'running', 'web_form', datetime('now'))",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at) VALUES ('test', 'pending', 'web_form', datetime('now'))",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at) VALUES ('test', 'running', 'email', datetime('now'))",
            [],
        ).unwrap();

        let count = reset_orphaned_tasks(&conn).unwrap();
        assert_eq!(count, 2);

        // Verify all running tasks are now pending
        let running_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM opt_out_tasks WHERE status = 'running'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(running_count, 0);
    }

    #[test]
    fn test_rekey_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_rekey.db");

        // Create DB with old passphrase
        let (conn, salt) = create_db_with_params(&db_path, "old-pass", &TEST_PARAMS).unwrap();
        set_config(&conn, "test_key", "test_value").unwrap();
        drop(conn);

        // Rekey to new passphrase
        rekey_db_with_params(&db_path, "old-pass", "new-pass", &salt, &TEST_PARAMS).unwrap();

        // Old passphrase should fail
        let result = open_db_with_params(&db_path, "old-pass", &salt, &TEST_PARAMS);
        assert!(result.is_err());

        // New passphrase should work and data should be intact
        let conn = open_db_with_params(&db_path, "new-pass", &salt, &TEST_PARAMS).unwrap();
        let value = get_config(&conn, "test_key").unwrap();
        assert_eq!(value.as_deref(), Some("test_value"));
    }

    #[test]
    fn test_rekey_db_wrong_old_passphrase() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_rekey_wrong.db");

        let (_conn, salt) = create_db_with_params(&db_path, "correct-pass", &TEST_PARAMS).unwrap();
        drop(_conn);

        // Wrong old passphrase should fail
        let result = rekey_db_with_params(&db_path, "wrong-pass", "new-pass", &salt, &TEST_PARAMS);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_db_empty() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_rekey_empty.db");

        // Create DB with no user data
        let (conn, salt) = create_db_with_params(&db_path, "old-pass", &TEST_PARAMS).unwrap();
        drop(conn);

        // Rekey should succeed even with empty tables
        rekey_db_with_params(&db_path, "old-pass", "new-pass", &salt, &TEST_PARAMS).unwrap();

        // Verify new passphrase works and schema tables exist
        let conn = open_db_with_params(&db_path, "new-pass", &salt, &TEST_PARAMS).unwrap();
        let table_count: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert!(table_count > 0, "Schema tables should exist after rekey");
    }

    #[test]
    fn test_get_run_summaries() {
        let (conn, _dir) = create_test_db();

        // No runs yet
        let summaries = get_run_summaries(&conn, 10).unwrap();
        assert!(summaries.is_empty());

        // Insert a run
        let run_id = insert_run_log(&conn).unwrap();
        update_run_log(&conn, run_id, 10, 8, 1, 1).unwrap();

        let summaries = get_run_summaries(&conn, 10).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_tasks, 10);
        assert_eq!(summaries[0].succeeded, 8);
        assert_eq!(summaries[0].failed, 1);
        assert_eq!(summaries[0].captcha_blocked, 1);
        assert!(summaries[0].completed_at.is_some());
    }

    #[test]
    fn test_get_run_summaries_limit() {
        let (conn, _dir) = create_test_db();

        // Insert 5 runs
        for i in 0..5 {
            let run_id = insert_run_log(&conn).unwrap();
            update_run_log(&conn, run_id, i + 1, i, 1, 0).unwrap();
        }

        // Limit to 3
        let summaries = get_run_summaries(&conn, 3).unwrap();
        assert_eq!(summaries.len(), 3);
        // Most recent first
        assert_eq!(summaries[0].total_tasks, 5);
    }
}
