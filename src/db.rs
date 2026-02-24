use anyhow::{Context, Result};
use rusqlite::Connection;
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
    let (key, _) = crypto::derive_key_with_params(passphrase.as_bytes(), Some(salt), params)?;
    let hex_key = crypto::key_to_sqlcipher_hex(&key);

    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    // Set SQLCipher encryption key
    conn.pragma_update(None, "key", &hex_key)
        .context("Failed to set SQLCipher key (wrong passphrase?)")?;

    // Verify the key works by attempting a read
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| anyhow::anyhow!(
            "Incorrect passphrase. Your data is safe — try again."
        ))?;

    // Enable WAL mode for read concurrency
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("Failed to enable WAL mode")?;

    // Foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("Failed to enable foreign keys")?;

    Ok(conn)
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

        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );
        ",
    )
    .context("Failed to apply database schema")?;

    // Set schema version
    let current_version: Option<i32> = conn
        .query_row(
            "SELECT version FROM schema_version LIMIT 1",
            [],
            |row| row.get(0),
        )
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
    let result = conn.query_row(
        "SELECT value FROM config WHERE key = ?1",
        [key],
        |row| row.get::<_, String>(0),
    );
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
    },
    /// Insert a new opt-out task.
    InsertTask {
        broker_id: String,
        channel: String,
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
) -> (mpsc::Sender<DbWriteMessage>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<DbWriteMessage>(256);

    let handle = tokio::task::spawn_blocking(move || {
        while let Some(msg) = rx.blocking_recv() {
            match msg {
                DbWriteMessage::Shutdown => break,
                DbWriteMessage::UpdateTask {
                    task_id,
                    status,
                    error_code,
                    error_message,
                    error_retryable,
                    duration_ms,
                    proof_path,
                    confirmation_text,
                } => {
                    let result = conn.execute(
                        "UPDATE opt_out_tasks SET status = ?1, error_code = ?2, error_message = ?3,
                         error_retryable = ?4, duration_ms = ?5, proof_path = ?6,
                         confirmation_text = ?7, completed_at = datetime('now')
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
                        ],
                    );
                    if let Err(e) = result {
                        tracing::error!("DB write failed for task {}: {}. Writing to journal.", task_id, e);
                        write_to_journal(&journal_path, &format!(
                            "{{\"type\":\"update_task\",\"task_id\":{},\"status\":\"{}\"}}",
                            task_id, status
                        ));
                    }
                }
                DbWriteMessage::InsertTask { broker_id, channel } => {
                    let result = conn.execute(
                        "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
                         VALUES (?1, 'pending', ?2, datetime('now'))",
                        rusqlite::params![broker_id, channel],
                    );
                    if let Err(e) = result {
                        tracing::error!("DB insert failed for broker {}: {}. Writing to journal.", broker_id, e);
                        write_to_journal(&journal_path, &format!(
                            "{{\"type\":\"insert_task\",\"broker_id\":\"{}\",\"channel\":\"{}\"}}",
                            broker_id, channel
                        ));
                    }
                }
            }
        }
    });

    (tx, handle)
}

/// Fallback: write failed DB operations to a journal file for later replay.
fn write_to_journal(journal_path: &std::path::PathBuf, line: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)
    {
        let _ = writeln!(file, "{}", line);
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
        let (conn, _salt) = create_db_with_params(&db_path, "test-passphrase", &TEST_PARAMS).unwrap();
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
}
