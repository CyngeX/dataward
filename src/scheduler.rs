use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

use crate::broker_registry;
use crate::db;

/// Result of a single scheduler tick.
#[derive(Debug, Default)]
pub struct TickResult {
    /// Number of new tasks created for uncovered brokers.
    pub tasks_created: usize,
    /// Tasks that are due for execution.
    pub due_tasks: Vec<db::DueTask>,
    /// Run log ID for this tick.
    pub run_id: i64,
}

/// Performs a single scheduler tick:
///
/// 1. Re-sync playbooks to DB (picks up new/modified playbooks).
/// 2. Create pending tasks for brokers without active tasks.
/// 3. Query for all due tasks.
/// 4. Insert a run_log entry.
///
/// The caller (orchestrator) is responsible for dispatching the due tasks.
pub fn scheduler_tick(
    read_conn: &Connection,
    playbooks_dir: &Path,
) -> Result<TickResult> {
    // 1. Re-load and sync playbooks
    let playbooks = broker_registry::load_playbooks(playbooks_dir)?;
    if !playbooks.is_empty() {
        broker_registry::sync_brokers_to_db(read_conn, &playbooks)?;
        tracing::debug!(count = playbooks.len(), "Synced playbooks to DB");
    }

    // 2. Create tasks for uncovered brokers
    let tasks_created = db::create_missing_tasks(read_conn)?;
    if tasks_created > 0 {
        tracing::info!(tasks_created, "Created tasks for uncovered brokers");
    }

    // 3. Query due tasks
    let due_tasks = db::get_due_tasks(read_conn)?;
    tracing::info!(
        due = due_tasks.len(),
        "Scheduler tick: {} tasks due",
        due_tasks.len()
    );

    // 4. Create run log entry
    let run_id = db::insert_run_log(read_conn)?;

    Ok(TickResult {
        tasks_created,
        due_tasks,
        run_id,
    })
}

/// Validates that all required PII fields exist for a task's playbook.
///
/// Returns the user data map if all fields are present, or an error describing
/// which fields are missing.
pub fn validate_required_fields(
    read_conn: &Connection,
    required_fields: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    let mut user_data = std::collections::HashMap::new();
    let mut missing = Vec::new();

    for field in required_fields {
        match db::get_profile_field(read_conn, field)? {
            Some(value) => {
                let s = String::from_utf8(value)
                    .with_context(|| format!("Profile field '{}' contains invalid UTF-8", field))?;
                if s.is_empty() {
                    missing.push(field.clone());
                } else {
                    user_data.insert(field.clone(), s);
                }
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

    Ok(user_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::TEST_PARAMS;
    use crate::db::{self, BrokerRow};
    use tempfile::tempdir;

    fn create_test_db() -> (Connection, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let (conn, _salt) =
            db::create_db_with_params(&db_path, "test-passphrase", &TEST_PARAMS).unwrap();
        (conn, dir)
    }

    fn insert_broker(conn: &Connection, id: &str, channel: &str) {
        let broker = BrokerRow {
            id: id.into(),
            name: format!("Test {}", id),
            category: "people_search".into(),
            opt_out_channel: channel.into(),
            recheck_days: 90,
            parent_company: None,
            playbook_path: format!("playbooks/official/{}.yaml", id),
            trust_tier: "official".into(),
            enabled: true,
        };
        db::upsert_broker(conn, &broker).unwrap();
    }

    #[test]
    fn test_scheduler_tick_creates_tasks_and_queries() {
        let (conn, dir) = create_test_db();

        // Insert brokers directly (no playbook files needed for this test)
        insert_broker(&conn, "broker1", "web_form");
        insert_broker(&conn, "broker2", "email");

        // Create playbooks dir (empty — scheduler_tick handles missing playbooks)
        let playbooks_dir = dir.path().join("playbooks");
        std::fs::create_dir_all(&playbooks_dir).unwrap();

        let result = scheduler_tick(&conn, &playbooks_dir).unwrap();

        // Should have created 2 tasks (one per broker)
        assert_eq!(result.tasks_created, 2);
        // Those tasks should be due immediately (no next_recheck_at)
        assert_eq!(result.due_tasks.len(), 2);
        // Run log should be created
        assert!(result.run_id > 0);
    }

    #[test]
    fn test_scheduler_tick_no_duplicate_tasks() {
        let (conn, dir) = create_test_db();
        insert_broker(&conn, "broker1", "web_form");

        // Manually create a pending task
        conn.execute(
            "INSERT INTO opt_out_tasks (broker_id, status, channel, created_at)
             VALUES ('broker1', 'pending', 'web_form', datetime('now'))",
            [],
        )
        .unwrap();

        let playbooks_dir = dir.path().join("playbooks");
        std::fs::create_dir_all(&playbooks_dir).unwrap();

        let result = scheduler_tick(&conn, &playbooks_dir).unwrap();

        // Should NOT create a duplicate task
        assert_eq!(result.tasks_created, 0);
        // The existing pending task should still be due
        assert_eq!(result.due_tasks.len(), 1);
    }

    #[test]
    fn test_validate_required_fields_success() {
        let (conn, _dir) = create_test_db();

        db::set_profile_field(&conn, "first_name", b"John").unwrap();
        db::set_profile_field(&conn, "email", b"john@example.com").unwrap();

        let fields = vec!["first_name".to_string(), "email".to_string()];
        let user_data = validate_required_fields(&conn, &fields).unwrap();

        assert_eq!(user_data.get("first_name").unwrap(), "John");
        assert_eq!(user_data.get("email").unwrap(), "john@example.com");
    }

    #[test]
    fn test_validate_required_fields_missing() {
        let (conn, _dir) = create_test_db();

        db::set_profile_field(&conn, "first_name", b"John").unwrap();
        // email is NOT set

        let fields = vec!["first_name".to_string(), "email".to_string()];
        let result = validate_required_fields(&conn, &fields);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("email"));
    }

    #[test]
    fn test_validate_required_fields_empty_value() {
        let (conn, _dir) = create_test_db();

        db::set_profile_field(&conn, "first_name", b"").unwrap();

        let fields = vec!["first_name".to_string()];
        let result = validate_required_fields(&conn, &fields);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("first_name"));
    }
}
