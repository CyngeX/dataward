use anyhow::{Context, Result};
use std::path::Path;

use crate::config::Config;
use crate::crypto;
use crate::db;

/// Runs the `dataward status` command.
///
/// Displays: broker table, CAPTCHA queue count, stale playbook warnings,
/// SMTP delivery stats, and next scheduled run.
pub fn run_status(data_dir: &Path) -> Result<()> {
    // Read passphrase and open DB
    let passphrase = crypto::get_passphrase("Passphrase: ")?;
    let salt = std::fs::read(data_dir.join(".salt"))
        .context("Failed to read salt file. Is Dataward initialized?")?;
    let conn = db::open_db(&data_dir.join("dataward.db"), &passphrase, &salt)?;

    let config = Config::load(data_dir)?;

    eprintln!("=== Dataward Status ===");
    eprintln!();

    // Query broker statuses once and share across functions
    let brokers = db::get_broker_statuses(&conn)?;

    // Broker table
    print_broker_table(&brokers)?;

    // CAPTCHA queue
    print_captcha_queue(&conn)?;

    // Stale playbook warnings
    print_stale_warnings(&brokers)?;

    // SMTP delivery stats
    print_smtp_stats(&conn, &config)?;

    // Last run summary
    print_last_run(&conn)?;

    // Next scheduled run
    print_next_run(&config)?;

    Ok(())
}

/// Prints the broker status table.
fn print_broker_table(brokers: &[db::BrokerStatusRow]) -> Result<()> {
    if brokers.is_empty() {
        eprintln!("No brokers configured. Add playbooks and run `dataward init`.");
        eprintln!();
        return Ok(());
    }

    eprintln!("Brokers:");
    eprintln!(
        "  {:<25} {:<10} {:<12} {:<8} {:<10} {}",
        "Name", "Channel", "Status", "Rate", "Tier", "Next Recheck"
    );
    eprintln!("  {}", "-".repeat(80));

    for b in brokers {
        let status =
            b.latest_status
                .as_deref()
                .unwrap_or(if b.enabled { "pending" } else { "disabled" });
        let status_display = format_status(status);
        let rate = format!("{:.0}%", b.success_rate * 100.0);
        let next = b
            .next_recheck
            .as_deref()
            .map(format_datetime)
            .unwrap_or_else(|| "-".to_string());

        eprintln!(
            "  {:<25} {:<10} {:<12} {:<8} {:<10} {}",
            truncate(&b.name, 25),
            b.channel,
            status_display,
            rate,
            b.trust_tier,
            next
        );
    }
    eprintln!();

    Ok(())
}

/// Prints the CAPTCHA queue count.
fn print_captcha_queue(conn: &rusqlite::Connection) -> Result<()> {
    let queue = db::get_captcha_queue(conn)?;
    let count = queue.len();

    if count > 0 {
        eprintln!("CAPTCHA Queue: {} task(s) waiting for resolution", count);
        for task in queue.iter().take(5) {
            eprintln!(
                "  - {} (queued: {})",
                task.broker_name,
                format_datetime(&task.created_at)
            );
        }
        if count > 5 {
            eprintln!("  ... and {} more", count - 5);
        }
    } else {
        eprintln!("CAPTCHA Queue: empty");
    }
    eprintln!();

    Ok(())
}

/// Prints warnings for stale brokers (last attempt > 30 days ago).
fn print_stale_warnings(brokers: &[db::BrokerStatusRow]) -> Result<()> {
    let mut stale = Vec::new();

    for b in brokers {
        if !b.enabled {
            continue;
        }
        if let Some(ref last) = b.last_attempt {
            if is_stale(last) {
                stale.push(b.name.as_str());
            }
        }
    }

    if !stale.is_empty() {
        eprintln!(
            "Stale Playbooks ({} broker(s) not attempted in 30+ days):",
            stale.len()
        );
        for name in &stale {
            eprintln!("  - {}", name);
        }
        eprintln!();
    }

    Ok(())
}

/// Prints SMTP delivery stats.
fn print_smtp_stats(conn: &rusqlite::Connection, config: &Config) -> Result<()> {
    let emails_today = db::get_daily_email_count(conn)?;
    let daily_limit = config.email.daily_limit;

    eprintln!("SMTP: {}/{} emails sent today", emails_today, daily_limit);
    eprintln!();

    Ok(())
}

/// Prints the last run summary.
fn print_last_run(conn: &rusqlite::Connection) -> Result<()> {
    let stats = db::get_health_stats(conn)?;

    match stats.last_run {
        Some(run) => {
            eprintln!("Last Run: {}", format_datetime(&run.started_at));
            eprintln!(
                "  {} total, {} succeeded, {} failed, {} captcha-blocked",
                run.total, run.succeeded, run.failed, run.captcha_blocked
            );
        }
        None => {
            eprintln!("Last Run: none (run `dataward run` to start)");
        }
    }
    eprintln!();

    Ok(())
}

/// Prints the next scheduled run time.
fn print_next_run(config: &Config) -> Result<()> {
    eprintln!(
        "Schedule: every {} hour(s)",
        config.scheduler.interval_hours
    );

    Ok(())
}

// -- Helpers --

/// Formats a status string for CLI display.
fn format_status(status: &str) -> &str {
    match status {
        "success" => "OK",
        "failure" => "FAILED",
        "pending" => "PENDING",
        "running" => "RUNNING",
        "captcha_blocked" => "CAPTCHA",
        "disabled" => "DISABLED",
        _ => status,
    }
}

/// Truncates a string to max length, adding "..." if needed.
/// When max < 3 and the string exceeds max, returns dots (e.g. max=0 → "", max=1 → ".", max=2 → "..").
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max < 3 {
        ".".repeat(max)
    } else {
        let truncated: String = s.chars().take(max - 3).collect();
        format!("{}...", truncated)
    }
}

/// Formats a datetime string for CLI display (shows date + time, no seconds).
/// Returns "-" for empty input.
fn format_datetime(dt: &str) -> String {
    if dt.is_empty() {
        return "-".to_string();
    }
    // Input might be "2026-03-10 14:30:00" or ISO 8601
    if dt.chars().count() >= 16 {
        dt.chars().take(16).collect()
    } else {
        dt.to_string()
    }
}

/// Checks if a datetime string is older than 30 days.
fn is_stale(dt: &str) -> bool {
    let parsed = chrono::NaiveDateTime::parse_from_str(dt, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(dt).map(|d| d.naive_utc()));

    match parsed {
        Ok(datetime) => {
            let now = chrono::Utc::now().naive_utc();
            now.signed_duration_since(datetime).num_days() > 30
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_status() {
        assert_eq!(format_status("success"), "OK");
        assert_eq!(format_status("failure"), "FAILED");
        assert_eq!(format_status("pending"), "PENDING");
        assert_eq!(format_status("running"), "RUNNING");
        assert_eq!(format_status("captcha_blocked"), "CAPTCHA");
        assert_eq!(format_status("disabled"), "DISABLED");
        assert_eq!(format_status("unknown"), "unknown");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(
            truncate("a very long broker name here", 15),
            "a very long ..."
        );
        assert_eq!(truncate("exact", 5), "exact");
    }

    #[test]
    fn test_truncate_unicode() {
        assert_eq!(truncate("café", 4), "café");
        assert_eq!(truncate("café extra", 6), "caf...");
    }

    #[test]
    fn test_format_datetime() {
        assert_eq!(format_datetime("2026-03-10 14:30:00"), "2026-03-10 14:30");
        assert_eq!(format_datetime("2026-03-10T14:30:00Z"), "2026-03-10T14:30");
        assert_eq!(format_datetime("short"), "short");
        assert_eq!(format_datetime(""), "-");
    }

    #[test]
    fn test_is_stale_recent() {
        let recent = chrono::Utc::now()
            .naive_utc()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert!(!is_stale(&recent));
    }

    #[test]
    fn test_is_stale_old() {
        assert!(is_stale("2020-01-01 00:00:00"));
    }

    #[test]
    fn test_is_stale_invalid() {
        assert!(!is_stale("not-a-date"));
    }

    #[test]
    fn test_truncate_empty() {
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn test_truncate_boundary() {
        // Exactly at boundary
        assert_eq!(truncate("abc", 3), "abc");
        // One over
        assert_eq!(truncate("abcd", 3), "...");
    }

    #[test]
    fn test_truncate_small_max() {
        // max < 3 should not panic (usize underflow guard)
        assert_eq!(truncate("hello", 0), "");
        assert_eq!(truncate("hello", 1), ".");
        assert_eq!(truncate("hello", 2), "..");
    }

    #[test]
    fn test_format_datetime_multibyte() {
        // Multi-byte UTF-8 should not panic on char boundary
        let dt_with_multibyte = "2026-03-10\u{00A0}14:30:00"; // non-breaking space
        let result = format_datetime(dt_with_multibyte);
        assert_eq!(result.chars().count(), 16);
    }
}
