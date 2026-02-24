use anyhow::{Context, Result};
use std::io::{self, Write};
use std::path::Path;

use crate::{broker_registry, config::Config, crypto, db};

/// Valid PII field names for user profile.
const PROFILE_FIELDS: &[(&str, &str, bool)] = &[
    ("first_name", "First name", true),
    ("last_name", "Last name", true),
    ("email", "Email address", true),
    ("phone", "Phone number (optional)", false),
    ("street", "Street address (optional)", false),
    ("city", "City (optional)", false),
    ("state", "State (optional)", false),
    ("zip", "ZIP code (optional)", false),
];

/// Runs the `dataward init` command.
pub async fn run_init(data_dir: &Path) -> Result<()> {
    // Check for existing installation
    if data_dir.join("dataward.db").exists() {
        eprintln!("Dataward is already initialized at: {}", data_dir.display());
        eprintln!();
        eprint!("Options: [u]pdate PII, [r]eset completely, [c]ancel: ");
        io::stderr().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        match choice.trim().to_lowercase().as_str() {
            "u" | "update" => return run_update_pii(data_dir).await,
            "r" | "reset" => {
                eprint!("This will DELETE all existing data. Are you sure? [y/N]: ");
                io::stderr().flush()?;
                let mut confirm = String::new();
                io::stdin().read_line(&mut confirm)?;
                if confirm.trim().to_lowercase() != "y" {
                    eprintln!("Cancelled.");
                    return Ok(());
                }
                // Delete existing data directory contents (but not the dir itself)
                cleanup_data_dir(data_dir)?;
            }
            _ => {
                eprintln!("Cancelled.");
                return Ok(());
            }
        }
    }

    eprintln!("=== Dataward Setup ===");
    eprintln!();

    // Create data directory
    create_data_dir(data_dir)?;

    // Step 1: Passphrase
    eprintln!("Choose a passphrase to encrypt your data.");
    eprintln!("WARNING: There is NO recovery mechanism. If you forget this passphrase,");
    eprintln!("your data cannot be recovered. Write it down somewhere safe.");
    eprintln!();

    let passphrase = crypto::get_passphrase("Passphrase: ")?;
    let confirm = crypto::get_passphrase("Confirm passphrase: ")?;
    if passphrase != confirm {
        anyhow::bail!("Passphrases do not match");
    }

    // Step 2: Create encrypted database
    let db_path = data_dir.join("dataward.db");
    let (conn, salt) = db::create_db(&db_path, &passphrase)?;

    // Store the salt in a separate file (not sensitive — only useful with passphrase)
    let salt_path = data_dir.join(".salt");
    std::fs::write(&salt_path, &salt)
        .context("Failed to write salt file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Step 3: Collect PII
    eprintln!();
    eprintln!("Enter your personal information (used for opt-out requests):");
    eprintln!();

    for &(field_name, prompt, required) in PROFILE_FIELDS {
        let value = prompt_field(prompt, required)?;
        if let Some(v) = value {
            db::set_profile_field(&conn, field_name, v.as_bytes())?;
        }
    }

    // Step 4: SMTP credentials (optional)
    eprintln!();
    eprint!("Configure SMTP for email opt-outs? [y/N]: ");
    io::stderr().flush()?;
    let mut smtp_choice = String::new();
    io::stdin().read_line(&mut smtp_choice)?;

    if smtp_choice.trim().to_lowercase() == "y" {
        collect_smtp_credentials(&conn)?;
    }

    // Step 5: Generate dashboard auth token
    let auth_token = crypto::generate_auth_token();
    db::set_config(&conn, "dashboard_token", &auth_token)?;
    eprintln!();
    eprintln!("Dashboard auth token generated. Access your dashboard at:");
    eprintln!("  http://127.0.0.1:9847?token={}", auth_token);
    eprintln!("Keep this token secret — it grants access to your dashboard.");

    // Step 6: Write default config
    Config::write_default(data_dir)?;

    // Step 7: Create playbook directories
    let playbooks_dir = data_dir.join("playbooks");
    for tier in &["official", "community", "local"] {
        let tier_dir = playbooks_dir.join(tier);
        std::fs::create_dir_all(&tier_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tier_dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Step 8: Create proofs and logs directories
    for dir_name in &["proofs", "logs"] {
        let dir = data_dir.join(dir_name);
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Step 9: Load and validate any bundled playbooks
    let playbooks = broker_registry::load_playbooks(&playbooks_dir)?;
    if !playbooks.is_empty() {
        broker_registry::sync_brokers_to_db(&conn, &playbooks)?;
        eprintln!();
        eprintln!("Loaded {} broker playbooks.", playbooks.len());
    }

    eprintln!();
    eprintln!("=== Dataward initialized successfully ===");
    eprintln!("Data directory: {}", data_dir.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Add broker playbooks to {}", playbooks_dir.display());
    eprintln!("  2. Run `dataward run` to start opt-out automation");
    eprintln!("  3. Run `dataward status` to check progress");

    Ok(())
}

/// Updates PII fields in an existing installation.
async fn run_update_pii(data_dir: &Path) -> Result<()> {
    let passphrase = crypto::get_passphrase("Passphrase: ")?;
    let salt = std::fs::read(data_dir.join(".salt"))
        .context("Failed to read salt file")?;
    let conn = db::open_db(&data_dir.join("dataward.db"), &passphrase, &salt)?;

    eprintln!("Enter new values (leave blank to keep existing):");
    eprintln!();

    for &(field_name, prompt, _required) in PROFILE_FIELDS {
        let existing = db::get_profile_field(&conn, field_name)?
            .map(|v| String::from_utf8_lossy(&v).to_string());

        let display = match &existing {
            Some(v) if !v.is_empty() => format!("{} [current: {}]", prompt, mask_pii(v)),
            _ => format!("{} [not set]", prompt),
        };

        eprint!("{}: ", display);
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();

        if !trimmed.is_empty() {
            validate_field_value(field_name, trimmed)?;
            db::set_profile_field(&conn, field_name, trimmed.as_bytes())?;
            eprintln!("  Updated {}", field_name);
        }
    }

    eprintln!();
    eprintln!("Profile updated.");
    Ok(())
}

/// Runs the `dataward purge` command.
pub async fn run_purge(data_dir: &Path, force: bool) -> Result<()> {
    if !data_dir.exists() {
        eprintln!("Nothing to purge — data directory does not exist: {}", data_dir.display());
        return Ok(());
    }

    if !force {
        eprintln!("WARNING: This will permanently delete ALL Dataward data:");
        eprintln!("  - Encrypted database (PII, broker data, config)");
        eprintln!("  - All proof screenshots");
        eprintln!("  - All log files");
        eprintln!("  - Configuration file");
        eprintln!();
        eprint!("Type 'DELETE' to confirm: ");
        io::stderr().flush()?;

        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;
        if confirm.trim() != "DELETE" {
            eprintln!("Cancelled. Your data is safe.");
            return Ok(());
        }
    }

    cleanup_data_dir(data_dir)?;

    eprintln!("All Dataward data has been permanently deleted.");
    eprintln!("Run `dataward init` to set up again.");
    Ok(())
}

/// Prompts for a single field with validation.
fn prompt_field(prompt: &str, required: bool) -> Result<Option<String>> {
    loop {
        eprint!("{}: ", prompt);
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();

        if trimmed.is_empty() {
            if required {
                eprintln!("  This field is required.");
                continue;
            }
            return Ok(None);
        }

        // Extract field name from prompt for validation
        let field_name = prompt
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();

        if let Err(e) = validate_field_value(&field_name, &trimmed) {
            eprintln!("  {}", e);
            continue;
        }

        return Ok(Some(trimmed));
    }
}

/// Validates a PII field value.
fn validate_field_value(field_name: &str, value: &str) -> Result<()> {
    // Universal checks
    if value.len() > 500 {
        anyhow::bail!("Value too long (max 500 characters)");
    }
    if value.contains('\0') {
        anyhow::bail!("Value cannot contain null bytes");
    }

    // Field-specific validation
    match field_name {
        "email" => {
            if !value.contains('@') || !value.contains('.') {
                anyhow::bail!("Invalid email format");
            }
            if value.len() < 5 {
                anyhow::bail!("Email too short");
            }
        }
        "phone" => {
            // Allow digits, spaces, hyphens, parentheses, plus sign
            let cleaned: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
            if cleaned.len() < 7 || cleaned.len() > 15 {
                anyhow::bail!("Phone number should have 7-15 digits");
            }
        }
        "zip" => {
            let cleaned: String = value.chars().filter(|c| c.is_ascii_digit() || *c == '-').collect();
            if cleaned.len() < 3 || cleaned.len() > 10 {
                anyhow::bail!("Invalid ZIP code format");
            }
        }
        _ => {} // No specific validation for other fields
    }

    Ok(())
}

/// Collects SMTP credentials and stores them in the encrypted DB.
fn collect_smtp_credentials(conn: &rusqlite::Connection) -> Result<()> {
    eprintln!("SMTP configuration (credentials stored in encrypted database):");

    eprint!("  SMTP server (e.g., smtp.gmail.com): ");
    io::stderr().flush()?;
    let mut server = String::new();
    io::stdin().read_line(&mut server)?;
    let server = server.trim();
    if server.is_empty() {
        anyhow::bail!("SMTP server is required");
    }

    eprint!("  SMTP port (default 587): ");
    io::stderr().flush()?;
    let mut port = String::new();
    io::stdin().read_line(&mut port)?;
    let port = port.trim();
    let port = if port.is_empty() { "587" } else { port };
    port.parse::<u16>().context("Invalid port number")?;

    eprint!("  SMTP username: ");
    io::stderr().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    let password = rpassword::prompt_password("  SMTP password: ")
        .context("Failed to read SMTP password")?;

    // Store in encrypted DB
    db::set_config(conn, "smtp_server", server)?;
    db::set_config(conn, "smtp_port", port)?;
    db::set_config(conn, "smtp_username", username)?;
    db::set_config(conn, "smtp_password", &password)?;

    if server.contains("gmail") {
        eprintln!();
        eprintln!("  Note: Gmail has a 100 email/day SMTP limit.");
        eprintln!("  Consider using a dedicated email address for opt-outs.");
    }

    Ok(())
}

/// Creates the data directory with restrictive permissions.
fn create_data_dir(data_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("Failed to create data directory: {}", data_dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

/// Removes all files within the data directory.
fn cleanup_data_dir(data_dir: &Path) -> Result<()> {
    if data_dir.exists() {
        for entry in std::fs::read_dir(data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path)
                    .with_context(|| format!("Failed to remove: {}", path.display()))?;
            } else {
                std::fs::remove_file(&path)
                    .with_context(|| format!("Failed to remove: {}", path.display()))?;
            }
        }
    }
    Ok(())
}

/// Masks PII for display (shows first 2 and last 2 characters).
fn mask_pii(value: &str) -> String {
    if value.len() <= 4 {
        return "****".to_string();
    }
    let first = &value[..2];
    let last = &value[value.len() - 2..];
    format!("{}...{}", first, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_field_value("email", "user@example.com").is_ok());
        assert!(validate_field_value("email", "invalid").is_err());
        assert!(validate_field_value("email", "a@b").is_err()); // too short
    }

    #[test]
    fn test_validate_phone() {
        assert!(validate_field_value("phone", "555-123-4567").is_ok());
        assert!(validate_field_value("phone", "+1 (555) 123-4567").is_ok());
        assert!(validate_field_value("phone", "123").is_err()); // too short
    }

    #[test]
    fn test_validate_zip() {
        assert!(validate_field_value("zip", "90210").is_ok());
        assert!(validate_field_value("zip", "90210-1234").is_ok());
        assert!(validate_field_value("zip", "AB").is_err()); // too short
    }

    #[test]
    fn test_validate_null_bytes() {
        assert!(validate_field_value("first_name", "John\0").is_err());
    }

    #[test]
    fn test_validate_too_long() {
        let long_value = "a".repeat(501);
        assert!(validate_field_value("first_name", &long_value).is_err());
    }

    #[test]
    fn test_mask_pii() {
        assert_eq!(mask_pii("john@example.com"), "jo...om");
        assert_eq!(mask_pii("ab"), "****");
        assert_eq!(mask_pii(""), "****");
    }

    #[test]
    fn test_mask_pii_unicode() {
        // Short unicode strings should be safe
        assert_eq!(mask_pii("abc"), "****");
    }
}
