use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use rusqlite::Connection;
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::db;

/// Default timeout for SMTP operations (30 seconds).
const SMTP_TIMEOUT_SECS: u64 = 30;

/// Maximum line length for email headers per RFC 5322 section 2.1.1.
const RFC5322_MAX_LINE_LEN: usize = 998;

/// Result of an email opt-out attempt.
#[derive(Debug)]
pub struct EmailResult {
    pub success: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_retryable: bool,
    pub duration_ms: i64,
    pub confirmation_text: Option<String>,
}

/// SMTP configuration loaded from the encrypted database.
///
/// The password field uses `Zeroizing<String>` to ensure credential
/// material is zeroed on drop (CONS-R3-005).
#[derive(Debug)]
struct SmtpConfig {
    server: String,
    port: u16,
    username: String,
    password: Zeroizing<String>,
}

/// Loads SMTP configuration from the database.
fn load_smtp_config(conn: &Connection) -> Result<SmtpConfig> {
    let server = db::get_config(conn, "smtp_server")?.ok_or_else(|| {
        anyhow::anyhow!("SMTP not configured. Run `dataward init` to set up SMTP.")
    })?;
    let port_str = db::get_config(conn, "smtp_port")?.unwrap_or_else(|| "587".to_string());
    let port: u16 = port_str.parse().context("Invalid SMTP port")?;
    // CONS-R2-007: Fail loudly on missing/empty SMTP credentials
    let username = db::get_config(conn, "smtp_username")?.unwrap_or_default();
    let password = db::get_config(conn, "smtp_password")?.unwrap_or_default();
    if username.is_empty() || password.is_empty() {
        anyhow::bail!(
            "SMTP credentials not configured (username or password is empty). \
             Run `dataward init` to set up SMTP authentication."
        );
    }

    Ok(SmtpConfig {
        server,
        port,
        username,
        password: Zeroizing::new(password),
    })
}

/// Sends an opt-out email for a broker.
///
/// Uses lettre with STARTTLS (TLS 1.2+ enforced). Checks the daily email
/// rate limit before sending.
pub async fn send_opt_out_email(
    read_conn: &Connection,
    broker_id: &str,
    broker_name: &str,
    broker_email: &str,
    user_data: &HashMap<String, String>,
    daily_limit: u32,
) -> Result<EmailResult> {
    let start = std::time::Instant::now();

    // CONS-R3-012: Validate broker_name is non-empty for well-formed email subject
    if broker_name.trim().is_empty() {
        return Ok(EmailResult {
            success: false,
            error_code: Some("playbook_error".to_string()),
            error_message: Some("Broker name is empty — cannot send opt-out email".to_string()),
            error_retryable: false,
            duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
            confirmation_text: None,
        });
    }

    // Check daily rate limit
    let daily_count = db::get_daily_email_count(read_conn)?;
    if daily_count >= daily_limit as i32 {
        return Ok(EmailResult {
            success: false,
            error_code: Some("rate_limited".to_string()),
            error_message: Some(format!(
                "Daily email limit reached ({}/{}). Will retry tomorrow.",
                daily_count, daily_limit
            )),
            error_retryable: true,
            duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
            confirmation_text: None,
        });
    }

    // Load SMTP config
    let smtp = match load_smtp_config(read_conn) {
        Ok(config) => config,
        Err(e) => {
            return Ok(EmailResult {
                success: false,
                error_code: Some("playbook_error".to_string()),
                error_message: Some(format!("SMTP configuration error: {}", e)),
                error_retryable: false,
                duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
                confirmation_text: None,
            });
        }
    };

    // Build email content
    let from_email = user_data
        .get("email")
        .ok_or_else(|| anyhow::anyhow!("Email address not set in profile"))?;
    let first_name = user_data
        .get("first_name")
        .map(|s| s.as_str())
        .unwrap_or("User");
    let last_name = user_data.get("last_name").map(|s| s.as_str()).unwrap_or("");

    // Sanitize inputs to prevent CRLF injection in email headers
    let safe_from = sanitize_email_header(from_email);
    let safe_to = sanitize_email_header(broker_email);
    let safe_name = sanitize_email_header(&format!("{} {}", first_name, last_name));

    let subject = format!(
        "Data Removal Request — {}",
        sanitize_email_header(broker_name)
    );

    let body = build_opt_out_email_body(
        first_name,
        last_name,
        from_email,
        user_data.get("phone").map(|s| s.as_str()),
        user_data.get("street").map(|s| s.as_str()),
        user_data.get("city").map(|s| s.as_str()),
        user_data.get("state").map(|s| s.as_str()),
        user_data.get("zip").map(|s| s.as_str()),
        broker_name,
    );

    let email = Message::builder()
        .from(
            format!("{} <{}>", safe_name, safe_from)
                .parse()
                .context("Invalid from address")?,
        )
        .to(safe_to.parse().context("Invalid broker email address")?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .context("Failed to build email message")?;

    // Build SMTP transport with STARTTLS
    // CONS-R3-016: Transport is rebuilt per email; acceptable for MVP volumes.
    // TODO(Phase 4): Reuse transport across emails within a tick.
    let creds = Credentials::new(smtp.username.clone(), smtp.password.as_str().to_string());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.server)
        .context("Failed to create SMTP transport")?
        .credentials(creds)
        .port(smtp.port)
        .timeout(Some(std::time::Duration::from_secs(SMTP_TIMEOUT_SECS)))
        .build();

    // Send
    match mailer.send(email).await {
        Ok(response) => {
            let confirmation = format!("Email sent to {} (SMTP {})", broker_email, response.code());
            tracing::info!(
                broker_id,
                code = %response.code(),
                "Opt-out email sent"
            );
            Ok(EmailResult {
                success: true,
                error_code: None,
                error_message: None,
                error_retryable: false,
                duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
                confirmation_text: Some(confirmation),
            })
        }
        Err(e) => {
            // CONS-R2-003: Truncate SMTP errors to avoid storing server internals
            let raw_error = e.to_string();
            let error_message: String = raw_error.chars().take(500).collect();
            let retryable = is_smtp_error_retryable(&error_message);
            tracing::warn!(
                broker_id,
                error = %error_message,
                retryable,
                "Opt-out email failed"
            );
            Ok(EmailResult {
                success: false,
                error_code: Some("playbook_error".to_string()),
                error_message: Some(error_message),
                error_retryable: retryable,
                duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
                confirmation_text: None,
            })
        }
    }
}

/// Builds the opt-out email body.
fn build_opt_out_email_body(
    first_name: &str,
    last_name: &str,
    email: &str,
    phone: Option<&str>,
    street: Option<&str>,
    city: Option<&str>,
    state: Option<&str>,
    zip: Option<&str>,
    broker_name: &str,
) -> String {
    let mut body = format!(
        "To Whom It May Concern,\n\n\
         I am writing to request the removal of my personal information from your database \
         pursuant to applicable privacy laws (including CCPA, GDPR, and state privacy regulations).\n\n\
         Please delete all records associated with the following information:\n\n\
         Name: {} {}\n\
         Email: {}\n",
        first_name, last_name, email
    );

    if let Some(phone) = phone {
        body.push_str(&format!("Phone: {}\n", phone));
    }

    let has_address = street.is_some() || city.is_some() || state.is_some() || zip.is_some();
    if has_address {
        body.push_str("Address: ");
        if let Some(street) = street {
            body.push_str(street);
            body.push_str(", ");
        }
        if let Some(city) = city {
            body.push_str(city);
            body.push_str(", ");
        }
        if let Some(state) = state {
            body.push_str(state);
            body.push(' ');
        }
        if let Some(zip) = zip {
            body.push_str(zip);
        }
        body.push('\n');
    }

    body.push_str(&format!(
        "\nPlease confirm once my data has been removed from {}.\n\n\
         I request that you:\n\
         1. Delete all personal information you hold about me\n\
         2. Cease any sale or sharing of my personal information\n\
         3. Direct any service providers to delete my information\n\n\
         Please respond within 30 days as required by law.\n\n\
         Thank you,\n\
         {} {}\n",
        broker_name, first_name, last_name
    ));

    body
}

/// Sanitizes a string for use in email headers.
///
/// Strips CRLF (prevents header injection) and caps length at 998 chars
/// per RFC 5322 line length limit.
fn sanitize_email_header(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c != '\r' && *c != '\n')
        .take(RFC5322_MAX_LINE_LEN)
        .collect()
}

/// Determines if an SMTP error is retryable.
///
/// Network errors, temporary failures (4xx), and timeouts are retryable.
/// Authentication failures, invalid addresses (5xx permanent) are not.
/// CONS-017: Unknown errors default to NOT retryable (conservative).
fn is_smtp_error_retryable(error_msg: &str) -> bool {
    let lower = error_msg.to_lowercase();
    // Temporary/transient errors are retryable
    if lower.contains("timeout")
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("temporary")
        || lower.contains("try again")
        || lower.contains("unavailable")
        || lower.contains("too many connections")
    {
        return true;
    }
    // Permanent errors are explicitly not retryable
    if lower.contains("authentication")
        || lower.contains("credentials")
        || lower.contains("relay access denied")
        || lower.contains("mailbox not found")
    {
        return false;
    }
    // Default: unknown errors are NOT retryable to avoid wasting retry budget
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_email_header() {
        assert_eq!(sanitize_email_header("normal text"), "normal text");
        assert_eq!(
            sanitize_email_header("inject\r\nBcc: evil@evil.com"),
            "injectBcc: evil@evil.com"
        );
        assert_eq!(sanitize_email_header("line\nbreak"), "linebreak");
        assert_eq!(sanitize_email_header(""), "");
    }

    #[test]
    fn test_build_opt_out_email_body_minimal() {
        let body = build_opt_out_email_body(
            "John",
            "Doe",
            "john@example.com",
            None,
            None,
            None,
            None,
            None,
            "Spokeo",
        );
        assert!(body.contains("John Doe"));
        assert!(body.contains("john@example.com"));
        assert!(body.contains("Spokeo"));
        assert!(body.contains("privacy laws"));
        assert!(!body.contains("Phone:"));
        assert!(!body.contains("Address:"));
    }

    #[test]
    fn test_build_opt_out_email_body_full() {
        let body = build_opt_out_email_body(
            "John",
            "Doe",
            "john@example.com",
            Some("555-1234"),
            Some("123 Main St"),
            Some("Springfield"),
            Some("IL"),
            Some("62701"),
            "BeenVerified",
        );
        assert!(body.contains("Phone: 555-1234"));
        assert!(body.contains("123 Main St"));
        assert!(body.contains("Springfield"));
        assert!(body.contains("IL"));
        assert!(body.contains("62701"));
        assert!(body.contains("BeenVerified"));
    }

    #[test]
    fn test_is_smtp_error_retryable() {
        // Retryable
        assert!(is_smtp_error_retryable("Connection timeout"));
        assert!(is_smtp_error_retryable("Connection refused"));
        assert!(is_smtp_error_retryable("Service temporarily unavailable"));
        assert!(is_smtp_error_retryable("Too many connections"));

        // Not retryable
        assert!(!is_smtp_error_retryable("Authentication failed"));
        assert!(!is_smtp_error_retryable("Invalid credentials"));
        assert!(!is_smtp_error_retryable("Relay access denied"));
    }

    #[test]
    fn test_is_smtp_error_retryable_unknown_defaults_false() {
        // CONS-017: Unknown errors should NOT be retried
        assert!(!is_smtp_error_retryable("some unknown error occurred"));
    }
}
