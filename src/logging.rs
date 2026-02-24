use anyhow::{Context, Result};
use std::path::Path;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// PII field names that must be redacted from all log output.
const PII_FIELDS: &[&str] = &[
    "first_name",
    "last_name",
    "email",
    "address",
    "phone",
    "street",
    "city",
    "zip",
    "ssn",
    "date_of_birth",
    "passphrase",
    "password",
];

/// Initializes the logging system with PII sanitization.
///
/// Logs go to both stderr (for interactive use) and a rotating file
/// in the data directory.
pub fn init_logging(data_dir: &Path, level: &str) -> Result<()> {
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let file_appender = rolling::daily(&log_dir, "dataward.log");

    let env_filter = EnvFilter::try_new(level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Stderr layer for interactive use
    let stderr_layer = fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(env_filter);

    // File layer with JSON formatting
    let file_filter = EnvFilter::try_new(level)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let file_layer = fmt::layer()
        .json()
        .with_writer(file_appender)
        .with_filter(file_filter);

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .init();

    Ok(())
}

/// Sanitizes a string by replacing known PII patterns.
///
/// This is used as a defense-in-depth measure. PII should never reach
/// the logging layer, but this catches accidental leaks.
pub fn sanitize_pii(input: &str) -> String {
    let mut output = input.to_string();

    for field in PII_FIELDS {
        // Redact JSON-style "field": "value" patterns
        let json_pattern = format!(r#""{}":"#, field);
        if let Some(start) = output.find(&json_pattern) {
            let value_start = start + json_pattern.len();
            if let Some(rest) = output.get(value_start..) {
                // Handle quoted values: "field": "value"
                let trimmed = rest.trim_start();
                if trimmed.starts_with('"') {
                    if let Some(end) = trimmed[1..].find('"') {
                        let full_end = value_start + (rest.len() - trimmed.len()) + 1 + end + 1;
                        output.replace_range(value_start..full_end, "\"[REDACTED]\"");
                    }
                }
            }
        }

        // Redact key=value patterns (common in structured logging)
        let kv_pattern = format!("{}=", field);
        let mut search_from = 0;
        while let Some(pos) = output[search_from..].find(&kv_pattern) {
            let start = search_from + pos;
            let value_start = start + kv_pattern.len();
            if let Some(rest) = output.get(value_start..) {
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == ',' || c == '}')
                    .unwrap_or(rest.len());
                let full_end = value_start + end;
                let replacement = "[REDACTED]";
                output.replace_range(value_start..full_end, replacement);
                search_from = value_start + replacement.len();
            } else {
                break;
            }
        }
    }

    output
}

/// Checks whether a string contains any PII field names.
///
/// Useful for asserting that log output is PII-free in tests.
pub fn contains_pii_fields(input: &str) -> bool {
    let lower = input.to_lowercase();
    for field in PII_FIELDS {
        // Check for JSON patterns: "field_name":
        if lower.contains(&format!("\"{}\":", field)) {
            return true;
        }
        // Check for key=value patterns
        if lower.contains(&format!("{}=", field)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_json_pii() {
        let input = r#"{"email": "john@example.com", "broker": "spokeo"}"#;
        let output = sanitize_pii(input);
        assert!(!output.contains("john@example.com"));
        assert!(output.contains("[REDACTED]"));
        assert!(output.contains("spokeo")); // Non-PII preserved
    }

    #[test]
    fn test_sanitize_kv_pii() {
        let input = "processing first_name=John last_name=Doe broker=spokeo";
        let output = sanitize_pii(input);
        assert!(!output.contains("John"));
        assert!(!output.contains("Doe"));
        assert!(output.contains("spokeo"));
    }

    #[test]
    fn test_sanitize_no_pii() {
        let input = "Processing broker spokeo, status: success";
        let output = sanitize_pii(input);
        assert_eq!(input, output); // No changes
    }

    #[test]
    fn test_contains_pii_fields_positive() {
        assert!(contains_pii_fields(r#""email": "test@test.com""#));
        assert!(contains_pii_fields("first_name=John"));
        assert!(contains_pii_fields(r#""phone": "555-1234""#));
    }

    #[test]
    fn test_contains_pii_fields_negative() {
        assert!(!contains_pii_fields("broker=spokeo status=success"));
        assert!(!contains_pii_fields("task completed in 5000ms"));
    }

    #[test]
    fn test_sanitize_multiple_pii_fields() {
        let input = r#"{"first_name": "John", "last_name": "Doe", "email": "j@d.com"}"#;
        let output = sanitize_pii(input);
        assert!(!output.contains("John"));
        assert!(!output.contains("Doe"));
        assert!(!output.contains("j@d.com"));
    }

    #[test]
    fn test_sanitize_passphrase() {
        let input = "passphrase=mysecretpass123";
        let output = sanitize_pii(input);
        assert!(!output.contains("mysecretpass123"));
    }
}
