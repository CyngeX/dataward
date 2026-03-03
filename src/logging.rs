use anyhow::{Context, Result};
use std::io;
use std::path::Path;
use tracing_appender::rolling;
use tracing_subscriber::{
    fmt, fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

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

/// A writer wrapper that buffers output line-by-line and applies PII
/// sanitization before forwarding to the inner writer.
struct SanitizingWriter<W: io::Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: io::Write> io::Write for SanitizingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        self.buf.extend_from_slice(buf);

        // Process complete lines
        while let Some(newline_pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..=newline_pos]);
            let sanitized = sanitize_pii(&line);
            self.inner.write_all(sanitized.as_bytes())?;
            self.buf.drain(..=newline_pos);
        }

        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let remaining = String::from_utf8_lossy(&self.buf);
            let sanitized = sanitize_pii(&remaining);
            self.inner.write_all(sanitized.as_bytes())?;
            self.buf.clear();
        }
        self.inner.flush()
    }
}

impl<W: io::Write> Drop for SanitizingWriter<W> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            let remaining = String::from_utf8_lossy(&self.buf);
            let sanitized = sanitize_pii(&remaining);
            let _ = self.inner.write_all(sanitized.as_bytes());
            self.buf.clear();
        }
        let _ = self.inner.flush();
    }
}

/// A MakeWriter wrapper that produces sanitizing writers.
struct SanitizingMakeWriter<M> {
    inner: M,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for SanitizingMakeWriter<M> {
    type Writer = SanitizingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        SanitizingWriter {
            inner: self.inner.make_writer(),
            buf: Vec::new(),
        }
    }
}

/// Initializes the logging system with PII sanitization.
///
/// All log output (stderr and file) passes through automatic PII redaction
/// via SanitizingMakeWriter. This is defense-in-depth — callers should still
/// avoid logging PII fields directly.
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

    let env_filter = EnvFilter::try_new(level).unwrap_or_else(|_| {
        eprintln!(
            "Warning: Invalid log level '{}', defaulting to 'info'",
            level
        );
        EnvFilter::new("info")
    });

    // Stderr layer with PII sanitization
    let stderr_layer = fmt::layer()
        .with_target(false)
        .with_writer(SanitizingMakeWriter { inner: io::stderr })
        .with_filter(env_filter);

    // File layer with JSON formatting and PII sanitization
    let file_filter = EnvFilter::try_new(level).unwrap_or_else(|_| {
        eprintln!(
            "Warning: Invalid log level '{}', defaulting to 'info'",
            level
        );
        EnvFilter::new("info")
    });
    let file_layer = fmt::layer()
        .json()
        .with_writer(SanitizingMakeWriter {
            inner: file_appender,
        })
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
        let mut search_from = 0;
        while let Some(start) = output[search_from..].find(&json_pattern) {
            let start = search_from + start;
            let value_start = start + json_pattern.len();
            if let Some(rest) = output.get(value_start..) {
                // Handle quoted values: "field": "value"
                let trimmed = rest.trim_start();
                if trimmed.starts_with('"') {
                    if let Some(end) = trimmed[1..].find('"') {
                        let full_end = value_start + (rest.len() - trimmed.len()) + 1 + end + 1;
                        output.replace_range(value_start..full_end, "\"[REDACTED]\"");
                        search_from = start + json_pattern.len() + "\"[REDACTED]\"".len();
                    } else {
                        break;
                    }
                } else {
                    search_from = start + json_pattern.len();
                }
            } else {
                break;
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

    #[test]
    fn test_sanitize_json_multiple_occurrences_same_field() {
        let input = r#"{"email":"a@a.com","other":"x","email":"b@b.com"}"#;
        let output = sanitize_pii(input);
        assert!(
            !output.contains("a@a.com"),
            "first occurrence should be redacted"
        );
        assert!(
            !output.contains("b@b.com"),
            "second occurrence should be redacted"
        );
    }
}
