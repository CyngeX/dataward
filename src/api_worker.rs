use anyhow::{Context, Result};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

/// Default timeout for API opt-out requests (15 seconds).
const API_TIMEOUT_SECS: u64 = 15;

/// Maximum response body size to read (1MB).
const MAX_RESPONSE_SIZE: usize = 1_048_576;

/// Result of an API opt-out attempt.
#[derive(Debug)]
pub struct ApiResult {
    pub success: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_retryable: bool,
    pub duration_ms: i64,
    pub confirmation_text: Option<String>,
}

/// Creates a reusable HTTP client with reasonable defaults.
///
/// The client is pooled and should be shared across API tasks.
pub fn create_api_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(API_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(10))
        .https_only(true)
        .user_agent("Dataward/0.1 (automated data removal request)")
        .pool_max_idle_per_host(2)
        .build()
        .context("Failed to create HTTP client")
}

/// Sends an API opt-out request for a broker.
///
/// The request is a POST with the user's PII as JSON body.
/// Expects a 2xx response to indicate success.
pub async fn send_opt_out_api(
    client: &Client,
    api_url: &str,
    user_data: &HashMap<String, String>,
    broker_id: &str,
) -> ApiResult {
    let start = std::time::Instant::now();

    // Validate URL is HTTPS
    if !api_url.starts_with("https://") {
        return ApiResult {
            success: false,
            error_code: Some("domain_violation".to_string()),
            error_message: Some("API URL must use HTTPS".to_string()),
            error_retryable: false,
            duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
            confirmation_text: None,
        };
    }

    let response = match client.post(api_url).json(user_data).send().await {
        Ok(resp) => resp,
        Err(e) => {
            let error_message = e.to_string();
            let retryable = is_api_error_retryable(&e);
            tracing::warn!(
                broker_id,
                url = api_url,
                error = %error_message,
                retryable,
                "API opt-out request failed"
            );
            return ApiResult {
                success: false,
                error_code: Some("playbook_error".to_string()),
                error_message: Some(error_message),
                error_retryable: retryable,
                duration_ms: start.elapsed().as_millis().min(i64::MAX as u128) as i64,
                confirmation_text: None,
            };
        }
    };

    let status = response.status();
    let duration_ms = start.elapsed().as_millis().min(i64::MAX as u128) as i64;

    // Read response body (with size limit)
    let body = match response.bytes().await {
        Ok(bytes) => {
            if bytes.len() > MAX_RESPONSE_SIZE {
                String::from_utf8_lossy(&bytes[..MAX_RESPONSE_SIZE]).to_string()
            } else {
                String::from_utf8_lossy(&bytes).to_string()
            }
        }
        Err(e) => {
            tracing::warn!(broker_id, "Failed to read API response body: {}", e);
            String::new()
        }
    };

    if status.is_success() {
        let confirmation = format!(
            "API opt-out request accepted (HTTP {})",
            status.as_u16()
        );
        tracing::info!(
            broker_id,
            status = status.as_u16(),
            "API opt-out request succeeded"
        );
        ApiResult {
            success: true,
            error_code: None,
            error_message: None,
            error_retryable: false,
            duration_ms,
            confirmation_text: Some(confirmation),
        }
    } else {
        let retryable = is_http_status_retryable(status.as_u16());
        // CONS-R2-014: Use char-based truncation to avoid UTF-8 boundary panic
        // CONS-R2-008: Only store HTTP status + truncated body
        // CONS-R3-011: Strip non-printable control chars to keep logs/DB clean
        let truncated_body: String = body.chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .take(200)
            .collect();
        let error_message = format!("HTTP {} {}", status.as_u16(), truncated_body);
        tracing::warn!(
            broker_id,
            status = status.as_u16(),
            retryable,
            "API opt-out request failed"
        );
        ApiResult {
            success: false,
            error_code: Some("playbook_error".to_string()),
            error_message: Some(error_message),
            error_retryable: retryable,
            duration_ms,
            confirmation_text: None,
        }
    }
}

/// Determines if a reqwest error is retryable.
///
/// Only network-level transient errors (timeout, connection) are retryable.
/// Request construction errors (is_request) are permanent and not retried.
fn is_api_error_retryable(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect()
}

/// Determines if an HTTP status code indicates a retryable failure.
///
/// 5xx server errors and 429 (rate limited) are retryable.
/// 4xx client errors (except 429) are not.
fn is_http_status_retryable(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_api_client() {
        let client = create_api_client();
        assert!(client.is_ok());
    }

    #[test]
    fn test_is_http_status_retryable() {
        // Retryable
        assert!(is_http_status_retryable(429)); // Too Many Requests
        assert!(is_http_status_retryable(500)); // Internal Server Error
        assert!(is_http_status_retryable(502)); // Bad Gateway
        assert!(is_http_status_retryable(503)); // Service Unavailable
        assert!(is_http_status_retryable(504)); // Gateway Timeout

        // Not retryable
        assert!(!is_http_status_retryable(400)); // Bad Request
        assert!(!is_http_status_retryable(401)); // Unauthorized
        assert!(!is_http_status_retryable(403)); // Forbidden
        assert!(!is_http_status_retryable(404)); // Not Found
        assert!(!is_http_status_retryable(200)); // OK (success)
    }

    #[tokio::test]
    async fn test_send_opt_out_api_rejects_http() {
        let client = create_api_client().unwrap();
        let user_data = HashMap::from([
            ("first_name".to_string(), "John".to_string()),
        ]);

        let result = send_opt_out_api(
            &client,
            "http://insecure.example.com/optout",
            &user_data,
            "test-broker",
        ).await;

        assert!(!result.success);
        assert_eq!(result.error_code.as_deref(), Some("domain_violation"));
        assert!(!result.error_retryable);
    }
}
