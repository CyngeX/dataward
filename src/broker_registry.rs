use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use url::Url;

use crate::db;

/// Maximum steps allowed per playbook (prevents abuse/mistakes).
const MAX_PLAYBOOK_STEPS: usize = 50;

/// Blocked URL schemes that could be used for code execution or data exfiltration.
const BLOCKED_SCHEMES: &[&str] = &["javascript", "data", "file", "blob"];

/// Valid opt-out channels.
const VALID_CHANNELS: &[&str] = &["web_form", "email", "api", "manual_only"];

/// Valid broker categories.
const VALID_CATEGORIES: &[&str] = &["people_search", "marketing", "background_check", "ad_tech"];

/// Valid on_error strategies.
const VALID_ON_ERROR: &[&str] = &["retry", "skip", "fail"];

/// Trust tier directory names and their levels.
const TRUST_TIERS: &[(&str, &str)] = &[
    ("official", "official"),
    ("community", "community"),
    ("local", "local"),
];

/// A parsed and validated playbook.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Playbook {
    pub broker: BrokerDefinition,
    pub required_fields: Vec<String>,
    pub steps: Vec<PlaybookStep>,
    pub on_error: String,
    pub max_retries: u32,
    pub trust_tier: String,
    pub file_path: PathBuf,
}

/// Broker metadata from the playbook YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerDefinition {
    pub id: String,
    pub name: String,
    pub url: String,
    pub category: String,
    pub recheck_days: i32,
    pub opt_out_channel: String,
    #[serde(default)]
    pub parent_company: Option<String>,
    /// Note: allowed_domains is self-declared by the playbook author. It prevents navigation to
    /// domains NOT listed, but does not prevent a malicious playbook author from declaring
    /// arbitrary domains.
    pub allowed_domains: Vec<String>,
}

/// Raw playbook YAML structure for deserialization.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlaybook {
    broker: BrokerDefinition,
    required_fields: Vec<String>,
    steps: Vec<RawStep>,
    #[serde(default = "default_on_error")]
    on_error: String,
    #[serde(default = "default_max_retries")]
    max_retries: u32,
}

fn default_on_error() -> String {
    "retry".to_string()
}

fn default_max_retries() -> u32 {
    3
}

/// Raw step from YAML — each step is one of the 6 MVP action types.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    #[serde(default)]
    navigate: Option<String>,
    #[serde(default)]
    fill: Option<FillParams>,
    #[serde(default)]
    click: Option<ClickParams>,
    #[serde(default)]
    select: Option<SelectParams>,
    #[serde(default)]
    wait: Option<WaitParams>,
    #[serde(default)]
    screenshot: Option<ScreenshotParams>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillParams {
    pub selector: String,
    pub field: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickParams {
    pub selector: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct SelectParams {
    pub selector: String,
    #[serde(alias = "value_or_field")]
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitParams {
    pub seconds: f32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotParams {
    pub name: String,
}

/// Validated playbook step.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum PlaybookStep {
    Navigate(String),
    Fill(FillParams),
    Click(ClickParams),
    Select(SelectParams),
    Wait(WaitParams),
    Screenshot(ScreenshotParams),
}

/// Loads and validates all playbooks from the playbooks directory.
///
/// Validates a single playbook file and returns it if valid.
///
/// This is the public entry point for the `dataward playbook validate` CLI command.
/// The trust tier defaults to "local" for standalone validation.
pub fn validate_playbook_file(path: &Path) -> Result<Playbook> {
    load_and_validate_playbook(path, "local")
}

/// Returns validated playbooks grouped by trust tier. Invalid playbooks
/// are logged as warnings but don't block loading of valid ones.
pub fn load_playbooks(playbooks_dir: &Path) -> Result<Vec<Playbook>> {
    let mut playbooks = Vec::new();
    let mut errors = Vec::new();

    for &(dir_name, tier) in TRUST_TIERS {
        let tier_dir = playbooks_dir.join(dir_name);
        if !tier_dir.exists() {
            continue;
        }

        let entries = std::fs::read_dir(&tier_dir).with_context(|| {
            format!("Failed to read playbook directory: {}", tier_dir.display())
        })?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml")
                && path.extension().and_then(|e| e.to_str()) != Some("yml")
            {
                continue;
            }

            match load_and_validate_playbook(&path, tier) {
                Ok(playbook) => {
                    if tier == "local" {
                        tracing::warn!(
                            broker_id = %playbook.broker.id,
                            "Loading unreviewed local playbook: {}. Verify before running.",
                            path.display()
                        );
                    }
                    playbooks.push(playbook);
                }
                Err(e) => {
                    errors.push(format!("{}: {}", path.display(), e));
                    tracing::warn!(
                        path = %path.display(),
                        "Skipping invalid playbook: {}",
                        e
                    );
                }
            }
        }
    }

    if !errors.is_empty() {
        tracing::warn!(
            count = errors.len(),
            "Skipped {} invalid playbooks",
            errors.len()
        );
    }

    Ok(playbooks)
}

/// Loads a single playbook and applies all validation rules.
fn load_and_validate_playbook(path: &Path, trust_tier: &str) -> Result<Playbook> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read playbook: {}", path.display()))?;

    let raw: RawPlaybook = serde_yaml::from_str(&content)
        .with_context(|| format!("YAML parse error in: {}", path.display()))?;

    // Validate broker metadata
    validate_broker_metadata(&raw.broker)?;

    // Validate on_error
    if !VALID_ON_ERROR.contains(&raw.on_error.as_str()) {
        anyhow::bail!(
            "Invalid on_error value '{}'. Must be one of: {}",
            raw.on_error,
            VALID_ON_ERROR.join(", ")
        );
    }

    // Validate step count
    if raw.steps.is_empty() {
        anyhow::bail!("Playbook has no steps");
    }
    if raw.steps.len() > MAX_PLAYBOOK_STEPS {
        anyhow::bail!(
            "Playbook has {} steps (max {})",
            raw.steps.len(),
            MAX_PLAYBOOK_STEPS
        );
    }

    // Validate and convert steps
    let required_fields: HashSet<&str> = raw.required_fields.iter().map(|s| s.as_str()).collect();
    let allowed_domains: HashSet<&str> = raw
        .broker
        .allowed_domains
        .iter()
        .map(|s| s.as_str())
        .collect();

    let mut steps = Vec::with_capacity(raw.steps.len());
    for (i, raw_step) in raw.steps.iter().enumerate() {
        let step = validate_step(raw_step, i, &required_fields, &allowed_domains)?;
        steps.push(step);
    }

    Ok(Playbook {
        broker: raw.broker,
        required_fields: raw.required_fields,
        steps,
        on_error: raw.on_error,
        max_retries: raw.max_retries,
        trust_tier: trust_tier.to_string(),
        file_path: path.to_path_buf(),
    })
}

/// Validates broker metadata fields.
fn validate_broker_metadata(broker: &BrokerDefinition) -> Result<()> {
    if broker.id.is_empty() {
        anyhow::bail!("Broker ID cannot be empty");
    }

    if !VALID_CATEGORIES.contains(&broker.category.as_str()) {
        anyhow::bail!(
            "Invalid category '{}'. Must be one of: {}",
            broker.category,
            VALID_CATEGORIES.join(", ")
        );
    }

    if !VALID_CHANNELS.contains(&broker.opt_out_channel.as_str()) {
        anyhow::bail!(
            "Invalid opt_out_channel '{}'. Must be one of: {}",
            broker.opt_out_channel,
            VALID_CHANNELS.join(", ")
        );
    }

    if broker.recheck_days < 1 || broker.recheck_days > 365 {
        anyhow::bail!(
            "recheck_days must be between 1 and 365 (got {})",
            broker.recheck_days
        );
    }

    if broker.allowed_domains.is_empty() {
        anyhow::bail!("allowed_domains cannot be empty — required for security");
    }

    // Validate the broker URL
    let url =
        Url::parse(&broker.url).with_context(|| format!("Invalid broker URL: {}", broker.url))?;
    if url.scheme() != "https" {
        anyhow::bail!("Broker URL must use HTTPS: {}", broker.url);
    }

    Ok(())
}

/// Validates a single playbook step.
fn validate_step(
    raw: &RawStep,
    index: usize,
    required_fields: &HashSet<&str>,
    allowed_domains: &HashSet<&str>,
) -> Result<PlaybookStep> {
    // Count how many action types are set (should be exactly 1)
    let action_count = [
        raw.navigate.is_some(),
        raw.fill.is_some(),
        raw.click.is_some(),
        raw.select.is_some(),
        raw.wait.is_some(),
        raw.screenshot.is_some(),
    ]
    .iter()
    .filter(|&&b| b)
    .count();

    if action_count == 0 {
        anyhow::bail!("Step {} has no action type", index);
    }
    if action_count > 1 {
        anyhow::bail!(
            "Step {} has multiple action types (must have exactly 1)",
            index
        );
    }

    if let Some(url_str) = &raw.navigate {
        validate_navigate_url(url_str, allowed_domains)
            .with_context(|| format!("Step {} (navigate)", index))?;
        return Ok(PlaybookStep::Navigate(url_str.clone()));
    }

    if let Some(fill) = &raw.fill {
        if !required_fields.contains(fill.field.as_str()) {
            anyhow::bail!(
                "Step {} (fill): field '{}' is not in required_fields",
                index,
                fill.field
            );
        }
        if fill.selector.is_empty() {
            anyhow::bail!("Step {} (fill): selector cannot be empty", index);
        }
        return Ok(PlaybookStep::Fill(fill.clone()));
    }

    if let Some(click) = &raw.click {
        if click.selector.is_empty() {
            anyhow::bail!("Step {} (click): selector cannot be empty", index);
        }
        return Ok(PlaybookStep::Click(click.clone()));
    }

    if let Some(select) = &raw.select {
        if select.selector.is_empty() {
            anyhow::bail!("Step {} (select): selector cannot be empty", index);
        }
        return Ok(PlaybookStep::Select(select.clone()));
    }

    if let Some(wait) = &raw.wait {
        if wait.seconds.is_nan()
            || wait.seconds.is_infinite()
            || wait.seconds <= 0.0
            || wait.seconds > 30.0
        {
            anyhow::bail!(
                "Step {} (wait): seconds must be between 0 and 30 (got {})",
                index,
                wait.seconds
            );
        }
        return Ok(PlaybookStep::Wait(wait.clone()));
    }

    if let Some(screenshot) = &raw.screenshot {
        if screenshot.name.is_empty() {
            anyhow::bail!("Step {} (screenshot): name cannot be empty", index);
        }
        return Ok(PlaybookStep::Screenshot(screenshot.clone()));
    }

    unreachable!("Step must have at least one action type (checked above)")
}

/// Validates a navigate URL against security rules.
fn validate_navigate_url(url_str: &str, allowed_domains: &HashSet<&str>) -> Result<()> {
    let url = Url::parse(url_str).with_context(|| format!("Invalid URL: {}", url_str))?;

    // Block dangerous schemes
    let scheme = url.scheme().to_lowercase();
    if BLOCKED_SCHEMES.contains(&scheme.as_str()) {
        anyhow::bail!(
            "Blocked URL scheme '{}' in navigate action: {}",
            scheme,
            url_str
        );
    }

    // Require HTTPS
    if scheme != "https" {
        anyhow::bail!("Navigate URLs must use HTTPS: {}", url_str);
    }

    // Check domain against allowlist
    let domain = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {}", url_str))?;

    if !allowed_domains.contains(domain) {
        anyhow::bail!(
            "Domain '{}' not in allowed_domains for this broker. URL: {}",
            domain,
            url_str
        );
    }

    Ok(())
}

/// Populates the brokers table from validated playbooks.
pub fn sync_brokers_to_db(conn: &rusqlite::Connection, playbooks: &[Playbook]) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    for playbook in playbooks {
        let broker_row = db::BrokerRow {
            id: playbook.broker.id.clone(),
            name: playbook.broker.name.clone(),
            category: playbook.broker.category.clone(),
            opt_out_channel: playbook.broker.opt_out_channel.clone(),
            recheck_days: playbook.broker.recheck_days,
            parent_company: playbook.broker.parent_company.clone(),
            playbook_path: playbook.file_path.to_string_lossy().to_string(),
            trust_tier: playbook.trust_tier.clone(),
            enabled: true,
        };
        if let Err(e) = db::upsert_broker(conn, &broker_row) {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    conn.execute_batch("COMMIT")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_playbook_yaml() -> String {
        r##"
broker:
  id: testbroker
  name: Test Broker
  url: https://www.testbroker.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains:
    - testbroker.com
    - www.testbroker.com

required_fields:
  - first_name
  - email

steps:
  - navigate: "https://www.testbroker.com/optout"
  - fill: { selector: "#first_name", field: "first_name" }
  - fill: { selector: "#email", field: "email" }
  - click: { selector: "#submit" }
  - wait: { seconds: 2 }
  - screenshot: { name: "confirmation" }

on_error: retry
max_retries: 3
"##
        .to_string()
    }

    fn write_playbook(dir: &Path, tier: &str, name: &str, content: &str) -> PathBuf {
        let tier_dir = dir.join(tier);
        std::fs::create_dir_all(&tier_dir).unwrap();
        let path = tier_dir.join(format!("{}.yaml", name));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_valid_playbook_loads() {
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "test", &valid_playbook_yaml());
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert_eq!(playbooks.len(), 1);
        assert_eq!(playbooks[0].broker.id, "testbroker");
        assert_eq!(playbooks[0].trust_tier, "official");
        assert_eq!(playbooks[0].steps.len(), 6);
    }

    #[test]
    fn test_reject_unknown_fields() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]
  evil_field: "should fail"

required_fields: [email]
steps:
  - navigate: "https://test.com/optout"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "bad", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with unknown fields should be rejected by deny_unknown_fields"
        );
    }

    #[test]
    fn test_reject_javascript_url() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "javascript:alert(1)"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "js", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with javascript: navigate URL should be rejected"
        );
    }

    #[test]
    fn test_reject_data_url() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "data:text/html,<h1>pwned</h1>"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "data", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with data: navigate URL should be rejected"
        );
    }

    #[test]
    fn test_reject_non_allowed_domain() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "https://evil.com/exfiltrate"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "domain", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook navigating to domain outside allowed_domains should be rejected"
        );
    }

    #[test]
    fn test_reject_http_url() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "http://test.com/optout"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "http", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with http: (non-HTTPS) navigate URL should be rejected"
        );
    }

    #[test]
    fn test_reject_field_not_in_required() {
        let yaml = r##"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - fill: { selector: "#phone", field: "phone" }
"##;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "field", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook using fill field not declared in required_fields should be rejected"
        );
    }

    #[test]
    fn test_reject_too_many_steps() {
        let mut steps = String::new();
        for _ in 0..51 {
            steps.push_str("  - wait: { seconds: 1 }\n");
        }
        let yaml = format!(
            r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
{}
"#,
            steps
        );
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "toomany", &yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook exceeding MAX_PLAYBOOK_STEPS (50) should be rejected"
        );
    }

    #[test]
    fn test_reject_empty_steps() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps: []
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "empty", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with empty steps list should be rejected"
        );
    }

    #[test]
    fn test_reject_invalid_category() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: invalid_category
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "https://test.com/optout"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "badcat", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with invalid broker category should be rejected"
        );
    }

    #[test]
    fn test_reject_missing_allowed_domains() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: []

required_fields: [email]
steps:
  - navigate: "https://test.com/optout"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "nodomains", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with empty allowed_domains should be rejected"
        );
    }

    #[test]
    fn test_wait_max_30_seconds() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - wait: { seconds: 31 }
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "longwait", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with wait seconds > 30 should be rejected"
        );
    }

    #[test]
    fn test_multiple_trust_tiers() {
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "broker1", &valid_playbook_yaml());

        let community_yaml = valid_playbook_yaml().replace("testbroker", "communitybroker");
        write_playbook(dir.path(), "community", "broker2", &community_yaml);

        let local_yaml = valid_playbook_yaml().replace("testbroker", "localbroker");
        write_playbook(dir.path(), "local", "broker3", &local_yaml);

        let playbooks = load_playbooks(dir.path()).unwrap();
        assert_eq!(playbooks.len(), 3);

        let tiers: HashSet<String> = playbooks.iter().map(|p| p.trust_tier.clone()).collect();
        assert!(tiers.contains("official"));
        assert!(tiers.contains("community"));
        assert!(tiers.contains("local"));
    }

    #[test]
    fn test_reject_file_url_scheme() {
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "file:///etc/passwd"
"#;
        let dir = tempfile::tempdir().unwrap();
        write_playbook(dir.path(), "official", "file", yaml);
        let playbooks = load_playbooks(dir.path()).unwrap();
        assert!(
            playbooks.is_empty(),
            "Playbook with file: navigate URL should be rejected"
        );
    }

    #[test]
    fn test_load_playbooks_missing_directory() {
        let missing = Path::new("/tmp/dataward_nonexistent_playbooks_dir_xyzzy");
        // load_playbooks skips non-existent tier subdirectories, so it returns Ok with empty list
        let result = load_playbooks(missing);
        match result {
            Ok(playbooks) => assert!(
                playbooks.is_empty(),
                "Missing playbooks directory should yield empty list, not panic"
            ),
            Err(_) => {} // Returning an error is also acceptable
        }
    }

    #[test]
    fn test_validate_playbook_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_playbook(dir.path(), "local", "test", &valid_playbook_yaml());
        let result = validate_playbook_file(&path);
        assert!(
            result.is_ok(),
            "Valid playbook should pass: {:?}",
            result.err()
        );
        let playbook = result.unwrap();
        assert_eq!(playbook.broker.id, "testbroker");
        assert_eq!(playbook.trust_tier, "local");
    }

    #[test]
    fn test_validate_playbook_file_missing_field() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

steps:
  - navigate: "https://test.com/optout"
"#;
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, yaml).unwrap();
        let result = validate_playbook_file(&path);
        assert!(result.is_err(), "Missing required_fields should fail");
    }

    #[test]
    fn test_validate_playbook_file_empty_steps() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: people_search
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps: []
"#;
        let path = dir.path().join("empty_steps.yaml");
        std::fs::write(&path, yaml).unwrap();
        let result = validate_playbook_file(&path);
        assert!(result.is_err(), "Empty steps should fail");
    }

    #[test]
    fn test_validate_playbook_file_invalid_category() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
broker:
  id: test
  name: Test
  url: https://test.com
  category: invalid_cat
  recheck_days: 90
  opt_out_channel: web_form
  allowed_domains: [test.com]

required_fields: [email]
steps:
  - navigate: "https://test.com/optout"
"#;
        let path = dir.path().join("bad_cat.yaml");
        std::fs::write(&path, yaml).unwrap();
        let result = validate_playbook_file(&path);
        assert!(result.is_err(), "Invalid category should fail");
    }

    #[test]
    fn test_validate_playbook_file_nonexistent() {
        let result = validate_playbook_file(Path::new("/nonexistent/playbook.yaml"));
        assert!(result.is_err(), "Nonexistent file should fail");
    }
}
