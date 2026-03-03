use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Application configuration loaded from config.toml.
///
/// Contains ONLY non-sensitive settings. Credentials are in SQLCipher DB.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// Scheduler settings
    #[serde(default)]
    pub scheduler: SchedulerConfig,

    /// Dashboard settings
    #[serde(default)]
    pub dashboard: DashboardConfig,

    /// Email settings (non-sensitive only — SMTP creds are in DB)
    #[serde(default)]
    pub email: EmailConfig,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralConfig {
    /// Maximum concurrent browser contexts (1-3)
    #[serde(default = "default_concurrency")]
    pub concurrency: u8,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            concurrency: default_concurrency(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerConfig {
    /// Interval in hours between full scheduler runs
    #[serde(default = "default_interval_hours")]
    pub interval_hours: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            interval_hours: default_interval_hours(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    /// Port for the web dashboard
    #[serde(default = "default_dashboard_port")]
    pub port: u16,

    /// Whether to start the dashboard on `dataward run`
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            port: default_dashboard_port(),
            enabled: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    /// Maximum emails to send per day
    #[serde(default = "default_daily_limit")]
    pub daily_limit: u32,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            daily_limit: default_daily_limit(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_concurrency() -> u8 {
    1
}
fn default_interval_hours() -> u32 {
    24
}
fn default_dashboard_port() -> u16 {
    9847
}
fn default_daily_limit() -> u32 {
    20
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            scheduler: SchedulerConfig::default(),
            dashboard: DashboardConfig::default(),
            email: EmailConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Config {
    /// Loads config from the given path. Returns default config if file doesn't exist.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let config_path = data_dir.join("config.toml");
        if !config_path.exists() {
            return Ok(Config::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Validates config values are within acceptable ranges.
    fn validate(&self) -> Result<()> {
        if self.general.concurrency == 0 || self.general.concurrency > 3 {
            anyhow::bail!(
                "general.concurrency must be between 1 and 3 (got {})",
                self.general.concurrency
            );
        }
        if self.scheduler.interval_hours == 0 {
            anyhow::bail!("scheduler.interval_hours must be at least 1");
        }
        if self.dashboard.port == 0 {
            anyhow::bail!("dashboard.port must be non-zero");
        }

        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            anyhow::bail!(
                "logging.level must be one of: {} (got '{}')",
                valid_levels.join(", "),
                self.logging.level
            );
        }

        Ok(())
    }

    /// Writes the default config file to disk.
    pub fn write_default(data_dir: &Path) -> Result<PathBuf> {
        let config_path = data_dir.join("config.toml");
        let content = r#"# Dataward Configuration
# Non-sensitive settings only. Credentials are stored in the encrypted database.

[general]
# Maximum concurrent browser contexts (1-3)
concurrency = 1

[scheduler]
# Hours between full scheduler runs
interval_hours = 24

[dashboard]
# Web dashboard port (binds to 127.0.0.1 only)
port = 9847
enabled = true

[email]
# Maximum opt-out emails per day
daily_limit = 20

[logging]
# Log level: trace, debug, info, warn, error
level = "info"
"#;

        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(config_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.concurrency, 1);
        assert_eq!(config.scheduler.interval_hours, 24);
        assert_eq!(config.dashboard.port, 9847);
        assert_eq!(config.email.daily_limit, 20);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_parse_valid_toml() {
        let toml = r#"
[general]
concurrency = 2

[scheduler]
interval_hours = 12

[dashboard]
port = 8080
enabled = false

[email]
daily_limit = 50

[logging]
level = "debug"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.general.concurrency, 2);
        assert_eq!(config.scheduler.interval_hours, 12);
        assert_eq!(config.dashboard.port, 8080);
        assert!(!config.dashboard.enabled);
        assert_eq!(config.email.daily_limit, 50);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_parse_partial_toml() {
        let toml = r#"
[general]
concurrency = 3
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.general.concurrency, 3);
        // Defaults for unspecified sections
        assert_eq!(config.scheduler.interval_hours, 24);
        assert_eq!(config.dashboard.port, 9847);
    }

    #[test]
    fn test_reject_unknown_fields() {
        let toml = r#"
[general]
concurrency = 1
secret_key = "should-not-be-here"
"#;
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_concurrency_bounds() {
        let mut config = Config::default();
        config.general.concurrency = 0;
        assert!(config.validate().is_err());

        config.general.concurrency = 4;
        assert!(config.validate().is_err());

        config.general.concurrency = 3;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_log_level() {
        let mut config = Config::default();
        config.logging.level = "invalid".to_string();
        assert!(config.validate().is_err());

        config.logging.level = "debug".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_negative_concurrency() {
        // concurrency is u8, so negative TOML values should fail to parse
        let toml = r#"
[general]
concurrency = -1
"#;
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_port_zero() {
        // port = 0 is explicitly rejected by validate()
        let mut config = Config::default();
        config.dashboard.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_port_max() {
        // port = 65535 is within u16 range and non-zero, should be valid
        let mut config = Config::default();
        config.dashboard.port = 65535;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_log_level() {
        let mut config = Config::default();
        config.logging.level = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.general.concurrency, 1);
    }

    #[test]
    fn test_write_and_load_default() {
        let dir = tempfile::tempdir().unwrap();
        Config::write_default(dir.path()).unwrap();
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.general.concurrency, 1);
        assert_eq!(config.dashboard.port, 9847);
    }
}
