mod api_worker;
mod broker_registry;
mod config;
mod crypto;
mod dashboard;
mod db;
mod discovery;
mod download;
mod email_worker;
mod init;
mod legal_ack;
mod logging;
mod orchestrator;
#[cfg(test)]
mod phase7_audit;
mod rekey;
mod retention;
mod scheduler;
mod status;
mod subprocess;
mod worker_setup;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "dataward",
    version,
    about = "Automated data broker opt-out daemon"
)]
struct Cli {
    /// Path to data directory (default: ~/.dataward)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize dataward: collect PII, create encrypted database, download dependencies
    Init,
    /// Run opt-out tasks for all due brokers
    Run {
        /// Run once and exit (default: daemon mode)
        #[arg(long)]
        once: bool,
    },
    /// Show current status of all brokers and pending tasks
    Status,
    /// Re-encrypt the database with a new passphrase
    Rekey,
    /// Playbook management commands
    Playbook {
        #[command(subcommand)]
        command: PlaybookCommands,
    },
    /// Delete all user data, proofs, and database
    Purge {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum PlaybookCommands {
    /// Validate a playbook YAML file against the schema
    Validate {
        /// Path to the playbook YAML file
        file: PathBuf,
    },
    /// Verify playbooks against a sha256 manifest (drift detection)
    Verify {
        /// Path to the .sums manifest (default: playbooks/platform.sums)
        #[arg(long, default_value = "playbooks/platform.sums")]
        sums: PathBuf,
        /// Directory the sums paths are relative to (default: parent of --sums)
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

/// Runs a plain `sha256sum -c`-style drift check against a `.sums` manifest.
/// Returns Ok(()) on a clean check, Err with the list of mismatches otherwise.
fn verify_playbook_sums(sums_path: &std::path::Path, root: &std::path::Path) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let content = std::fs::read_to_string(sums_path)
        .with_context(|| format!("Failed to read sums file: {}", sums_path.display()))?;

    let mut failed: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: "<hex>  <relative/path>" (coreutils sha256sum output).
        let mut parts = line.splitn(2, "  ");
        let expected = parts.next().unwrap_or("");
        let relpath = parts.next().unwrap_or("");
        if expected.is_empty() || relpath.is_empty() {
            anyhow::bail!(
                "{}:{}: malformed sums line",
                sums_path.display(),
                lineno + 1
            );
        }
        let file_path = root.join(relpath);
        let mut file = std::fs::File::open(&file_path)
            .with_context(|| format!("Failed to open: {}", file_path.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            failed.push(format!("{}: expected {} got {}", relpath, expected, actual));
        } else {
            eprintln!("OK: {}", relpath);
        }
        checked += 1;
    }

    if checked == 0 {
        anyhow::bail!("sums file contains no entries");
    }
    if !failed.is_empty() {
        for f in &failed {
            eprintln!("FAIL: {}", f);
        }
        anyhow::bail!("{} playbook(s) failed drift check", failed.len());
    }
    eprintln!("All {} playbook(s) verified.", checked);
    Ok(())
}

fn data_dir(cli_override: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = cli_override {
        return Ok(dir.clone());
    }
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".dataward"))
}

fn require_initialized(data_dir: &std::path::Path) -> anyhow::Result<()> {
    if !data_dir.join("dataward.db").exists() {
        anyhow::bail!(
            "Dataward is not initialized. Run `dataward init` first.\nData directory: {}",
            data_dir.display()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Phase 7.0 §L: harden against core dumps before loading any secrets.
    // Prevents crash-time memory snapshots from leaking keys or PII.
    if let Err(e) = crypto::harden_core_dumps() {
        eprintln!("WARNING: failed to harden against core dumps: {}", e);
        eprintln!("  Continuing, but memory-dump protection is NOT in effect.");
    }

    let cli = Cli::parse();
    let data_dir = data_dir(cli.data_dir.as_ref())?;

    match cli.command {
        Commands::Init => {
            init::run_init(&data_dir).await?;
        }
        Commands::Run { once } => {
            require_initialized(&data_dir)?;
            orchestrator::run(&data_dir, once).await?;
        }
        Commands::Status => {
            require_initialized(&data_dir)?;
            status::run_status(&data_dir)?;
        }
        Commands::Rekey => {
            require_initialized(&data_dir)?;
            rekey::run_rekey(&data_dir)?;
        }
        Commands::Playbook { command } => match command {
            PlaybookCommands::Verify { sums, root } => {
                let root = root
                    .unwrap_or_else(|| sums.parent().map(|p| p.to_path_buf()).unwrap_or_default());
                verify_playbook_sums(&sums, &root)?;
            }
            PlaybookCommands::Validate { file } => {
                match broker_registry::validate_playbook_file(&file) {
                    Ok(playbook) => {
                        eprintln!("VALID: {} ({})", playbook.broker.name, playbook.broker.id);
                        eprintln!("  Category: {}", playbook.broker.category);
                        eprintln!("  Channel: {}", playbook.broker.opt_out_channel);
                        eprintln!("  Steps: {}", playbook.steps.len());
                        eprintln!("  Required fields: {}", playbook.required_fields.join(", "));
                        eprintln!(
                            "  Allowed domains: {}",
                            playbook.broker.allowed_domains.join(", ")
                        );
                    }
                    Err(e) => {
                        eprintln!("INVALID: {}", file.display());
                        eprintln!("  Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Purge { force } => {
            init::run_purge(&data_dir, force).await?;
        }
    }

    Ok(())
}
