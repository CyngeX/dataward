mod broker_registry;
mod config;
mod crypto;
mod db;
mod init;
mod logging;
mod api_worker;
mod email_worker;
mod orchestrator;
mod scheduler;
mod subprocess;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dataward", version, about = "Automated data broker opt-out daemon")]
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
    /// Delete all user data, proofs, and database
    Purge {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

fn data_dir(cli_override: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = cli_override {
        return Ok(dir.clone());
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
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
            // Phase 6: status implementation
            eprintln!("Status command not yet implemented (Phase 6)");
        }
        Commands::Purge { force } => {
            init::run_purge(&data_dir, force).await?;
        }
    }

    Ok(())
}
