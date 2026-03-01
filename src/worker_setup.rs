use anyhow::{Context, Result};
use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(feature = "embedded-worker")]
use crate::download;

/// Minimum required Node.js major version.
const MIN_NODE_MAJOR_VERSION: u32 = 18;

/// Pinned Patchright version for supply chain safety.
const PATCHRIGHT_VERSION: &str = "1.49.1";

/// Embedded worker tarball (created by build.rs).
/// Contains worker/dist/, package.json, and package-lock.json.
/// Does NOT contain node_modules — those are installed at init time via `npm ci`.
#[cfg(feature = "embedded-worker")]
const WORKER_TARBALL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/worker.tar.gz"));

/// SHA-256 hash of the embedded worker tarball (set by build.rs).
#[cfg(feature = "embedded-worker")]
const WORKER_TARBALL_HASH: &str = include_str!(concat!(env!("OUT_DIR"), "/worker.tar.gz.sha256"));

/// Sentinel file name written after successful extraction.
const SENTINEL_FILE: &str = ".worker-version";

/// Lock file for preventing concurrent init.
const INIT_LOCK_FILE: &str = ".init-lock";

/// Timeout for quick local subprocesses (node --version, chromium check).
const LOCAL_CMD_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for network-dependent subprocesses (npm ci).
const NPM_CI_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for browser download (npx patchright install chromium ~150MB).
const PATCHRIGHT_TIMEOUT: Duration = Duration::from_secs(600);

/// Sets up the worker runtime in the data directory.
///
/// Steps:
/// 1. Check Node.js >= 18 is available
/// 2. Extract embedded worker tarball (if needed)
/// 3. Run `npm ci --production` to install dependencies
/// 4. Run `npx patchright@<pinned> install chromium`
/// 5. Verify Chromium binary exists
pub fn setup_worker(data_dir: &Path) -> Result<()> {
    let worker_dir = data_dir.join("worker");

    // Step 1: Check Node.js
    check_nodejs()?;

    // Step 2: Extract worker if needed
    if needs_extraction(&worker_dir)? {
        eprintln!("Extracting worker runtime...");
        extract_worker_tarball(data_dir)?;
        eprintln!("  Worker extracted.");
    } else {
        eprintln!("Worker runtime already up to date.");
    }

    // Step 3: Install npm dependencies
    eprintln!("Installing worker dependencies (npm ci)...");
    run_npm_ci(&worker_dir)?;
    eprintln!("  Dependencies installed.");

    // Step 4: Install Patchright + Chromium
    eprintln!("Installing browser (Patchright + Chromium)...");
    eprintln!("  This may take a few minutes on first run (~150MB download).");
    run_patchright_install(&worker_dir)?;

    // Step 5: Verify Chromium binary
    verify_chromium(&worker_dir)?;
    eprintln!("  Browser installed and verified.");

    Ok(())
}

/// Checks that Node.js is installed and meets the minimum version requirement.
pub fn check_nodejs() -> Result<()> {
    let output = run_command_with_timeout(
        std::process::Command::new("node")
            .arg("--version")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
        LOCAL_CMD_TIMEOUT,
        "node --version",
    )
    .context(
        "Node.js not found. Dataward requires Node.js >= 18.\n\
         Install from: https://nodejs.org/\n\
         Or via package manager:\n\
         - macOS: brew install node\n\
         - Ubuntu/Debian: sudo apt install nodejs\n\
         - Arch Linux: sudo pacman -S nodejs"
    )?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to check Node.js version. Ensure Node.js >= {} is installed.",
            MIN_NODE_MAJOR_VERSION
        );
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version_str = version_str.trim();
    let major = parse_node_major_version(version_str)?;

    if major < MIN_NODE_MAJOR_VERSION {
        anyhow::bail!(
            "Node.js version {} is too old. Dataward requires Node.js >= {}.\n\
             Current: {}\n\
             Install from: https://nodejs.org/",
            version_str,
            MIN_NODE_MAJOR_VERSION,
            version_str,
        );
    }

    Ok(())
}

/// Parses the major version from a Node.js version string (e.g., "v20.11.0" → 20).
fn parse_node_major_version(version: &str) -> Result<u32> {
    let stripped = version.strip_prefix('v').unwrap_or(version);
    let major_str = stripped.split('.').next()
        .ok_or_else(|| anyhow::anyhow!("Cannot parse Node.js version: {}", version))?;
    major_str.parse::<u32>()
        .with_context(|| format!("Cannot parse Node.js major version from: {}", version))
}

/// Checks whether the worker needs to be (re-)extracted.
///
/// Returns true if:
/// - Worker directory doesn't exist
/// - Sentinel file is missing
/// - Sentinel hash doesn't match embedded tarball hash
fn needs_extraction(worker_dir: &Path) -> Result<bool> {
    if !worker_dir.exists() {
        return Ok(true);
    }

    let sentinel_path = worker_dir.join(SENTINEL_FILE);
    if !sentinel_path.exists() {
        return Ok(true);
    }

    // Read sentinel and compare hash
    let stored_hash = std::fs::read_to_string(&sentinel_path)
        .with_context(|| format!("Failed to read sentinel: {}", sentinel_path.display()))?;
    let stored_hash = stored_hash.trim();

    let expected_hash = get_embedded_hash();
    Ok(stored_hash != expected_hash)
}

/// Returns the SHA-256 hash of the embedded worker tarball.
#[cfg(feature = "embedded-worker")]
fn get_embedded_hash() -> &'static str {
    WORKER_TARBALL_HASH.trim()
}

/// Fallback when embedded worker is not available (development mode).
#[cfg(not(feature = "embedded-worker"))]
fn get_embedded_hash() -> &'static str {
    "dev-mode-no-embedded-worker"
}

/// Extracts the embedded worker tarball to data_dir/worker/.
///
/// Uses a temporary directory + atomic rename for crash safety.
/// Validates all paths against the target directory to prevent path traversal.
fn extract_worker_tarball(data_dir: &Path) -> Result<()> {
    #[cfg(not(feature = "embedded-worker"))]
    {
        anyhow::bail!(
            "This binary was built without an embedded worker (development mode).\n\
             The worker directory must be set up manually.\n\
             See: worker/README.md"
        );
    }

    #[cfg(feature = "embedded-worker")]
    {
        let worker_dir = data_dir.join("worker");
        let tmp_dir = data_dir.join("worker.extracting");

        // Acquire init lock
        let lock = acquire_init_lock(data_dir)?;

        // Scopeguard: clean up tmp dir on failure
        let _guard = scopeguard::guard((), |_| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        });

        // Remove any previous partial extraction
        if tmp_dir.exists() {
            std::fs::remove_dir_all(&tmp_dir)
                .with_context(|| format!("Failed to remove partial extraction: {}", tmp_dir.display()))?;
        }

        // Verify embedded tarball integrity
        download::verify_sha256(WORKER_TARBALL, WORKER_TARBALL_HASH.trim())?;

        // Decompress and extract
        std::fs::create_dir_all(&tmp_dir)?;
        let decoder = flate2::read::GzDecoder::new(WORKER_TARBALL);
        let mut archive = tar::Archive::new(decoder);

        let canonical_tmp = std::fs::canonicalize(&tmp_dir)
            .with_context(|| format!("Failed to canonicalize: {}", tmp_dir.display()))?;

        for entry in archive.entries()? {
            let mut entry = entry.context("Failed to read tarball entry")?;

            // Path traversal defense: validate every path
            let entry_path = entry.path()?.to_path_buf();
            validate_archive_entry_path(&entry_path)?;

            // Reject symlinks and hardlinks
            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                anyhow::bail!(
                    "Tarball contains symlink or hardlink (rejected for security): {}",
                    entry_path.display()
                );
            }

            let dest = tmp_dir.join(&entry_path);

            // After joining, canonicalize parent and verify containment
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
                let canonical_parent = std::fs::canonicalize(parent)?;
                if !canonical_parent.starts_with(&canonical_tmp) {
                    anyhow::bail!(
                        "Path traversal detected in tarball entry: {}",
                        entry_path.display()
                    );
                }
            }

            entry.unpack(&dest)?;
        }

        // Write sentinel into tmp_dir before rename so it's included atomically.
        let sentinel_path = tmp_dir.join(SENTINEL_FILE);
        std::fs::write(&sentinel_path, get_embedded_hash())
            .with_context(|| format!("Failed to write sentinel: {}", sentinel_path.display()))?;

        // Atomic swap: rename old → .old, rename tmp → worker, delete .old.
        // This avoids a window where worker_dir is absent (visible to concurrent readers).
        let old_dir = data_dir.join("worker.old");
        if worker_dir.exists() {
            // Move old out of the way (instead of deleting first)
            if old_dir.exists() {
                let _ = std::fs::remove_dir_all(&old_dir);
            }
            std::fs::rename(&worker_dir, &old_dir)
                .with_context(|| format!("Failed to move old worker aside: {}", worker_dir.display()))?;
        }

        if let Err(e) = std::fs::rename(&tmp_dir, &worker_dir) {
            // Attempt to restore old worker directory before failing
            if old_dir.exists() {
                let _ = std::fs::rename(&old_dir, &worker_dir);
            }
            return Err(e).context("Failed to rename extracted worker into place");
        }

        // Defuse scopeguard — rename succeeded, tmp_dir no longer exists
        let _ = scopeguard::ScopeGuard::into_inner(_guard);

        // Clean up old worker dir (best-effort)
        if old_dir.exists() {
            let _ = std::fs::remove_dir_all(&old_dir);
        }

        // Release lock
        drop(lock);

        Ok(())
    }
}

/// Validates that a tarball entry path is safe.
///
/// Rejects:
/// - Absolute paths
/// - Path components containing ".."
/// - Paths with null bytes
fn validate_archive_entry_path(path: &Path) -> Result<()> {
    // Reject absolute paths
    if path.is_absolute() {
        anyhow::bail!("Tarball contains absolute path (rejected): {}", path.display());
    }

    // Reject paths with null bytes (check raw bytes to handle non-UTF-8 paths)
    if path.as_os_str().as_encoded_bytes().contains(&0u8) {
        anyhow::bail!("Tarball entry path contains null byte: {}", path.display());
    }

    // Reject ".." components
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            anyhow::bail!(
                "Tarball contains path traversal component '..': {}",
                path.display()
            );
        }
    }

    Ok(())
}

/// Acquires an exclusive init lock file.
///
/// Prevents concurrent init processes from corrupting the worker directory.
fn acquire_init_lock(data_dir: &Path) -> Result<std::fs::File> {
    use fs2::FileExt;

    let lock_path = data_dir.join(INIT_LOCK_FILE);
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .with_context(|| format!("Failed to open init lock: {}", lock_path.display()))?;

    lock_file.try_lock_exclusive().map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            anyhow::anyhow!(
                "Another dataward init appears to be in progress (lock held).\n\
                 The lock is automatically released when the other process exits.\n\
                 If no other init is running, please try again."
            )
        } else {
            anyhow::anyhow!("Failed to acquire init lock: {}", e)
        }
    })?;

    Ok(lock_file)
}

/// Runs `npm ci --production` in the worker directory.
fn run_npm_ci(worker_dir: &Path) -> Result<()> {
    let output = run_command_with_timeout(
        std::process::Command::new("npm")
            .args(["ci", "--production", "--ignore-scripts"])
            .current_dir(worker_dir)
            .env("NODE_ENV", "production")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
        NPM_CI_TIMEOUT,
        "npm ci",
    )
    .with_context(|| format!(
        "Failed to run npm ci in {}. Is npm installed?",
        worker_dir.display()
    ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "npm ci failed in {}.\n\
             Check your network connection and try again.\n\
             Output: {}",
            worker_dir.display(),
            stderr.chars().take(500).collect::<String>(),
        );
    }

    Ok(())
}

/// Runs `npx patchright@<pinned> install chromium` in the worker directory.
fn run_patchright_install(worker_dir: &Path) -> Result<()> {
    let patchright_pkg = format!("patchright@{}", PATCHRIGHT_VERSION);

    let output = run_command_with_timeout(
        std::process::Command::new("npx")
            .args([&patchright_pkg, "install", "chromium"])
            .current_dir(worker_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
        PATCHRIGHT_TIMEOUT,
        "patchright install chromium",
    )
    .with_context(|| {
        format!(
            "Failed to install Chromium browser.\n\
             Manual install: cd {} && npx {} install chromium",
            worker_dir.display(),
            patchright_pkg,
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Patchright browser install failed.\n\
             This usually means a network issue during the ~150MB Chromium download.\n\
             Manual install: cd {} && npx {} install chromium\n\
             Output: {}",
            worker_dir.display(),
            patchright_pkg,
            stderr.chars().take(500).collect::<String>(),
        );
    }

    Ok(())
}

/// Verifies that the Chromium binary exists after Patchright installation.
///
/// Does not trust npx exit code alone — checks the binary is actually present.
fn verify_chromium(worker_dir: &Path) -> Result<()> {
    // Patchright stores browsers in a platform-specific cache directory.
    // The simplest reliable check: ask node to resolve the executable path.
    let patchright_pkg = format!("patchright@{}", PATCHRIGHT_VERSION);
    let output = run_command_with_timeout(
        std::process::Command::new("node")
            .args([
                "-e",
                "const { chromium } = require('patchright'); console.log(chromium.executablePath())"
            ])
            .current_dir(worker_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
        LOCAL_CMD_TIMEOUT,
        "verify chromium",
    )
    .context("Failed to verify Chromium installation")?;

    if !output.status.success() {
        anyhow::bail!(
            "Patchright reported success but Chromium binary not found.\n\
             Manual install: cd {} && npx {} install chromium",
            worker_dir.display(),
            patchright_pkg,
        );
    }

    let chromium_path = String::from_utf8_lossy(&output.stdout);
    let chromium_path = chromium_path.trim();

    if chromium_path.is_empty() || !Path::new(chromium_path).exists() {
        anyhow::bail!(
            "Chromium binary not found after installation.\n\
             Manual install: cd {} && npx {} install chromium",
            worker_dir.display(),
            patchright_pkg,
        );
    }

    Ok(())
}

/// Runs a command with a timeout, killing it if it exceeds the duration.
///
/// Spawns the child process, reads stdout/stderr in background threads
/// (to prevent pipe buffer deadlock), and polls for completion with timeout.
fn run_command_with_timeout(
    cmd: &mut std::process::Command,
    timeout: Duration,
    description: &str,
) -> Result<std::process::Output> {
    let mut child = cmd.spawn()
        .with_context(|| format!("Failed to spawn: {}", description))?;

    // Take ownership of piped streams and read them in background threads
    // to prevent pipe buffer deadlock.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut out) = stdout_handle {
            if let Err(e) = std::io::Read::read_to_end(&mut out, &mut buf) {
                eprintln!("Warning: failed to read subprocess stdout: {}", e);
            }
        }
        buf
    });

    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut err) = stderr_handle {
            if let Err(e) = std::io::Read::read_to_end(&mut err, &mut buf) {
                eprintln!("Warning: failed to read subprocess stderr: {}", e);
            }
        }
        buf
    });

    // Poll for completion with timeout
    let start = Instant::now();
    let status = loop {
        match child.try_wait().context("Failed to check process status")? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!(
                        "{} timed out after {}s",
                        description,
                        timeout.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    Ok(std::process::Output { status, stdout, stderr })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_version_standard() {
        assert_eq!(parse_node_major_version("v20.11.0").unwrap(), 20);
        assert_eq!(parse_node_major_version("v18.0.0").unwrap(), 18);
        assert_eq!(parse_node_major_version("v22.1.3").unwrap(), 22);
    }

    #[test]
    fn test_parse_node_version_no_v_prefix() {
        assert_eq!(parse_node_major_version("20.11.0").unwrap(), 20);
    }

    #[test]
    fn test_parse_node_version_invalid() {
        assert!(parse_node_major_version("not-a-version").is_err());
        assert!(parse_node_major_version("").is_err());
    }

    #[test]
    fn test_validate_path_normal() {
        assert!(validate_archive_entry_path(Path::new("dist/worker.js")).is_ok());
        assert!(validate_archive_entry_path(Path::new("package.json")).is_ok());
        assert!(validate_archive_entry_path(Path::new("dist/sub/file.js")).is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        assert!(validate_archive_entry_path(Path::new("../etc/passwd")).is_err());
        assert!(validate_archive_entry_path(Path::new("dist/../../etc")).is_err());
        assert!(validate_archive_entry_path(Path::new("a/b/../../../c")).is_err());
    }

    #[test]
    fn test_validate_path_absolute() {
        assert!(validate_archive_entry_path(Path::new("/etc/passwd")).is_err());
        assert!(validate_archive_entry_path(Path::new("/tmp/evil")).is_err());
    }

    #[test]
    fn test_validate_path_null_byte() {
        assert!(validate_archive_entry_path(Path::new("dist/file\0.js")).is_err());
    }

    #[test]
    fn test_needs_extraction_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let worker_dir = dir.path().join("worker");
        assert!(needs_extraction(&worker_dir).unwrap());
    }

    #[test]
    fn test_needs_extraction_no_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let worker_dir = dir.path().join("worker");
        std::fs::create_dir_all(&worker_dir).unwrap();
        assert!(needs_extraction(&worker_dir).unwrap());
    }

    #[test]
    fn test_needs_extraction_matching_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let worker_dir = dir.path().join("worker");
        std::fs::create_dir_all(&worker_dir).unwrap();
        std::fs::write(
            worker_dir.join(SENTINEL_FILE),
            get_embedded_hash(),
        ).unwrap();
        assert!(!needs_extraction(&worker_dir).unwrap());
    }

    #[test]
    fn test_needs_extraction_stale_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let worker_dir = dir.path().join("worker");
        std::fs::create_dir_all(&worker_dir).unwrap();
        std::fs::write(
            worker_dir.join(SENTINEL_FILE),
            "old-hash-that-no-longer-matches",
        ).unwrap();
        assert!(needs_extraction(&worker_dir).unwrap());
    }

    #[test]
    fn test_init_lock_prevents_concurrent() {
        let dir = tempfile::tempdir().unwrap();
        let _lock1 = acquire_init_lock(dir.path()).unwrap();
        let result = acquire_init_lock(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("in progress"), "Error should mention concurrent: {}", err);
    }

    #[test]
    fn test_init_lock_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = acquire_init_lock(dir.path()).unwrap();
        }
        // Should be able to acquire again after drop
        let _lock2 = acquire_init_lock(dir.path()).unwrap();
    }

    #[test]
    fn test_run_command_with_timeout_success() {
        let output = run_command_with_timeout(
            std::process::Command::new("echo")
                .arg("hello")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
            Duration::from_secs(5),
            "echo hello",
        )
        .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.trim().contains("hello"), "stdout should contain 'hello': {}", stdout);
    }

    #[test]
    fn test_run_command_with_timeout_kills_on_timeout() {
        let result = run_command_with_timeout(
            std::process::Command::new("sleep")
                .arg("30")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
            Duration::from_secs(2),
            "sleep 30",
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out"), "Error should mention timeout: {}", err);
    }

    #[test]
    fn test_run_command_with_timeout_captures_stderr() {
        let output = run_command_with_timeout(
            std::process::Command::new("sh")
                .args(["-c", "echo errdata >&2; exit 1"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
            Duration::from_secs(5),
            "stderr test",
        )
        .unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("errdata"), "stderr should contain 'errdata': {}", stderr);
    }

    #[test]
    fn test_run_npm_ci_nonexistent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("no-such-dir");
        let result = run_npm_ci(&nonexistent);
        assert!(result.is_err(), "npm ci in nonexistent dir should fail");
    }

    #[test]
    fn test_run_patchright_install_nonexistent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("no-such-dir");
        let result = run_patchright_install(&nonexistent);
        assert!(result.is_err(), "patchright install in nonexistent dir should fail");
    }
}
