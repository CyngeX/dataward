use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::Path;

/// Verifies that a byte slice matches an expected SHA-256 hex digest.
///
/// Uses constant-time comparison via the `subtle` crate to prevent
/// timing side-channel leakage.
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<()> {
    let digest = Sha256::digest(data);
    let actual_hex = hex::encode(digest);

    // Constant-time comparison on decoded bytes.
    // No early-exit on length mismatch — that would be a timing oracle leaking
    // whether the hash was the right length. ct_eq on differing-length slices
    // returns 0 (unequal), and hex::decode errors surface naturally for invalid input.
    use subtle::ConstantTimeEq;
    let actual_bytes = hex::decode(&actual_hex)
        .context("BUG: hex::encode produced invalid hex")?;
    let expected_bytes = match hex::decode(expected_hex) {
        Ok(b) => b,
        Err(_) => {
            // Invalid hex in expected — treat as mismatch without timing leak.
            anyhow::bail!(
                "SHA-256 checksum mismatch: expected {}, got {}",
                expected_hex,
                actual_hex,
            );
        }
    };
    let equal: bool = actual_bytes.ct_eq(&expected_bytes).into();

    if !equal {
        anyhow::bail!(
            "SHA-256 checksum mismatch: expected {}, got {}",
            expected_hex,
            actual_hex,
        );
    }
    Ok(())
}

/// Computes SHA-256 of a byte slice, returning the hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Computes SHA-256 of a file using streaming (BufReader chunks).
///
/// Never loads the entire file into memory — processes in 64KB chunks.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file for checksum: {}", path.display()))?;
    let mut reader = io::BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = reader.read(&mut buf)
            .with_context(|| format!("Failed to read file for checksum: {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Atomically writes data to a file: writes to a `.tmp` sibling first,
/// then renames into place.
///
/// The temp file is created in the same directory as the target to guarantee
/// the rename is atomic (same mount point). If the write or rename fails,
/// the temp file is cleaned up.
pub fn atomic_write(target: &Path, data: &[u8]) -> Result<()> {
    let parent = target.parent()
        .ok_or_else(|| anyhow::anyhow!("Target path has no parent: {}", target.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;

    let tmp_name = format!(
        "{}.{}.{:?}.tmp",
        target.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
        std::process::id(),
        std::thread::current().id(),
    );
    let tmp_path = parent.join(tmp_name);

    // Scopeguard: clean up temp file on any failure path.
    let _guard = scopeguard::guard((), |_| {
        let _ = std::fs::remove_file(&tmp_path);
    });

    let mut file = std::fs::File::create(&tmp_path)
        .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
    file.write_all(data)
        .with_context(|| format!("Failed to write temp file: {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to sync temp file: {}", tmp_path.display()))?;
    drop(file);

    std::fs::rename(&tmp_path, target)
        .with_context(|| format!("Failed to rename {} -> {}", tmp_path.display(), target.display()))?;

    // Rename succeeded — defuse the guard so it doesn't delete the target.
    let _ = scopeguard::ScopeGuard::into_inner(_guard);

    Ok(())
}

/// Atomically writes data to a file with SHA-256 verification.
///
/// Writes to `.tmp`, computes streaming checksum, verifies against expected,
/// then renames into place. On checksum mismatch, the temp file is deleted.
pub fn atomic_write_verified(target: &Path, data: &[u8], expected_sha256: &str) -> Result<()> {
    verify_sha256(data, expected_sha256)?;
    atomic_write(target, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sha256_hex_known_value() {
        // SHA-256 of empty string
        let hash = sha256_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_hex_hello() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_verify_sha256_correct() {
        let data = b"test data for checksum";
        let hash = sha256_hex(data);
        assert!(verify_sha256(data, &hash).is_ok());
    }

    #[test]
    fn test_verify_sha256_wrong_hash() {
        let data = b"test data";
        let result = verify_sha256(data, "0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "Error should mention mismatch: {}", err);
    }

    #[test]
    fn test_verify_sha256_empty_data() {
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(verify_sha256(b"", empty_hash).is_ok());
    }

    #[test]
    fn test_verify_sha256_truncated_hash() {
        // Truncated hash string should fail
        let result = verify_sha256(b"data", "abcd");
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_file_matches_in_memory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        let data = b"file content for hashing";
        std::fs::write(&path, data).unwrap();

        let file_hash = sha256_file(&path).unwrap();
        let mem_hash = sha256_hex(data);
        assert_eq!(file_hash, mem_hash);
    }

    #[test]
    fn test_sha256_file_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();

        let hash = sha256_file(&path).unwrap();
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_file_not_found() {
        let result = sha256_file(Path::new("/nonexistent/file.bin"));
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("output.bin");
        atomic_write(&target, b"hello world").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello world");
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("output.bin");
        std::fs::write(&target, b"old content").unwrap();
        atomic_write(&target, b"new content").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new content");
    }

    #[test]
    fn test_atomic_write_no_tmp_residue() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("output.bin");
        atomic_write(&target, b"data").unwrap();

        // No .tmp file should remain in the directory
        let tmp_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "tmp").unwrap_or(false))
            .collect();
        assert!(tmp_files.is_empty(), "No .tmp files should remain after successful write");
    }

    #[test]
    fn test_atomic_write_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("sub").join("dir").join("output.bin");
        atomic_write(&target, b"nested").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"nested");
    }

    #[test]
    fn test_atomic_write_verified_correct() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("verified.bin");
        let data = b"verified content";
        let hash = sha256_hex(data);
        atomic_write_verified(&target, data, &hash).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), data);
    }

    #[test]
    fn test_atomic_write_verified_wrong_hash_no_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("should_not_exist.bin");
        let result = atomic_write_verified(&target, b"data", "bad_hash");
        assert!(result.is_err());
        assert!(!target.exists(), "Target should not exist after checksum failure");
    }
}
