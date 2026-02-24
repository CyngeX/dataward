use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result};
use argon2::Argon2;
use std::path::Path;
use zeroize::Zeroize;

/// Argon2id parameters per plan: memory=64MB, iterations=3, parallelism=4
const ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Length of derived key for SQLCipher and AES-256-GCM (32 bytes = 256 bits)
const KEY_LEN: usize = 32;

/// Nonce length for AES-256-GCM (12 bytes = 96 bits)
const NONCE_LEN: usize = 12;

/// Salt length for Argon2id (16 bytes recommended)
const SALT_LEN: usize = 16;

/// Argon2id parameter set.
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Production Argon2id parameters (64MB, 3 iterations, 4 threads).
pub const PRODUCTION_PARAMS: Argon2Params = Argon2Params {
    memory_kib: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
};

/// Fast Argon2id parameters for tests (256KB, 1 iteration, 1 thread).
#[cfg(test)]
pub const TEST_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 256,
    iterations: 1,
    parallelism: 1,
};

/// Derives a 256-bit key from a passphrase using Argon2id.
///
/// Returns (key, salt). The salt must be stored alongside the encrypted data
/// for key re-derivation.
pub fn derive_key(passphrase: &[u8], salt: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
    derive_key_with_params(passphrase, salt, &PRODUCTION_PARAMS)
}

/// Derives a key with explicit Argon2id parameters (used by tests).
pub fn derive_key_with_params(
    passphrase: &[u8],
    salt: Option<&[u8]>,
    params: &Argon2Params,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut s = vec![0u8; SALT_LEN];
            getrandom::fill(&mut s).map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;
            s
        }
    };

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|e| anyhow::anyhow!("Invalid Argon2id parameters: {}", e))?,
    );

    let mut key = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, &salt_bytes, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

    Ok((key, salt_bytes))
}

/// Converts a derived key to the hex string format SQLCipher expects for PRAGMA key.
pub fn key_to_sqlcipher_hex(key: &[u8]) -> String {
    format!("x'{}'", hex::encode(key))
}

/// Encrypts data using AES-256-GCM.
///
/// Returns (nonce || ciphertext). The nonce is prepended to simplify storage.
pub fn encrypt_aes256gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Invalid AES-256-GCM key: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data encrypted with `encrypt_aes256gcm`.
///
/// Expects input format: (nonce || ciphertext).
pub fn decrypt_aes256gcm(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_LEN {
        anyhow::bail!("Encrypted data too short (missing nonce)");
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Invalid AES-256-GCM key: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM decryption failed (wrong key or corrupted data): {}", e))
}

/// Encrypts a file on disk using AES-256-GCM.
///
/// Reads the file, encrypts it, writes to `path.enc`, then deletes the original.
pub fn encrypt_file(key: &[u8], path: &Path) -> Result<std::path::PathBuf> {
    let plaintext = std::fs::read(path)
        .with_context(|| format!("Failed to read file for encryption: {}", path.display()))?;

    let encrypted = encrypt_aes256gcm(key, &plaintext)?;

    let enc_path = path.with_extension(
        format!(
            "{}.enc",
            path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("bin")
        ),
    );

    std::fs::write(&enc_path, &encrypted)
        .with_context(|| format!("Failed to write encrypted file: {}", enc_path.display()))?;

    // Set restrictive permissions on encrypted file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Remove the unencrypted original
    std::fs::remove_file(path)
        .with_context(|| format!("Failed to remove unencrypted file: {}", path.display()))?;

    Ok(enc_path)
}

/// Decrypts a `.enc` file in memory (does NOT write to disk).
///
/// Returns the decrypted bytes for in-memory use only.
pub fn decrypt_file_to_memory(key: &[u8], enc_path: &Path) -> Result<Vec<u8>> {
    let encrypted = std::fs::read(enc_path)
        .with_context(|| format!("Failed to read encrypted file: {}", enc_path.display()))?;

    decrypt_aes256gcm(key, &encrypted)
}

/// Generates a cryptographically random token for dashboard auth.
pub fn generate_auth_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG failed");
    hex::encode(bytes)
}

/// Strips the passphrase environment variable if set.
///
/// Call this immediately after reading the passphrase to prevent propagation
/// to child processes.
pub fn strip_passphrase_env() {
    // SAFETY: We only remove a single known env var, and this is called
    // before any child process spawning.
    unsafe {
        std::env::remove_var("DATAWARD_PASSPHRASE");
    }
}

/// Reads passphrase from env var or prompts the user.
///
/// If read from env, the var is immediately stripped.
pub fn get_passphrase(prompt: &str) -> Result<String> {
    if let Ok(mut passphrase) = std::env::var("DATAWARD_PASSPHRASE") {
        strip_passphrase_env();
        if passphrase.is_empty() {
            passphrase.zeroize();
            anyhow::bail!("DATAWARD_PASSPHRASE is set but empty");
        }
        return Ok(passphrase);
    }

    let passphrase = rpassword::prompt_password(prompt)
        .context("Failed to read passphrase")?;

    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty");
    }

    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: derive key with fast test parameters.
    fn test_derive_key(passphrase: &[u8], salt: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
        derive_key_with_params(passphrase, salt, &TEST_PARAMS).unwrap()
    }

    #[test]
    fn test_derive_key_deterministic_with_same_salt() {
        let passphrase = b"test-passphrase-123";
        let (key1, salt) = test_derive_key(passphrase, None);
        let (key2, _) = test_derive_key(passphrase, Some(&salt));
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), KEY_LEN);
    }

    #[test]
    fn test_derive_key_different_salt_different_key() {
        let passphrase = b"test-passphrase-123";
        let (key1, _) = test_derive_key(passphrase, None);
        let (key2, _) = test_derive_key(passphrase, None);
        // Different random salts should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_aes256gcm_roundtrip() {
        let (key, _) = test_derive_key(b"test-pass", None);
        let plaintext = b"sensitive PII data: John Doe, john@example.com";
        let encrypted = encrypt_aes256gcm(&key, plaintext).unwrap();
        let decrypted = decrypt_aes256gcm(&key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes256gcm_wrong_key_fails() {
        let (key1, _) = test_derive_key(b"correct-pass", None);
        let (key2, _) = test_derive_key(b"wrong-pass", None);
        let encrypted = encrypt_aes256gcm(&key1, b"secret").unwrap();
        let result = decrypt_aes256gcm(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes256gcm_empty_data() {
        let (key, _) = test_derive_key(b"test-pass", None);
        let encrypted = encrypt_aes256gcm(&key, b"").unwrap();
        let decrypted = decrypt_aes256gcm(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes256gcm_truncated_data_fails() {
        let result = decrypt_aes256gcm(&[0u8; KEY_LEN], &[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_auth_token() {
        let token1 = generate_auth_token();
        let token2 = generate_auth_token();
        assert_eq!(token1.len(), 64); // 32 bytes hex-encoded
        assert_ne!(token1, token2); // Random tokens should differ
    }

    #[test]
    fn test_key_to_sqlcipher_hex() {
        let key = vec![0xAB, 0xCD, 0xEF];
        let hex = key_to_sqlcipher_hex(&key);
        assert_eq!(hex, "x'abcdef'");
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.png");
        let content = b"fake png content for testing";
        std::fs::write(&file_path, content).unwrap();

        let (key, _) = test_derive_key(b"test-pass", None);
        let enc_path = encrypt_file(&key, &file_path).unwrap();

        // Original should be deleted
        assert!(!file_path.exists());
        // Encrypted file should exist
        assert!(enc_path.exists());
        assert!(enc_path.to_str().unwrap().ends_with(".png.enc"));

        // Decrypt should return original content
        let decrypted = decrypt_file_to_memory(&key, &enc_path).unwrap();
        assert_eq!(content.as_slice(), decrypted.as_slice());
    }
}
