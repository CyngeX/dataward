use anyhow::{Context, Result};
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;

use crate::crypto;
use crate::db;

/// Runs the `dataward rekey` command.
///
/// Prompts for the old passphrase, then the new passphrase (with confirmation),
/// and re-encrypts the database using SQLCipher's PRAGMA rekey.
pub fn run_rekey(data_dir: &Path) -> Result<()> {
    eprintln!("=== Dataward Rekey ===");
    eprintln!();
    eprintln!("This will re-encrypt your database with a new passphrase.");
    eprintln!("WARNING: If the process is interrupted, your database may be corrupted.");
    eprintln!("         Consider backing up your data directory first.");
    eprintln!();

    // Prompt for old passphrase
    let old_passphrase = crypto::get_passphrase("Current passphrase: ")?;

    // Verify old passphrase works before asking for new one
    let salt = std::fs::read(data_dir.join(".salt"))
        .context("Failed to read salt file. Is Dataward initialized?")?;
    let db_path = data_dir.join("dataward.db");

    // Test that old passphrase is correct
    let test_conn = db::open_db(&db_path, &old_passphrase, &salt)?;
    drop(test_conn);

    eprintln!("Current passphrase verified.");
    eprintln!();

    // Prompt for new passphrase
    let mut new_passphrase = crypto::get_passphrase("New passphrase: ")?;
    let mut confirm = crypto::get_passphrase("Confirm new passphrase: ")?;

    if new_passphrase != confirm {
        new_passphrase.zeroize();
        confirm.zeroize();
        anyhow::bail!("Passphrases do not match");
    }
    confirm.zeroize();

    if new_passphrase == old_passphrase {
        new_passphrase.zeroize();
        anyhow::bail!("New passphrase is the same as the current one");
    }

    // Confirm before proceeding
    eprintln!();
    eprint!("Re-encrypt database with new passphrase? [y/N]: ");
    io::stderr().flush()?;
    let mut confirm_input = String::new();
    io::stdin().read_line(&mut confirm_input)?;
    if confirm_input.trim().to_lowercase() != "y" {
        new_passphrase.zeroize();
        eprintln!("Cancelled.");
        return Ok(());
    }

    // Perform rekey
    eprintln!("Re-encrypting database...");
    db::rekey_db(&db_path, &old_passphrase, &new_passphrase, &salt)?;

    // Also re-encrypt any .enc files (proof screenshots) with the new key
    rekey_encrypted_files(data_dir, &old_passphrase, &new_passphrase, &salt)?;

    new_passphrase.zeroize();

    eprintln!("Database re-encrypted successfully.");
    eprintln!();
    eprintln!("IMPORTANT: Remember your new passphrase. There is NO recovery mechanism.");

    Ok(())
}

/// Re-encrypts proof files that were encrypted with the old key.
fn rekey_encrypted_files(
    data_dir: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    salt: &[u8],
) -> Result<()> {
    let proofs_dir = data_dir.join("proofs");
    if !proofs_dir.exists() {
        return Ok(());
    }

    // Derive old and new AES keys
    let (old_key, _) = crypto::derive_key(old_passphrase.as_bytes(), Some(salt))?;
    let (new_key, _) = crypto::derive_key(new_passphrase.as_bytes(), Some(salt))?;

    let mut count = 0;
    for entry in std::fs::read_dir(&proofs_dir)
        .with_context(|| format!("Failed to read proofs directory: {}", proofs_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) == Some("enc") {
            match crypto::decrypt_aes256gcm(&old_key, &std::fs::read(&path)?) {
                Ok(plaintext) => {
                    let encrypted = crypto::encrypt_aes256gcm(&new_key, &plaintext)?;
                    std::fs::write(&path, &encrypted).with_context(|| {
                        format!("Failed to write re-encrypted file: {}", path.display())
                    })?;
                    count += 1;
                }
                Err(e) => {
                    // Log but don't fail — some files might not be encrypted with this key
                    eprintln!("  Warning: could not re-encrypt {}: {}", path.display(), e);
                }
            }
        }
    }

    if count > 0 {
        eprintln!("Re-encrypted {} proof file(s).", count);
    }

    Ok(())
}
