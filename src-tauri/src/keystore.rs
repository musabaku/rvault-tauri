use crate::crypto::{self, decrypt_with_key, encrypt_with_key};
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use directories::ProjectDirs;
use rand::RngCore;
use std::{
    fs,
    path::{Path, PathBuf},
};

const KEYSTORE_NAME: &str = "keystore.rvault"; // file name
const EK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub fn keystore_path() -> Result<PathBuf, String> {
    if let Some(pd) = ProjectDirs::from("com", "tauri", "rvault") {
        let dir = pd.config_dir();
        fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
        Ok(dir.join(KEYSTORE_NAME))
    } else {
        Err("Could not find project directories".to_string())
    }
}

/// Creates a new, encrypted vault file containing a newly generated Master Encryption Key (MEK).
pub fn create_key_vault(master_password: &str, path: &Path) -> Result<[u8; EK_LEN], String> {
    // 1. Generate a new, random 32-byte Master Encryption Key (MEK). This is the key we will protect.
    let mek = crypto::generate_raw_key();
    // 2) Derive KEK from master + raw 16-byte salt
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let kek = crypto::derive_kek(master_password.as_bytes(), &salt)?;

    // 3. Encrypt the MEK using the KEK.
    let (ciphertext_b64, nonce_b64) = encrypt_with_key(&kek, &mek)?;

    // 4) Write raw: [salt][nonce][ct]
    let nonce = Base64.decode(&nonce_b64).map_err(|e| e.to_string())?;
    if nonce.len() != NONCE_LEN {
        return Err("Unexpected nonce length".into());
    }
    let ct = Base64.decode(&ciphertext_b64).map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    // ensure parent exists (avoids ENOENT on first run)
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }

    // actually write the keystore
    std::fs::write(path, &out).map_err(|e| format!("write keystore: {e}"))?;

    Ok(mek)
}

/// Loads and decrypts the Master Encryption Key (MEK) from the vault file.
pub fn load_key_from_vault(master_password: &str, path: &Path) -> Result<[u8; EK_LEN], String> {
    let file_bytes = fs::read(path).map_err(|e| format!("Failed to read vault file: {}", e))?;

    // 1. Parse the file: [16-byte salt][12-byte nonce][encrypted MEK]
    if file_bytes.len() < SALT_LEN + NONCE_LEN {
        return Err("Invalid or corrupt vault file.".to_string());
    }
    let salt = &file_bytes[0..SALT_LEN];
    let nonce_b64 = Base64.encode(&file_bytes[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let encrypted_mek_b64 = Base64.encode(&file_bytes[SALT_LEN + NONCE_LEN..]);

    // 2. Re-derive the Key Encryption Key (KEK) from the password and salt.
    let kek = crypto::derive_kek(master_password.as_bytes(), salt)?;

    // 3. Decrypt the MEK using the KEK.
    // FIXED: Now correctly handles the Vec<u8> result from decrypt_with_key
    let mek_vec = decrypt_with_key(&kek, &encrypted_mek_b64, &nonce_b64)?;
    
    // The decrypted key should be raw bytes, attempt to convert Vec<u8> to [u8; 32]
    let mek_bytes = mek_vec.try_into().map_err(|_| "Decrypted key has incorrect length.".to_string())?;

    Ok(mek_bytes)
}
