use argon2::{
    password_hash::{self, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use zeroize::Zeroize;

const EK_LEN: usize = 32;

pub fn generate_raw_key() -> [u8; 32] {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    key.into()
}

pub fn generate_password(length: u8, _special_characters: bool) -> String {
    if length == 0 {
        return String::new();
    }
    Alphanumeric.sample_string(&mut thread_rng(), length as usize)
}

pub fn encrypt_with_key(key: &[u8], data: &[u8]) -> Result<(String, String), String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| e.to_string())?;

    Ok((Base64.encode(&ciphertext), Base64.encode(&nonce)))
}

// FIXED: This function now correctly returns raw bytes (Vec<u8>) instead of trying
// to interpret them as a UTF-8 string, which could fail.
pub fn decrypt_with_key(
    key: &[u8],
    ciphertext_b64: &str,
    nonce_b64: &str,
) -> Result<Vec<u8>, String> {
    let ciphertext = Base64.decode(ciphertext_b64).map_err(|e| e.to_string())?;
    let nonce_bytes = Base64.decode(nonce_b64).map_err(|e| e.to_string())?;
    
    // Ensure the nonce has the correct length before creating a Nonce instance.
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| e.to_string())?;
    Ok(plaintext)
}

pub fn derive_kek(
    master_password: &[u8],
    salt: &[u8],
) -> Result<Key, String> {
    // Default params for KDF
    let params = Params::new(15000, 2, 1, Some(EK_LEN))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; EK_LEN];
    a2.hash_password_into(master_password, salt, &mut out)
        .map_err(|e| format!("Argon2 derive: {e}"))?;
    
    let key = Key::from(out);
    out.zeroize();
    Ok(key)
}
