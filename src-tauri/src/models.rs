use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// This struct holds the application's shared state.
pub struct AppState {
    // The encryption key is stored here when the vault is unlocked.
    // It's an Option because it's None when the vault is locked.
    // The Mutex ensures safe access from multiple threads.
    pub encryption_key: Mutex<Option<[u8; 32]>>,
}

// This struct represents a single entry in the vault.
#[derive(Serialize, Deserialize, Debug)]
pub struct VaultEntry {
    pub platform: String,
    pub user_id: String,
    // These fields are needed for database operations but are not always sent to the frontend.
    pub password: String,
    pub salt: Option<String>,
    pub nonce: Option<String>,
}

