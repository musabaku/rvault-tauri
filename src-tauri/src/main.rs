// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod error;
mod keystore;
mod models;
mod storage;

use crate::models::{AppState, VaultEntry};
use std::sync::Mutex;
use tauri::State;

// --- Tauri Commands ---

#[tauri::command]
fn check_setup() -> Result<bool, String> {
    let keystore_path = keystore::keystore_path()?;
    Ok(!keystore_path.exists())
}

#[tauri::command]
fn setup_vault(master_password: &str, app_state: State<'_, AppState>) -> Result<(), String> {
    let path = keystore::keystore_path()?;
    if path.exists() {
        return Err("Vault has already been set up.".to_string());
    }
    let encryption_key = keystore::create_key_vault(master_password, &path)?;

    // Store the key in memory after setup
    let mut key_guard = app_state.encryption_key.lock().unwrap();
    *key_guard = Some(encryption_key);

    // Also, create the initial database
    let db = storage::Database::new().map_err(|e| e.to_string())?;
    let _table = storage::Table::new(&db, None).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
fn unlock_vault(master_password: &str, app_state: State<'_, AppState>) -> Result<(), String> {
    let path = keystore::keystore_path()?;
    let key = keystore::load_key_from_vault(master_password, &path)?;

    // Store the unlocked key in the shared state
    let mut key_guard = app_state.encryption_key.lock().unwrap();
    *key_guard = Some(key);

    Ok(())
}

#[tauri::command]
fn lock_vault(app_state: State<'_, AppState>) -> Result<(), String> {
    let mut key_guard = app_state.encryption_key.lock().unwrap();
    *key_guard = None; // Clear the key from memory
    Ok(())
}

// ADDED: New command to completely reset the vault
#[tauri::command]
fn reset_vault(app_state: State<'_, AppState>) -> Result<(), String> {
    // 1. Clear the in-memory key first
    let mut key_guard = app_state.encryption_key.lock().unwrap();
    *key_guard = None;

    // 2. Delete the keystore file
    let keystore_path = keystore::keystore_path()?;
    if keystore_path.exists() {
        std::fs::remove_file(keystore_path)
            .map_err(|e| format!("Failed to delete keystore: {}", e))?;
    }

    // 3. Delete the database file
    let db_path = storage::database_path().map_err(|e| e.to_string())?;
    if db_path.exists() {
        std::fs::remove_file(db_path)
            .map_err(|e| format!("Failed to delete database: {}", e))?;
    }

    Ok(())
}

#[tauri::command]
fn get_all_entries(app_state: State<'_, AppState>) -> Result<Vec<VaultEntry>, String> {
    // Ensure the vault is unlocked by checking for the key
    let key_guard = app_state.encryption_key.lock().unwrap();
    if key_guard.is_none() {
        return Err("Vault is locked.".to_string());
    }

    let db = storage::Database::new().map_err(|e| e.to_string())?;
    let table = storage::Table::new(&db, None).map_err(|e| e.to_string())?;
    let entries = table.list(&db).map_err(|e| e.to_string())?;

    // We only return platform and user_id for the list view
    let safe_entries = entries
        .into_iter()
        .map(|e| VaultEntry {
            platform: e.platform,
            user_id: e.user_id,
            // Do not expose password, salt, or nonce to the UI list
            password: "".to_string(),
            salt: None,
            nonce: None,
        })
        .collect();

    Ok(safe_entries)
}

#[tauri::command]
fn add_entry(
    platform: String,
    user_id: String,
    password: String,
    app_state: State<'_, AppState>,
) -> Result<(), String> {
    let key_guard = app_state.encryption_key.lock().unwrap();
    let encryption_key = key_guard.as_ref().ok_or("Vault is locked.")?;

    let db = storage::Database::new().map_err(|e| e.to_string())?;
    let table = storage::Table::new(&db, None).map_err(|e| e.to_string())?;

    table
        .add_entry_with_key(&db, encryption_key, platform, user_id, password)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn remove_entry(
    platform: String,
    user_id: String,
    app_state: State<'_, AppState>,
) -> Result<(), String> {
    // Check lock state
    let key_guard = app_state.encryption_key.lock().unwrap();
    if key_guard.is_none() {
        return Err("Vault is locked.".to_string());
    }

    let db = storage::Database::new().map_err(|e| e.to_string())?;
    let table = storage::Table::new(&db, None).map_err(|e| e.to_string())?;
    table
        .remove_entry(&db, platform, user_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn get_password(
    platform: String,
    user_id: String,
    app_state: State<'_, AppState>,
) -> Result<String, String> {
    let key_guard = app_state.encryption_key.lock().unwrap();
    let encryption_key = key_guard.as_ref().ok_or("Vault is locked.")?;

    let db = storage::Database::new().map_err(|e| e.to_string())?;
    let table = storage::Table::new(&db, None).map_err(|e| e.to_string())?;
    let password = table
        .get_password_with_key(&db, encryption_key, platform, user_id)
        .map_err(|e| e.to_string())?;
    
    // The password is now returned to the frontend
    Ok(password)
}

#[tauri::command]
fn generate_password(length: u8, special_characters: bool) -> Result<String, String> {
    Ok(crypto::generate_password(length, special_characters))
}

fn main() {
    // Initialize logging
    env_logger::init();

    tauri::Builder::default()
        .manage(AppState {
            encryption_key: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            check_setup,
            setup_vault,
            unlock_vault,
            lock_vault,
            reset_vault, // ADDED: Register the new command
            get_all_entries,
            add_entry,
            remove_entry,
            get_password,
            generate_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
