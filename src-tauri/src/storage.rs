use crate::{
    crypto::{decrypt_with_key, encrypt_with_key},
    error::DatabaseError,
    models::VaultEntry,
};
use argon2::{password_hash::SaltString, Argon2};
use directories::ProjectDirs;
use rusqlite::{params, Connection};
use std::path::PathBuf;

pub fn database_path() -> Result<PathBuf, DatabaseError> {
    if let Some(project_dirs) = ProjectDirs::from("com", "tauri", "rvault") {
        let project_dir = project_dirs.data_dir();
        let database_dir = project_dir.join("databases");
        std::fs::create_dir_all(&database_dir)?;
        Ok(database_dir.join("default_vault.sqlite"))
    } else {
        Err(DatabaseError::Path)
    }
}

pub struct Database {
    pub connection: Connection,
}
impl Database {
    pub fn new() -> Result<Self, DatabaseError> {
        let final_path = database_path()?;
        let connection = Connection::open(&final_path)?;
        Ok(Self { connection })
    }
}

pub struct Table {
    table_name: String,
}

// In Rust, methods associated with a struct must be in an `impl` block.
impl Table {
    pub fn new(db: &Database, table_name: Option<String>) -> Result<Self, DatabaseError> {
        let connection = &db.connection;
        let full_table_name = table_name.unwrap_or_else(|| "main".to_string());

        let query = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                user_id TEXT NOT NULL,
                password TEXT NOT NULL,
                nonce TEXT,
                salt TEXT,
                UNIQUE(platform, user_id)
                )",
            full_table_name
        );
        connection.execute(&query, [])?;
        Ok(Self {
            table_name: full_table_name,
        })
    }

    /// Adds an entry using the main Encryption Key to derive a unique key for this entry.
    pub fn add_entry_with_key(
        &self,
        db: &Database,
        encryption_key: &[u8],
        platform: String,
        user_id: String,
        password: String,
    ) -> Result<(), DatabaseError> {
        // 1. Generate a new, unique salt for this specific entry.
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

        // 2. Derive a unique key for this entry from the main EK and the new salt.
        let mut entry_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(encryption_key, salt.as_ref().as_bytes(), &mut entry_key)
            .unwrap();

        // 3. Encrypt the data with the derived per-entry key.
        let (ciphertext, nonce) = encrypt_with_key(&entry_key, password.as_bytes()).unwrap();

        let query = format!(
            "INSERT INTO {} (platform, user_id, password, nonce, salt)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(platform, user_id) DO UPDATE SET
             password = ?3,
             nonce = ?4,
             salt = ?5;",
            &self.table_name
        );
        db.connection.execute(
            &query,
            params![
                platform,
                user_id.to_string(),
                ciphertext,
                nonce,
                salt.to_string()
            ],
        )?;
        Ok(())
    }
    
    pub fn remove_entry(&self,db: &Database, platform: String, user_id: String) -> Result<(), DatabaseError>{
        let query = format!(
            "DELETE FROM {} WHERE platform = (?1) AND user_id = (?2)",
            &self.table_name
        );
        db.connection.execute(&query, [platform.to_string(),user_id.to_string()])?;
        Ok(())
    }

    /// Retrieves an entry by re-deriving its unique key from the main Encryption Key and the entry's salt.
    pub fn get_password_with_key(
        &self,
        db: &Database,
        encryption_key: &[u8],
        platform: String,
        user_id: String,
    ) -> Result<String, DatabaseError> {
        let query = format!(
            "SELECT password, nonce, salt FROM {} WHERE platform = (?1) AND user_id = (?2)",
            &self.table_name
        );

        let (ciphertext, nonce, salt_str): (String, String, String) =
            db.connection
                .query_row(&query, [platform.to_string(), user_id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;

        // 1. Re-derive the exact same per-entry key using the fetched salt.
        let salt = salt_str.as_bytes();
        let mut entry_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(encryption_key, salt, &mut entry_key)
            .unwrap();

        // 2. Decrypt with the derived key.
        decrypt_with_key(&entry_key, &ciphertext, &nonce)
            .map_err(|e| DatabaseError::Custom(e))
    }
    
    pub fn list(&self, db: &Database) -> Result<Vec<VaultEntry>, DatabaseError> {
        let query = format!(
            "SELECT platform, user_id, password, salt, nonce FROM {}",
            &self.table_name
        );
        let mut statement = db.connection.prepare(&query)?;
        let rows = statement.query_map([], |row| {
            Ok(VaultEntry {
                platform: row.get(0)?,
                user_id: row.get(1)?,
                password: row.get(2)?,
                salt: row.get(3)?,
                nonce: row.get(4)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

