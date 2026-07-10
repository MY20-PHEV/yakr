use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use rusqlite::Connection;

pub const MAX_RELAY_BLOB_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct StoredBlob {
    pub mailbox_tag: [u8; 32],
    pub expires_at: u64,
    pub ciphertext: Vec<u8>,
    pub stored_at: u64,
}

pub fn b64encode(data: &[u8]) -> String {
    URL_SAFE.encode(data).trim_end_matches('=').to_string()
}

pub fn b64decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let rem = value.len() % 4;
    let padded = if rem == 0 {
        value.to_string()
    } else {
        format!("{value}{}", "=".repeat(4 - rem))
    };
    URL_SAFE.decode(padded)
}

pub struct BlobStore {
    pub root: PathBuf,
    pub max_blob_size: usize,
    pub max_blobs_per_tag: usize,
    db_path: PathBuf,
    lock: Mutex<()>,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>, max_blob_size: usize, max_blobs_per_tag: usize) -> Self {
        let root = root.into();
        std::fs::create_dir_all(&root).ok();
        let db_path = root.join("relay.db");
        let store = Self {
            root,
            max_blob_size,
            max_blobs_per_tag,
            db_path,
            lock: Mutex::new(()),
        };
        store.init_db();
        store
    }

    fn init_db(&self) {
        let conn = self.connect();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mailbox_tag BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                stored_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_blobs_tag ON blobs(mailbox_tag);",
        )
        .expect("init relay db");
    }

    fn connect(&self) -> Connection {
        Connection::open(&self.db_path).expect("open relay db")
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub fn store(
        &self,
        mailbox_tag: &[u8],
        expires_at: u64,
        ciphertext: &[u8],
    ) -> Result<(), String> {
        if mailbox_tag.len() != 32 {
            return Err("mailbox_tag must be 32 bytes".into());
        }
        if ciphertext.len() > self.max_blob_size {
            return Err("blob too large".into());
        }
        let now = Self::now_ms();
        if expires_at <= now {
            return Err("blob already expired".into());
        }
        if expires_at > now + MAX_RELAY_BLOB_TTL_MS {
            return Err("blob TTL exceeds 24 hour relay maximum".into());
        }

        let _guard = self.lock.lock().unwrap();
        let conn = self.connect();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blobs WHERE mailbox_tag = ?1 AND expires_at > ?2",
                rusqlite::params![mailbox_tag, now as i64],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if count as usize >= self.max_blobs_per_tag {
            return Err("mailbox tag blob limit exceeded".into());
        }
        conn.execute(
            "INSERT INTO blobs (mailbox_tag, expires_at, ciphertext, stored_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![mailbox_tag, expires_at as i64, ciphertext, now as i64],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn fetch(&self, mailbox_tag: &[u8]) -> Result<Vec<StoredBlob>, String> {
        if mailbox_tag.len() != 32 {
            return Err("mailbox_tag must be 32 bytes".into());
        }
        let now = Self::now_ms();
        let _guard = self.lock.lock().unwrap();
        let conn = self.connect();
        let mut stmt = conn
            .prepare(
                "SELECT mailbox_tag, expires_at, ciphertext, stored_at
                 FROM blobs WHERE mailbox_tag = ?1 AND expires_at > ?2
                 ORDER BY stored_at ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![mailbox_tag, now as i64], |row| {
                let tag: Vec<u8> = row.get(0)?;
                let expires_at: i64 = row.get(1)?;
                let ciphertext: Vec<u8> = row.get(2)?;
                let stored_at: i64 = row.get(3)?;
                Ok(StoredBlob {
                    mailbox_tag: tag.try_into().unwrap(),
                    expires_at: expires_at as u64,
                    ciphertext,
                    stored_at: stored_at as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}
