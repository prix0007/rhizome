//! SQLite history: first/last seen per (network, device) and per-network meta.
//! Only parameterised statements; the schema is static SQL.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::model::Device;

pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredDevice {
    pub id: String,
    pub mac: String,
    pub last_ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub kind: String,
    pub randomized: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (creating if needed) the database at `path`. A directory created
    /// here is 0700 and the file is always 0600; pre-existing parent
    /// directories are left untouched.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if let Some(parent) = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && !p.exists())
        {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        // Create the file ourselves so it never exists with a wider mode.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let store = Self {
            conn: Mutex::new(Connection::open(path)?),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let store = Self {
            conn: Mutex::new(Connection::open_in_memory()?),
        };
        store.migrate()?;
        Ok(store)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Apply pending migrations (tracked in `PRAGMA user_version`). Safe to repeat.
    pub fn migrate(&self) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 1 {
            let tx = conn.transaction()?;
            tx.execute_batch(include_str!("schema.sql"))?;
            tx.execute_batch("PRAGMA user_version = 1")?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn user_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn()
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// One transaction. `first_seen` is kept from the first insert; `last_seen`
    /// only moves forward; everything else takes the latest value.
    pub fn upsert_many(&self, network_id: &str, devices: &[Device]) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO devices (network_id, id, mac, last_ip, hostname, vendor, kind, randomized, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(network_id, id) DO UPDATE SET
                    mac = excluded.mac,
                    last_ip = excluded.last_ip,
                    hostname = excluded.hostname,
                    vendor = excluded.vendor,
                    kind = excluded.kind,
                    randomized = excluded.randomized,
                    last_seen = MAX(devices.last_seen, excluded.last_seen)",
            )?;
            for d in devices {
                st.execute(rusqlite::params![
                    network_id,
                    d.id,
                    d.mac.to_string(),
                    d.ip.to_string(),
                    d.hostname,
                    d.vendor,
                    d.kind.as_str(),
                    d.randomized_mac,
                    d.first_seen,
                    d.last_seen,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load(&self, network_id: &str) -> Result<Vec<StoredDevice>, StoreError> {
        let conn = self.conn();
        let mut st = conn.prepare_cached(
            "SELECT id, mac, last_ip, hostname, vendor, kind, randomized, first_seen, last_seen
             FROM devices WHERE network_id = ?1 ORDER BY id",
        )?;
        let rows = st.query_map([network_id], |r| {
            Ok(StoredDevice {
                id: r.get(0)?,
                mac: r.get(1)?,
                last_ip: r.get(2)?,
                hostname: r.get(3)?,
                vendor: r.get(4)?,
                kind: r.get(5)?,
                randomized: r.get(6)?,
                first_seen: r.get(7)?,
                last_seen: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_meta(&self, network_id: &str, key: &str) -> Result<Option<String>, StoreError> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE network_id = ?1 AND key = ?2",
                [network_id, key],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn set_meta(&self, network_id: &str, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO meta (network_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(network_id, key) DO UPDATE SET value = excluded.value",
            [network_id, key, value],
        )?;
        Ok(())
    }
}

impl StoredDevice {
    /// Rebuild a (currently offline) device from history. Returns `None` for
    /// rows whose MAC or IP no longer parse.
    pub fn into_device(self) -> Option<Device> {
        Some(Device {
            id: self.id,
            mac: self.mac.parse().ok()?,
            ip: self.last_ip.parse().ok()?,
            vendor: self.vendor,
            hostname: self.hostname.clone(),
            hostname_source: self.hostname.as_ref().map(|_| "history".to_string()),
            kind: crate::model::DeviceKind::from_db(&self.kind),
            services: vec![],
            ssdp_server: None,
            ssdp_types: vec![],
            ssdp_location: None,
            is_gateway: false,
            is_self: false,
            randomized_mac: self.randomized,
            shared_mac: false,
            online: false,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            is_new: false,
        })
    }
}
