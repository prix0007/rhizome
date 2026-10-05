//! SQLite history: first/last seen per (network, device) and per-network meta.
//! Only parameterised statements; the schema is static SQL.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::model::Device;

pub const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "this database was created by a newer rhizome (schema version {found}, this build supports up to {supported}); upgrade rhizome or use another --db"
    )]
    TooNew { found: i64, supported: i64 },
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
    pub custom_name: Option<String>,
    pub notes: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub dns_name: Option<String>,
    pub netbios_name: Option<String>,
    pub os_hint: Option<String>,
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
        use rusqlite::TransactionBehavior;
        let mut conn = self.conn();
        // IMMEDIATE takes the write lock first, so the version is read and the
        // steps applied atomically even if another process opens the file now.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::TooNew {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        if version < 1 {
            tx.execute_batch(include_str!("schema.sql"))?;
            tx.execute_batch("PRAGMA user_version = 1")?;
        }
        if version < 2 {
            tx.execute_batch(include_str!("schema_v2.sql"))?;
            tx.execute_batch("PRAGMA user_version = 2")?;
        }
        tx.commit()?;
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
                "INSERT INTO devices (network_id, id, mac, last_ip, hostname, vendor, kind, randomized, first_seen, last_seen,
                                      friendly_name, manufacturer, model, dns_name, netbios_name, os_hint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(network_id, id) DO UPDATE SET
                    mac = excluded.mac,
                    last_ip = excluded.last_ip,
                    hostname = excluded.hostname,
                    vendor = excluded.vendor,
                    kind = excluded.kind,
                    randomized = excluded.randomized,
                    -- Learned fields take the newest value, including NULL: the scanner keeps a
                    -- value while its source is quiet and drops it only on an authoritative
                    -- miss (see merge), so the database simply mirrors the live state.
                    last_seen = MAX(devices.last_seen, excluded.last_seen),
                    friendly_name = excluded.friendly_name,
                    manufacturer = excluded.manufacturer,
                    model = excluded.model,
                    dns_name = excluded.dns_name,
                    netbios_name = excluded.netbios_name,
                    os_hint = excluded.os_hint",
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
                    d.friendly_name,
                    d.manufacturer,
                    d.model,
                    d.dns_name,
                    d.netbios_name,
                    d.os_hint,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load(&self, network_id: &str) -> Result<Vec<StoredDevice>, StoreError> {
        let conn = self.conn();
        let mut st = conn.prepare_cached(
            "SELECT id, mac, last_ip, hostname, vendor, kind, randomized, first_seen, last_seen,
                    custom_name, notes, friendly_name, manufacturer, model, dns_name, netbios_name, os_hint
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
                custom_name: r.get(9)?,
                notes: r.get(10)?,
                friendly_name: r.get(11)?,
                manufacturer: r.get(12)?,
                model: r.get(13)?,
                dns_name: r.get(14)?,
                netbios_name: r.get(15)?,
                os_hint: r.get(16)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Store the user's name and notes for one device (clearing with `None`).
    /// Inserts the device row first if it is not stored yet; ordinary
    /// `upsert_many` calls never touch these two columns.
    pub fn set_user_meta(&self, network_id: &str, device: &Device) -> Result<(), StoreError> {
        self.upsert_many(network_id, std::slice::from_ref(device))?;
        self.conn().execute(
            "UPDATE devices SET custom_name = ?3, notes = ?4 WHERE network_id = ?1 AND id = ?2",
            rusqlite::params![network_id, device.id, device.custom_name, device.notes],
        )?;
        Ok(())
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
        let mac: crate::model::MacAddr = self.mac.parse().ok()?;
        let ip = self.last_ip.parse().ok()?;
        Some(Device {
            id: self.id,
            vendor: self.vendor,
            hostname: self.hostname.clone(),
            hostname_source: self.hostname.as_ref().map(|_| "history".to_string()),
            kind: crate::model::DeviceKind::from_db(&self.kind),
            randomized_mac: self.randomized,
            last_seen: self.last_seen,
            custom_name: self.custom_name,
            notes: self.notes,
            friendly_name: self.friendly_name,
            manufacturer: self.manufacturer,
            model: self.model,
            dns_name: self.dns_name,
            netbios_name: self.netbios_name,
            os_hint: self.os_hint,
            ..Device::new(mac, ip, self.first_seen)
        })
    }
}
