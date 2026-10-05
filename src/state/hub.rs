//! Shared live state: current snapshot plus a broadcast channel of changes.

use std::collections::BTreeMap;
use std::sync::RwLock;

use tokio::sync::broadcast;

use crate::model::{Device, DeviceEvent, DeviceMap, ScanStatus, UserMeta};

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub devices: Vec<Device>,
    pub status: Option<ScanStatus>,
}

pub struct Hub {
    inner: RwLock<(DeviceMap, Option<ScanStatus>)>,
    /// The user's names and notes, the single source of truth for those two
    /// fields: whatever the scanner publishes is overlaid with these. (Lock
    /// order: `inner` before `meta`.)
    meta: RwLock<BTreeMap<String, UserMeta>>,
    /// Identity of the network being shown (set by the scanner once observed).
    network: RwLock<Option<String>>,
    tx: broadcast::Sender<DeviceEvent>,
}

fn overlay(d: &mut Device, meta: &BTreeMap<String, UserMeta>) {
    if let Some(u) = meta.get(&d.id) {
        d.custom_name = u.custom_name.clone();
        d.notes = u.notes.clone();
    }
}

impl Hub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self {
            inner: RwLock::new((DeviceMap::new(), None)),
            meta: RwLock::new(BTreeMap::new()),
            network: RwLock::new(None),
            tx,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            devices: g.0.values().cloned().collect(),
            status: g.1.clone(),
        }
    }

    /// The current device map, i.e. what a client that is up to date knows.
    pub fn device_map(&self) -> DeviceMap {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    pub fn set_network_id(&self, id: Option<String>) {
        *self.network.write().unwrap_or_else(|e| e.into_inner()) = id;
    }

    pub fn network_id(&self) -> Option<String> {
        self.network
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn user_meta_snapshot(&self) -> BTreeMap<String, UserMeta> {
        self.meta.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Replace all user metadata (e.g. when history for a network is loaded).
    pub fn load_user_meta(&self, meta: BTreeMap<String, UserMeta>) {
        *self.meta.write().unwrap_or_else(|e| e.into_inner()) = meta;
    }

    /// Record the user's name/notes for a known device, update the snapshot and
    /// broadcast the change. `None` if the device is not known.
    pub fn commit_user_meta(&self, id: &str, new: UserMeta) -> Option<Device> {
        let updated = {
            let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
            let d = g.0.get_mut(id)?;
            d.custom_name = new.custom_name.clone();
            d.notes = new.notes.clone();
            let updated = d.clone();
            self.meta
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id.to_string(), new);
            updated
        };
        let _ = self.tx.send(DeviceEvent::Upsert(Box::new(updated.clone())));
        Some(updated)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.tx.subscribe()
    }

    /// Apply one event to the snapshot and broadcast it.
    pub fn publish(&self, mut event: DeviceEvent) {
        {
            let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
            let meta = self.meta.read().unwrap_or_else(|e| e.into_inner());
            match &mut event {
                DeviceEvent::Upsert(d) => {
                    overlay(d, &meta);
                    g.0.insert(d.id.clone(), (**d).clone());
                }
                DeviceEvent::Removed(id) => {
                    g.0.remove(id);
                }
                DeviceEvent::Scan(s) => g.1 = Some((**s).clone()),
            }
        }
        // No receivers is fine.
        let _ = self.tx.send(event);
    }

    /// Replace the full device map (so `last_seen` stays fresh in snapshots),
    /// then broadcast the changes and the scan status.
    pub fn apply_scan(&self, devices: &DeviceMap, events: Vec<DeviceEvent>, status: ScanStatus) {
        let events: Vec<DeviceEvent> = {
            let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
            let meta = self.meta.read().unwrap_or_else(|e| e.into_inner());
            let mut map = devices.clone();
            for d in map.values_mut() {
                overlay(d, &meta);
            }
            g.0 = map;
            g.1 = Some(status.clone());
            // Events carry the user's current text too, so a late edit is not undone.
            events
                .into_iter()
                .map(|mut ev| {
                    if let DeviceEvent::Upsert(d) = &mut ev {
                        overlay(d, &meta);
                    }
                    ev
                })
                .collect()
        };
        for ev in events {
            let _ = self.tx.send(ev);
        }
        let _ = self.tx.send(DeviceEvent::Scan(Box::new(status)));
    }

    /// Seed the snapshot (e.g. from history) without broadcasting.
    pub fn seed(&self, devices: &DeviceMap) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let meta = self.meta.read().unwrap_or_else(|e| e.into_inner());
        let mut map = devices.clone();
        for d in map.values_mut() {
            overlay(d, &meta);
        }
        g.0 = map;
    }
}
