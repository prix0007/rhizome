//! Shared live state: current snapshot plus a broadcast channel of changes.

use std::sync::RwLock;

use tokio::sync::broadcast;

use crate::model::{Device, DeviceEvent, DeviceMap, ScanStatus};

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub devices: Vec<Device>,
    pub status: Option<ScanStatus>,
}

pub struct Hub {
    inner: RwLock<(DeviceMap, Option<ScanStatus>)>,
    tx: broadcast::Sender<DeviceEvent>,
}

impl Hub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self {
            inner: RwLock::new((DeviceMap::new(), None)),
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

    pub fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.tx.subscribe()
    }

    /// Apply one event to the snapshot and broadcast it.
    pub fn publish(&self, event: DeviceEvent) {
        {
            let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
            match &event {
                DeviceEvent::Upsert(d) => {
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
        {
            let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
            g.0 = devices.clone();
            g.1 = Some(status.clone());
        }
        for ev in events {
            let _ = self.tx.send(ev);
        }
        let _ = self.tx.send(DeviceEvent::Scan(Box::new(status)));
    }

    /// Seed the snapshot (e.g. from history) without broadcasting.
    pub fn seed(&self, devices: &DeviceMap) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        g.0 = devices.clone();
    }
}
