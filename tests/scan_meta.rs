//! User-set names survive scan cycles and restarts, and merge never overwrites them.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use rhizomon::discovery::arp_parse::ArpEntry;
use rhizomon::model::{DeviceEvent, UserMeta};
use rhizomon::net::iface_select::Selected;
use rhizomon::scanner::{Collected, Collector, Peek, Scanner, ScannerConfig};
use rhizomon::state::hub::Hub;
use rhizomon::store::Store;

const T0: i64 = 1_000_000;
const NET: &str = "68:7f:f0:00:00:01";
const PHONE: &str = "02:00:00:00:00:62";

fn sel() -> Selected {
    Selected {
        name: "en0".into(),
        ip: "192.168.0.172".parse().unwrap(),
        net: "192.168.0.0/24".parse().unwrap(),
        mac: "32:00:00:00:00:84".parse().unwrap(),
        gateway_ip: Some("192.168.0.1".parse().unwrap()),
    }
}

fn arp(ip: &str, mac: &str) -> ArpEntry {
    ArpEntry {
        ip: ip.parse().unwrap(),
        mac: Some(mac.parse().unwrap()),
        iface: "en0".into(),
        permanent: false,
    }
}

fn collected() -> Collected {
    let arp = vec![arp("192.168.0.1", NET), arp("192.168.0.82", PHONE)];
    let mut c = Collected {
        selected: sel(),
        arp,
        ..Collected::default()
    };
    for e in &c.arp {
        c.ping_alive.insert(e.ip);
    }
    c
}

struct Fixed(Mutex<Collected>);

impl Collector for Fixed {
    fn peek(&self) -> Pin<Box<dyn Future<Output = Peek> + Send + '_>> {
        Box::pin(async move {
            let c = self.0.lock().unwrap();
            Some((c.selected.clone(), c.arp.clone()))
        })
    }
    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<Collected, String>> + Send + '_>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }
}

fn scanner(hub: Arc<Hub>, store: Arc<Store>) -> Scanner {
    Scanner::new(
        Box::new(Fixed(Mutex::new(collected()))),
        hub,
        ScannerConfig {
            interval_s: 30,
            offline_after_ms: 90_000,
            new_window_ms: 600_000,
            max_devices: 2048,
        },
    )
    .with_store(store)
}

fn name_it(hub: &Hub, store: &Store) {
    let mut dev = hub.device_map().get(PHONE).cloned().unwrap();
    dev.custom_name = Some("Dad's phone".into());
    dev.notes = Some("Pixel".into());
    store.set_user_meta(NET, &dev).unwrap();
    hub.commit_user_meta(
        PHONE,
        UserMeta {
            custom_name: dev.custom_name.clone(),
            notes: dev.notes.clone(),
        },
    )
    .unwrap();
}

#[tokio::test]
async fn the_hub_learns_the_network_id_from_the_first_observed_gateway() {
    let hub = Arc::new(Hub::new(64));
    let mut s = scanner(hub.clone(), Arc::new(Store::open_in_memory().unwrap()));
    assert_eq!(hub.network_id(), None);
    s.run_cycle(T0).await;
    assert_eq!(hub.network_id().as_deref(), Some(NET));
}

#[tokio::test]
async fn user_metadata_survives_later_scans_and_no_event_strips_it() {
    let hub = Arc::new(Hub::new(64));
    let store = Arc::new(Store::open_in_memory().unwrap());
    let mut s = scanner(hub.clone(), store.clone());
    s.run_cycle(T0).await;
    name_it(&hub, &store);

    let mut rx = hub.subscribe();
    s.run_cycle(T0 + 30_000).await;
    s.run_cycle(T0 + 60_000).await;
    let d = hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.id == PHONE)
        .unwrap();
    assert_eq!(d.custom_name.as_deref(), Some("Dad's phone"));
    assert_eq!(d.notes.as_deref(), Some("Pixel"));
    while let Ok(ev) = rx.try_recv() {
        if let DeviceEvent::Upsert(d) = ev
            && d.id == PHONE
        {
            assert_eq!(
                d.custom_name.as_deref(),
                Some("Dad's phone"),
                "events must carry the user's name"
            );
        }
    }
    // and the persisted copy was not clobbered by the per-cycle upserts
    let row = store
        .load(NET)
        .unwrap()
        .into_iter()
        .find(|r| r.id == PHONE)
        .unwrap();
    assert_eq!(row.custom_name.as_deref(), Some("Dad's phone"));
}

#[tokio::test]
async fn user_metadata_is_restored_after_a_restart_even_for_offline_devices() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    {
        let hub = Arc::new(Hub::new(64));
        let mut s = scanner(hub.clone(), store.clone());
        s.run_cycle(T0).await;
        name_it(&hub, &store);
    }
    let hub = Arc::new(Hub::new(64));
    let mut s = scanner(hub.clone(), store.clone());
    s.init(T0 + 86_400_000).await; // a day later, before any scan finishes
    let d = hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.id == PHONE)
        .unwrap();
    assert!(!d.online);
    assert_eq!(d.custom_name.as_deref(), Some("Dad's phone"));
    assert_eq!(d.notes.as_deref(), Some("Pixel"));
    // a later edit after the restart still works and persists
    s.run_cycle(T0 + 86_400_000 + 1000).await;
    let mut dev = hub.device_map().get(PHONE).cloned().unwrap();
    dev.custom_name = None;
    store.set_user_meta(NET, &dev).unwrap();
    hub.commit_user_meta(
        PHONE,
        UserMeta {
            custom_name: None,
            notes: Some("Pixel".into()),
        },
    )
    .unwrap();
    s.run_cycle(T0 + 86_400_000 + 31_000).await;
    let d = hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.id == PHONE)
        .unwrap();
    assert_eq!(d.custom_name, None, "a cleared name stays cleared");
    assert_eq!(d.notes.as_deref(), Some("Pixel"));
}
