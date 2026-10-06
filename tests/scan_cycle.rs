//! Scanner cycles driven by a scripted collector (no network).

mod common;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use rhizomon::discovery::arp_parse::ArpEntry;
use rhizomon::model::DeviceEvent;
use rhizomon::net::iface_select::Selected;
use rhizomon::scanner::{Collected, Collector, Scanner, ScannerConfig};
use rhizomon::state::hub::Hub;
use rhizomon::store::Store;

fn sel() -> Selected {
    Selected {
        name: "en0".into(),
        ip: "192.168.0.172".parse().unwrap(),
        net: "192.168.0.0/24".parse().unwrap(),
        mac: "32:00:00:00:00:84".parse().unwrap(),
        gateway_ip: Some("192.168.0.1".parse().unwrap()),
    }
}

fn e(ip: &str, mac: &str) -> ArpEntry {
    ArpEntry {
        ip: ip.parse().unwrap(),
        mac: Some(mac.parse().unwrap()),
        iface: "en0".into(),
        permanent: false,
    }
}

struct Script(Mutex<Vec<Result<Collected, String>>>);

impl Collector for Script {
    fn peek(&self) -> Pin<Box<dyn Future<Output = rhizomon::scanner::Peek> + Send + '_>> {
        Box::pin(async move {
            let q = self.0.lock().unwrap();
            q[0].as_ref()
                .ok()
                .map(|c| (c.selected.clone(), c.arp.clone()))
        })
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<Collected, String>> + Send + '_>> {
        Box::pin(async move {
            let mut q = self.0.lock().unwrap();
            if q.len() > 1 {
                q.remove(0)
            } else {
                q[0].clone()
            }
        })
    }
}

fn collected(arp: Vec<ArpEntry>) -> Collected {
    Collected {
        selected: sel(),
        arp,
        ..Collected::default()
    }
}

fn scanner(script: Vec<Result<Collected, String>>, hub: Arc<Hub>) -> Scanner {
    Scanner::new(
        Box::new(Script(Mutex::new(script))),
        hub,
        ScannerConfig {
            interval_s: 30,
            offline_after_ms: 90_000,
            new_window_ms: 600_000,
            max_devices: 2048,
        },
    )
}

#[tokio::test]
async fn cycle_publishes_upserts_then_scan_status() {
    let hub = Arc::new(Hub::new(64));
    let mut rx = hub.subscribe();
    let mut s = scanner(
        vec![Ok(collected(vec![
            e("192.168.0.1", "68:7f:f0:00:00:01"),
            e("192.168.0.82", "2:0:0:0:0:62"),
        ]))],
        hub.clone(),
    );
    s.run_cycle(1_000_000).await;

    let mut kinds = vec![];
    while let Ok(ev) = rx.try_recv() {
        kinds.push(match ev {
            DeviceEvent::Upsert(_) => "upsert",
            DeviceEvent::Removed(_) => "removed",
            DeviceEvent::Scan(_) => "scan",
        });
    }
    assert_eq!(kinds, vec!["upsert", "upsert", "upsert", "scan"]);
    let snap = hub.snapshot();
    assert_eq!(snap.devices.len(), 3);
    let st = snap.status.unwrap();
    assert_eq!(st.iface, "en0");
    assert_eq!(st.net, "192.168.0.0/24");
    assert_eq!(st.gateway.as_deref(), Some("192.168.0.1"));
    assert_eq!(st.devices, 3);
}

#[tokio::test]
async fn second_identical_cycle_emits_only_scan() {
    let hub = Arc::new(Hub::new(64));
    let mut s = scanner(
        vec![Ok(collected(vec![e("192.168.0.1", "68:7f:f0:00:00:01")]))],
        hub.clone(),
    );
    s.run_cycle(1_000_000).await;
    let mut rx = hub.subscribe();
    s.run_cycle(1_030_000).await;
    assert!(matches!(rx.try_recv().unwrap(), DeviceEvent::Scan(_)));
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn collector_failure_is_reported_and_does_not_panic_or_wipe_state() {
    let hub = Arc::new(Hub::new(64));
    let mut s = scanner(
        vec![
            Ok(collected(vec![e("192.168.0.1", "68:7f:f0:00:00:01")])),
            Err("no usable network interface".into()),
        ],
        hub.clone(),
    );
    s.run_cycle(1_000_000).await;
    s.run_cycle(1_030_000).await;
    let snap = hub.snapshot();
    assert_eq!(snap.devices.len(), 2, "state survives a failed cycle");
    let st = snap.status.unwrap();
    assert!(
        st.warnings
            .iter()
            .any(|w| w.contains("no usable network interface")),
        "{:?}",
        st.warnings
    );
}

#[tokio::test]
async fn probe_evidence_keeps_devices_online_across_many_cycles() {
    let hub = Arc::new(Hub::new(64));
    let mut c = collected(vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ]);
    c.ping_alive.insert("192.168.0.82".parse().unwrap());
    c.tcp_alive.insert("192.168.0.1".parse().unwrap());
    c.ping_method = "icmp-dgram".into();
    let mut s = scanner(vec![Ok(c)], hub.clone());
    for i in 0..10 {
        s.run_cycle(1_000_000 + i * 30_000).await;
    }
    let snap = hub.snapshot();
    assert!(
        snap.devices.iter().all(|d| d.online),
        "{:?}",
        snap.devices
            .iter()
            .map(|d| (&d.ip, d.online))
            .collect::<Vec<_>>()
    );
    assert_eq!(snap.status.unwrap().ping_method, "icmp-dgram");
}

#[tokio::test]
async fn source_warnings_reach_the_status() {
    let hub = Arc::new(Hub::new(64));
    let mut c = collected(vec![]);
    c.warnings.push("Local Network access looks denied".into());
    let mut s = scanner(vec![Ok(c)], hub.clone());
    s.run_cycle(1_000_000).await;
    assert_eq!(
        hub.snapshot().status.unwrap().warnings,
        vec!["Local Network access looks denied".to_string()]
    );
}

fn with_store(script: Vec<Result<Collected, String>>, hub: Arc<Hub>, store: Arc<Store>) -> Scanner {
    scanner(script, hub).with_store(store)
}

fn ping_all(mut c: Collected) -> Collected {
    for e in &c.arp {
        c.ping_alive.insert(e.ip);
    }
    c
}

const T0: i64 = 1_000_000;

#[tokio::test]
async fn history_survives_a_restart_and_shows_devices_offline() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let arp = vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ];
    {
        let hub = Arc::new(Hub::new(64));
        let mut s = with_store(
            vec![Ok(ping_all(collected(arp.clone())))],
            hub,
            store.clone(),
        );
        s.run_cycle(T0).await;
    }
    // "Restart": a new scanner and hub over the same database, long after.
    let hub = Arc::new(Hub::new(64));
    let mut s = with_store(vec![Ok(collected(arp))], hub.clone(), store);
    s.init(T0 + 86_400_000).await;
    let snap = hub.snapshot();
    assert_eq!(
        snap.devices.len(),
        3,
        "gateway, .82 and this machine are restored before any scan"
    );
    let phone = snap
        .devices
        .iter()
        .find(|d| d.ip.to_string() == "192.168.0.82")
        .unwrap();
    assert!(!phone.online);
    assert_eq!(phone.last_seen, T0);
    assert_eq!(phone.first_seen, T0);
    assert!(snap.devices.iter().find(|d| d.is_self).unwrap().online);
    assert!(snap.devices.iter().any(|d| d.is_gateway));
}

#[tokio::test]
async fn first_scan_sets_the_baseline_and_later_arrivals_are_new_even_after_restart() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let base = vec![e("192.168.0.1", "68:7f:f0:00:00:01")];
    let hub = Arc::new(Hub::new(64));
    let mut s = with_store(
        vec![Ok(ping_all(collected(base.clone())))],
        hub.clone(),
        store.clone(),
    );
    s.run_cycle(T0).await;
    assert!(
        hub.snapshot().devices.iter().all(|d| !d.is_new),
        "fresh install: nothing is new"
    );
    assert_eq!(
        store
            .get_meta("68:7f:f0:00:00:01", "baseline_at")
            .unwrap()
            .as_deref(),
        Some(T0.to_string().as_str())
    );

    let mut more = base.clone();
    more.push(e("192.168.0.99", "aa:bb:cc:dd:ee:99"));
    let hub2 = Arc::new(Hub::new(64));
    let mut s2 = with_store(vec![Ok(ping_all(collected(more)))], hub2.clone(), store);
    s2.init(T0 + 60_000).await;
    s2.run_cycle(T0 + 60_000).await;
    let snap = hub2.snapshot();
    let fresh = snap
        .devices
        .iter()
        .find(|d| d.ip.to_string() == "192.168.0.99")
        .unwrap();
    assert!(fresh.is_new);
    assert!(!snap.devices.iter().find(|d| d.is_gateway).unwrap().is_new);
}

#[tokio::test]
async fn each_cycle_persists_last_seen() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let hub = Arc::new(Hub::new(64));
    let mut s = with_store(
        vec![Ok(ping_all(collected(vec![e(
            "192.168.0.1",
            "68:7f:f0:00:00:01",
        )])))],
        hub,
        store.clone(),
    );
    s.run_cycle(T0).await;
    s.run_cycle(T0 + 30_000).await;
    let rows = store.load("68:7f:f0:00:00:01").unwrap();
    let gw = rows.iter().find(|r| r.id == "68:7f:f0:00:00:01").unwrap();
    assert_eq!(gw.first_seen, T0);
    assert_eq!(gw.last_seen, T0 + 30_000);
}

#[tokio::test]
async fn history_is_not_mixed_across_networks() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let hub = Arc::new(Hub::new(64));
    let net_a = ping_all(collected(vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ]));
    let mut net_b = ping_all(collected(vec![
        e("10.0.0.1", "aa:aa:aa:aa:aa:01"),
        e("10.0.0.5", "aa:aa:aa:aa:aa:05"),
    ]));
    net_b.selected.ip = "10.0.0.172".parse().unwrap();
    net_b.selected.net = "10.0.0.0/24".parse().unwrap();
    net_b.selected.gateway_ip = Some("10.0.0.1".parse().unwrap());
    let mut s = with_store(vec![Ok(net_a), Ok(net_b)], hub.clone(), store.clone());
    s.run_cycle(T0).await;
    let mut rx = hub.subscribe();
    s.run_cycle(T0 + 30_000).await;
    let ips: Vec<String> = hub
        .snapshot()
        .devices
        .iter()
        .map(|d| d.ip.to_string())
        .collect();
    assert!(ips.iter().all(|i| i.starts_with("10.0.0.")), "{ips:?}");
    let mut removed = 0;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev, rhizomon::model::DeviceEvent::Removed(_)) {
            removed += 1;
        }
    }
    assert!(
        removed >= 2,
        "old network's devices are removed from clients"
    );
    assert_eq!(store.load("68:7f:f0:00:00:01").unwrap().len(), 3);
    assert_eq!(store.load("aa:aa:aa:aa:aa:01").unwrap().len(), 3);
}

#[tokio::test]
async fn mdns_hits_flow_into_devices_and_availability_into_status() {
    use rhizomon::model::MdnsHit;
    let hub = Arc::new(Hub::new(64));
    let mut c = collected(vec![e("192.168.0.82", "2:0:0:0:0:62")]);
    c.mdns = vec![MdnsHit {
        ip: "192.168.0.82".parse().unwrap(),
        hostname: Some("Anuragis-iPhone".into()),
        service_types: vec!["_apple-mobdev2".into()],
        fresh: true,
        ..Default::default()
    }];
    c.mdns_available = true;
    let mut s = scanner(vec![Ok(c)], hub.clone());
    s.run_cycle(T0).await;
    let snap = hub.snapshot();
    assert!(snap.status.as_ref().unwrap().mdns_available);
    assert_eq!(
        snap.devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.0.82")
            .unwrap()
            .hostname
            .as_deref(),
        Some("Anuragis-iPhone")
    );
}

#[tokio::test]
async fn mdns_failing_to_start_leaves_the_scanner_running() {
    use rhizomon::discovery::mdns::{MdnsSource, collect_mdns};
    struct Failing;
    impl MdnsSource for Failing {
        fn hits(&self, _fresh: std::time::Duration) -> Vec<rhizomon::model::MdnsHit> {
            unreachable!("a failed source is never queried")
        }
    }
    let failed: Result<Arc<dyn MdnsSource>, String> =
        Err("Address already in use (os error 48)".into());
    let (hits, available, warning) = collect_mdns(&failed, std::time::Duration::from_secs(30));
    assert!(hits.is_empty());
    assert!(!available);
    assert!(warning.unwrap().contains("mDNS"));
    let ok: Result<Arc<dyn MdnsSource>, String> = Ok(Arc::new(Failing) as Arc<dyn MdnsSource>);
    let _ = &ok; // constructing it must not query it

    // The scanner keeps producing cycles with mdns_available=false.
    let hub = Arc::new(Hub::new(64));
    let mut c = collected(vec![e("192.168.0.1", "68:7f:f0:00:00:01")]);
    c.mdns_available = available;
    c.warnings.extend(Some("mDNS unavailable".to_string()));
    let mut s = scanner(vec![Ok(c)], hub.clone());
    s.run_cycle(T0).await;
    s.run_cycle(T0 + 30_000).await;
    let st = hub.snapshot().status.unwrap();
    assert!(!st.mdns_available);
    assert_eq!(st.devices, 2);
}

#[tokio::test]
async fn ssdp_observations_reach_devices() {
    use rhizomon::model::{SsdpHit, SsdpObservation};
    let hub = Arc::new(Hub::new(64));
    let mut c = collected(vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ]);
    c.ssdp = vec![SsdpObservation {
        ip: "192.168.0.1".parse().unwrap(),
        hit: SsdpHit {
            server: Some("Linux/4.14 UPnP/1.1 MiniUPnPd/2.1".into()),
            st: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into()),
            usn: None,
            location: None,
        },
    }];
    let mut s = scanner(vec![Ok(c)], hub.clone());
    s.run_cycle(T0).await;
    let gw = hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.is_gateway)
        .unwrap();
    assert_eq!(
        gw.ssdp_server.as_deref(),
        Some("Linux/4.14 UPnP/1.1 MiniUPnPd/2.1")
    );
}

// ---- review fixes ----

fn at_a_cap(script: Vec<Result<Collected, String>>, hub: Arc<Hub>, max: usize) -> Scanner {
    Scanner::new(
        Box::new(Script(Mutex::new(script))),
        hub,
        ScannerConfig {
            interval_s: 30,
            offline_after_ms: 90_000,
            new_window_ms: 600_000,
            max_devices: max,
        },
    )
}

#[tokio::test]
async fn a_failed_collect_still_ages_devices_offline_and_expires_new() {
    let hub = Arc::new(Hub::new(64));
    let base = vec![e("192.168.0.1", "68:7f:f0:00:00:01")];
    let mut more = base.clone();
    more.push(e("192.168.0.82", "2:0:0:0:0:62"));
    let mut s = scanner(
        vec![
            Ok(ping_all(collected(base))),
            Ok(ping_all(collected(more))),
            Err("Wi-Fi dropped".into()),
        ],
        hub.clone(),
    );
    s.run_cycle(T0).await; // baseline
    s.run_cycle(T0 + 30_000).await; // .82 arrives: new
    let phone = |h: &Hub| {
        h.snapshot()
            .devices
            .into_iter()
            .find(|d| d.ip.to_string() == "192.168.0.82")
            .unwrap()
    };
    assert!(phone(&hub).is_new && phone(&hub).online);

    s.run_cycle(T0 + 30_000 + 700_000).await; // the collect fails 11+ minutes later
    let p = phone(&hub);
    assert!(
        !p.online,
        "devices must age out while the network is unreadable"
    );
    assert!(!p.is_new, "the new window must still expire");
    let snap = hub.snapshot();
    assert!(snap.devices.iter().find(|d| d.is_self).unwrap().online);
    assert!(
        snap.status
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("Wi-Fi dropped"))
    );
}

#[tokio::test]
async fn failed_collect_emits_the_flip_events_to_clients() {
    let hub = Arc::new(Hub::new(64));
    let mut s = scanner(
        vec![
            Ok(ping_all(collected(vec![e("192.168.0.82", "2:0:0:0:0:62")]))),
            Err("down".into()),
        ],
        hub.clone(),
    );
    s.run_cycle(T0).await;
    let mut rx = hub.subscribe();
    s.run_cycle(T0 + 400_000).await;
    let mut offline_events = 0;
    while let Ok(ev) = rx.try_recv() {
        if let DeviceEvent::Upsert(d) = ev
            && !d.online
        {
            offline_events += 1;
        }
    }
    assert!(offline_events >= 1);
}

#[tokio::test]
async fn an_empty_arp_cycle_does_not_switch_network_wipe_state_or_persist_under_another_id() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let hub = Arc::new(Hub::new(64));
    let arp = vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ];
    let mut s = with_store(
        vec![
            Ok(ping_all(collected(arp.clone()))),
            Ok(collected(vec![])),
            Ok(ping_all(collected(arp))),
        ],
        hub.clone(),
        store.clone(),
    );
    s.run_cycle(T0).await;
    let baseline = store.get_meta("68:7f:f0:00:00:01", "baseline_at").unwrap();
    let mut rx = hub.subscribe();
    s.run_cycle(T0 + 30_000).await; // ARP came back empty (read failed / gateway incomplete)
    let snap = hub.snapshot();
    assert_eq!(snap.devices.len(), 3, "devices survive an empty-ARP cycle");
    while let Ok(ev) = rx.try_recv() {
        assert!(
            !matches!(ev, DeviceEvent::Removed(_)),
            "no Removed events: {ev:?}"
        );
    }
    assert!(
        store.load("net:192.168.0.0/24").unwrap().is_empty(),
        "nothing is stored under a fallback id"
    );
    assert_eq!(
        store.get_meta("net:192.168.0.0/24", "baseline_at").unwrap(),
        None
    );
    assert_eq!(
        store.get_meta("68:7f:f0:00:00:01", "baseline_at").unwrap(),
        baseline
    );
    s.run_cycle(T0 + 60_000).await;
    assert_eq!(hub.snapshot().devices.len(), 3);
}

#[tokio::test]
async fn an_empty_arp_first_cycle_sets_no_baseline_so_later_devices_are_not_all_new() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let hub = Arc::new(Hub::new(64));
    let arp = vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ];
    let mut s = with_store(
        vec![Ok(collected(vec![])), Ok(ping_all(collected(arp)))],
        hub.clone(),
        store.clone(),
    );
    s.run_cycle(T0).await;
    assert_eq!(
        store.get_meta("net:192.168.0.0/24", "baseline_at").unwrap(),
        None
    );
    assert!(store.load("net:192.168.0.0/24").unwrap().is_empty());
    s.run_cycle(T0 + 30_000).await;
    assert!(
        hub.snapshot().devices.iter().all(|d| !d.is_new),
        "the first real scan becomes the baseline"
    );
    assert!(
        store
            .get_meta("68:7f:f0:00:00:01", "baseline_at")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn baseline_and_new_detection_work_without_a_store() {
    let hub = Arc::new(Hub::new(64));
    let base = vec![e("192.168.0.1", "68:7f:f0:00:00:01")];
    let mut more = base.clone();
    more.push(e("192.168.0.99", "aa:bb:cc:dd:ee:99"));
    let mut s = scanner(
        vec![Ok(ping_all(collected(base))), Ok(ping_all(collected(more)))],
        hub.clone(),
    );
    s.run_cycle(T0).await;
    s.run_cycle(T0 + 30_000).await;
    let snap = hub.snapshot();
    assert!(
        snap.devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.0.99")
            .unwrap()
            .is_new
    );
    assert!(
        snap.devices
            .iter()
            .filter(|d| d.ip.to_string() != "192.168.0.99")
            .all(|d| !d.is_new)
    );
}

#[tokio::test]
async fn scan_finished_at_is_the_real_finish_time() {
    let hub = Arc::new(Hub::new(64));
    let mut s = scanner(
        vec![Ok(collected(vec![e("192.168.0.1", "68:7f:f0:00:00:01")]))],
        hub.clone(),
    )
    .with_clock(Box::new(|| 1_007_000));
    s.run_cycle(1_000_000).await;
    let st = hub.snapshot().status.unwrap();
    assert_eq!(st.scan_started_at, 1_000_000);
    assert_eq!(st.scan_finished_at, 1_007_000);
}

#[tokio::test]
async fn hitting_the_device_cap_is_reported_in_the_status() {
    let hub = Arc::new(Hub::new(64));
    let arp: Vec<ArpEntry> = (10..30u8)
        .map(|n| {
            e(
                &format!("192.168.0.{n}"),
                &format!("aa:bb:cc:dd:ee:{n:02x}"),
            )
        })
        .collect();
    let mut s = at_a_cap(vec![Ok(ping_all(collected(arp)))], hub.clone(), 4);
    s.run_cycle(T0).await;
    let snap = hub.snapshot();
    assert_eq!(snap.devices.len(), 4);
    assert!(
        snap.status
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("device limit")),
        "a warning must say new devices are being ignored"
    );
}

#[tokio::test]
async fn under_the_cap_there_is_no_limit_warning() {
    let hub = Arc::new(Hub::new(64));
    let mut s = at_a_cap(
        vec![Ok(ping_all(collected(vec![e(
            "192.168.0.1",
            "68:7f:f0:00:00:01",
        )])))],
        hub.clone(),
        100,
    );
    s.run_cycle(T0).await;
    assert!(hub.snapshot().status.unwrap().warnings.is_empty());
}

#[tokio::test]
async fn only_source_verified_identity_is_persisted_never_mdns_txt() {
    use rhizomon::model::{HostInfo, MdnsHit};
    let store = Arc::new(Store::open_in_memory().unwrap());
    let hub = Arc::new(Hub::new(64));
    let mut c = ping_all(collected(vec![
        e("192.168.0.1", "68:7f:f0:00:00:01"),
        e("192.168.0.82", "2:0:0:0:0:62"),
    ]));
    c.mdns = vec![MdnsHit {
        ip: "192.168.0.82".parse().unwrap(),
        fresh: true,
        model: Some("Forged Chromecast".into()),
        friendly_name: Some("Forged".into()),
        manufacturer: Some("Forger Inc".into()),
        ..Default::default()
    }];
    c.host_info.insert(
        "192.168.0.1".parse().unwrap(),
        HostInfo {
            model: Some("Archer".into()),
            upnp_answered: true,
            ..Default::default()
        },
    );
    let mut s = with_store(vec![Ok(c)], hub.clone(), store.clone());
    s.run_cycle(T0).await;
    let shown = hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.ip.to_string() == "192.168.0.82")
        .unwrap();
    assert_eq!(
        shown.model.as_deref(),
        Some("Forged Chromecast"),
        "displayed, flagged unverified"
    );
    let rows = store.load("68:7f:f0:00:00:01").unwrap();
    let phone = rows.iter().find(|r| r.last_ip == "192.168.0.82").unwrap();
    assert_eq!(
        (
            phone.model.as_deref(),
            phone.friendly_name.as_deref(),
            phone.manufacturer.as_deref()
        ),
        (None, None, None),
        "TXT identity must not reach the database"
    );
    let gw = rows.iter().find(|r| r.last_ip == "192.168.0.1").unwrap();
    assert_eq!(
        gw.model.as_deref(),
        Some("Archer"),
        "UPnP-verified identity is stored"
    );
}
