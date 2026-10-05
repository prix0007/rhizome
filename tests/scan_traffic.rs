//! The scan cycle feeds per-device loss and jitter into the traffic hub.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use rhizome::discovery::arp_parse::ArpEntry;
use rhizome::model::HostInfo;
use rhizome::net::iface_select::Selected;
use rhizome::scanner::{Collected, Collector, Scanner, ScannerConfig};
use rhizome::state::hub::Hub;
use rhizome::traffic::TrafficHub;

fn sel() -> Selected {
    Selected {
        name: "en0".into(),
        ip: "192.168.0.172".parse().unwrap(),
        net: "192.168.0.0/24".parse().unwrap(),
        mac: "32:ec:3b:00:00:01".parse().unwrap(),
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

const GW: &str = "68:7f:f0:00:00:01";
const TV: &str = "02:21:49:00:00:82";
const GHOST: &str = "aa:bb:cc:00:00:09";

struct Script(Mutex<Vec<Collected>>);

impl Collector for Script {
    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<Collected, String>> + Send + '_>> {
        Box::pin(async move {
            let mut q = self.0.lock().unwrap();
            Ok(if q.len() > 1 {
                q.remove(0)
            } else {
                q[0].clone()
            })
        })
    }
}

/// One cycle: the gateway and TV reply (TV with the given RTT), the ghost does not.
fn cycle(tv_rtt: f64, ping: bool) -> Collected {
    let mut c = Collected {
        selected: sel(),
        arp: vec![
            arp("192.168.0.1", GW),
            arp("192.168.0.82", TV),
            arp("192.168.0.9", GHOST),
        ],
        ping_method: if ping {
            "icmp-dgram".into()
        } else {
            String::new()
        },
        ..Collected::default()
    };
    let reply = |rtt: f64| HostInfo {
        rtt_ms: Some(rtt),
        ..Default::default()
    };
    c.host_info
        .insert("192.168.0.1".parse().unwrap(), reply(1.0));
    c.host_info
        .insert("192.168.0.82".parse().unwrap(), reply(tv_rtt));
    c
}

fn scanner(script: Vec<Collected>, traffic: Arc<TrafficHub>) -> (Scanner, Arc<Hub>) {
    let hub = Arc::new(Hub::new(64));
    let s = Scanner::new(
        Box::new(Script(Mutex::new(script))),
        hub.clone(),
        ScannerConfig {
            interval_s: 30,
            offline_after_ms: 90_000,
            new_window_ms: 600_000,
            max_devices: 2048,
        },
    )
    .with_traffic(traffic);
    (s, hub)
}

#[tokio::test]
async fn loss_and_jitter_accumulate_from_the_sweeps_own_results() {
    let t = Arc::new(TrafficHub::new(false));
    let (mut s, _) = scanner(
        vec![
            cycle(10.0, true),
            cycle(12.0, true),
            cycle(11.0, true),
            cycle(15.0, true),
        ],
        t.clone(),
    );
    for i in 0..4 {
        s.run_cycle(1_000_000 + i * 30_000).await;
    }
    let q = t.compose(0, None, &[]).devices;
    let tv = &q[TV];
    assert_eq!(tv.loss_pct, Some(0.0));
    assert_eq!(tv.jitter_ms, Some(2.3), "|12-10|, |11-12|, |15-11| -> 7/3");
    assert!(
        !tv.measured && tv.rx_bps.is_none() && tv.tx_bps.is_none(),
        "no capture: no per-device rates"
    );
    let ghost = &q[GHOST];
    assert_eq!(
        ghost.loss_pct,
        Some(100.0),
        "pinged four times, never answered"
    );
    assert_eq!(ghost.jitter_ms, None);
}

#[tokio::test]
async fn too_little_history_reports_nothing_rather_than_a_misleading_number() {
    let t = Arc::new(TrafficHub::new(false));
    let (mut s, _) = scanner(vec![cycle(10.0, true)], t.clone());
    s.run_cycle(1_000_000).await;
    s.run_cycle(1_030_000).await;
    let q = t.compose(0, None, &[]).devices;
    assert_eq!(
        (q[TV].loss_pct, q[TV].jitter_ms),
        (None, None),
        "two samples are not enough"
    );
}

#[tokio::test]
async fn this_machine_and_cycles_without_a_ping_sweep_are_not_measured() {
    let t = Arc::new(TrafficHub::new(false));
    let (mut s, hub) = scanner(vec![cycle(10.0, false)], t.clone());
    for i in 0..5 {
        s.run_cycle(1_000_000 + i * 30_000).await;
    }
    assert!(
        t.compose(0, None, &[]).devices.is_empty(),
        "no sweep ran, so there is nothing to measure"
    );
    let me = hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.is_self)
        .unwrap();
    let t2 = Arc::new(TrafficHub::new(false));
    let (mut s2, _) = scanner(vec![cycle(10.0, true)], t2.clone());
    for i in 0..5 {
        s2.run_cycle(2_000_000 + i * 30_000).await;
    }
    assert!(
        !t2.compose(0, None, &[]).devices.contains_key(&me.id),
        "this machine is never pinged"
    );
}

#[tokio::test]
async fn the_hub_learns_which_interface_is_being_scanned() {
    let t = Arc::new(TrafficHub::new(false));
    let (mut s, _) = scanner(vec![cycle(1.0, true)], t.clone());
    assert!(t.selected().is_none());
    s.run_cycle(1_000_000).await;
    assert_eq!(t.selected().unwrap().name, "en0");
    assert_eq!(t.compose(5, None, &[]).host.iface.as_deref(), Some("en0"));
}

#[tokio::test]
async fn devices_that_left_the_arp_table_stop_being_measured() {
    let t = Arc::new(TrafficHub::new(false));
    let mut gone = cycle(10.0, true);
    gone.arp.retain(|e| e.ip.to_string() != "192.168.0.9");
    let (mut s, _) = scanner(
        vec![
            cycle(10.0, true),
            cycle(10.0, true),
            cycle(10.0, true),
            gone,
        ],
        t.clone(),
    );
    for i in 0..4 {
        s.run_cycle(1_000_000 + i * 30_000).await;
    }
    let q = t.compose(0, None, &[]).devices;
    assert_eq!(
        q[GHOST].loss_pct,
        Some(100.0),
        "recorded only while in the ARP table; the cycle after it left adds no sample"
    );
    assert_eq!(q[GHOST].jitter_ms, None);
}
