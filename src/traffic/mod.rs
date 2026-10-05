//! Live traffic and link-quality measurements.
//!
//! * Tier 1 (always on, no privileges): host throughput from the interface byte
//!   counters, link information, WAN throughput from the gateway's UPnP
//!   counters, and per-device loss/jitter from the scan's own ping results.
//! * Tier 2 (opt-in, `--capture`): per-second flow summaries from the system
//!   `tcpdump`. See `capture` for the privacy rules.
//!
//! One `Sample` per second is published through `TrafficHub`: `GET /api/traffic`
//! returns the latest, and the SSE stream carries each as a `traffic` event.

pub mod capture;
pub mod link;
pub mod quality;
pub mod rate;
pub mod wan;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

pub use capture::FlowOut;
pub use link::LinkInfo;

use crate::discovery::upnp_parse::IgdControl;
use crate::model::MacAddr;
use crate::net::iface_select::Selected;
use crate::platform::{Os, first_existing, tcpdump_candidates};
use crate::state::hub::Hub;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct HostTraffic {
    pub iface: Option<String>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub link: LinkInfo,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WanTraffic {
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub source: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct DeviceTraffic {
    pub loss_pct: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    /// True when `rx_bps`/`tx_bps` come from packet capture.
    pub measured: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct CaptureInfo {
    pub enabled: bool,
    pub available: bool,
    pub reason: Option<String>,
    pub flows: Vec<FlowOut>,
}

/// One second of measurements: the wire format of `/api/traffic` and the SSE
/// `traffic` event.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Sample {
    pub ts: i64,
    pub host: HostTraffic,
    pub wan: Option<WanTraffic>,
    pub devices: BTreeMap<String, DeviceTraffic>,
    pub capture: CaptureInfo,
}

pub const CAPTURE_OFF_REASON: &str =
    "Packet capture is off. Start rhizome with --capture to enable it.";

impl Sample {
    pub fn empty(capture_enabled: bool, ts: i64) -> Self {
        Sample {
            ts,
            capture: CaptureInfo {
                enabled: capture_enabled,
                available: false,
                reason: (!capture_enabled).then(|| CAPTURE_OFF_REASON.to_string()),
                flows: vec![],
            },
            ..Sample::default()
        }
    }
}

#[derive(Default)]
struct CaptureShared {
    available: bool,
    reason: Option<String>,
    flows: Vec<FlowOut>,
    devices: BTreeMap<String, (u64, u64)>,
}

/// Shared state between the producers (scanner, pollers, capture) and the
/// readers (the 1 Hz composer, the HTTP API).
pub struct TrafficHub {
    capture_enabled: bool,
    latest: RwLock<Sample>,
    tx: broadcast::Sender<Sample>,
    selected: RwLock<Option<Selected>>,
    quality: RwLock<quality::QualitySnapshot>,
    link: RwLock<LinkInfo>,
    wan: RwLock<Option<WanTraffic>>,
    capture: RwLock<CaptureShared>,
}

fn rd<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}
fn wr<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

impl TrafficHub {
    pub fn new(capture_enabled: bool) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            capture_enabled,
            latest: RwLock::new(Sample::empty(capture_enabled, crate::scanner::now_ms())),
            tx,
            selected: RwLock::new(None),
            quality: RwLock::new(BTreeMap::new()),
            link: RwLock::new(LinkInfo::default()),
            wan: RwLock::new(None),
            capture: RwLock::new(CaptureShared {
                reason: (!capture_enabled).then(|| CAPTURE_OFF_REASON.to_string()),
                ..CaptureShared::default()
            }),
        }
    }

    pub fn capture_enabled(&self) -> bool {
        self.capture_enabled
    }

    pub fn latest(&self) -> Sample {
        rd(&self.latest).clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Sample> {
        self.tx.subscribe()
    }

    /// Store as the latest sample and broadcast it.
    pub fn publish(&self, s: Sample) {
        *wr(&self.latest) = s.clone();
        let _ = self.tx.send(s);
    }

    pub fn set_selected(&self, sel: Selected) {
        *wr(&self.selected) = Some(sel);
    }

    pub fn selected(&self) -> Option<Selected> {
        rd(&self.selected).clone()
    }

    /// Replace loss/jitter for all devices (called once per scan cycle).
    pub fn set_quality(&self, q: quality::QualitySnapshot) {
        *wr(&self.quality) = q;
    }

    pub fn set_link(&self, l: LinkInfo) {
        *wr(&self.link) = l;
    }

    pub fn set_wan(&self, w: Option<WanTraffic>) {
        *wr(&self.wan) = w;
    }

    pub fn set_capture_status(&self, available: bool, reason: Option<String>) {
        let mut c = wr(&self.capture);
        c.available = available;
        c.reason = reason;
        if !available {
            c.flows.clear();
            c.devices.clear();
        }
    }

    pub fn set_capture_flows(&self, d: capture::Drained) {
        let mut c = wr(&self.capture);
        c.flows = d.flows;
        c.devices = d.devices;
    }

    /// Compose this second's sample from everything the producers have stored.
    pub fn compose(
        &self,
        ts: i64,
        host_rates: Option<(u64, u64)>,
        known_devices: &[String],
    ) -> Sample {
        let sel = self.selected();
        let cap = rd(&self.capture);
        let measured = self.capture_enabled && cap.available;
        let mut devices: BTreeMap<String, DeviceTraffic> = BTreeMap::new();
        for (id, (loss, jitter)) in rd(&self.quality).iter() {
            devices.insert(
                id.clone(),
                DeviceTraffic {
                    loss_pct: *loss,
                    jitter_ms: *jitter,
                    ..Default::default()
                },
            );
        }
        if measured {
            for id in known_devices.iter().chain(cap.devices.keys()) {
                devices.entry(id.clone()).or_default();
            }
            for (id, d) in devices.iter_mut() {
                let (rx, tx) = cap.devices.get(id).copied().unwrap_or((0, 0));
                d.rx_bps = Some(rx);
                d.tx_bps = Some(tx);
                d.measured = true;
            }
        }
        Sample {
            ts,
            host: HostTraffic {
                iface: sel.map(|s| s.name),
                rx_bps: host_rates.map(|r| r.0),
                tx_bps: host_rates.map(|r| r.1),
                link: rd(&self.link).clone(),
            },
            wan: rd(&self.wan).clone(),
            devices,
            capture: CaptureInfo {
                enabled: self.capture_enabled,
                available: measured,
                reason: if measured { None } else { cap.reason.clone() },
                flows: if measured { cap.flows.clone() } else { vec![] },
            },
        }
    }
}

/// Where the discovery side leaves the router's WAN counter endpoint.
#[derive(Default, Debug)]
pub struct IgdSlot(Mutex<Option<IgdControl>>);

impl IgdSlot {
    pub fn set(&self, c: Option<IgdControl>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = c;
    }
    pub fn get(&self) -> Option<IgdControl> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

// ---------------------------------------------------------------------------
// Producers
// ---------------------------------------------------------------------------

/// Byte counters of the selected interface (via `netdev`, which reads
/// `getifaddrs` on macOS, sysfs on Linux and `GetIfEntry2` on Windows).
struct HostCounters {
    name: String,
    iface: netdev::Interface,
    rx: rate::CounterRate,
    tx: rate::CounterRate,
}

impl HostCounters {
    fn open(name: &str) -> Option<Self> {
        // macOS counters are 32-bit and wrap at 4 GiB; the others are 64-bit.
        let width = if cfg!(target_vendor = "apple") {
            rate::Width::Bits32
        } else {
            rate::Width::Bits64
        };
        let iface = netdev::get_interfaces()
            .into_iter()
            .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name))?;
        Some(Self {
            name: name.to_string(),
            iface,
            rx: rate::CounterRate::new(width),
            tx: rate::CounterRate::new(width),
        })
    }

    /// `(rx_bps, tx_bps)` since the previous call.
    fn sample(&mut self, now_ms: i64) -> Option<(u64, u64)> {
        self.iface.update_stats().ok()?;
        let s = self.iface.stats.as_ref()?;
        let (rx, tx) = (
            self.rx.update(s.rx_bytes, now_ms),
            self.tx.update(s.tx_bytes, now_ms),
        );
        rx.zip(tx)
            .map(|(a, b)| (a.round() as u64, b.round() as u64))
    }
}

/// Options for the background producers.
#[derive(Clone)]
pub struct TrafficOptions {
    pub capture: bool,
    /// `false` with `--no-upnp`: the router's counters are then never read.
    pub wan: bool,
    pub igd: Arc<IgdSlot>,
}

/// Run all producers and the 1 Hz composer until `shutdown`.
pub async fn run(
    hub: Arc<TrafficHub>,
    devices: Arc<Hub>,
    opts: TrafficOptions,
    shutdown: CancellationToken,
) {
    tokio::spawn(link_poller(hub.clone(), shutdown.clone()));
    if opts.wan {
        tokio::spawn(wan_poller(hub.clone(), opts.igd.clone(), shutdown.clone()));
    }
    if opts.capture {
        tokio::spawn(capture_supervisor(
            hub.clone(),
            devices.clone(),
            shutdown.clone(),
        ));
    }
    let mut counters: Option<HostCounters> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
        let now = crate::scanner::now_ms();
        let want = hub.selected().map(|s| s.name);
        if counters.as_ref().map(|c| &c.name) != want.as_ref() {
            // The interface changed (or appeared): new baseline, no cross-interface deltas.
            counters = want.as_deref().and_then(HostCounters::open);
        }
        let rates = counters.as_mut().and_then(|c| c.sample(now));
        let known: Vec<String> = devices.device_map().keys().cloned().collect();
        hub.publish(hub.compose(now, rates, &known));
    }
}

async fn link_poller(hub: Arc<TrafficHub>, shutdown: CancellationToken) {
    let mut last: Option<(String, std::time::Instant, Duration)> = None;
    loop {
        if let Some(sel) = hub.selected() {
            let due = match &last {
                Some((name, at, every)) => *name != sel.name || at.elapsed() >= *every,
                None => true,
            };
            if due {
                let (info, every) = link::read_link(&sel).await;
                hub.set_link(info);
                last = Some((sel.name.clone(), std::time::Instant::now(), every));
            }
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

async fn wan_poller(hub: Arc<TrafficHub>, slot: Arc<IgdSlot>, shutdown: CancellationToken) {
    let mut mon = wan::WanMonitor::new();
    let mut current: Option<IgdControl> = None;
    loop {
        let ctl = slot.get();
        if ctl != current {
            mon.reset();
            current = ctl.clone();
        }
        let mut wait = Duration::from_secs(3);
        match ctl {
            None => hub.set_wan(None),
            Some(_) if mon.gave_up() => {
                // The router does not (or no longer) serve the counters: stay quiet, retry rarely.
                hub.set_wan(None);
                wait = Duration::from_secs(120);
                mon.reset();
            }
            Some(c) => match mon.poll(&c, crate::scanner::now_ms()).await {
                Some((rx, tx)) => hub.set_wan(Some(WanTraffic {
                    rx_bps: rx.round() as u64,
                    tx_bps: tx.round() as u64,
                    source: "upnp-igd",
                })),
                None if mon.gave_up() => hub.set_wan(None),
                None => {}
            },
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// Start `tcpdump` on the selected interface and keep its summaries flowing
/// into the hub, restarting on interface changes. Never escalates privileges:
/// when it cannot start, the reason says what to grant.
async fn capture_supervisor(hub: Arc<TrafficHub>, devices: Arc<Hub>, shutdown: CancellationToken) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let os = Os::current();
    loop {
        let Some(sel) = hub.selected() else {
            tokio::select! { _ = shutdown.cancelled() => return, _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
            continue;
        };
        let started = start_tcpdump(os, &sel.name).await;
        let mut child = match started {
            Ok(c) => c,
            Err(reason) => {
                tracing::info!("capture unavailable: {reason}");
                hub.set_capture_status(false, Some(reason));
                // Retry rarely (permissions may be granted meanwhile) or when the interface changes.
                for _ in 0..30 {
                    tokio::select! { _ = shutdown.cancelled() => return, _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
                    if hub.selected().map(|s| s.name) != Some(sel.name.clone()) {
                        break;
                    }
                }
                continue;
            }
        };
        hub.set_capture_status(true, None);
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut lines = BufReader::new(stdout).lines();
        let mut acc = capture::FlowAccumulator::default();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = std::time::Instant::now();
        let mut ctx_ids: BTreeMap<MacAddr, String> = BTreeMap::new();
        let mut self_id = sel.mac.to_string();
        #[allow(unused_assignments)]
        let mut why_stopped: Option<String> = None;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => { let _ = child.start_kill(); return; }
                _ = tick.tick() => {
                    let secs = last.elapsed().as_secs_f64();
                    last = std::time::Instant::now();
                    hub.set_capture_flows(acc.drain(secs));
                    // Refresh the MAC -> device id map once a second.
                    ctx_ids = devices.device_map().values().map(|d| (d.mac, d.id.clone())).collect();
                    self_id = ctx_ids.get(&sel.mac).cloned().unwrap_or_else(|| sel.mac.to_string());
                    if hub.selected().map(|s| s.name) != Some(sel.name.clone()) {
                        why_stopped = Some("the scanned interface changed".into());
                        break;
                    }
                }
                line = lines.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            if let Some(f) = capture::parse_tcpdump_line(&l) {
                                let ctx = capture::Ctx { self_mac: sel.mac, self_id: &self_id, net: sel.net, ids: &ctx_ids };
                                if let Some(a) = capture::classify_frame(&f, &ctx) {
                                    acc.add(&a);
                                }
                            }
                        }
                        _ => {
                            let mut err = String::new();
                            if let Some(e) = child.stderr.take() {
                                let _ = e.take(8 * 1024).read_to_string(&mut err).await;
                            }
                            why_stopped = Some(capture::unavailable_reason(os, true, &err));
                            break;
                        }
                    }
                }
            }
        }
        let _ = child.start_kill();
        let _ = child.wait().await;
        hub.set_capture_status(
            false,
            Some(why_stopped.unwrap_or_else(|| "tcpdump stopped".to_string())),
        );
        tokio::select! { _ = shutdown.cancelled() => return, _ = tokio::time::sleep(Duration::from_secs(5)) => {} }
    }
}

/// Spawn `tcpdump` (headers only, non-promiscuous, summaries to stdout) and
/// confirm it actually opened the device; `Err` carries the user-facing reason.
async fn start_tcpdump(os: Os, iface: &str) -> Result<tokio::process::Child, String> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    if os == Os::Windows {
        return Err(capture::unavailable_reason(os, false, ""));
    }
    let Some(exe) = first_existing(&tcpdump_candidates(os)) else {
        return Err(capture::unavailable_reason(os, false, ""));
    };
    if !capture::valid_iface_arg(iface) {
        return Err(format!(
            "capture is not possible on an interface named {iface:?}"
        ));
    }
    let mut cmd = tokio::process::Command::new(exe);
    // -p: not promiscuous (only our own traffic plus broadcast/multicast)
    // -s 96: headers only, payload is never even copied from the kernel
    // -e -q -nn -tt -l: Ethernet header summary, quiet, numeric, line-buffered
    cmd.args([
        "-i", iface, "-nn", "-e", "-q", "-l", "-p", "-s", "96", "-tt",
    ])
    .env_clear();
    for (k, v) in crate::platform::minimal_env(os, &crate::platform::system_root()) {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("tcpdump could not be started: {e}"))?;
    // If it is going to fail (no permission, no such device) it does so at once.
    match tokio::time::timeout(Duration::from_millis(1200), child.wait()).await {
        Err(_) => Ok(child),
        Ok(_) => {
            let mut err = String::new();
            if let Some(e) = child.stderr.take() {
                let _ = e.take(8 * 1024).read_to_string(&mut err).await;
            }
            Err(capture::unavailable_reason(os, true, &err))
        }
    }
}
