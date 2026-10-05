//! The scan loop: collect observations, merge, publish.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::discovery::arp_parse::ArpEntry;
use crate::discovery::keyed::Keyed;
use crate::discovery::mdns::{MdnsService, MdnsSource, collect_mdns};
use crate::discovery::ping::{PingMethod, Verdict, classify_failure, sweep_binary, sweep_dgram};
use crate::discovery::ssdp::ssdp_outcome;
use crate::discovery::tcp_probe;
use crate::enrich::oui::OuiDb;
use crate::model::{Device, DeviceEvent, DeviceMap, MacAddr, MdnsHit, ScanStatus, SsdpObservation};
use crate::net::iface_select::Selected;
use crate::net::subnet::enumerate_targets;
use crate::state::hub::Hub;
use crate::state::merge::{MergeCtx, ScanInputs, diff, merge, network_id};
use crate::store::Store;

/// Raw observations from the I/O adapters for one cycle.
#[derive(Clone, Debug)]
pub struct Collected {
    pub selected: Selected,
    pub arp: Vec<ArpEntry>,
    pub ping_alive: BTreeSet<Ipv4Addr>,
    pub tcp_alive: BTreeSet<Ipv4Addr>,
    pub mdns: Vec<MdnsHit>,
    pub ssdp: Vec<SsdpObservation>,
    pub local_macs: BTreeSet<MacAddr>,
    pub mdns_available: bool,
    pub ping_method: String,
    pub warnings: Vec<String>,
}

impl Default for Collected {
    fn default() -> Self {
        Self {
            selected: Selected {
                name: String::new(),
                ip: std::net::Ipv4Addr::UNSPECIFIED,
                net: ipnet::Ipv4Net::default(),
                mac: crate::model::MacAddr([0; 6]),
                gateway_ip: None,
            },
            arp: vec![],
            ping_alive: BTreeSet::new(),
            tcp_alive: BTreeSet::new(),
            mdns: vec![],
            ssdp: vec![],
            local_macs: BTreeSet::new(),
            mdns_available: false,
            ping_method: String::new(),
            warnings: vec![],
        }
    }
}

/// A fast look at the network: the selected interface and its ARP entries.
pub type Peek = Option<(Selected, Vec<ArpEntry>)>;

/// Source of observations (injected so cycles can be tested without a network).
pub trait Collector: Send + Sync {
    /// A fast look (interface + ARP cache, no probing) used at startup to
    /// identify the network and restore its history before the first scan.
    fn peek(&self) -> Pin<Box<dyn Future<Output = Peek> + Send + '_>> {
        Box::pin(async { None })
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<Collected, String>> + Send + '_>>;
}

#[derive(Clone, Debug)]
pub struct ScannerConfig {
    pub interval_s: u64,
    pub offline_after_ms: i64,
    pub new_window_ms: i64,
    pub max_devices: usize,
}

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

pub struct Scanner {
    collector: Box<dyn Collector>,
    hub: Arc<Hub>,
    cfg: ScannerConfig,
    store: Option<Arc<Store>>,
    /// Only ever set from an observed gateway MAC (or a gateway-less subnet).
    network_id: Option<String>,
    prev: DeviceMap,
    baseline_at: Option<i64>,
    /// The interface of the last successful collect, so a failed one can still age devices.
    last_selected: Option<Selected>,
    clock: Clock,
}

impl Scanner {
    pub fn new(collector: Box<dyn Collector>, hub: Arc<Hub>, cfg: ScannerConfig) -> Self {
        Self {
            collector,
            hub,
            cfg,
            store: None,
            network_id: None,
            prev: DeviceMap::new(),
            baseline_at: None,
            last_selected: None,
            clock: Box::new(now_ms),
        }
    }

    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Replace the wall clock used for `scan_finished_at` (tests).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn merge_ctx(&self, now: i64) -> MergeCtx {
        MergeCtx {
            now,
            baseline_at: self.baseline_at,
            offline_after_ms: self.cfg.offline_after_ms,
            new_window_ms: self.cfg.new_window_ms,
            oui: Some(OuiDb::embedded()),
            max_devices: self.cfg.max_devices,
        }
    }

    /// Identify the network from the ARP cache and restore its history so
    /// that known devices show up (offline) before the first scan finishes.
    pub async fn init(&mut self, now: i64) {
        if let Some((sel, arp)) = self.collector.peek().await
            && let Some(nid) = network_id(&sel, &arp)
        {
            self.switch_network(nid, &sel, now).await;
            self.hub.seed(&self.prev);
        }
    }

    /// Start (or switch to) a network: load its history and baseline.
    async fn switch_network(&mut self, nid: String, sel: &Selected, now: i64) {
        let (history, baseline) = match self.store.clone() {
            Some(store) => {
                let id = nid.clone();
                let loaded = tokio::task::spawn_blocking(move || {
                    let rows = store.load(&id)?;
                    let baseline = store
                        .get_meta(&id, "baseline_at")?
                        .and_then(|v| v.parse::<i64>().ok());
                    Ok::<_, crate::store::StoreError>((rows, baseline))
                })
                .await;
                match loaded {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        tracing::warn!("could not load history: {e}");
                        (vec![], None)
                    }
                    Err(e) => {
                        tracing::warn!("history load task failed: {e}");
                        (vec![], None)
                    }
                }
            }
            None => (vec![], None),
        };
        let mut restored: DeviceMap = history
            .into_iter()
            .filter_map(|r| r.into_device())
            .map(|d| (d.id.clone(), d))
            .collect();
        // First identification of the network: what we already saw this run
        // (before the gateway MAC was observable) is kept, not thrown away.
        if self.network_id.is_none() {
            for (id, d) in &self.prev {
                restored.insert(id.clone(), d.clone());
            }
        }
        self.baseline_at = baseline;
        let ctx = self.merge_ctx(now);
        // Merging nothing normalises the restored devices (self, gateway, kinds, online state).
        let (map, _) = merge(&restored, &ScanInputs::new(sel.clone(), now), &ctx);
        self.prev = map;
        self.network_id = Some(nid);
    }

    /// Write the device map (and the baseline, when newly set) to the store.
    async fn persist(&self, baseline_to_set: Option<i64>, warnings: &mut Vec<String>) {
        let (Some(store), Some(nid)) = (self.store.clone(), self.network_id.clone()) else {
            return;
        };
        let devices: Vec<Device> = self.prev.values().cloned().collect();
        let r = tokio::task::spawn_blocking(move || {
            store.upsert_many(&nid, &devices)?;
            if let Some(b) = baseline_to_set {
                store.set_meta(&nid, "baseline_at", &b.to_string())?;
            }
            Ok::<_, crate::store::StoreError>(())
        })
        .await;
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!("could not save history: {e}");
                warnings.push(format!("history not saved: {e}"));
            }
            Err(e) => warnings.push(format!("history not saved: {e}")),
        }
    }

    /// Events relative to what clients already have (the hub), not to our
    /// private history, so restored devices still get announced.
    fn events_vs_hub(&self) -> Vec<DeviceEvent> {
        let known = self.hub.device_map();
        let mut events: Vec<DeviceEvent> = known
            .keys()
            .filter(|id| !self.prev.contains_key(*id))
            .map(|id| DeviceEvent::Removed(id.clone()))
            .collect();
        events.extend(diff(&known, &self.prev));
        events
    }

    /// One full cycle. Never panics or returns an error: a failing source
    /// becomes a warning on the status, and the devices keep ageing.
    pub async fn run_cycle(&mut self, now: i64) {
        let collected = match self.collector.collect().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("scan failed: {e}");
                // No observations, but time still passes: age devices out and
                // expire the "new" window with an evidence-free merge.
                if let Some(sel) = self.last_selected.clone() {
                    let (next, _) =
                        merge(&self.prev, &ScanInputs::new(sel, now), &self.merge_ctx(now));
                    self.prev = next;
                }
                let events = self.events_vs_hub();
                let mut status = self.hub.snapshot().status.unwrap_or_default();
                status.scan_started_at = now;
                status.scan_finished_at = (self.clock)().max(now);
                status.devices = self.prev.len();
                status.online = self.prev.values().filter(|d| d.online).count();
                status.warnings = vec![e];
                self.hub.apply_scan(&self.prev, events, status);
                return;
            }
        };
        let sel = collected.selected.clone();
        // The network is only (re)identified from an observed gateway MAC. An
        // empty or failed ARP read keeps the current identity.
        let observed = network_id(&sel, &collected.arp);
        if let Some(nid) = observed.clone()
            && self.network_id.as_deref() != Some(nid.as_str())
        {
            if self.network_id.is_some() {
                tracing::info!("network changed (id {nid}); switching history");
            }
            self.switch_network(nid, &sel, now).await;
        }
        self.last_selected = Some(sel.clone());

        let mut inputs = ScanInputs::new(sel.clone(), now);
        inputs.arp = collected.arp;
        inputs.ping_alive = collected.ping_alive;
        inputs.tcp_alive = collected.tcp_alive;
        inputs.mdns = collected.mdns;
        inputs.ssdp = collected.ssdp;
        inputs.local_macs = collected.local_macs;
        let (next, _) = merge(&self.prev, &inputs, &self.merge_ctx(now));
        self.prev = next;
        let events = self.events_vs_hub();

        let mut warnings = collected.warnings;
        // Baseline and persistence only on a cycle where the network identity
        // was actually observed (works with or without a store).
        let mut baseline_to_set = None;
        if observed.is_some() {
            if self.baseline_at.is_none() {
                self.baseline_at = Some(now);
                baseline_to_set = Some(now);
            }
            self.persist(baseline_to_set, &mut warnings).await;
        }

        if self.prev.len() >= self.cfg.max_devices
            && inputs.arp.iter().any(|e| {
                e.mac
                    .is_some_and(|m| !self.prev.contains_key(&m.to_string()))
            })
        {
            warnings.push(format!(
                "device limit ({}) reached; new devices are being ignored",
                self.cfg.max_devices
            ));
        }

        let status = ScanStatus {
            scan_started_at: now,
            scan_finished_at: (self.clock)().max(now),
            devices: self.prev.len(),
            online: self.prev.values().filter(|d| d.online).count(),
            iface: sel.name.clone(),
            net: sel.net.to_string(),
            gateway: sel.gateway_ip.map(|g| g.to_string()),
            interval_s: self.cfg.interval_s,
            ping_method: collected.ping_method,
            mdns_available: collected.mdns_available,
            warnings,
        };
        self.hub.apply_scan(&self.prev, events, status);
    }

    pub async fn run(mut self, shutdown: CancellationToken) {
        self.init(now_ms()).await;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(self.cfg.interval_s));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tick.tick() => {}
            }
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = self.run_cycle(now_ms()) => {}
            }
        }
        tracing::info!("scanner stopped");
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub const LOCAL_NETWORK_HINT: &str = "macOS appears to be blocking access to the local network. Open System Settings > Privacy & Security > Local Network and enable the app you launched rhizome from (Terminal, iTerm, VS Code, ...), then restart rhizome.";

/// The real collector: ping sweep (fills the ARP cache), then ARP, then TCP probes.
pub struct LiveCollector {
    pub iface_override: Option<String>,
    pub max_hosts: usize,
    pub tcp_probe: bool,
    /// mDNS entries seen within this window count as liveness; older ones only enrich.
    pub fresh_window: Duration,
    use_ping_binary: AtomicBool,
    /// mDNS follows the selected interface; a failed start is never cached.
    mdns: Keyed<Arc<dyn MdnsSource>>,
}

impl LiveCollector {
    pub fn new(
        iface_override: Option<String>,
        max_hosts: usize,
        tcp_probe: bool,
        fresh_window: Duration,
    ) -> Self {
        Self {
            iface_override,
            max_hosts,
            tcp_probe,
            fresh_window,
            use_ping_binary: AtomicBool::new(false),
            mdns: Keyed::new(),
        }
    }

    /// Start mDNS for `sel`'s interface (or reuse it); restarts when the
    /// interface changes. Must run inside the tokio runtime.
    fn mdns_for(&self, sel: &Selected) -> Result<Arc<dyn MdnsSource>, String> {
        self.mdns.get_or_start(&sel.name, || {
            MdnsService::start(&sel.name, sel.net).map(|s| Arc::new(s) as Arc<dyn MdnsSource>)
        })
    }
}

impl Collector for LiveCollector {
    fn peek(&self) -> Pin<Box<dyn Future<Output = Peek> + Send + '_>> {
        Box::pin(async move {
            let (selected, _) =
                crate::net::iface::select_with_locals_now(self.iface_override.as_deref()).ok()?;
            let arp = crate::discovery::arp::read_arp(&selected.name).await.ok()?;
            // Start listening early so the first cycle already has answers.
            let _ = self.mdns_for(&selected);
            Some((selected, arp))
        })
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<Collected, String>> + Send + '_>> {
        Box::pin(async move {
            // One OS snapshot decides both the interface and this machine's live NICs.
            let (selected, local_macs) =
                crate::net::iface::select_with_locals_now(self.iface_override.as_deref())
                    .map_err(|e| e.to_string())?;
            let mut warnings = vec![];
            let targets = enumerate_targets(
                selected.net,
                selected.ip,
                selected.gateway_ip,
                self.max_hosts,
            );

            let mut method = if self.use_ping_binary.load(Ordering::Relaxed) {
                PingMethod::PingBinary
            } else {
                PingMethod::SurgeDgram
            };
            let sweep = if method == PingMethod::SurgeDgram {
                match sweep_dgram(
                    selected.net,
                    &targets,
                    selected.gateway_ip,
                    Duration::from_millis(1000),
                )
                .await
                {
                    Ok(r) => r,
                    Err(f) => {
                        if classify_failure(f) == Verdict::FallbackToPingBinary {
                            tracing::warn!(
                                "unprivileged ICMP socket unavailable (errno {:?}); falling back to /sbin/ping",
                                f.errno
                            );
                            self.use_ping_binary.store(true, Ordering::Relaxed);
                        }
                        method = PingMethod::PingBinary;
                        sweep_binary(selected.net, &targets, selected.gateway_ip).await
                    }
                }
            } else {
                sweep_binary(selected.net, &targets, selected.gateway_ip).await
            };
            if sweep
                .failures
                .iter()
                .any(|f| classify_failure(*f) == Verdict::LocalNetworkDenied)
            {
                tracing::warn!("{LOCAL_NETWORK_HINT}");
                warnings.push(LOCAL_NETWORK_HINT.to_string());
            }

            let arp = match crate::discovery::arp::read_arp(&selected.name).await {
                Ok(a) => a,
                Err(e) => {
                    warnings.push(format!("arp: {e}"));
                    vec![]
                }
            };

            let (ssdp, ssdp_warning) = ssdp_outcome(
                crate::discovery::ssdp::search(selected.ip, selected.net, Duration::from_secs(3))
                    .await,
            );
            if let Some(w) = ssdp_warning {
                tracing::warn!("{w}");
                warnings.push(w);
            }

            let mut tcp_alive = BTreeSet::new();
            if self.tcp_probe {
                let silent: Vec<Ipv4Addr> = arp
                    .iter()
                    .filter(|e| {
                        e.mac.is_some() && e.ip != selected.ip && !sweep.alive.contains(&e.ip)
                    })
                    .map(|e| e.ip)
                    .collect();
                tcp_alive = tcp_probe::probe(selected.net, &silent).await;
            }
            // Read mDNS last: by now it has been listening through the sweep and SSDP window.
            let mdns_src = self.mdns_for(&selected);
            let (mdns, mdns_available, mdns_warning) = collect_mdns(&mdns_src, self.fresh_window);
            warnings.extend(mdns_warning);

            Ok(Collected {
                selected,
                arp,
                ping_alive: sweep.alive,
                tcp_alive,
                mdns,
                ssdp,
                local_macs,
                mdns_available,
                ping_method: method.as_str().to_string(),
                warnings,
            })
        })
    }
}
