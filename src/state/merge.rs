//! Pure merge of scan observations into device state.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::discovery::arp_parse::ArpEntry;
use crate::enrich::classify::{ClassifyInput, classify};
use crate::enrich::oui::OuiDb;
use crate::model::{
    Device, DeviceEvent, DeviceMap, HostInfo, MacAddr, MdnsHit, SsdpObservation, TxtSourced,
};
use crate::net::iface_select::Selected;
use crate::net::subnet::is_scan_target;

/// Per-IP SSDP facts: (servers, search targets, locations).
type SsdpFacts<'a> = (BTreeSet<&'a str>, BTreeSet<&'a str>, BTreeSet<&'a str>);

pub const MAX_SSDP_TYPES: usize = 16;
pub const DEFAULT_MAX_DEVICES: usize = 2048;
pub const DEFAULT_NEW_WINDOW_MS: i64 = 10 * 60 * 1000;

/// Everything observed in one scan cycle.
#[derive(Clone, Debug)]
pub struct ScanInputs {
    pub arp: Vec<ArpEntry>,
    pub ping_alive: BTreeSet<Ipv4Addr>,
    pub tcp_alive: BTreeSet<Ipv4Addr>,
    pub mdns: Vec<MdnsHit>,
    pub ssdp: Vec<SsdpObservation>,
    /// MACs of every interface of this machine (a Mac can be on one subnet through several).
    pub local_macs: BTreeSet<MacAddr>,
    /// Extra facts per IP (UPnP description, gateway DNS, NetBIOS, ping RTT/TTL).
    pub host_info: BTreeMap<Ipv4Addr, HostInfo>,
    pub selected: Selected,
    pub scan_started_at: i64,
}

impl ScanInputs {
    pub fn new(selected: Selected, scan_started_at: i64) -> Self {
        Self {
            arp: vec![],
            ping_alive: BTreeSet::new(),
            tcp_alive: BTreeSet::new(),
            mdns: vec![],
            ssdp: vec![],
            local_macs: BTreeSet::new(),
            host_info: BTreeMap::new(),
            selected,
            scan_started_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MergeCtx {
    pub now: i64,
    /// `None` until the first scan of a network has completed.
    pub baseline_at: Option<i64>,
    pub offline_after_ms: i64,
    pub new_window_ms: i64,
    /// Vendor database; `None` disables vendor lookup.
    pub oui: Option<&'static OuiDb>,
    /// Hard cap on devices per network; new MACs beyond it are ignored.
    pub max_devices: usize,
}

impl MergeCtx {
    pub fn new(now: i64) -> Self {
        Self {
            now,
            baseline_at: None,
            offline_after_ms: 90_000,
            new_window_ms: DEFAULT_NEW_WINDOW_MS,
            oui: None,
            max_devices: DEFAULT_MAX_DEVICES,
        }
    }
}

/// Fold one scan into the previous device state.
///
/// Devices absent from this scan are kept (they age to offline). The only
/// liveness evidence in this function is what the scan actually observed;
/// ARP presence alone proves nothing because the OS cache lingers.
/// Identifies a network for history scoping: the gateway's MAC when ARP knows
/// it, else the subnet itself.
pub fn network_id(sel: &Selected, arp: &[ArpEntry]) -> Option<String> {
    match sel.gateway_ip {
        // No gateway on this segment: the subnet itself is the stable identity.
        None => Some(format!("net:{}", sel.net)),
        // A gateway exists: the network is only known once its MAC was observed.
        // A missing/incomplete entry means "unknown right now", not "another network".
        Some(gw) => arp
            .iter()
            .find(|e| e.ip == gw)
            .and_then(|e| e.mac)
            .map(|m| m.to_string()),
    }
}

pub fn merge(
    prev: &DeviceMap,
    inputs: &ScanInputs,
    ctx: &MergeCtx,
) -> (DeviceMap, Vec<DeviceEvent>) {
    let now = ctx.now;
    let sel = &inputs.selected;
    let mut next = prev.clone();

    // This machine comes from the interface, never from ARP. (Inserted before
    // the device cap is applied so it can never be crowded out.)
    let self_id = sel.mac.to_string();
    let me = next
        .entry(self_id.clone())
        .or_insert_with(|| blank_device(sel.mac, sel.ip, now));
    me.ip = sel.ip;
    me.last_seen = now;

    // mDNS knowledge per IP, merged deterministically (BTree ordering). All
    // hits enrich; only hits observed in this scan window count as liveness.
    let mut mdns_by_ip: BTreeMap<Ipv4Addr, (BTreeSet<&str>, BTreeSet<&str>)> = BTreeMap::new();
    let mut mdns_fresh: BTreeSet<Ipv4Addr> = BTreeSet::new();
    for h in &inputs.mdns {
        let slot = mdns_by_ip.entry(h.ip).or_default();
        if let Some(n) = h.hostname.as_deref() {
            slot.0.insert(n);
        }
        slot.1.extend(h.service_types.iter().map(String::as_str));
        if h.fresh {
            mdns_fresh.insert(h.ip);
        }
    }

    // SSDP, only from in-subnet unicast sources (anything else is dropped).
    let mut ssdp_by_ip: BTreeMap<Ipv4Addr, SsdpFacts> = BTreeMap::new();
    for o in inputs.ssdp.iter().filter(|o| is_scan_target(o.ip, sel.net)) {
        let slot = ssdp_by_ip.entry(o.ip).or_default();
        slot.0.extend(o.hit.server.as_deref());
        slot.1.extend(o.hit.st.as_deref());
        slot.2.extend(o.hit.location.as_deref());
    }

    let alive = |ip: &Ipv4Addr| {
        inputs.ping_alive.contains(ip)
            || inputs.tcp_alive.contains(ip)
            || mdns_fresh.contains(ip)
            || ssdp_by_ip.contains_key(ip)
    };

    // ARP, grouped by MAC (one MAC can legitimately have several IPs), in-subnet
    // only: link-local or foreign-subnet entries are never probed so never devices.
    let mut by_mac: BTreeMap<MacAddr, BTreeSet<Ipv4Addr>> = BTreeMap::new();
    for e in &inputs.arp {
        let Some(mac) = e.mac else { continue };
        if mac == sel.mac || e.ip == sel.ip || !is_scan_target(e.ip, sel.net) {
            continue; // the permanent self entry, or not ours to track
        }
        by_mac.entry(mac).or_default().insert(e.ip);
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(self_id.clone());
    let mut ips_of: BTreeMap<String, Vec<Ipv4Addr>> = BTreeMap::new();
    ips_of.insert(self_id.clone(), vec![sel.ip]);

    for (mac, ips) in &by_mac {
        let id = mac.to_string();
        let known = prev.get(&id);
        if known.is_none() && next.len() >= ctx.max_devices {
            continue; // device cap reached: ignore new MACs
        }
        let alive_ips: Vec<Ipv4Addr> = ips.iter().copied().filter(|ip| alive(ip)).collect();
        // Prefer an address that answered, then keep the previous one while it
        // is still listed (no flapping), then the lowest.
        let chosen = alive_ips
            .first()
            .copied()
            .or_else(|| known.map(|k| k.ip).filter(|kip| ips.contains(kip)))
            .or_else(|| ips.iter().next().copied())
            .expect("a MAC group is never empty");
        let dev = next
            .entry(id.clone())
            .or_insert_with(|| blank_device(*mac, chosen, now));
        // A new MAC, or an address we have not seen it at, counts as evidence.
        let ip_is_new = known.is_none_or(|k| !ips.contains(&k.ip));
        dev.ip = chosen;
        if ip_is_new || !alive_ips.is_empty() {
            dev.last_seen = now;
        }
        seen.insert(id.clone());
        ips_of.insert(id, ips.iter().copied().collect());
    }

    // Join mDNS and SSDP through any of a device's addresses; only to devices
    // ARP (or the interface) already knows.
    for (id, d) in next.iter_mut().filter(|(id, _)| seen.contains(*id)) {
        let ips = ips_of.get(id).cloned().unwrap_or_else(|| vec![d.ip]);
        let mut names: BTreeSet<&str> = BTreeSet::new();
        let mut services: BTreeSet<&str> = BTreeSet::new();
        let mut servers: BTreeSet<&str> = BTreeSet::new();
        let mut types: BTreeSet<&str> = BTreeSet::new();
        let mut locations: BTreeSet<&str> = BTreeSet::new();
        let mut txt_names: BTreeSet<&str> = BTreeSet::new();
        let mut txt_models: BTreeSet<&str> = BTreeSet::new();
        let mut txt_makers: BTreeSet<&str> = BTreeSet::new();
        for h in inputs.mdns.iter().filter(|h| ips.contains(&h.ip)) {
            txt_names.extend(h.friendly_name.as_deref());
            txt_models.extend(h.model.as_deref());
            txt_makers.extend(h.manufacturer.as_deref());
        }
        for ip in &ips {
            if let Some((n, s)) = mdns_by_ip.get(ip) {
                names.extend(n);
                services.extend(s);
            }
            if let Some((sv, t, l)) = ssdp_by_ip.get(ip) {
                servers.extend(sv);
                types.extend(t);
                locations.extend(l);
            }
        }
        if let Some(n) = names.iter().next() {
            d.hostname = Some((*n).to_string());
            d.hostname_source = Some("mdns".to_string());
        }
        if !services.is_empty() {
            d.services = services.iter().map(|s| s.to_string()).collect();
        }
        if let Some(s) = servers.iter().next() {
            d.ssdp_server = Some((*s).to_string());
        }
        if !types.is_empty() {
            d.ssdp_types = types
                .iter()
                .take(MAX_SSDP_TYPES)
                .map(|t| t.to_string())
                .collect();
        }
        if let Some(l) = locations.iter().next() {
            d.ssdp_location = Some((*l).to_string());
        }
        // Identity. UPnP (source-verified) wins and replaces exactly; mDNS TXT is
        // unverified and may only fill what no verified value holds.
        let upnp = ips
            .iter()
            .filter_map(|ip| inputs.host_info.get(ip))
            .find(|h| h.upnp_answered);
        if let Some(h) = upnp {
            d.friendly_name = h.friendly_name.clone();
            d.manufacturer = h.manufacturer.clone();
            d.model = h.model.clone();
            d.txt_sourced = TxtSourced::default();
        }
        // Per-host extras from the other sources: first IP with a value wins.
        for ip in &ips {
            let Some(h) = inputs.host_info.get(ip) else {
                continue;
            };
            if upnp.is_none() {
                // not a full description: any verified value that is present still applies
                for (slot, new, flag) in [
                    (
                        &mut d.friendly_name,
                        &h.friendly_name,
                        &mut d.txt_sourced.friendly_name,
                    ),
                    (
                        &mut d.manufacturer,
                        &h.manufacturer,
                        &mut d.txt_sourced.manufacturer,
                    ),
                    (&mut d.model, &h.model, &mut d.txt_sourced.model),
                ] {
                    if new.is_some() {
                        *slot = new.clone();
                        *flag = false;
                    }
                }
            }
            fill(&mut d.dns_name, &h.dns_name);
            fill(&mut d.netbios_name, &h.netbios_name);
            fill(&mut d.os_hint, &h.os_hint);
        }
        if ips
            .iter()
            .filter_map(|ip| inputs.host_info.get(ip))
            .any(|h| h.dns_cleared)
            && !ips
                .iter()
                .filter_map(|ip| inputs.host_info.get(ip))
                .any(|h| h.dns_name.is_some())
        {
            d.dns_name = None;
        }
        if ips
            .iter()
            .filter_map(|ip| inputs.host_info.get(ip))
            .any(|h| h.netbios_cleared)
            && !ips
                .iter()
                .filter_map(|ip| inputs.host_info.get(ip))
                .any(|h| h.netbios_name.is_some())
        {
            d.netbios_name = None;
        }
        // mDNS TXT: fills an empty slot or replaces an earlier TXT value, never a verified one.
        for (slot, new, flag) in [
            (
                &mut d.friendly_name,
                txt_names.iter().next(),
                &mut d.txt_sourced.friendly_name,
            ),
            (
                &mut d.manufacturer,
                txt_makers.iter().next(),
                &mut d.txt_sourced.manufacturer,
            ),
            (
                &mut d.model,
                txt_models.iter().next(),
                &mut d.txt_sourced.model,
            ),
        ] {
            if let Some(v) = new
                && (slot.is_none() || *flag)
            {
                *slot = Some((*v).to_string());
                *flag = true;
            }
        }
        d.rtt_ms = inputs.host_info.get(&d.ip).and_then(|h| h.rtt_ms);
    }
    // A device that was not seen this scan has no latest round-trip time.
    for (id, d) in next.iter_mut().filter(|(id, _)| !seen.contains(*id)) {
        let _ = id;
        d.rtt_ms = None;
    }

    // A local interface that is up is alive by definition.
    for d in next
        .values_mut()
        .filter(|d| inputs.local_macs.contains(&d.mac))
    {
        d.last_seen = now;
    }

    // Self flags: the selected interface is the primary self (always online);
    // this machine's other interfaces are also "this machine" but need evidence.
    for (id, d) in next.iter_mut() {
        d.is_self = *id == self_id || inputs.local_macs.contains(&d.mac);
    }

    // An IP now claimed by a seen device cannot also be the gateway of a stale one.
    let claimed: BTreeMap<Ipv4Addr, String> = next
        .iter()
        .filter(|(id, _)| seen.contains(*id))
        .map(|(id, d)| (d.ip, id.clone()))
        .collect();
    for (id, d) in next.iter_mut() {
        let stale_conflict = !seen.contains(id) && claimed.contains_key(&d.ip);
        d.is_gateway = !stale_conflict && Some(d.ip) == sel.gateway_ip;
        d.online = d.id == self_id || now - d.last_seen < ctx.offline_after_ms;
        // This machine is never "new", whichever interface it is using.
        d.is_new = !d.is_self
            && ctx.baseline_at.is_some_and(|b| d.first_seen > b)
            && now - d.first_seen < ctx.new_window_ms;
        d.randomized_mac = d.mac.is_locally_administered();
        if d.randomized_mac {
            d.vendor = None; // a private address says nothing about the maker
        } else if let Some(v) = ctx.oui.and_then(|db| db.lookup(d.mac)) {
            d.vendor = Some(v.to_string());
        }
        d.kind = classify(&ClassifyInput {
            vendor: d.vendor.as_deref(),
            hostname: d.hostname.as_deref(),
            services: &d.services,
            ssdp_server: d.ssdp_server.as_deref(),
            ssdp_types: &d.ssdp_types,
            // mDNS-TXT-only identity is unverified and never classifies a device.
            friendly_name: d
                .friendly_name
                .as_deref()
                .filter(|_| !d.txt_sourced.friendly_name),
            manufacturer: d
                .manufacturer
                .as_deref()
                .filter(|_| !d.txt_sourced.manufacturer),
            model: d.model.as_deref().filter(|_| !d.txt_sourced.model),
            dns_name: d.dns_name.as_deref(),
            netbios_name: d.netbios_name.as_deref(),
            is_gw: d.is_gateway,
            is_self: d.is_self,
        });
    }

    let events = diff(prev, &next);
    (next, events)
}

/// Overwrite with a newly reported value (the source is authoritative).
fn fill(slot: &mut Option<String>, new: &Option<String>) {
    if new.is_some() {
        *slot = new.clone();
    }
}

fn blank_device(mac: MacAddr, ip: Ipv4Addr, now: i64) -> Device {
    Device::new(mac, ip, now)
}

/// Upserts for every device that changed, ignoring `last_seen` alone (it moves
/// every scan; clients only need it when a device flips state).
pub fn diff(prev: &DeviceMap, next: &DeviceMap) -> Vec<DeviceEvent> {
    next.iter()
        .filter(|(id, d)| match prev.get(*id) {
            None => true,
            Some(p) => {
                let mut p = p.clone();
                p.last_seen = d.last_seen;
                // Latency jitter is not news; a real change or a reply appearing/vanishing is.
                if let (Some(a), Some(b)) = (p.rtt_ms, d.rtt_ms)
                    && (a - b).abs() <= (a.abs() * 0.5).max(1.0)
                {
                    p.rtt_ms = d.rtt_ms;
                }
                &p != *d
            }
        })
        .map(|(_, d)| DeviceEvent::Upsert(Box::new(d.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Device, DeviceKind};

    pub(crate) fn sel() -> Selected {
        Selected {
            name: "en0".into(),
            ip: "192.168.0.172".parse().unwrap(),
            net: "192.168.0.0/24".parse().unwrap(),
            mac: "32:00:00:00:00:84".parse().unwrap(),
            gateway_ip: Some("192.168.0.1".parse().unwrap()),
        }
    }

    pub(crate) fn arp(ip: &str, mac: &str) -> ArpEntry {
        ArpEntry {
            ip: ip.parse().unwrap(),
            mac: Some(mac.parse().unwrap()),
            iface: "en0".into(),
            permanent: false,
        }
    }

    fn inputs(entries: Vec<ArpEntry>, now: i64) -> ScanInputs {
        let mut i = ScanInputs::new(sel(), now);
        i.arp = entries;
        i
    }

    fn base_arp() -> Vec<ArpEntry> {
        vec![
            arp("192.168.0.1", "68:7f:f0:00:00:01"),
            arp("192.168.0.82", "2:0:0:0:0:62"),
            ArpEntry {
                permanent: true,
                ..arp("192.168.0.172", "32:00:00:00:00:84")
            },
        ]
    }

    fn upserts(ev: &[DeviceEvent]) -> Vec<&Device> {
        ev.iter()
            .filter_map(|e| {
                if let DeviceEvent::Upsert(d) = e {
                    Some(&**d)
                } else {
                    None
                }
            })
            .collect()
    }

    const T0: i64 = 1_000_000;

    #[test]
    fn new_macs_and_self_produce_upserts_without_duplicating_self() {
        let (map, ev) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        assert_eq!(map.len(), 3);
        assert_eq!(upserts(&ev).len(), 3);
        assert_eq!(map.values().filter(|d| d.is_self).count(), 1);
        let me = map.values().find(|d| d.is_self).unwrap();
        assert_eq!(me.ip.to_string(), "192.168.0.172");
        assert_eq!(me.kind, DeviceKind::ThisMachine);
    }

    #[test]
    fn gateway_is_flagged_by_ip() {
        let (map, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let gw = map.values().find(|d| d.is_gateway).unwrap();
        assert_eq!(gw.mac.to_string(), "68:7f:f0:00:00:01");
        assert_eq!(gw.kind, DeviceKind::Gateway);
        assert_eq!(map.values().filter(|d| d.is_gateway).count(), 1);
    }

    #[test]
    fn incomplete_arp_entries_are_ignored() {
        let mut a = base_arp();
        a.push(ArpEntry {
            mac: None,
            ..arp("192.168.0.173", "0:0:0:0:0:1")
        });
        let (map, _) = merge(&DeviceMap::new(), &inputs(a, T0), &MergeCtx::new(T0));
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn unchanged_scan_produces_no_events() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let (m2, ev) = merge(
            &m1,
            &inputs(base_arp(), T0 + 30_000),
            &MergeCtx::new(T0 + 30_000),
        );
        assert!(ev.is_empty(), "{ev:?}");
        assert_eq!(m2.len(), m1.len());
    }

    #[test]
    fn ip_change_produces_upsert_with_new_ip() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let mut a = base_arp();
        a[1] = arp("192.168.0.90", "2:0:0:0:0:62");
        let (m2, ev) = merge(&m1, &inputs(a, T0 + 30_000), &MergeCtx::new(T0 + 30_000));
        let ups = upserts(&ev);
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].ip.to_string(), "192.168.0.90");
        assert_eq!(m2.len(), 3);
    }

    #[test]
    fn ip_claimed_by_new_mac_keeps_old_device_with_last_ip() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let mut a = base_arp();
        a[1] = arp("192.168.0.82", "aa:bb:cc:dd:ee:01");
        let (m2, _) = merge(&m1, &inputs(a, T0 + 30_000), &MergeCtx::new(T0 + 30_000));
        assert_eq!(m2.len(), 4);
        let old = m2.get("02:00:00:00:00:62").unwrap();
        assert_eq!(old.ip.to_string(), "192.168.0.82");
        let new = m2.get("aa:bb:cc:dd:ee:01").unwrap();
        assert_eq!(new.ip.to_string(), "192.168.0.82");
    }

    #[test]
    fn vanished_device_stays_online_until_offline_after_then_goes_offline() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let gone: Vec<ArpEntry> = base_arp()
            .into_iter()
            .filter(|e| e.ip.to_string() != "192.168.0.82")
            .collect();

        let t1 = T0 + 60_000;
        let (m2, ev) = merge(&m1, &inputs(gone.clone(), t1), &MergeCtx::new(t1));
        assert!(m2["02:00:00:00:00:62"].online);
        assert!(ev.is_empty());

        let t2 = T0 + 90_000;
        let (m3, ev) = merge(&m2, &inputs(gone, t2), &MergeCtx::new(t2));
        assert!(!m3["02:00:00:00:00:62"].online);
        // ARP presence alone is not evidence, so everything without a probe ages out together.
        let ups = upserts(&ev);
        let flipped = ups
            .iter()
            .find(|d| d.id == "02:00:00:00:00:62")
            .expect("flip event for the vanished device");
        assert!(!flipped.online);
        assert!(ups.iter().all(|d| d.is_self || !d.online));
        assert_eq!(
            m3["02:00:00:00:00:62"].last_seen, T0,
            "last_seen freezes at last evidence"
        );
    }

    #[test]
    fn self_is_always_online() {
        let (m1, _) = merge(&DeviceMap::new(), &inputs(vec![], T0), &MergeCtx::new(T0));
        let far = T0 + 10_000_000_000;
        let (m2, _) = merge(&m1, &inputs(vec![], far), &MergeCtx::new(far));
        assert!(m2.values().find(|d| d.is_self).unwrap().online);
    }

    #[test]
    fn output_does_not_depend_on_input_order() {
        let mut a = base_arp();
        a.push(arp("192.168.0.194", "8c:fd:49:0:0:4"));
        let mut b = a.clone();
        b.reverse();
        let (m1, _) = merge(&DeviceMap::new(), &inputs(a, T0), &MergeCtx::new(T0));
        let (m2, _) = merge(&DeviceMap::new(), &inputs(b, T0), &MergeCtx::new(T0));
        assert_eq!(m1, m2);
    }

    #[test]
    fn first_seen_is_preserved_across_scans() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let (m2, _) = merge(
            &m1,
            &inputs(base_arp(), T0 + 30_000),
            &MergeCtx::new(T0 + 30_000),
        );
        assert_eq!(m2["02:00:00:00:00:62"].first_seen, T0);
    }

    // ---- this machine on several interfaces ----

    fn sel_en8() -> Selected {
        Selected {
            name: "en8".into(),
            ip: "192.168.0.173".parse().unwrap(),
            mac: "3c:e1:a1:00:00:53".parse().unwrap(),
            ..sel()
        }
    }

    #[test]
    fn stale_self_flag_is_cleared_when_the_selected_interface_changes() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        assert!(m1["32:00:00:00:00:84"].is_self);
        // Next cycle the default route moved to en8; ARP on en8 lists the old en0 as an ordinary host.
        let mut i = ScanInputs::new(sel_en8(), T0 + 30_000);
        i.arp = vec![
            arp("192.168.0.1", "68:7f:f0:00:00:01"),
            arp("192.168.0.172", "32:00:00:00:00:84"),
        ];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(T0 + 30_000));
        assert_eq!(
            m2.values().filter(|d| d.is_self).count(),
            1,
            "exactly one primary self"
        );
        assert!(m2["3c:e1:a1:00:00:53"].is_self);
        assert!(!m2["32:00:00:00:00:84"].is_self);
        assert_ne!(m2["32:00:00:00:00:84"].kind, DeviceKind::ThisMachine);
    }

    #[test]
    fn a_live_secondary_interface_is_this_machine_and_online() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let t1 = T0 + 600_000;
        let mut i = ScanInputs::new(sel_en8(), t1);
        i.arp = vec![arp("192.168.0.172", "32:00:00:00:00:84")];
        // The collector lists only interfaces that are up with an address on this subnet.
        i.local_macs = [
            "32:00:00:00:00:84".parse().unwrap(),
            "3c:e1:a1:00:00:53".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(t1));
        let other = &m2["32:00:00:00:00:84"];
        assert!(other.is_self);
        assert_eq!(other.kind, DeviceKind::ThisMachine);
        assert!(
            other.online,
            "an interface that is up is alive without needing a ping reply"
        );
        assert_eq!(other.last_seen, t1);
    }

    #[test]
    fn an_interface_that_is_no_longer_local_stops_being_self_and_ages_out() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let t1 = T0 + 600_000;
        let mut i = ScanInputs::new(sel_en8(), t1);
        i.arp = vec![arp("192.168.0.172", "32:00:00:00:00:84")];
        i.local_macs = ["3c:e1:a1:00:00:53".parse().unwrap()].into_iter().collect(); // en0 went away
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(t1));
        let gone = &m2["32:00:00:00:00:84"];
        assert!(!gone.is_self);
        assert!(!gone.online);
    }

    // ---- slice 7: SSDP ----

    use crate::model::SsdpHit;

    fn obs(ip: &str, server: Option<&str>, st: Option<&str>) -> SsdpObservation {
        SsdpObservation {
            ip: ip.parse().unwrap(),
            hit: SsdpHit {
                server: server.map(String::from),
                st: st.map(String::from),
                usn: None,
                location: Some("http://x/desc.xml".into()),
            },
        }
    }

    #[test]
    fn ssdp_hit_joins_by_ip_and_feeds_classification() {
        let mut i = inputs(base_arp(), T0);
        i.ssdp = vec![
            obs(
                "192.168.0.82",
                Some("Linux UPnP/1.0 Roku/9.4"),
                Some("upnp:rootdevice"),
            ),
            obs(
                "192.168.0.82",
                Some("Linux UPnP/1.0 Roku/9.4"),
                Some("urn:schemas-upnp-org:device:MediaRenderer:1"),
            ),
        ];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let d = &m["02:00:00:00:00:62"];
        assert_eq!(d.ssdp_server.as_deref(), Some("Linux UPnP/1.0 Roku/9.4"));
        assert_eq!(
            d.ssdp_types,
            vec![
                "upnp:rootdevice".to_string(),
                "urn:schemas-upnp-org:device:MediaRenderer:1".to_string()
            ]
        );
        assert_eq!(d.ssdp_location.as_deref(), Some("http://x/desc.xml"));
        assert_eq!(d.kind, DeviceKind::Tv);
    }

    #[test]
    fn ssdp_source_outside_the_subnet_is_dropped() {
        let mut i = inputs(base_arp(), T0);
        i.ssdp = vec![
            obs("8.8.8.8", Some("evil"), None),
            obs("192.168.1.50", Some("other-subnet"), None),
            obs("224.0.0.1", Some("mc"), None),
        ];
        i.arp.push(arp("192.168.1.50", "aa:bb:cc:dd:ee:50")); // even if ARP somehow listed it
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert!(
            m.values().all(|d| d.ssdp_server.is_none()),
            "{:?}",
            m.values().map(|d| &d.ssdp_server).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ssdp_for_an_ip_not_in_arp_is_not_a_device_and_ssdp_counts_as_evidence() {
        let mut i = inputs(base_arp(), T0);
        i.ssdp = vec![obs("192.168.0.222", Some("ghost"), None)];
        let (m1, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(m1.len(), 3);
        let now = T0 + 300_000;
        let mut i = inputs(base_arp(), now);
        i.ssdp = vec![obs("192.168.0.82", Some("x"), None)];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(now));
        assert!(m2["02:00:00:00:00:62"].online);
    }

    #[test]
    fn ssdp_fields_stick_when_a_scan_brings_none_and_order_does_not_matter() {
        let mut a = inputs(base_arp(), T0);
        a.ssdp = vec![
            obs("192.168.0.82", Some("b-server"), Some("t2")),
            obs("192.168.0.82", Some("a-server"), Some("t1")),
        ];
        let mut b = a.clone();
        b.ssdp.reverse();
        let (m1, _) = merge(&DeviceMap::new(), &a, &MergeCtx::new(T0));
        let (m2, _) = merge(&DeviceMap::new(), &b, &MergeCtx::new(T0));
        assert_eq!(m1, m2);
        assert_eq!(
            m1["02:00:00:00:00:62"].ssdp_server.as_deref(),
            Some("a-server")
        );
        let (m3, _) = merge(
            &m1,
            &inputs(base_arp(), T0 + 30_000),
            &MergeCtx::new(T0 + 30_000),
        );
        assert_eq!(
            m3["02:00:00:00:00:62"].ssdp_server.as_deref(),
            Some("a-server")
        );
    }

    #[test]
    fn ssdp_types_are_capped() {
        let mut i = inputs(base_arp(), T0);
        i.ssdp = (0..100)
            .map(|n| obs("192.168.0.82", None, Some(&format!("type-{n:03}"))))
            .collect();
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(m["02:00:00:00:00:62"].ssdp_types.len(), 16);
    }

    // ---- slice 6: mDNS ----

    fn hit(ip: &str, host: Option<&str>, services: &[&str]) -> MdnsHit {
        MdnsHit {
            ip: ip.parse().unwrap(),
            hostname: host.map(String::from),
            service_types: services.iter().map(|s| s.to_string()).collect(),
            fresh: true,
            ..Default::default()
        }
    }

    fn stale_hit(ip: &str, host: Option<&str>, services: &[&str]) -> MdnsHit {
        MdnsHit {
            fresh: false,
            ..hit(ip, host, services)
        }
    }

    #[test]
    fn mdns_hit_joins_by_ip_and_sets_hostname_and_services() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![hit(
            "192.168.0.82",
            Some("Anuragis-iPhone"),
            &["_companion-link", "_apple-mobdev2"],
        )];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let d = &m["02:00:00:00:00:62"];
        assert_eq!(d.hostname.as_deref(), Some("Anuragis-iPhone"));
        assert_eq!(d.hostname_source.as_deref(), Some("mdns"));
        assert_eq!(
            d.services,
            vec!["_apple-mobdev2".to_string(), "_companion-link".to_string()]
        );
        assert_eq!(d.kind, DeviceKind::Phone);
    }

    #[test]
    fn mdns_hit_for_an_ip_not_in_arp_is_not_a_device() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![hit("192.168.0.222", Some("ghost"), &["_ipp"])];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(m.len(), 3);
        assert!(m.values().all(|d| d.hostname.as_deref() != Some("ghost")));
    }

    #[test]
    fn cached_mdns_is_not_liveness_but_still_enriches() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![hit("192.168.0.82", Some("old-name"), &["_ipp"])];
        let (m1, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        // Much later the Chromecast is switched off: only a 15-minute cache entry remains.
        let now = T0 + 600_000;
        let mut i = inputs(base_arp(), now);
        i.mdns = vec![stale_hit(
            "192.168.0.82",
            Some("new-name"),
            &["_ipp", "_ssh"],
        )];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(now));
        let d = &m2["02:00:00:00:00:62"];
        assert!(
            !d.online,
            "a cached mDNS entry must not keep the device online"
        );
        assert_eq!(d.last_seen, T0, "and must not refresh last_seen");
        assert_eq!(
            d.hostname.as_deref(),
            Some("new-name"),
            "enrichment still applies"
        );
        assert_eq!(d.services, vec!["_ipp".to_string(), "_ssh".to_string()]);
    }

    #[test]
    fn mdns_hit_counts_as_liveness_evidence() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let now = T0 + 300_000;
        let mut i = inputs(base_arp(), now);
        i.mdns = vec![hit("192.168.0.82", None, &["_hap"])];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(now));
        assert!(m2["02:00:00:00:00:62"].online);
        assert!(!m2["68:7f:f0:00:00:01"].online);
    }

    #[test]
    fn mdns_hostname_replaces_older_hostname_and_services_stick_between_scans() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![hit("192.168.0.82", Some("old-name"), &["_ipp"])];
        let (m1, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let mut i = inputs(base_arp(), T0 + 30_000);
        i.mdns = vec![hit("192.168.0.82", Some("new-name"), &[])];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(T0 + 30_000));
        assert_eq!(
            m2["02:00:00:00:00:62"].hostname.as_deref(),
            Some("new-name")
        );
        assert_eq!(
            m2["02:00:00:00:00:62"].services,
            vec!["_ipp".to_string()],
            "services persist when a scan brings none"
        );
        let (m3, _) = merge(
            &m2,
            &inputs(base_arp(), T0 + 60_000),
            &MergeCtx::new(T0 + 60_000),
        );
        assert_eq!(
            m3["02:00:00:00:00:62"].hostname.as_deref(),
            Some("new-name"),
            "hostname persists when mDNS is silent"
        );
    }

    #[test]
    fn multiple_hits_for_one_ip_merge_deterministically() {
        let hits = vec![
            hit("192.168.0.82", Some("b-name"), &["_ssh"]),
            hit("192.168.0.82", Some("a-name"), &["_ipp"]),
        ];
        let mut i1 = inputs(base_arp(), T0);
        i1.mdns = hits.clone();
        let mut i2 = inputs(base_arp(), T0);
        i2.mdns = hits.into_iter().rev().collect();
        let (m1, _) = merge(&DeviceMap::new(), &i1, &MergeCtx::new(T0));
        let (m2, _) = merge(&DeviceMap::new(), &i2, &MergeCtx::new(T0));
        assert_eq!(m1, m2);
        assert_eq!(m1["02:00:00:00:00:62"].hostname.as_deref(), Some("a-name"));
        assert_eq!(
            m1["02:00:00:00:00:62"].services,
            vec!["_ipp".to_string(), "_ssh".to_string()]
        );
    }

    #[test]
    fn mdns_hostname_on_this_machine_from_its_own_ip_is_applied() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![hit("192.168.0.172", Some("my-mac"), &["_workstation"])];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(m["32:00:00:00:00:84"].hostname.as_deref(), Some("my-mac"));
        assert_eq!(m["32:00:00:00:00:84"].kind, DeviceKind::ThisMachine);
    }

    // ---- slice 5: baseline and "new" ----

    fn ctx_baseline(now: i64, baseline: Option<i64>) -> MergeCtx {
        MergeCtx {
            baseline_at: baseline,
            ..MergeCtx::new(now)
        }
    }

    #[test]
    fn everything_in_the_first_scan_is_not_new() {
        let (m, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &ctx_baseline(T0, None),
        );
        assert!(m.values().all(|d| !d.is_new));
    }

    #[test]
    fn a_later_arrival_is_new_until_the_window_expires() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &ctx_baseline(T0, None),
        );
        let mut a = base_arp();
        a.push(arp("192.168.0.99", "aa:bb:cc:dd:ee:99"));
        let t1 = T0 + 30_000;
        let (m2, ev) = merge(&m1, &inputs(a.clone(), t1), &ctx_baseline(t1, Some(T0)));
        assert!(m2["aa:bb:cc:dd:ee:99"].is_new);
        assert!(
            !m2["68:7f:f0:00:00:01"].is_new,
            "pre-baseline devices are never new"
        );
        assert!(
            upserts(&ev)
                .iter()
                .any(|d| d.id == "aa:bb:cc:dd:ee:99" && d.is_new)
        );

        let t2 = t1 + DEFAULT_NEW_WINDOW_MS - 1;
        let mut i = inputs(a.clone(), t2);
        i.ping_alive.insert("192.168.0.99".parse().unwrap());
        let (m3, _) = merge(&m2, &i, &ctx_baseline(t2, Some(T0)));
        assert!(m3["aa:bb:cc:dd:ee:99"].is_new);

        let t3 = t1 + DEFAULT_NEW_WINDOW_MS;
        let mut i = inputs(a, t3);
        i.ping_alive.insert("192.168.0.99".parse().unwrap());
        let (m4, ev) = merge(&m3, &i, &ctx_baseline(t3, Some(T0)));
        assert!(!m4["aa:bb:cc:dd:ee:99"].is_new);
        assert!(
            upserts(&ev)
                .iter()
                .any(|d| d.id == "aa:bb:cc:dd:ee:99" && !d.is_new),
            "the flip is announced"
        );
    }

    #[test]
    fn network_id_is_only_known_when_the_gateway_mac_was_observed() {
        assert_eq!(
            network_id(&sel(), &base_arp()).as_deref(),
            Some("68:7f:f0:00:00:01")
        );
        // A gateway exists but ARP did not show it: unknown, NOT a different network.
        assert_eq!(network_id(&sel(), &[]), None);
        let incomplete = vec![ArpEntry {
            mac: None,
            ..arp("192.168.0.1", "0:0:0:0:0:1")
        }];
        assert_eq!(network_id(&sel(), &incomplete), None);
        // No gateway at all (isolated segment): the subnet is the stable identity.
        let mut no_gw = sel();
        no_gw.gateway_ip = None;
        assert_eq!(
            network_id(&no_gw, &base_arp()).as_deref(),
            Some("net:192.168.0.0/24")
        );
        assert_eq!(
            network_id(&no_gw, &[]).as_deref(),
            Some("net:192.168.0.0/24")
        );
    }

    // ---- richer device information ----

    fn info(f: impl FnOnce(&mut HostInfo)) -> HostInfo {
        let mut h = HostInfo::default();
        f(&mut h);
        h
    }

    fn with_info(ip: &str, h: HostInfo, now: i64) -> ScanInputs {
        let mut i = inputs(base_arp(), now);
        i.host_info.insert(ip.parse().unwrap(), h);
        i
    }

    const PHONE: &str = "02:00:00:00:00:62";

    #[test]
    fn host_info_is_joined_by_ip_and_fills_the_new_fields() {
        let h = info(|h| {
            h.friendly_name = Some("Living Room TV".into());
            h.manufacturer = Some("Sony".into());
            h.model = Some("BRAVIA".into());
            h.dns_name = Some("tv.lan".into());
            h.netbios_name = Some("TV".into());
            h.rtt_ms = Some(2.5);
            h.os_hint = Some("Linux/Unix/macOS-like".into());
        });
        let (m, _) = merge(
            &DeviceMap::new(),
            &with_info("192.168.0.82", h, T0),
            &MergeCtx::new(T0),
        );
        let d = &m[PHONE];
        assert_eq!(d.friendly_name.as_deref(), Some("Living Room TV"));
        assert_eq!(d.manufacturer.as_deref(), Some("Sony"));
        assert_eq!(d.model.as_deref(), Some("BRAVIA"));
        assert_eq!(d.dns_name.as_deref(), Some("tv.lan"));
        assert_eq!(d.netbios_name.as_deref(), Some("TV"));
        assert_eq!(d.rtt_ms, Some(2.5));
        assert_eq!(d.os_hint.as_deref(), Some("Linux/Unix/macOS-like"));
        assert_eq!(
            d.kind,
            DeviceKind::Tv,
            "BRAVIA is classified through the model"
        );
        assert!(m["68:7f:f0:00:00:01"].friendly_name.is_none());
    }

    #[test]
    fn learned_fields_stick_but_rtt_reflects_only_the_latest_scan() {
        let h = info(|h| {
            h.friendly_name = Some("Den".into());
            h.rtt_ms = Some(1.0);
            h.os_hint = Some("Windows-like".into());
        });
        let (m1, _) = merge(
            &DeviceMap::new(),
            &with_info("192.168.0.82", h, T0),
            &MergeCtx::new(T0),
        );
        let (m2, _) = merge(
            &m1,
            &inputs(base_arp(), T0 + 30_000),
            &MergeCtx::new(T0 + 30_000),
        );
        let d = &m2[PHONE];
        assert_eq!(
            d.friendly_name.as_deref(),
            Some("Den"),
            "a cached source going quiet does not erase it"
        );
        assert_eq!(d.os_hint.as_deref(), Some("Windows-like"));
        assert_eq!(d.rtt_ms, None, "no reply this scan, no round-trip time");
    }

    #[test]
    fn upnp_beats_mdns_txt_for_name_and_model_but_txt_fills_gaps() {
        let mut i = with_info(
            "192.168.0.82",
            info(|h| h.friendly_name = Some("From UPnP".into())),
            T0,
        );
        i.mdns = vec![MdnsHit {
            ip: "192.168.0.82".parse().unwrap(),
            fresh: true,
            friendly_name: Some("From mDNS".into()),
            model: Some("Cast model".into()),
            manufacturer: Some("Google".into()),
            ..Default::default()
        }];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let d = &m[PHONE];
        assert_eq!(d.friendly_name.as_deref(), Some("From UPnP"));
        assert_eq!(d.model.as_deref(), Some("Cast model"));
        assert_eq!(d.manufacturer.as_deref(), Some("Google"));
    }

    #[test]
    fn host_info_joins_through_any_ip_of_a_multi_ip_mac_and_ignores_unknown_ips() {
        let mut i = inputs(
            vec![
                arp("192.168.0.5", "aa:bb:cc:dd:ee:05"),
                arp("192.168.0.50", "aa:bb:cc:dd:ee:05"),
            ],
            T0,
        );
        i.host_info.insert(
            "192.168.0.50".parse().unwrap(),
            info(|h| h.dns_name = Some("moved.lan".into())),
        );
        i.host_info.insert(
            "192.168.0.222".parse().unwrap(),
            info(|h| h.dns_name = Some("ghost.lan".into())),
        );
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(
            m["aa:bb:cc:dd:ee:05"].dns_name.as_deref(),
            Some("moved.lan")
        );
        assert_eq!(m.len(), 2, "host info never creates a device");
        assert!(
            m.values()
                .all(|d| d.dns_name.as_deref() != Some("ghost.lan"))
        );
    }

    #[test]
    fn merge_never_overwrites_the_users_name_or_notes() {
        let mut prev = DeviceMap::new();
        let (m1, _) = merge(&prev, &inputs(base_arp(), T0), &MergeCtx::new(T0));
        prev = m1;
        let d = prev.get_mut(PHONE).unwrap();
        d.custom_name = Some("Dad's phone".into());
        d.notes = Some("do not remove".into());
        // a scan full of data that would otherwise rename it
        let mut i = with_info(
            "192.168.0.82",
            info(|h| {
                h.friendly_name = Some("Pixel 8".into());
                h.dns_name = Some("pixel.lan".into());
                h.netbios_name = Some("PIXEL".into());
            }),
            T0 + 30_000,
        );
        i.mdns = vec![MdnsHit {
            ip: "192.168.0.82".parse().unwrap(),
            hostname: Some("pixel".into()),
            fresh: true,
            friendly_name: Some("Other".into()),
            ..Default::default()
        }];
        let (m2, _) = merge(&prev, &i, &MergeCtx::new(T0 + 30_000));
        assert_eq!(m2[PHONE].custom_name.as_deref(), Some("Dad's phone"));
        assert_eq!(m2[PHONE].notes.as_deref(), Some("do not remove"));
        assert_eq!(
            m2[PHONE].friendly_name.as_deref(),
            Some("Pixel 8"),
            "the learned name is separate"
        );
    }

    #[test]
    fn small_rtt_jitter_is_not_an_event_but_real_changes_and_appearance_are() {
        let rtt = |ms: f64| with_info("192.168.0.82", info(|h| h.rtt_ms = Some(ms)), T0);
        let (m1, _) = merge(&DeviceMap::new(), &rtt(2.0), &MergeCtx::new(T0));
        let (_, ev) = merge(&m1, &rtt(2.4), &MergeCtx::new(T0));
        assert!(
            ev.is_empty(),
            "jitter must not wake every SSE client: {ev:?}"
        );
        let (_, ev) = merge(&m1, &rtt(40.0), &MergeCtx::new(T0));
        assert_eq!(upserts(&ev).len(), 1, "a real latency change is announced");
        let (_, ev) = merge(&m1, &inputs(base_arp(), T0), &MergeCtx::new(T0));
        assert_eq!(
            upserts(&ev).len(),
            1,
            "going from a reply to none is announced"
        );
    }

    // ---- trust and drop rules for learned identity ----
    //
    // Rules (also in the README):
    //  * UPnP fields (friendly_name, manufacturer, model) are source-verified. Each
    //    successfully fetched description replaces them exactly; a field it no
    //    longer has is dropped. A failed or not-due fetch keeps the old values.
    //  * dns_name / netbios_name are replaced by each newer answer and dropped when
    //    a completed query for a host that answered ping finds no name. A silent
    //    host keeps its name.
    //  * mDNS TXT identity is unverified (no source address from mdns-sd): shown,
    //    replaced by newer TXT, kept while mDNS is quiet, never classified, never
    //    stored, and never allowed to override a verified value.
    //  * os_hint is replaced by each reply and kept when there is none.

    fn txt_hit(model: Option<&str>, name: Option<&str>) -> MdnsHit {
        MdnsHit {
            ip: "192.168.0.82".parse().unwrap(),
            fresh: true,
            model: model.map(String::from),
            friendly_name: name.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn mdns_txt_identity_is_shown_but_flagged_and_never_drives_classification() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![txt_hit(Some("Chromecast Ultra"), Some("Forged TV"))];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let d = &m[PHONE];
        assert_eq!(d.model.as_deref(), Some("Chromecast Ultra"));
        assert!(d.txt_sourced.model && d.txt_sourced.friendly_name);
        assert_eq!(
            d.kind,
            DeviceKind::Unknown,
            "an unverified model must not classify the device"
        );
    }

    #[test]
    fn a_newer_txt_value_replaces_an_older_one_and_it_sticks_while_mdns_is_quiet() {
        let mut i = inputs(base_arp(), T0);
        i.mdns = vec![txt_hit(Some("Old"), None)];
        let (m1, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let mut i = inputs(base_arp(), T0 + 30_000);
        i.mdns = vec![txt_hit(Some("New"), None)];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(T0 + 30_000));
        assert_eq!(m2[PHONE].model.as_deref(), Some("New"));
        let (m3, _) = merge(
            &m2,
            &inputs(base_arp(), T0 + 60_000),
            &MergeCtx::new(T0 + 60_000),
        );
        assert_eq!(m3[PHONE].model.as_deref(), Some("New"));
        assert!(m3[PHONE].txt_sourced.model);
    }

    #[test]
    fn a_verified_upnp_value_wins_over_txt_and_is_not_displaced_by_it_later() {
        let mut i = with_info(
            "192.168.0.82",
            info(|h| {
                h.model = Some("BRAVIA".into());
                h.upnp_answered = true;
            }),
            T0,
        );
        i.mdns = vec![txt_hit(Some("Forged"), None)];
        let (m1, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(m1[PHONE].model.as_deref(), Some("BRAVIA"));
        assert!(!m1[PHONE].txt_sourced.model);
        assert_eq!(m1[PHONE].kind, DeviceKind::Tv);
        // the UPnP cache momentarily has nothing; a forged TXT must not take the verified slot
        let mut i = inputs(base_arp(), T0 + 30_000);
        i.mdns = vec![txt_hit(Some("Forged"), None)];
        let (m2, _) = merge(&m1, &i, &MergeCtx::new(T0 + 30_000));
        assert_eq!(m2[PHONE].model.as_deref(), Some("BRAVIA"));
        assert!(!m2[PHONE].txt_sourced.model);
    }

    #[test]
    fn a_new_upnp_description_replaces_exactly_and_drops_fields_it_no_longer_has() {
        let full = info(|h| {
            h.friendly_name = Some("Den".into());
            h.manufacturer = Some("Acme".into());
            h.model = Some("X1".into());
            h.upnp_answered = true;
        });
        let (m1, _) = merge(
            &DeviceMap::new(),
            &with_info("192.168.0.82", full, T0),
            &MergeCtx::new(T0),
        );
        let slim = info(|h| {
            h.friendly_name = Some("Den 2".into());
            h.upnp_answered = true;
        });
        let (m2, _) = merge(
            &m1,
            &with_info("192.168.0.82", slim, T0 + 1),
            &MergeCtx::new(T0 + 1),
        );
        let d = &m2[PHONE];
        assert_eq!(d.friendly_name.as_deref(), Some("Den 2"));
        assert_eq!((d.manufacturer.clone(), d.model.clone()), (None, None));
    }

    #[test]
    fn dns_and_netbios_names_are_replaced_dropped_on_an_authoritative_miss_and_kept_when_silent() {
        let named = info(|h| {
            h.dns_name = Some("a.lan".into());
            h.netbios_name = Some("PC-A".into());
        });
        let (m1, _) = merge(
            &DeviceMap::new(),
            &with_info("192.168.0.82", named, T0),
            &MergeCtx::new(T0),
        );
        let renamed = info(|h| h.dns_name = Some("b.lan".into()));
        let (m2, _) = merge(
            &m1,
            &with_info("192.168.0.82", renamed, T0 + 1),
            &MergeCtx::new(T0 + 1),
        );
        assert_eq!(
            m2[PHONE].dns_name.as_deref(),
            Some("b.lan"),
            "newer answer replaces"
        );
        assert_eq!(
            m2[PHONE].netbios_name.as_deref(),
            Some("PC-A"),
            "silence keeps it"
        );
        let (m3, _) = merge(&m2, &inputs(base_arp(), T0 + 2), &MergeCtx::new(T0 + 2));
        assert_eq!(m3[PHONE].dns_name.as_deref(), Some("b.lan"));
        let miss = info(|h| {
            h.dns_cleared = true;
            h.netbios_cleared = true;
        });
        let (m4, _) = merge(
            &m3,
            &with_info("192.168.0.82", miss, T0 + 3),
            &MergeCtx::new(T0 + 3),
        );
        assert_eq!(
            (m4[PHONE].dns_name.clone(), m4[PHONE].netbios_name.clone()),
            (None, None)
        );
    }

    #[test]
    fn os_hint_is_replaced_by_each_reply_and_kept_without_one() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &with_info(
                "192.168.0.82",
                info(|h| h.os_hint = Some("Windows-like".into())),
                T0,
            ),
            &MergeCtx::new(T0),
        );
        let (m2, _) = merge(
            &m1,
            &with_info(
                "192.168.0.82",
                info(|h| h.os_hint = Some("Linux/Unix/macOS-like".into())),
                T0 + 1,
            ),
            &MergeCtx::new(T0 + 1),
        );
        assert_eq!(m2[PHONE].os_hint.as_deref(), Some("Linux/Unix/macOS-like"));
        let (m3, _) = merge(&m2, &inputs(base_arp(), T0 + 2), &MergeCtx::new(T0 + 2));
        assert_eq!(m3[PHONE].os_hint.as_deref(), Some("Linux/Unix/macOS-like"));
    }

    #[test]
    fn none_of_this_ever_touches_the_users_name_or_notes() {
        let (mut m, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let d = m.get_mut(PHONE).unwrap();
        d.custom_name = Some("Mine".into());
        d.notes = Some("n".into());
        let mut i = with_info(
            "192.168.0.82",
            info(|h| {
                h.friendly_name = Some("X".into());
                h.upnp_answered = true;
                h.dns_cleared = true;
            }),
            T0 + 1,
        );
        i.mdns = vec![txt_hit(Some("Forged"), Some("Forged"))];
        let (m2, _) = merge(&m, &i, &MergeCtx::new(T0 + 1));
        assert_eq!(
            (m2[PHONE].custom_name.as_deref(), m2[PHONE].notes.as_deref()),
            (Some("Mine"), Some("n"))
        );
    }

    // ---- review fixes ----

    #[test]
    fn one_mac_with_two_arp_ips_follows_the_probed_ip_and_stays_online() {
        // The device moved from .5 to .50; the old ARP entry lingers.
        let mk = || {
            vec![
                arp("192.168.0.1", "68:7f:f0:00:00:01"),
                arp("192.168.0.5", "aa:bb:cc:dd:ee:05"),
                arp("192.168.0.50", "aa:bb:cc:dd:ee:05"),
            ]
        };
        let (mut map, _) = merge(&DeviceMap::new(), &inputs(mk(), T0), &MergeCtx::new(T0));
        for step in 1..=6 {
            let now = T0 + step * 30_000;
            let mut i = inputs(mk(), now);
            i.ping_alive.insert("192.168.0.50".parse().unwrap());
            map = merge(&map, &i, &MergeCtx::new(now)).0;
        }
        let d = &map["aa:bb:cc:dd:ee:05"];
        assert_eq!(
            d.ip.to_string(),
            "192.168.0.50",
            "the answering address wins over the lower one"
        );
        assert!(d.online);
        assert_eq!(d.last_seen, T0 + 180_000);
    }

    #[test]
    fn mdns_and_ssdp_join_through_any_ip_of_the_mac() {
        let mut i = inputs(
            vec![
                arp("192.168.0.5", "aa:bb:cc:dd:ee:05"),
                arp("192.168.0.50", "aa:bb:cc:dd:ee:05"),
            ],
            T0,
        );
        i.mdns = vec![hit("192.168.0.50", Some("moved-host"), &["_ipp"])];
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        let d = &m["aa:bb:cc:dd:ee:05"];
        assert_eq!(d.hostname.as_deref(), Some("moved-host"));
        assert_eq!(
            d.ip.to_string(),
            "192.168.0.50",
            "fresh mDNS at .50 is evidence for that address"
        );
    }

    #[test]
    fn previous_ip_is_kept_while_still_listed_and_nothing_is_probed() {
        let both = || {
            vec![
                arp("192.168.0.5", "aa:bb:cc:dd:ee:05"),
                arp("192.168.0.50", "aa:bb:cc:dd:ee:05"),
            ]
        };
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(vec![arp("192.168.0.50", "aa:bb:cc:dd:ee:05")], T0),
            &MergeCtx::new(T0),
        );
        assert_eq!(m1["aa:bb:cc:dd:ee:05"].ip.to_string(), "192.168.0.50");
        let (m2, ev) = merge(
            &m1,
            &inputs(both(), T0 + 30_000),
            &MergeCtx::new(T0 + 30_000),
        );
        assert_eq!(
            m2["aa:bb:cc:dd:ee:05"].ip.to_string(),
            "192.168.0.50",
            "no flapping to the lowest IP"
        );
        assert!(ev.is_empty());
    }

    #[test]
    fn lowest_ip_is_the_tie_break_for_a_new_multi_ip_mac_and_order_is_irrelevant() {
        let a = vec![
            arp("192.168.0.50", "aa:bb:cc:dd:ee:05"),
            arp("192.168.0.5", "aa:bb:cc:dd:ee:05"),
        ];
        let mut b = a.clone();
        b.reverse();
        let (m1, _) = merge(&DeviceMap::new(), &inputs(a, T0), &MergeCtx::new(T0));
        let (m2, _) = merge(&DeviceMap::new(), &inputs(b, T0), &MergeCtx::new(T0));
        assert_eq!(m1, m2);
        assert_eq!(m1["aa:bb:cc:dd:ee:05"].ip.to_string(), "192.168.0.5");
    }

    #[test]
    fn arp_entries_outside_the_scanned_subnet_do_not_become_devices() {
        let mut a = base_arp();
        a.extend([
            arp("169.254.10.10", "aa:bb:cc:dd:ee:01"),
            arp("10.9.9.9", "aa:bb:cc:dd:ee:02"),
            arp("192.168.1.50", "aa:bb:cc:dd:ee:03"),
            arp("192.168.0.255", "aa:bb:cc:dd:ee:04"),
            arp("192.168.0.0", "aa:bb:cc:dd:ee:05"),
        ]);
        let (m, _) = merge(&DeviceMap::new(), &inputs(a, T0), &MergeCtx::new(T0));
        assert_eq!(
            m.len(),
            3,
            "{:?}",
            m.values().map(|d| d.ip).collect::<Vec<_>>()
        );
        assert!(m.values().all(|d| d.ip.octets()[..3] == [192, 168, 0]));
    }

    #[test]
    fn this_machine_is_never_flagged_new() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &ctx_baseline(T0, None),
        );
        // Later the default route moves to a brand-new interface after the baseline exists.
        let t1 = T0 + 60_000;
        let mut i = ScanInputs::new(sel_en8(), t1);
        i.arp = vec![arp("192.168.0.1", "68:7f:f0:00:00:01")];
        i.local_macs = [
            "3c:e1:a1:00:00:53".parse().unwrap(),
            "32:00:00:00:00:84".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let (m2, _) = merge(&m1, &i, &ctx_baseline(t1, Some(T0)));
        assert!(m2["3c:e1:a1:00:00:53"].is_self);
        assert!(!m2["3c:e1:a1:00:00:53"].is_new);
        assert!(m2.values().filter(|d| d.is_self).all(|d| !d.is_new));
    }

    #[test]
    fn device_count_is_capped_but_self_and_known_devices_keep_working() {
        let mut arp_list = base_arp();
        for n in 10..40u8 {
            arp_list.push(arp(
                &format!("192.168.0.{n}"),
                &format!("aa:bb:cc:dd:ee:{n:02x}"),
            ));
        }
        let ctx = MergeCtx {
            max_devices: 5,
            ..MergeCtx::new(T0)
        };
        let (m1, _) = merge(&DeviceMap::new(), &inputs(arp_list.clone(), T0), &ctx);
        assert_eq!(m1.len(), 5);
        assert!(m1.values().any(|d| d.is_self), "self is always kept");
        // Known devices are still updated at the cap.
        let ctx2 = MergeCtx {
            now: T0 + 30_000,
            max_devices: 5,
            ..MergeCtx::new(T0)
        };
        let mut i = inputs(arp_list, T0 + 30_000);
        i.ping_alive.extend(m1.values().map(|d| d.ip));
        let (m2, _) = merge(&m1, &i, &ctx2);
        assert_eq!(m2.len(), 5);
        assert!(m2.values().all(|d| d.last_seen == T0 + 30_000));
    }

    // ---- slice 4: enrichment ----

    fn small_db() -> &'static OuiDb {
        Box::leak(Box::new(OuiDb::from_csv(
            "Registry,Assignment,Organization Name,Organization Address\nMA-L,687FF0,Acme Networks,x\nMA-L,8CFD49,Brother Industries,x\nMA-L,022149,Bogus Vendor,x\n",
        )))
    }

    fn ctx_with_oui(now: i64) -> MergeCtx {
        MergeCtx {
            oui: Some(small_db()),
            ..MergeCtx::new(now)
        }
    }

    #[test]
    fn vendor_is_filled_from_oui_and_drives_classification() {
        let mut a = base_arp();
        a.push(arp("192.168.0.194", "8c:fd:49:0:0:4"));
        let (m, _) = merge(&DeviceMap::new(), &inputs(a, T0), &ctx_with_oui(T0));
        let gw = &m["68:7f:f0:00:00:01"];
        assert_eq!(gw.vendor.as_deref(), Some("Acme Networks"));
        assert!(!gw.randomized_mac);
        let printer = &m["8c:fd:49:00:00:04"];
        assert_eq!(printer.vendor.as_deref(), Some("Brother Industries"));
        assert_eq!(printer.kind, DeviceKind::Printer);
        assert_eq!(gw.kind, DeviceKind::Gateway, "gateway beats vendor rules");
    }

    #[test]
    fn randomized_mac_gets_no_vendor_even_if_the_prefix_collides() {
        let (m, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &ctx_with_oui(T0),
        );
        let d = &m["02:00:00:00:00:62"];
        assert!(d.randomized_mac);
        assert_eq!(
            d.vendor, None,
            "02:21:49 is in the small DB but the MAC is locally administered"
        );
    }

    #[test]
    fn self_is_flagged_randomized_when_its_mac_is_locally_administered() {
        let (m, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &ctx_with_oui(T0),
        );
        assert!(m["32:00:00:00:00:84"].randomized_mac);
    }

    #[test]
    fn unchanged_scan_with_enrichment_still_emits_no_events() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &ctx_with_oui(T0),
        );
        let (_, ev) = merge(
            &m1,
            &inputs(base_arp(), T0 + 30_000),
            &ctx_with_oui(T0 + 30_000),
        );
        assert!(ev.is_empty());
    }

    // ---- slice 3: active liveness evidence ----

    #[test]
    fn ping_evidence_keeps_a_device_online() {
        let (mut map, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        for step in 1..=6 {
            let now = T0 + step * 30_000;
            let mut i = inputs(base_arp(), now);
            i.ping_alive.insert("192.168.0.82".parse().unwrap());
            map = merge(&map, &i, &MergeCtx::new(now)).0;
        }
        assert!(map["02:00:00:00:00:62"].online);
        assert_eq!(map["02:00:00:00:00:62"].last_seen, T0 + 180_000);
        assert!(
            !map["68:7f:f0:00:00:01"].online,
            "ARP-only gateway has no evidence and ages out"
        );
    }

    #[test]
    fn tcp_evidence_counts_as_alive() {
        let (map, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let now = T0 + 120_000;
        let mut i = inputs(base_arp(), now);
        i.tcp_alive.insert("192.168.0.1".parse().unwrap());
        let (m2, _) = merge(&map, &i, &MergeCtx::new(now));
        assert!(m2["68:7f:f0:00:00:01"].online);
        assert!(!m2["02:00:00:00:00:62"].online);
    }

    #[test]
    fn evidence_for_an_ip_not_in_arp_does_not_create_a_device() {
        let mut i = inputs(base_arp(), T0);
        i.ping_alive.insert("192.168.0.222".parse().unwrap());
        let (m, _) = merge(&DeviceMap::new(), &i, &MergeCtx::new(T0));
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn a_device_that_comes_back_via_ping_goes_online_with_an_event() {
        let (m1, _) = merge(
            &DeviceMap::new(),
            &inputs(base_arp(), T0),
            &MergeCtx::new(T0),
        );
        let t1 = T0 + 200_000;
        let (m2, _) = merge(&m1, &inputs(base_arp(), t1), &MergeCtx::new(t1));
        assert!(!m2["02:00:00:00:00:62"].online);
        let t2 = t1 + 30_000;
        let mut i = inputs(base_arp(), t2);
        i.ping_alive.insert("192.168.0.82".parse().unwrap());
        let (m3, ev) = merge(&m2, &i, &MergeCtx::new(t2));
        assert!(m3["02:00:00:00:00:62"].online);
        assert!(
            upserts(&ev)
                .iter()
                .any(|d| d.id == "02:00:00:00:00:62" && d.online)
        );
    }
}
