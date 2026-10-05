//! Optional per-host information sources, combined behind caches:
//!
//! * UPnP device descriptions (HTTP to the SSDP LOCATION, policy-checked),
//! * reverse DNS through the gateway only (UDP 53),
//! * NetBIOS node status (UDP 137, in-subnet unicast).
//!
//! Each source is isolated: a failure becomes a warning for that source and
//! never aborts the others or the scan. Results are cached, so a slow or silent
//! source costs one bounded wait the first time and nothing afterwards.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::time::Duration;

use futures_util::StreamExt;
use ipnet::Ipv4Net;

use super::dns_ptr::lookup_ptrs;
use super::netbios::{NETBIOS_PORT, probe};
use super::ttlcache::TtlCache;
use super::upnp::{
    FAILURE_TTL_MS, FETCH_CONCURRENCY, MAX_FETCHES_PER_CYCLE, SUCCESS_TTL_MS, choose_locations,
    due, fetch_location,
};
use super::upnp_parse::UpnpInfo;
use crate::model::{HostInfo, SsdpObservation};
use crate::net::subnet::is_scan_target;

const DNS_TTL_MS: i64 = 60 * 60 * 1000;
const NETBIOS_HIT_TTL_MS: i64 = 6 * 60 * 60 * 1000;
const NETBIOS_MISS_TTL_MS: i64 = 60 * 60 * 1000;
const MAX_LOOKUPS_PER_CYCLE: usize = 64;
const CACHE_CAP: usize = 1024;
const DNS_WINDOW: Duration = Duration::from_millis(1500);
const NETBIOS_WINDOW: Duration = Duration::from_millis(1200);
/// All UPnP fetches of one cycle together may take this long at most.
const UPNP_BUDGET: Duration = Duration::from_secs(5);

pub struct EnrichInput<'a> {
    pub now: i64,
    pub net: Ipv4Net,
    pub iface_ip: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    /// Hosts we know about (ARP / ping); anything not an in-subnet target is ignored.
    pub hosts: &'a [Ipv4Addr],
    /// Hosts that answered ping this scan: only a miss for one of these is a real
    /// "no such name" (a silent host just keeps the name it had).
    pub alive: &'a BTreeSet<Ipv4Addr>,
    pub ssdp: &'a [SsdpObservation],
}

#[derive(Debug, Default)]
pub struct EnrichOutput {
    pub info: BTreeMap<Ipv4Addr, HostInfo>,
    pub warnings: Vec<String>,
}

/// Which optional sources are switched on (`--no-upnp`, `--no-dns`, `--no-netbios`).
#[derive(Clone, Copy, Debug)]
pub struct EnrichOptions {
    pub upnp: bool,
    pub dns: bool,
    pub netbios: bool,
}

impl Default for EnrichOptions {
    fn default() -> Self {
        Self {
            upnp: true,
            dns: true,
            netbios: true,
        }
    }
}

/// A cached DNS/NetBIOS result. `name: None` with `host_was_alive` is an
/// authoritative miss (drop any stored name); without it, just "no answer".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub name: Option<String>,
    pub host_was_alive: bool,
}

pub struct Enricher {
    upnp: Mutex<TtlCache<Ipv4Addr, Option<UpnpInfo>>>,
    dns: Mutex<TtlCache<Ipv4Addr, Lookup>>,
    netbios: Mutex<TtlCache<Ipv4Addr, Lookup>>,
    opts: EnrichOptions,
    /// Receives the gateway's WAN counter endpoint when its description has one.
    igd: Option<std::sync::Arc<crate::traffic::IgdSlot>>,
}

/// Hosts we may probe: in-subnet unicast targets other than ourselves, sorted, unique.
pub fn eligible_hosts(hosts: &[Ipv4Addr], net: Ipv4Net, me: Ipv4Addr) -> Vec<Ipv4Addr> {
    let set: BTreeSet<Ipv4Addr> = hosts
        .iter()
        .copied()
        .filter(|ip| *ip != me && is_scan_target(*ip, net))
        .collect();
    set.into_iter().collect()
}

/// The only DNS server we ever talk to: the gateway, and only if it is itself an
/// in-subnet scan target. (The system resolver is never used.)
pub fn dns_server(gateway: Option<Ipv4Addr>, net: Ipv4Net) -> Option<SocketAddrV4> {
    gateway
        .filter(|g| is_scan_target(*g, net))
        .map(|g| SocketAddrV4::new(g, 53))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Enricher {
    pub fn new(opts: EnrichOptions) -> Self {
        Self {
            upnp: Mutex::new(TtlCache::new(CACHE_CAP)),
            dns: Mutex::new(TtlCache::new(CACHE_CAP)),
            netbios: Mutex::new(TtlCache::new(CACHE_CAP)),
            opts,
            igd: None,
        }
    }

    pub fn with_igd(mut self, slot: Option<std::sync::Arc<crate::traffic::IgdSlot>>) -> Self {
        self.igd = slot;
        self
    }

    pub async fn run(&self, i: EnrichInput<'_>) -> EnrichOutput {
        let hosts = eligible_hosts(i.hosts, i.net, i.iface_ip);
        let (w_upnp, w_dns, w_nb) = tokio::join!(
            self.upnp_step(&i, &hosts),
            self.dns_step(&i, &hosts),
            self.netbios_step(&i, &hosts),
        );
        // Hand the gateway's WAN counter endpoint to the traffic poller (never with
        // --no-upnp: the description is not fetched then, so there is none).
        if let (Some(slot), Some(gw), true) = (&self.igd, i.gateway, self.opts.upnp)
            && let Some(entry) = lock(&self.upnp).get(&gw, i.now)
        {
            slot.set(entry.as_ref().and_then(|u| u.igd.clone()));
        }
        let mut out = EnrichOutput::default();
        out.warnings.extend(w_upnp);
        out.warnings.extend(w_dns);
        out.warnings.extend(w_nb);

        let (upnp, dns, nb) = (lock(&self.upnp), lock(&self.dns), lock(&self.netbios));
        for ip in &hosts {
            let mut h = HostInfo::default();
            if let Some(Some(u)) = upnp.get(ip, i.now) {
                h.upnp_answered = true;
                h.friendly_name = u.friendly_name.clone();
                h.manufacturer = u.manufacturer.clone();
                h.model = u.model();
            }
            if let Some(l) = dns.get(ip, i.now) {
                h.dns_name = l.name.clone();
                h.dns_cleared = l.name.is_none() && l.host_was_alive;
            }
            if let Some(l) = nb.get(ip, i.now) {
                h.netbios_name = l.name.clone();
                h.netbios_cleared = l.name.is_none() && l.host_was_alive;
            }
            if h != HostInfo::default() {
                out.info.insert(*ip, h);
            }
        }
        out
    }

    async fn upnp_step(&self, i: &EnrichInput<'_>, hosts: &[Ipv4Addr]) -> Option<String> {
        if !self.opts.upnp {
            return None;
        }
        let allowed: BTreeSet<Ipv4Addr> = hosts.iter().copied().collect();
        let locations = choose_locations(i.ssdp, &|ip| allowed.contains(&ip));
        let todo = due(
            &lock(&self.upnp),
            locations.keys().copied(),
            i.now,
            MAX_FETCHES_PER_CYCLE,
        );
        if todo.is_empty() {
            return None;
        }
        let net = i.net;
        let mut stream = futures_util::stream::iter(todo.iter().copied())
            .map(|ip| {
                let loc = locations[&ip].clone();
                async move { (ip, fetch_location(&loc, ip, net).await) }
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .boxed();
        let deadline = tokio::time::Instant::now() + UPNP_BUDGET;
        let (mut attempted, mut succeeded) = (0usize, 0usize);
        while let Ok(Some((ip, result))) = tokio::time::timeout_at(deadline, stream.next()).await {
            attempted += 1;
            succeeded += usize::from(result.is_some());
            let ttl = if result.is_some() {
                SUCCESS_TTL_MS
            } else {
                FAILURE_TTL_MS
            };
            lock(&self.upnp).put(ip, result, i.now, ttl);
        }
        // Individual devices refusing is normal; everything failing is worth saying.
        (attempted >= 3 && succeeded == 0).then(|| {
            format!("UPnP descriptions: all {attempted} fetches failed; model and friendly names are unavailable")
        })
    }

    async fn dns_step(&self, i: &EnrichInput<'_>, hosts: &[Ipv4Addr]) -> Option<String> {
        if !self.opts.dns {
            return None;
        }
        let server = dns_server(i.gateway, i.net)?;
        let todo = due(
            &lock(&self.dns),
            hosts.iter().copied(),
            i.now,
            MAX_LOOKUPS_PER_CYCLE,
        );
        if todo.is_empty() {
            return None;
        }
        match lookup_ptrs(i.iface_ip, server, &todo, DNS_WINDOW).await {
            Ok(found) => {
                let mut c = lock(&self.dns);
                for ip in todo {
                    let l = Lookup {
                        name: found.get(&ip).cloned(),
                        host_was_alive: i.alive.contains(&ip),
                    };
                    c.put(ip, l, i.now, DNS_TTL_MS);
                }
                None
            }
            Err(e) => Some(format!(
                "gateway DNS lookups failed ({e}); DNS names are unavailable"
            )),
        }
    }

    async fn netbios_step(&self, i: &EnrichInput<'_>, hosts: &[Ipv4Addr]) -> Option<String> {
        if !self.opts.netbios {
            return None;
        }
        let todo = due(
            &lock(&self.netbios),
            hosts.iter().copied(),
            i.now,
            MAX_LOOKUPS_PER_CYCLE,
        );
        if todo.is_empty() {
            return None;
        }
        let targets: Vec<SocketAddrV4> = todo
            .iter()
            .map(|ip| SocketAddrV4::new(*ip, NETBIOS_PORT))
            .collect();
        match probe(i.iface_ip, &targets, NETBIOS_WINDOW).await {
            Ok(found) => {
                let mut c = lock(&self.netbios);
                for ip in todo {
                    let l = Lookup {
                        name: found.get(&ip).cloned(),
                        host_was_alive: i.alive.contains(&ip),
                    };
                    let ttl = if l.name.is_some() {
                        NETBIOS_HIT_TTL_MS
                    } else {
                        NETBIOS_MISS_TTL_MS
                    };
                    c.put(ip, l, i.now, ttl);
                }
                None
            }
            Err(e) => Some(format!(
                "NetBIOS queries failed ({e}); NetBIOS names are unavailable"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn net() -> Ipv4Net {
        "192.168.0.0/24".parse().unwrap()
    }

    #[test]
    fn only_in_subnet_unicast_hosts_other_than_us_are_probed() {
        let hosts = [
            ip("192.168.0.5"),
            ip("192.168.0.5"),
            ip("192.168.0.172"),
            ip("8.8.8.8"),
            ip("192.168.1.5"),
            ip("192.168.0.255"),
            ip("169.254.1.1"),
            ip("127.0.0.1"),
            ip("192.168.0.2"),
        ];
        assert_eq!(
            eligible_hosts(&hosts, net(), ip("192.168.0.172")),
            vec![ip("192.168.0.2"), ip("192.168.0.5")]
        );
    }

    #[test]
    fn dns_goes_to_the_gateway_only_and_only_when_it_is_on_the_subnet() {
        assert_eq!(
            dns_server(Some(ip("192.168.0.1")), net()),
            Some(SocketAddrV4::new(ip("192.168.0.1"), 53))
        );
        assert_eq!(dns_server(None, net()), None);
        assert_eq!(
            dns_server(Some(ip("8.8.8.8")), net()),
            None,
            "never a public resolver"
        );
        assert_eq!(
            dns_server(Some(ip("192.168.1.1")), net()),
            None,
            "never off-subnet"
        );
        assert_eq!(dns_server(Some(ip("127.0.0.1")), net()), None);
    }

    #[tokio::test]
    async fn with_nothing_to_do_no_source_runs_and_nothing_is_returned() {
        let e = Enricher::new(EnrichOptions::default());
        let out = e
            .run(EnrichInput {
                now: 0,
                net: net(),
                iface_ip: ip("192.168.0.172"),
                gateway: None,
                hosts: &[],
                alive: &BTreeSet::new(),
                ssdp: &[],
            })
            .await;
        assert!(out.info.is_empty());
        assert!(out.warnings.is_empty());
    }

    #[tokio::test]
    async fn disabled_netbios_never_touches_the_network() {
        let e = Enricher::new(EnrichOptions {
            netbios: false,
            ..Default::default()
        });
        let hosts = [ip("192.168.0.9")];
        let w = e
            .netbios_step(
                &EnrichInput {
                    now: 0,
                    net: net(),
                    iface_ip: ip("192.168.0.172"),
                    gateway: None,
                    hosts: &hosts,
                    alive: &BTreeSet::new(),
                    ssdp: &[],
                },
                &hosts,
            )
            .await;
        assert!(w.is_none());
        assert!(lock(&e.netbios).is_empty(), "no queries were recorded");
    }

    fn obs(ip: &str) -> SsdpObservation {
        SsdpObservation {
            ip: ip.parse().unwrap(),
            hit: crate::model::SsdpHit {
                location: Some(format!("http://{ip}/d.xml")),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn disabled_dns_and_upnp_make_no_queries_and_no_cache_entries() {
        let e = Enricher::new(EnrichOptions {
            upnp: false,
            dns: false,
            netbios: false,
        });
        let hosts = [ip("192.168.0.9")];
        let ssdp = [obs("192.168.0.9")];
        let input = EnrichInput {
            now: 0,
            net: net(),
            iface_ip: ip("192.168.0.172"),
            gateway: Some(ip("192.168.0.1")),
            hosts: &hosts,
            alive: &BTreeSet::new(),
            ssdp: &ssdp,
        };
        let out = e.run(input).await;
        assert!(out.info.is_empty() && out.warnings.is_empty());
        assert!(lock(&e.dns).is_empty(), "no PTR query was sent or recorded");
        assert!(
            lock(&e.upnp).is_empty(),
            "no description was fetched or recorded"
        );
        assert!(lock(&e.netbios).is_empty());
    }
}
