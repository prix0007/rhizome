//! I/O adapter: mDNS browsing with `mdns-sd`, pinned to the scan interface.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent};

use super::mdns_map::{
    RawResolution, instance_from_fullname, map_resolution, retain_in_subnet, valid_service_type,
};
use crate::model::MdnsHit;
use crate::net::subnet::is_scan_target;

/// Something that can report the current mDNS knowledge (injectable for tests).
pub trait MdnsSource: Send + Sync {
    /// Everything known; entries seen within `fresh_within` are marked `fresh`.
    fn hits(&self, fresh_within: Duration) -> Vec<MdnsHit>;
}

/// Query the source if it started; otherwise report it unavailable with a warning.
pub fn collect_mdns(
    src: &Result<Arc<dyn MdnsSource>, String>,
    fresh_within: Duration,
) -> (Vec<MdnsHit>, bool, Option<String>) {
    match src {
        Ok(s) => (s.hits(fresh_within), true, None),
        Err(e) => (
            vec![],
            false,
            Some(format!(
                "mDNS unavailable ({e}); hostnames and service hints are disabled"
            )),
        ),
    }
}

const META_QUERY: &str = "_services._dns-sd._udp.local.";
/// Observations older than this are forgotten.
pub const TTL: Duration = Duration::from_secs(15 * 60);
/// A hostile host announcing endless service types must not make us browse forever.
pub const MAX_BROWSED_TYPES: usize = 64;
pub const MAX_CACHE_ENTRIES: usize = 1024;

type Key = (Ipv4Addr, Option<String>);

/// What we remember about one (host, service) observation.
struct Entry {
    hostname: Option<String>,
    friendly_name: Option<String>,
    model: Option<String>,
    manufacturer: Option<String>,
    seen: Instant,
}

/// Bounded cache of mDNS observations with a TTL.
pub struct HitCache {
    map: HashMap<Key, Entry>,
    cap: usize,
}

impl HitCache {
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Store a hit. Known keys are always refreshed; new keys are refused once
    /// the cache is full of unexpired entries. Returns whether it was stored.
    pub fn insert(&mut self, hit: &MdnsHit, now: Instant) -> bool {
        let key = (hit.ip, hit.service_types.first().cloned());
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            self.map
                .retain(|_, e| now.saturating_duration_since(e.seen) < TTL);
            if self.map.len() >= self.cap {
                return false;
            }
        }
        self.map.insert(
            key,
            Entry {
                hostname: hit.hostname.clone(),
                friendly_name: hit.friendly_name.clone(),
                model: hit.model.clone(),
                manufacturer: hit.manufacturer.clone(),
                seen: now,
            },
        );
        true
    }

    /// Unexpired hits, sorted; `fresh` is set for those seen within `fresh_within`.
    pub fn hits(&mut self, now: Instant, fresh_within: Duration) -> Vec<MdnsHit> {
        self.map
            .retain(|_, e| now.saturating_duration_since(e.seen) < TTL);
        let mut out: Vec<MdnsHit> = self
            .map
            .iter()
            .map(|((ip, svc), e)| MdnsHit {
                ip: *ip,
                hostname: e.hostname.clone(),
                service_types: svc.iter().cloned().collect(),
                fresh: now.saturating_duration_since(e.seen) <= fresh_within,
                friendly_name: e.friendly_name.clone(),
                model: e.model.clone(),
                manufacturer: e.manufacturer.clone(),
            })
            .collect();
        out.sort_by(|a, b| (a.ip, &a.service_types).cmp(&(b.ip, &b.service_types)));
        out
    }
}

pub struct MdnsService {
    daemon: ServiceDaemon,
    cache: Arc<Mutex<HitCache>>,
}

impl MdnsService {
    /// Start browsing on `iface` only (IPv4). Must be called inside a tokio runtime.
    /// Hits from addresses outside `net` are ignored. Fails without side effects.
    pub fn start(iface_ip: std::net::Ipv4Addr, net: Ipv4Net) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
        let setup = || -> Result<(), mdns_sd::Error> {
            daemon.disable_interface(IfKind::All)?;
            // By address, not name: interface names differ per OS (and are GUIDs on
            // Windows), the selected address does not.
            daemon.enable_interface(IfKind::Addr(std::net::IpAddr::V4(iface_ip)))?;
            daemon.disable_interface(IfKind::IPv6)?;
            Ok(())
        };
        setup().map_err(|e| e.to_string())?;
        let cache = Arc::new(Mutex::new(HitCache::new(MAX_CACHE_ENTRIES)));
        let meta = daemon.browse(META_QUERY).map_err(|e| e.to_string())?;

        let d = daemon.clone();
        let c = cache.clone();
        tokio::spawn(async move {
            let mut browsed: HashSet<String> = HashSet::new();
            while let Ok(ev) = meta.recv_async().await {
                let ServiceEvent::ServiceFound(_, announced) = ev else {
                    continue;
                };
                // Network-supplied: validate before browsing or logging.
                let Some(ty) = valid_service_type(&announced) else {
                    continue;
                };
                if browsed.len() >= MAX_BROWSED_TYPES || !browsed.insert(ty.clone()) {
                    continue;
                }
                match d.browse(&ty) {
                    Ok(rx) => {
                        let c = c.clone();
                        tokio::spawn(async move {
                            while let Ok(ev) = rx.recv_async().await {
                                if let ServiceEvent::ServiceResolved(r) = ev {
                                    record(
                                        &c,
                                        &RawResolution {
                                            host: r.host.clone(),
                                            addresses: r
                                                .addresses
                                                .iter()
                                                .map(|a| a.to_ip_addr())
                                                .collect(),
                                            service_type: r.ty_domain.clone(),
                                            instance: instance_from_fullname(
                                                &r.fullname,
                                                &r.ty_domain,
                                            )
                                            .unwrap_or_default(),
                                            // bounded: a host controls these
                                            txt: r
                                                .txt_properties
                                                .iter()
                                                .take(32)
                                                .map(|p| {
                                                    (
                                                        p.key().chars().take(64).collect(),
                                                        p.val_str().chars().take(256).collect(),
                                                    )
                                                })
                                                .collect(),
                                        },
                                        net,
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => tracing::debug!("mdns browse {ty}: {e}"),
                }
            }
        });
        Ok(Self { daemon, cache })
    }
}

fn record(cache: &Mutex<HitCache>, r: &RawResolution, net: Ipv4Net) {
    let hits = retain_in_subnet(map_resolution(r), net);
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    for h in &hits {
        debug_assert!(is_scan_target(h.ip, net));
        g.insert(h, now);
    }
}

impl MdnsSource for MdnsService {
    fn hits(&self, fresh_within: Duration) -> Vec<MdnsHit> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .hits(Instant::now(), fresh_within)
    }
}

impl Drop for MdnsService {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Vec<MdnsHit>);
    impl MdnsSource for Fixed {
        fn hits(&self, _fresh_within: Duration) -> Vec<MdnsHit> {
            self.0.clone()
        }
    }

    fn hit(ip: &str, svc: &str) -> MdnsHit {
        MdnsHit {
            ip: ip.parse().unwrap(),
            hostname: Some("h".into()),
            service_types: if svc.is_empty() {
                vec![]
            } else {
                vec![svc.to_string()]
            },
            fresh: true,
            ..Default::default()
        }
    }

    #[test]
    fn working_source_is_available() {
        let h = hit("10.0.0.2", "");
        let src: Result<Arc<dyn MdnsSource>, String> = Ok(Arc::new(Fixed(vec![h.clone()])));
        let (hits, ok, warn) = collect_mdns(&src, Duration::from_secs(30));
        assert_eq!(hits, vec![h]);
        assert!(ok);
        assert!(warn.is_none());
    }

    #[test]
    fn record_drops_out_of_subnet_addresses_and_ipv6() {
        let net: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        let cache = Mutex::new(HitCache::new(16));
        record(
            &cache,
            &RawResolution {
                host: "Printer.local.".into(),
                addresses: vec![
                    "192.168.0.50".parse().unwrap(),
                    "fe80::1".parse().unwrap(),
                    "8.8.8.8".parse().unwrap(),
                    "10.1.1.1".parse().unwrap(),
                ],
                service_type: "_ipp._tcp.local.".into(),
                instance: String::new(),
                txt: vec![],
            },
            net,
        );
        let mut g = cache.lock().unwrap();
        assert_eq!(g.len(), 1);
        let hits = g.hits(Instant::now(), Duration::from_secs(30));
        assert_eq!(hits[0].ip.to_string(), "192.168.0.50");
        assert_eq!(hits[0].service_types, vec!["_ipp".to_string()]);
        assert_eq!(hits[0].hostname.as_deref(), Some("Printer"));
    }

    #[test]
    fn cache_marks_only_recent_hits_fresh_and_keeps_old_ones_for_enrichment() {
        let mut c = HitCache::new(16);
        let t0 = Instant::now();
        c.insert(&hit("10.0.0.2", "_ipp"), t0);
        c.insert(&hit("10.0.0.3", "_ssh"), t0 + Duration::from_secs(100));
        let now = t0 + Duration::from_secs(110);
        let hits = c.hits(now, Duration::from_secs(30));
        assert_eq!(hits.len(), 2, "old entries stay (enrichment)");
        let old = hits
            .iter()
            .find(|h| h.ip.to_string() == "10.0.0.2")
            .unwrap();
        let recent = hits
            .iter()
            .find(|h| h.ip.to_string() == "10.0.0.3")
            .unwrap();
        assert!(!old.fresh);
        assert!(recent.fresh);
    }

    #[test]
    fn re_inserting_refreshes_freshness() {
        let mut c = HitCache::new(16);
        let t0 = Instant::now();
        c.insert(&hit("10.0.0.2", "_ipp"), t0);
        c.insert(&hit("10.0.0.2", "_ipp"), t0 + Duration::from_secs(200));
        let hits = c.hits(t0 + Duration::from_secs(210), Duration::from_secs(30));
        assert!(hits[0].fresh);
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let mut c = HitCache::new(16);
        let t0 = Instant::now();
        c.insert(&hit("10.0.0.2", "_ipp"), t0);
        assert!(
            c.hits(t0 + TTL + Duration::from_secs(1), Duration::from_secs(30))
                .is_empty()
        );
        assert!(c.is_empty());
    }

    #[test]
    fn cache_is_bounded_and_flooding_cannot_evict_known_entries() {
        let mut c = HitCache::new(3);
        let t0 = Instant::now();
        for i in 1..=3 {
            assert!(c.insert(&hit(&format!("10.0.0.{i}"), "_ipp"), t0));
        }
        assert!(
            !c.insert(&hit("10.0.0.99", "_ipp"), t0),
            "new key refused when full"
        );
        assert_eq!(c.len(), 3);
        assert!(
            c.insert(&hit("10.0.0.1", "_ipp"), t0),
            "known key may refresh"
        );
        // once old entries expire there is room again
        assert!(c.insert(&hit("10.0.0.99", "_ipp"), t0 + TTL + Duration::from_secs(1)));
    }

    #[test]
    fn browsed_types_are_capped() {
        assert_eq!(MAX_BROWSED_TYPES, 64);
    }

    #[tokio::test]
    #[ignore = "needs a real LAN and multicast; set RHIZOME_TEST_IP and RHIZOME_TEST_NET"]
    async fn live_browse_coexists_with_mdnsresponder() {
        let iface = std::env::var("RHIZOME_TEST_IP").unwrap().parse().unwrap();
        let net: Ipv4Net = std::env::var("RHIZOME_TEST_NET").unwrap().parse().unwrap();
        let svc =
            MdnsService::start(iface, net).expect("mdns-sd must start alongside mDNSResponder");
        tokio::time::sleep(Duration::from_secs(10)).await;
        let hits = svc.hits(Duration::from_secs(30));
        for h in &hits {
            eprintln!(
                "mdns hit: {} {:?} {:?} fresh={}",
                h.ip, h.hostname, h.service_types, h.fresh
            );
        }
        eprintln!("total mdns hits: {}", hits.len());
        assert!(!hits.is_empty(), "no mDNS answers received in 10 s");
    }
}
