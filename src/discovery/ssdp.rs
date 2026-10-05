//! I/O adapter: send one M-SEARCH and collect unicast replies for a few seconds.
//!
//! The socket is bound to an ephemeral port on the scan interface's address,
//! so nothing ever listens on 1900. The only destination is the SSDP
//! multicast group; LOCATION URLs are never fetched.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ipnet::Ipv4Net;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::ssdp_parse::{MAX_RESPONSE, build_msearch, parse_response};
use crate::model::SsdpObservation;
use crate::net::subnet::is_scan_target;

/// Hard limits on what one 3-second window may keep (a LAN host can flood us).
pub const MAX_OBSERVATIONS: usize = 512;
pub const MAX_PER_IP: usize = 32;

/// Deduplicating, bounded collection of SSDP observations.
#[derive(Default)]
pub struct ObservationSet {
    out: Vec<SsdpObservation>,
    seen: BTreeSet<(Ipv4Addr, Option<String>, Option<String>)>,
    per_ip: std::collections::BTreeMap<Ipv4Addr, usize>,
}

impl ObservationSet {
    /// Add an observation unless it is a duplicate or a limit is reached.
    pub fn offer(&mut self, obs: SsdpObservation) -> bool {
        if self.out.len() >= MAX_OBSERVATIONS {
            return false;
        }
        let key = (obs.ip, obs.hit.st.clone(), obs.hit.usn.clone());
        if self.seen.contains(&key) {
            return false;
        }
        let n = self.per_ip.entry(obs.ip).or_insert(0);
        if *n >= MAX_PER_IP {
            return false;
        }
        *n += 1;
        self.seen.insert(key);
        self.out.push(obs);
        true
    }
    pub fn len(&self) -> usize {
        self.out.len()
    }
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }
    pub fn into_vec(self) -> Vec<SsdpObservation> {
        self.out
    }
}

/// Turn a search result into (observations, warning for the status bar).
pub fn ssdp_outcome(
    r: std::io::Result<Vec<SsdpObservation>>,
) -> (Vec<SsdpObservation>, Option<String>) {
    match r {
        Ok(v) => (v, None),
        Err(e) => (
            vec![],
            Some(format!(
                "SSDP search failed ({e}); UPnP hints are unavailable this scan"
            )),
        ),
    }
}

const GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

fn open_socket(iface_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.bind(&SocketAddrV4::new(iface_ip, 0).into())?;
    sock.set_multicast_if_v4(&iface_ip)?;
    sock.set_multicast_ttl_v4(1)?;
    sock.set_multicast_loop_v4(false)?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

/// Search for `window`, returning one observation per distinct (ip, ST, USN).
pub async fn search(
    iface_ip: Ipv4Addr,
    net: Ipv4Net,
    window: Duration,
) -> std::io::Result<Vec<SsdpObservation>> {
    let sock = open_socket(iface_ip)?;
    let request = build_msearch();
    sock.send_to(&request, GROUP).await?;
    let resend_at = Instant::now() + Duration::from_millis(400);
    let deadline = Instant::now() + window;
    let mut resent = false;
    let mut set = ObservationSet::default();
    let mut buf = vec![0u8; MAX_RESPONSE + 1]; // one spare byte so oversize datagrams are detectable
    loop {
        if !resent && Instant::now() >= resend_at {
            resent = true;
            let _ = sock.send_to(&request, GROUP).await;
        }
        let wake = if resent {
            deadline
        } else {
            resend_at.min(deadline)
        };
        match tokio::time::timeout_at(wake, sock.recv_from(&mut buf)).await {
            Err(_) => {
                if Instant::now() >= deadline {
                    break;
                }
            }
            // Windows reports an earlier ICMP "port unreachable" as ConnectionReset on
            // the next receive; that is not the end of the window.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Ok(Err(_)) => break,
            Ok(Ok((n, SocketAddr::V4(from)))) => {
                let ip = *from.ip();
                if n > MAX_RESPONSE || !is_scan_target(ip, net) {
                    continue;
                }
                if let Some(hit) = parse_response(&buf[..n]) {
                    set.offer(SsdpObservation { ip, hit });
                }
            }
            Ok(Ok(_)) => {}
        }
    }
    Ok(set.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SsdpHit;

    fn obs(ip: &str, usn: &str) -> SsdpObservation {
        SsdpObservation {
            ip: ip.parse().unwrap(),
            hit: SsdpHit {
                server: Some("s".into()),
                st: Some("st".into()),
                usn: Some(usn.into()),
                location: None,
            },
        }
    }

    #[test]
    fn duplicates_are_ignored() {
        let mut s = ObservationSet::default();
        assert!(s.offer(obs("10.0.0.2", "a")));
        assert!(!s.offer(obs("10.0.0.2", "a")));
        assert!(s.offer(obs("10.0.0.3", "a")));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn one_source_cannot_exceed_the_per_ip_cap() {
        let mut s = ObservationSet::default();
        for i in 0..1000 {
            s.offer(obs("10.0.0.2", &format!("usn-{i}")));
        }
        assert_eq!(s.len(), MAX_PER_IP);
        assert!(s.offer(obs("10.0.0.3", "x")), "other hosts are still heard");
    }

    #[test]
    fn total_observations_are_capped() {
        let mut s = ObservationSet::default();
        for host in 1..=200u32 {
            for i in 0..MAX_PER_IP {
                s.offer(obs(
                    &format!("10.0.{}.{}", host / 250, host % 250 + 1),
                    &format!("u{i}"),
                ));
            }
        }
        assert_eq!(s.len(), MAX_OBSERVATIONS);
        assert!(!s.offer(obs("10.9.9.9", "late")));
    }

    #[test]
    fn a_failed_search_becomes_a_status_warning() {
        let (v, w) = ssdp_outcome(Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no route",
        )));
        assert!(v.is_empty());
        let w = w.unwrap();
        assert!(w.contains("SSDP") && w.contains("no route"), "{w}");
        let (v, w) = ssdp_outcome(Ok(vec![obs("10.0.0.2", "a")]));
        assert_eq!(v.len(), 1);
        assert!(w.is_none());
    }

    #[tokio::test]
    #[ignore = "needs a real LAN with multicast; set RHIZOME_TEST_IP and RHIZOME_TEST_NET"]
    async fn live_search_finds_upnp_devices() {
        let ip: Ipv4Addr = std::env::var("RHIZOME_TEST_IP").unwrap().parse().unwrap();
        let net: Ipv4Net = std::env::var("RHIZOME_TEST_NET").unwrap().parse().unwrap();
        let hits = search(ip, net, Duration::from_secs(3)).await.unwrap();
        for h in &hits {
            eprintln!("ssdp: {} server={:?} st={:?}", h.ip, h.hit.server, h.hit.st);
        }
        eprintln!("total ssdp observations: {}", hits.len());
        assert!(hits.iter().all(|h| is_scan_target(h.ip, net)));
    }
}
