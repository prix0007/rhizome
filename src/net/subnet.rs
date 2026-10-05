//! Pure subnet math: which addresses may we probe, and in what order.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Hosts to sweep: every host address in `net` except `self_ip`, nearest to the
/// gateway (or to us when there is none) first, capped at `max_hosts`.
pub fn enumerate_targets(
    net: Ipv4Net,
    self_ip: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    max_hosts: usize,
) -> Vec<Ipv4Addr> {
    let anchor = i64::from(u32::from(gateway.unwrap_or(self_ip)));
    let mut t: Vec<Ipv4Addr> = net
        .hosts()
        .filter(|ip| *ip != self_ip && is_scan_target(*ip, net))
        .collect();
    t.sort_by_key(|ip| ((i64::from(u32::from(*ip)) - anchor).abs(), *ip));
    t.truncate(max_hosts);
    t
}

/// The guard every probe target must pass: a private, in-subnet unicast host
/// address (not the network or broadcast address).
pub fn is_scan_target(ip: Ipv4Addr, net: Ipv4Net) -> bool {
    if !net.network().is_private() || !net.contains(&ip) {
        return false;
    }
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local()
        || !ip.is_private()
    {
        return false;
    }
    // /31 and /32 have no network/broadcast address.
    !(net.prefix_len() <= 30 && (ip == net.network() || ip == net.broadcast()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn slash_24_gives_253_targets_excluding_self() {
        let t = enumerate_targets(
            net("192.168.0.0/24"),
            ip("192.168.0.172"),
            Some(ip("192.168.0.1")),
            1024,
        );
        assert_eq!(t.len(), 253);
        assert!(!t.contains(&ip("192.168.0.172")));
        assert!(!t.contains(&ip("192.168.0.0")));
        assert!(!t.contains(&ip("192.168.0.255")));
        assert!(t.contains(&ip("192.168.0.1")));
    }

    #[test]
    fn slash_30_edge_case() {
        let t = enumerate_targets(net("10.0.0.0/30"), ip("10.0.0.1"), None, 1024);
        assert_eq!(t, vec![ip("10.0.0.2")]);
    }

    #[test]
    fn slash_31_and_32_do_not_panic() {
        assert_eq!(
            enumerate_targets(net("10.0.0.0/31"), ip("10.0.0.0"), None, 10),
            vec![ip("10.0.0.1")]
        );
        assert!(enumerate_targets(net("10.0.0.5/32"), ip("10.0.0.5"), None, 10).is_empty());
    }

    #[test]
    fn slash_16_is_capped_nearest_to_gateway_first() {
        let gw = ip("10.1.0.1");
        let t = enumerate_targets(net("10.1.0.0/16"), ip("10.1.0.50"), Some(gw), 1024);
        assert_eq!(t.len(), 1024);
        assert_eq!(t[0], gw, "the gateway itself is nearest");
        let dist = |a: Ipv4Addr| (u32::from(a) as i64 - u32::from(gw) as i64).abs();
        assert!(
            t.windows(2).all(|w| dist(w[0]) <= dist(w[1])),
            "sorted by distance"
        );
        assert!(t.iter().all(|a| dist(*a) <= 1024));
    }

    #[test]
    fn without_gateway_distance_is_from_self() {
        let t = enumerate_targets(net("10.1.0.0/16"), ip("10.1.200.7"), None, 4);
        assert_eq!(t.len(), 4);
        assert!(t.iter().all(|a| a.octets()[2] == 200));
    }

    #[test]
    fn max_hosts_smaller_than_subnet() {
        assert_eq!(
            enumerate_targets(
                net("192.168.0.0/24"),
                ip("192.168.0.2"),
                Some(ip("192.168.0.1")),
                5
            )
            .len(),
            5
        );
        assert!(enumerate_targets(net("192.168.0.0/24"), ip("192.168.0.2"), None, 0).is_empty());
    }

    #[test]
    fn is_scan_target_accepts_only_in_subnet_unicast_hosts() {
        let n = net("192.168.0.0/24");
        assert!(is_scan_target(ip("192.168.0.5"), n));
        for bad in [
            "8.8.8.8",
            "224.0.0.251",
            "239.255.255.250",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.5",
            "192.168.0.255",
            "192.168.0.0",
            "255.255.255.255",
            "169.254.1.1",
        ] {
            assert!(!is_scan_target(ip(bad), n), "{bad}");
        }
    }

    #[test]
    fn public_subnets_are_never_scanned() {
        assert!(!is_scan_target(ip("8.8.8.8"), net("8.8.8.0/24")));
    }

    #[test]
    fn point_to_point_slash_31_hosts_are_targets() {
        assert!(is_scan_target(ip("10.0.0.0"), net("10.0.0.0/31")));
        assert!(is_scan_target(ip("10.0.0.1"), net("10.0.0.0/31")));
    }
}
