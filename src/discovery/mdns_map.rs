//! Pure mapping from raw mDNS resolutions to per-IP hits.

use std::net::IpAddr;

use crate::enrich::sanitize::sanitize;
use crate::model::MdnsHit;
use crate::net::subnet::is_scan_target;

/// What the mDNS adapter learned from one resolved service instance.
#[derive(Clone, Debug)]
pub struct RawResolution {
    /// e.g. `Living-Room.local.`
    pub host: String,
    pub addresses: Vec<IpAddr>,
    /// e.g. `_ipp._tcp.local.`
    pub service_type: String,
}

/// `Living-Room.local.` -> `Living-Room`; sanitised; `None` if nothing is left.
pub fn clean_hostname(host: &str) -> Option<String> {
    let h = host.trim_end_matches('.');
    let h = match h.len().checked_sub(6) {
        Some(cut) if h.is_char_boundary(cut) && h[cut..].eq_ignore_ascii_case(".local") => {
            &h[..cut]
        }
        _ => h,
    };
    let clean = sanitize(h);
    (!clean.is_empty() && !clean.eq_ignore_ascii_case("localhost")).then_some(clean)
}

/// `_ipp._tcp.local.` -> `_ipp`; `None` for the meta-query type or junk.
pub fn service_label(ty: &str) -> Option<String> {
    let first = ty.trim_end_matches('.').split('.').next()?;
    if !first.starts_with('_') || first == "_services" {
        return None;
    }
    let label = sanitize(first);
    (label.len() > 1).then_some(label)
}

/// Validate a service type announced on the meta-query before it is browsed or
/// logged: ASCII DNS-SD name only, e.g. `_ipp._tcp.local.`. Anything else is `None`.
pub fn valid_service_type(ty: &str) -> Option<String> {
    const MAX_LEN: usize = 100;
    let ok_chars = ty
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ty.len() > MAX_LEN || !ok_chars {
        return None;
    }
    let labels: Vec<&str> = ty.strip_suffix('.').unwrap_or(ty).split('.').collect();
    // exactly `_name._tcp|_udp.local`
    let [name, proto, domain] = labels[..] else {
        return None;
    };
    let name_ok =
        name.len() > 1 && name.starts_with('_') && name != "_services" && !name[1..].contains('_');
    let proto_ok = proto == "_tcp" || proto == "_udp";
    (name_ok && proto_ok && domain.eq_ignore_ascii_case("local")).then(|| ty.to_string())
}

/// Keep only hits whose address is an in-subnet scan target.
pub fn retain_in_subnet(hits: Vec<MdnsHit>, net: ipnet::Ipv4Net) -> Vec<MdnsHit> {
    hits.into_iter()
        .filter(|h| is_scan_target(h.ip, net))
        .collect()
}

/// One hit per IPv4 address; IPv6 is ignored.
pub fn map_resolution(r: &RawResolution) -> Vec<MdnsHit> {
    let hostname = clean_hostname(&r.host);
    let service_types: Vec<String> = service_label(&r.service_type).into_iter().collect();
    r.addresses
        .iter()
        .filter_map(|a| match a {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() && !v4.is_multicast() => {
                Some(*v4)
            }
            _ => None,
        })
        .map(|ip| MdnsHit {
            ip,
            hostname: hostname.clone(),
            service_types: service_types.clone(),
            fresh: true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(host: &str, addrs: &[&str], ty: &str) -> RawResolution {
        RawResolution {
            host: host.into(),
            addresses: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            service_type: ty.into(),
        }
    }

    #[test]
    fn local_suffix_is_stripped() {
        assert_eq!(
            clean_hostname("Living-Room.local.").as_deref(),
            Some("Living-Room")
        );
        assert_eq!(
            clean_hostname("Living-Room.local").as_deref(),
            Some("Living-Room")
        );
        assert_eq!(
            clean_hostname("Living-Room.LOCAL.").as_deref(),
            Some("Living-Room")
        );
        assert_eq!(clean_hostname("a.b.local.").as_deref(), Some("a.b"));
        assert_eq!(clean_hostname("plain").as_deref(), Some("plain"));
    }

    #[test]
    fn empty_or_hostile_hostnames() {
        assert_eq!(clean_hostname(""), None);
        assert_eq!(clean_hostname(".local."), None);
        assert_eq!(clean_hostname("\0\x07.local."), None);
        assert_eq!(
            clean_hostname("evil\u{202e}name\x1b[0m.local.").as_deref(),
            Some("evilname[0m")
        );
        assert_eq!(
            clean_hostname(&format!("{}.local.", "x".repeat(1000)))
                .unwrap()
                .chars()
                .count(),
            255
        );
        assert_eq!(
            clean_hostname("<img src=x onerror=1>.local.").as_deref(),
            Some("<img src=x onerror=1>")
        );
    }

    #[test]
    fn bogus_localhost_hostname_is_dropped() {
        // Seen live: an Android TV announces `localhost.local.` for its AirPlay service.
        assert_eq!(clean_hostname("localhost.local."), None);
        assert_eq!(clean_hostname("LocalHost"), None);
        assert_eq!(
            clean_hostname("localhost-nas.local.").as_deref(),
            Some("localhost-nas")
        );
    }

    #[test]
    fn service_labels() {
        assert_eq!(service_label("_ipp._tcp.local.").as_deref(), Some("_ipp"));
        assert_eq!(
            service_label("_airplay._tcp.local").as_deref(),
            Some("_airplay")
        );
        assert_eq!(
            service_label("_companion-link._tcp.local.").as_deref(),
            Some("_companion-link")
        );
        assert_eq!(service_label("_services._dns-sd._udp.local."), None);
        assert_eq!(service_label("garbage"), None);
        assert_eq!(service_label(""), None);
        assert_eq!(service_label("_\u{0}x._tcp.local.").as_deref(), Some("_x"));
    }

    #[test]
    fn multiple_addresses_give_multiple_hits_and_ipv6_is_ignored() {
        let hits = map_resolution(&raw(
            "Printer.local.",
            &["192.168.0.50", "fe80::1", "192.168.0.51"],
            "_ipp._tcp.local.",
        ));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].ip.to_string(), "192.168.0.50");
        assert_eq!(hits[1].ip.to_string(), "192.168.0.51");
        assert!(hits.iter().all(|h| h.hostname.as_deref() == Some("Printer")
            && h.service_types == vec!["_ipp".to_string()]));
    }

    #[test]
    fn ipv6_only_gives_nothing() {
        assert!(map_resolution(&raw("x.local.", &["fe80::1"], "_ipp._tcp.local.")).is_empty());
        assert!(map_resolution(&raw("x.local.", &[], "_ipp._tcp.local.")).is_empty());
    }

    #[test]
    fn hits_for_the_meta_type_carry_no_service() {
        let hits = map_resolution(&raw(
            "x.local.",
            &["10.0.0.2"],
            "_services._dns-sd._udp.local.",
        ));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].service_types.is_empty());
    }

    #[test]
    fn loopback_and_unspecified_addresses_are_ignored() {
        assert!(
            map_resolution(&raw(
                "x.local.",
                &["127.0.0.1", "0.0.0.0", "224.0.0.251"],
                "_ipp._tcp.local."
            ))
            .is_empty()
        );
    }

    #[test]
    fn service_type_validation_accepts_only_plain_dns_sd_names() {
        assert_eq!(
            valid_service_type("_ipp._tcp.local.").as_deref(),
            Some("_ipp._tcp.local.")
        );
        assert_eq!(
            valid_service_type("_companion-link._tcp.local.").as_deref(),
            Some("_companion-link._tcp.local.")
        );
        assert_eq!(
            valid_service_type("_a._udp.local.").as_deref(),
            Some("_a._udp.local.")
        );
        for bad in [
            "",
            "ipp._tcp.local.",
            "_ipp._tcp.example.com.",
            "_ipp._tcp",
            "_ip p._tcp.local.",
            "_ipp\x1b[31m._tcp.local.",
            "_ipp\n._tcp.local.",
            "_ipp._tcp.local.\0",
            "_é._tcp.local.",
            "_services._dns-sd._udp.local.",
            "_a._sub._b._tcp.local.",
        ] {
            assert_eq!(valid_service_type(bad), None, "{bad:?}");
        }
        assert_eq!(
            valid_service_type(&format!("_{}._tcp.local.", "x".repeat(200))),
            None,
            "length is capped"
        );
    }

    #[test]
    fn hits_outside_the_scanned_subnet_are_dropped() {
        let net: ipnet::Ipv4Net = "192.168.0.0/24".parse().unwrap();
        let mk = |ip: &str| MdnsHit {
            ip: ip.parse().unwrap(),
            hostname: None,
            service_types: vec![],
            fresh: true,
        };
        let kept = retain_in_subnet(
            vec![
                mk("192.168.0.5"),
                mk("8.8.8.8"),
                mk("10.0.0.1"),
                mk("169.254.1.1"),
                mk("192.168.0.255"),
                mk("192.168.1.5"),
            ],
            net,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].ip.to_string(), "192.168.0.5");
    }
}
