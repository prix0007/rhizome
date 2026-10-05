//! Pure parser for macOS `arp -an` output.

use std::net::Ipv4Addr;

use crate::model::MacAddr;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    /// `None` for `(incomplete)` entries.
    pub mac: Option<MacAddr>,
    pub iface: String,
    pub permanent: bool,
}

/// Parse `arp -an` text. Multicast/broadcast MACs are dropped, as are lines
/// for other interfaces when `iface` is given. Malformed lines are skipped.
pub fn parse_arp(text: &str, iface: Option<&str>) -> Vec<ArpEntry> {
    text.lines()
        .filter_map(parse_line)
        .filter(|e| iface.is_none_or(|want| e.iface == want))
        .collect()
}

/// `? (192.168.0.1) at 68:7f:f0:00:00:01 on en0 ifscope [permanent] [ethernet]`
fn parse_line(line: &str) -> Option<ArpEntry> {
    let mut t = line.split_whitespace();
    let _name = t.next()?;
    let ip_tok = t.next()?;
    let ip: Ipv4Addr = ip_tok.strip_prefix('(')?.strip_suffix(')')?.parse().ok()?;
    if t.next()? != "at" {
        return None;
    }
    let mac_tok = t.next()?;
    let mac = if mac_tok == "(incomplete)" {
        None
    } else {
        let m: MacAddr = mac_tok.parse().ok()?;
        if m.is_multicast() {
            return None;
        }
        Some(m)
    };
    if t.next()? != "on" {
        return None;
    }
    let iface = t.next()?.to_string();
    let permanent = t.any(|x| x == "permanent");
    Some(ArpEntry {
        ip,
        mac,
        iface,
        permanent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC: &str = include_str!("../../tests/fixtures/arp_macos_basic.txt");
    const EDGE: &str = include_str!("../../tests/fixtures/arp_macos_edge.txt");

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_normal_line_with_short_octets() {
        let e = parse_arp(
            "? (192.168.0.194) at 8c:fd:49:0:0:4 on en0 ifscope [ethernet]\n",
            None,
        );
        assert_eq!(
            e,
            vec![ArpEntry {
                ip: "192.168.0.194".parse().unwrap(),
                mac: Some(mac("8c:fd:49:00:00:04")),
                iface: "en0".into(),
                permanent: false,
            }]
        );
    }

    #[test]
    fn incomplete_gives_none_mac() {
        let e = parse_arp(
            "? (192.168.0.173) at (incomplete) on en0 ifscope [ethernet]",
            None,
        );
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].mac, None);
    }

    #[test]
    fn permanent_flag_is_detected() {
        let e = parse_arp(BASIC, Some("en0"));
        let own = e
            .iter()
            .find(|x| x.ip.to_string() == "192.168.0.172")
            .unwrap();
        assert!(own.permanent);
        let gw = e
            .iter()
            .find(|x| x.ip.to_string() == "192.168.0.1")
            .unwrap();
        assert!(!gw.permanent);
    }

    #[test]
    fn multicast_and_broadcast_are_filtered() {
        let e = parse_arp(BASIC, None);
        assert!(e.iter().all(|x| x.ip.to_string() != "224.0.0.251"));
        assert!(e.iter().all(|x| x.ip.to_string() != "239.255.255.250"));
        assert!(e.iter().all(|x| x.ip.to_string() != "192.168.0.255"));
    }

    #[test]
    fn real_fixture_yields_five_entries() {
        // gw, .82, self (permanent), .173 incomplete, .194
        let e = parse_arp(BASIC, Some("en0"));
        assert_eq!(e.len(), 5);
        assert_eq!(e.iter().filter(|x| x.mac.is_none()).count(), 1);
    }

    #[test]
    fn other_interfaces_are_filtered_when_filter_given() {
        let e = parse_arp(EDGE, Some("en0"));
        assert!(e.iter().all(|x| x.iface == "en0"));
        assert!(e.iter().all(|x| x.ip.to_string() != "10.0.0.2"));
        assert!(e.iter().all(|x| x.ip.to_string() != "10.0.0.3"));
        let all = parse_arp(EDGE, None);
        assert!(all.iter().any(|x| x.iface == "utun3"));
        assert!(all.iter().any(|x| x.iface == "bridge100"));
    }

    #[test]
    fn garbage_blank_and_crlf_lines_do_not_panic() {
        let e = parse_arp(EDGE, Some("en0"));
        let ips: Vec<String> = e.iter().map(|x| x.ip.to_string()).collect();
        assert_eq!(ips, vec!["10.0.0.1", "10.0.0.9"]);
    }

    #[test]
    fn named_host_prefix_is_supported() {
        let e = parse_arp(EDGE, Some("en0"));
        assert_eq!(e[1].mac, Some(mac("0:1:2:3:4:5")));
    }

    #[test]
    fn trailing_whitespace_is_tolerated() {
        let e = parse_arp(
            "? (10.0.0.2) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]   \t\r\n",
            None,
        );
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn empty_and_binary_input() {
        assert!(parse_arp("", None).is_empty());
        assert!(parse_arp("\0\0\u{1b}[31m((((at at at", None).is_empty());
    }
}
