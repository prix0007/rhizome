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

/// Linux `/proc/net/arp`:
///
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.0.1      0x1         0x2         68:7f:f0:00:00:01     *        eth0
/// ```
///
/// Flag bit 0x2 means the entry is complete, 0x4 that it is permanent.
/// Incomplete entries and the all-zero MAC give `mac: None`. Multicast MACs and
/// other interfaces (when `iface` is given) are dropped. The header and any
/// malformed line are skipped.
pub fn parse_proc_net_arp(text: &str, iface: Option<&str>) -> Vec<ArpEntry> {
    text.lines()
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() < 6 {
                return None;
            }
            let ip: Ipv4Addr = t[0].parse().ok()?;
            let flags = u32::from_str_radix(t[2].trim_start_matches("0x"), 16).ok()?;
            let mac_parsed: MacAddr = t[3].parse().ok()?;
            let device = t[5].to_string();
            let complete = flags & 0x2 != 0 && !mac_parsed.is_zero();
            if complete && mac_parsed.is_multicast() {
                return None;
            }
            Some(ArpEntry {
                ip,
                mac: complete.then_some(mac_parsed),
                iface: device,
                permanent: flags & 0x4 != 0,
            })
        })
        .filter(|e| iface.is_none_or(|want| e.iface == want))
        .collect()
}

/// Windows `arp -a`, parsed by structure so that localised output works:
///
/// ```text
/// Interface: 192.168.0.172 --- 0x7
///   Internet Address      Physical Address      Type
///   192.168.0.1           68-7f-f0-00-00-01     dynamic
/// ```
///
/// A section header is any line containing `---` and an IPv4 address; an entry
/// is `<ipv4> <six dash- or colon-separated hex pairs> <word>`. The English
/// word `static` marks a permanent entry (other languages are not recognised
/// and are treated as dynamic). `iface_ip` keeps only that interface's section.
/// `ArpEntry::iface` holds the section's interface address.
pub fn parse_windows_arp(text: &str, iface_ip: Option<Ipv4Addr>) -> Vec<ArpEntry> {
    let mut out = Vec::new();
    let mut section: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if line.contains("---") {
            section = t.iter().find_map(|tok| tok.parse::<Ipv4Addr>().ok());
            continue;
        }
        let Some(sec) = section else { continue };
        if iface_ip.is_some_and(|want| want != sec) || t.len() < 3 {
            continue;
        }
        let (Ok(ip), Ok(mac)) = (t[0].parse::<Ipv4Addr>(), t[1].parse::<MacAddr>()) else {
            continue;
        };
        if mac.is_multicast() {
            continue;
        }
        out.push(ArpEntry {
            ip,
            mac: (!mac.is_zero()).then_some(mac),
            iface: sec.to_string(),
            permanent: t[2].eq_ignore_ascii_case("static"),
        });
    }
    out
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

    // ---- Linux /proc/net/arp ----

    const LINUX: &str = include_str!("../../tests/fixtures/arp_linux_proc.txt");

    #[test]
    fn linux_proc_entries_for_one_interface() {
        let e = parse_proc_net_arp(LINUX, Some("eth0"));
        let ips: Vec<String> = e.iter().map(|x| x.ip.to_string()).collect();
        assert_eq!(
            ips,
            [
                "192.168.0.1",
                "192.168.0.82",
                "192.168.0.173",
                "192.168.0.194",
                "192.168.0.250"
            ]
        );
        assert_eq!(e[0].mac, Some(mac("68:7f:f0:00:00:01")));
        assert!(e.iter().all(|x| x.iface == "eth0"));
    }

    #[test]
    fn linux_incomplete_entries_have_no_mac_and_permanent_is_flagged() {
        let e = parse_proc_net_arp(LINUX, Some("eth0"));
        let inc = e
            .iter()
            .find(|x| x.ip.to_string() == "192.168.0.173")
            .unwrap();
        assert_eq!(inc.mac, None, "flags 0x0 with a zero MAC is incomplete");
        let perm = e
            .iter()
            .find(|x| x.ip.to_string() == "192.168.0.250")
            .unwrap();
        assert!(perm.permanent && perm.mac.is_some());
        assert!(!e[0].permanent);
    }

    #[test]
    fn linux_multicast_and_other_interfaces_are_filtered() {
        let all = parse_proc_net_arp(LINUX, None);
        assert!(all.iter().all(|x| x.ip.to_string() != "224.0.0.251"));
        assert!(all.iter().any(|x| x.iface == "wg0"));
        assert!(
            parse_proc_net_arp(LINUX, Some("eth0"))
                .iter()
                .all(|x| x.iface != "wg0")
        );
        assert!(parse_proc_net_arp(LINUX, Some("eth9")).is_empty());
    }

    #[test]
    fn linux_garbage_header_only_and_empty_input_do_not_panic() {
        assert!(parse_proc_net_arp("", None).is_empty());
        assert!(
            parse_proc_net_arp("IP address HW type Flags HW address Mask Device\n", None)
                .is_empty()
        );
        assert!(
            parse_proc_net_arp(
                "\0\0 junk\n1.2.3.4 0x1 zz aa:bb 7 x\n999.1.1.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n",
                None
            )
            .is_empty()
        );
        let crlf = "192.168.0.1 0x1 0x2 68:7f:f0:00:00:01 * eth0\r\n";
        assert_eq!(parse_proc_net_arp(crlf, None).len(), 1);
    }

    // ---- Windows arp -a ----

    const WIN: &str = include_str!("../../tests/fixtures/arp_windows.txt");
    const WIN_DE: &str = include_str!("../../tests/fixtures/arp_windows_de.txt");

    #[test]
    fn windows_sections_are_split_by_interface_address() {
        let ip: Ipv4Addr = "192.168.0.172".parse().unwrap();
        let e = parse_windows_arp(WIN, Some(ip));
        let ips: Vec<String> = e.iter().map(|x| x.ip.to_string()).collect();
        assert_eq!(
            ips,
            ["192.168.0.1", "192.168.0.82", "192.168.0.194"],
            "broadcast and multicast are dropped"
        );
        assert_eq!(
            e[0].mac,
            Some(mac("68:7f:f0:00:00:01")),
            "dash-separated MACs parse"
        );
        assert!(e.iter().all(|x| x.iface == "192.168.0.172"));
        let other = parse_windows_arp(WIN, Some("10.8.0.2".parse().unwrap()));
        assert_eq!(other.len(), 1);
        assert_eq!(
            parse_windows_arp(WIN, None).len(),
            4,
            "all sections when unfiltered"
        );
        assert!(parse_windows_arp(WIN, Some("1.2.3.4".parse().unwrap())).is_empty());
    }

    #[test]
    fn windows_parsing_is_structural_so_localised_output_works() {
        let e = parse_windows_arp(WIN_DE, Some("192.168.0.172".parse().unwrap()));
        assert_eq!(e.len(), 2, "German headers and type words still parse");
        assert_eq!(e[1].mac, Some(mac("02:21:49:00:00:82")));
    }

    #[test]
    fn windows_static_is_permanent_and_crlf_is_handled() {
        let text = "Interface: 10.0.0.5 --- 0x3\r\n  10.0.0.1  aa-bb-cc-00-00-01  static\r\n  10.0.0.2  aa-bb-cc-00-00-02  dynamic\r\n";
        let e = parse_windows_arp(text, None);
        assert!(e[0].permanent && !e[1].permanent);
    }

    #[test]
    fn windows_garbage_and_entries_outside_any_section_are_ignored() {
        assert!(parse_windows_arp("", None).is_empty());
        assert!(
            parse_windows_arp("  10.0.0.1  aa-bb-cc-00-00-01  dynamic\n", None).is_empty(),
            "no section header yet"
        );
        assert!(
            parse_windows_arp(
                "Interface: nonsense --- 0x1\n  10.0.0.1  aa-bb-cc-00-00-01  dynamic\n",
                None
            )
            .is_empty()
        );
        assert!(parse_windows_arp("Interface: 10.0.0.5 --- 0x3\n  10.0.0.1  zz-bb-cc-00-00-01  dynamic\n  10.0.0.2\n  \0\n", None).is_empty());
        let zero = parse_windows_arp(
            "Interface: 10.0.0.5 --- 0x3\n  10.0.0.1  00-00-00-00-00-00  dynamic\n",
            None,
        );
        assert_eq!(zero[0].mac, None);
    }
}
