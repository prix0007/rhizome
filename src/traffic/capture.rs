//! Opt-in packet-flow summaries (`--capture`).
//!
//! Approach: parse the text output of the system `tcpdump` (absolute path, no
//! shell). Rationale: it needs no native link-time dependency, so the default
//! build for all six release targets is unaffected, and the privilege grant
//! applies to `tcpdump` (a BPF group on macOS, a file capability on Linux),
//! never to rhizome itself.
//!
//! Privacy rules, enforced by the types here:
//! * Only counts survive: bytes and packets by (sender, receiver, protocol
//!   class). Payloads are never read: tcpdump is told to capture headers only
//!   (`-s 96`) and we parse only its one-line summaries.
//! * Remote (off-subnet) addresses are never recorded. Traffic to or from one
//!   becomes a single "other" flow on this machine's own node.
//! * Traffic is captured non-promiscuously (`-p`): only what this machine sends
//!   or receives, plus broadcast and multicast.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::Ipv4Net;

use crate::model::MacAddr;

/// Cap on flows listed per sample.
pub const MAX_FLOWS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Arp,
    Mdns,
    Ssdp,
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Arp => "arp",
            Proto::Mdns => "mdns",
            Proto::Ssdp => "ssdp",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Other => "other",
        }
    }
}

/// One summarised frame. Addresses are kept only long enough to decide whether
/// the frame is local; they are not stored anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub len: u32,
    pub proto: Proto,
    pub ips: Option<(IpAddr, IpAddr)>,
}

/// Parse one line of `tcpdump -e -q -nn -tt` output. `None` for anything that
/// is not a recognisable Ethernet frame summary (so junk never counts).
pub fn parse_tcpdump_line(line: &str) -> Option<Frame> {
    // "<ts> <src mac> > <dst mac>, ethertype <NAME> (0x....), length <N>: <summary>"
    let (_ts, rest) = line.split_once(' ')?;
    let (macs, after) = rest.split_once(", ethertype ")?;
    let (src_s, dst_s) = macs.split_once(" > ")?;
    let (src, dst): (MacAddr, MacAddr) = (src_s.trim().parse().ok()?, dst_s.trim().parse().ok()?);
    let ether = after.split_whitespace().next()?;
    let (_, len_and_tail) = after.split_once(", length ")?;
    let (len_s, tail) = len_and_tail
        .split_once(": ")
        .unwrap_or((len_and_tail.trim_end_matches(':'), ""));
    let len: u32 = len_s.trim().parse().ok()?;
    let tail = tail.trim();

    match ether {
        "ARP" => Some(Frame {
            src,
            dst,
            len,
            proto: Proto::Arp,
            ips: None,
        }),
        "IPv4" | "IPv6" => {
            // "<src>[.port] > <dst>[.port]: <proto summary>"
            let (flow, what) = tail.split_once(": ")?;
            let (a, b) = flow.split_once(" > ")?;
            let ((ip_a, port_a), (ip_b, port_b)) = (endpoint(a)?, endpoint(b)?);
            let ports = [port_a, port_b];
            let proto = if what.starts_with("UDP") {
                if ports.contains(&Some(5353)) {
                    Proto::Mdns
                } else if ports.contains(&Some(1900)) {
                    Proto::Ssdp
                } else {
                    Proto::Udp
                }
            } else if what.starts_with("tcp") || what.starts_with("Flags [") {
                Proto::Tcp
            } else if what.starts_with("ICMP") {
                Proto::Icmp
            } else {
                Proto::Other
            };
            Some(Frame {
                src,
                dst,
                len,
                proto,
                ips: Some((ip_a, ip_b)),
            })
        }
        _ => Some(Frame {
            src,
            dst,
            len,
            proto: Proto::Other,
            ips: None,
        }),
    }
}

/// `192.168.0.1.443`, `192.168.0.1`, `fe80::1.5353`, `ff02::fb` -> (address, port).
fn endpoint(s: &str) -> Option<(IpAddr, Option<u16>)> {
    let s = s.trim().trim_end_matches(':');
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some((ip, None));
    }
    let (addr, port) = s.rsplit_once('.')?;
    Some((addr.parse().ok()?, Some(port.parse().ok()?)))
}

/// Who a frame belongs to, for the flows list. Ids are device ids; `Broadcast`
/// and `Multicast` are the contract's literal destinations.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum End {
    Device(String),
    Broadcast,
    Multicast,
}

impl End {
    pub fn label(&self) -> String {
        match self {
            End::Device(id) => id.clone(),
            End::Broadcast => "broadcast".into(),
            End::Multicast => "multicast".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: String,
    pub dst: End,
    pub proto: Proto,
}

/// What the classifier needs to know about this LAN.
pub struct Ctx<'a> {
    pub self_mac: MacAddr,
    pub self_id: &'a str,
    pub net: Ipv4Net,
    /// MAC to device id (this machine included).
    pub ids: &'a BTreeMap<MacAddr, String>,
}

/// Decide which flow a frame counts towards (and in which direction relative to
/// this machine), or drop it. Never returns an address.
pub fn classify_frame(f: &Frame, ctx: &Ctx<'_>) -> Option<Attribution> {
    let involves_self = f.src == ctx.self_mac || f.dst == ctx.self_mac;
    // Anything that touches an address outside the LAN is reduced to one
    // anonymous bucket on this machine, and only if it is our own traffic.
    if let Some((a, b)) = f.ips
        && !(is_lan_addr(a, ctx.net) && is_lan_addr(b, ctx.net))
    {
        return involves_self.then(|| Attribution {
            key: FlowKey {
                src: ctx.self_id.to_string(),
                dst: End::Device(ctx.self_id.to_string()),
                proto: Proto::Other,
            },
            bytes: f.len,
            device: None,
        });
    }
    let src_id = ctx.ids.get(&f.src)?;
    let broadcast = f.dst == MacAddr([0xff; 6]);
    if broadcast || f.dst.is_multicast() {
        let dst = if broadcast {
            End::Broadcast
        } else {
            End::Multicast
        };
        return Some(Attribution {
            key: FlowKey {
                src: src_id.clone(),
                dst,
                proto: f.proto,
            },
            bytes: f.len,
            device: None,
        });
    }
    // Unicast: only traffic between this machine and a device we know.
    if !involves_self {
        return None;
    }
    let dst_id = ctx.ids.get(&f.dst)?;
    let device = if f.src == ctx.self_mac {
        (dst_id.clone(), Direction::ToDevice)
    } else {
        (src_id.clone(), Direction::FromDevice)
    };
    Some(Attribution {
        key: FlowKey {
            src: src_id.clone(),
            dst: End::Device(dst_id.clone()),
            proto: f.proto,
        },
        bytes: f.len,
        device: Some(device),
    })
}

/// On the LAN: in the subnet, or link-local / multicast / broadcast / unspecified
/// (neighbour discovery, mDNS, DHCP). Everything else is "somewhere remote".
fn is_lan_addr(ip: IpAddr, net: Ipv4Net) -> bool {
    match ip {
        IpAddr::V4(a) => {
            net.contains(&a)
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_link_local()
                || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            a.is_unspecified() || a.is_multicast() || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// A classified frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribution {
    pub key: FlowKey,
    pub bytes: u32,
    /// For unicast traffic between this machine and a device: that device and
    /// whether the bytes came from it (`true`, its "rx" from us) or went to it.
    pub device: Option<(String, Direction)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the device to this machine.
    FromDevice,
    /// From this machine to the device.
    ToDevice,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct FlowOut {
    pub src: String,
    pub dst: String,
    pub proto: &'static str,
    pub bps: u64,
    pub pps: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Drained {
    pub flows: Vec<FlowOut>,
    /// Per device: (rx_bps, tx_bps) between this machine and that device.
    pub devices: BTreeMap<String, (u64, u64)>,
}

/// Sums frames over one window and turns the sums into rates.
#[derive(Default)]
pub struct FlowAccumulator {
    flows: BTreeMap<FlowKey, (u64, u64)>,
    devices: BTreeMap<String, (u64, u64)>,
}

impl FlowAccumulator {
    pub fn add(&mut self, a: &Attribution) {
        let f = self.flows.entry(a.key.clone()).or_insert((0, 0));
        f.0 += u64::from(a.bytes);
        f.1 += 1;
        if let Some((dev, dir)) = &a.device {
            let d = self.devices.entry(dev.clone()).or_insert((0, 0));
            match dir {
                Direction::FromDevice => d.0 += u64::from(a.bytes),
                Direction::ToDevice => d.1 += u64::from(a.bytes),
            }
        }
    }

    /// Rates over `secs` seconds (at least 0.001), largest flows first, at most
    /// `MAX_FLOWS`; the accumulator is emptied.
    pub fn drain(&mut self, secs: f64) -> Drained {
        let secs = secs.max(0.001);
        let bps = |bytes: u64| (bytes as f64 * 8.0 / secs).round() as u64;
        let mut flows: Vec<FlowOut> = std::mem::take(&mut self.flows)
            .into_iter()
            .map(|(k, (bytes, pkts))| FlowOut {
                src: k.src,
                dst: k.dst.label(),
                proto: k.proto.as_str(),
                bps: bps(bytes),
                pps: (pkts as f64 / secs).ceil() as u64,
            })
            .collect();
        flows.sort_by(|a, b| {
            b.bps
                .cmp(&a.bps)
                .then_with(|| a.src.cmp(&b.src))
                .then_with(|| a.dst.cmp(&b.dst))
        });
        flows.truncate(MAX_FLOWS);
        let devices = std::mem::take(&mut self.devices)
            .into_iter()
            .map(|(d, (rx, tx))| (d, (bps(rx), bps(tx))))
            .collect();
        Drained { flows, devices }
    }
}

/// Is `name` safe to hand to tcpdump as `-i <name>` (no option injection)?
pub fn valid_iface_arg(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= 32
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Why capture cannot run, in words that tell the user what to do on this OS.
/// `stderr` is tcpdump's own message (or empty when it was not found).
pub fn unavailable_reason(os: crate::platform::Os, tool_found: bool, stderr: &str) -> String {
    use crate::platform::Os;
    if os == Os::Windows {
        return "Packet capture is not available on Windows builds: it would need the Npcap driver, which Rhizome does not bundle. Everything else (host throughput, link info, loss and jitter) works without it.".to_string();
    }
    if !tool_found {
        return match os {
            Os::Mac => "/usr/sbin/tcpdump was not found; capture needs the system tcpdump.".to_string(),
            _ => "tcpdump was not found in the standard locations (/usr/bin, /usr/sbin, /sbin, /bin); install it with your package manager (for example `apt install tcpdump`), then restart rhizome.".to_string(),
        };
    }
    let first = crate::enrich::sanitize::sanitize(stderr.lines().next().unwrap_or(""));
    let lower = stderr.to_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") || lower.contains("denied") {
        return match os {
            Os::Mac => "macOS did not allow opening the packet capture device (/dev/bpf*). Give your user read access to it instead of running rhizome with elevated rights: install Wireshark's ChmodBPF helper (it creates an access_bpf group that can read /dev/bpf*) and add your user to that group, or make /dev/bpf* readable by your user, then restart rhizome.".to_string(),
            _ => "The kernel denied raw packet access to tcpdump. Grant it to tcpdump only, not to rhizome: `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`, or add your user to the group your distribution uses for packet capture (often `pcap` or `wireshark`), then restart rhizome.".to_string(),
        };
    }
    if lower.contains("no such device") || lower.contains("no suitable device") {
        return format!(
            "tcpdump could not find the selected network interface ({first}); capture follows the interface rhizome scans (see --iface)."
        );
    }
    format!("tcpdump could not start capture: {first}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Os;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    const ME: &str = "3c:e1:a1:00:00:01";
    const GW: &str = "68:7f:f0:00:00:01";
    const TV: &str = "02:21:49:00:00:82";
    const PC: &str = "aa:bb:cc:00:00:07";

    fn ids() -> BTreeMap<MacAddr, String> {
        [(ME, "me"), (GW, "gw"), (TV, "tv"), (PC, "pc")]
            .into_iter()
            .map(|(m, id)| (mac(m), id.to_string()))
            .collect()
    }

    fn ctx(ids: &BTreeMap<MacAddr, String>) -> Ctx<'_> {
        Ctx {
            self_mac: mac(ME),
            self_id: "me",
            net: "192.168.0.0/24".parse().unwrap(),
            ids,
        }
    }

    fn line(src: &str, dst: &str, ether: &str, len: u32, tail: &str) -> String {
        format!("1696612345.123456 {src} > {dst}, ethertype {ether}, length {len}: {tail}")
    }

    // ---- parsing real tcpdump shapes ----

    #[test]
    fn parses_a_tcp_line() {
        let l = line(
            GW,
            ME,
            "IPv4 (0x0800)",
            66,
            "192.168.0.1.443 > 192.168.0.173.52000: tcp 0",
        );
        let f = parse_tcpdump_line(&l).unwrap();
        assert_eq!(
            (f.src, f.dst, f.len, f.proto),
            (mac(GW), mac(ME), 66, Proto::Tcp)
        );
        assert_eq!(
            f.ips,
            Some((
                "192.168.0.1".parse().unwrap(),
                "192.168.0.173".parse().unwrap()
            ))
        );
    }

    #[test]
    fn udp_ports_pick_out_mdns_and_ssdp() {
        let m = parse_tcpdump_line(&line(
            TV,
            "01:00:5e:00:00:fb",
            "IPv4 (0x0800)",
            90,
            "192.168.0.82.5353 > 224.0.0.251.5353: UDP, length 48",
        ))
        .unwrap();
        assert_eq!(m.proto, Proto::Mdns);
        let s = parse_tcpdump_line(&line(
            TV,
            "01:00:5e:7f:ff:fa",
            "IPv4 (0x0800)",
            200,
            "192.168.0.82.50000 > 239.255.255.250.1900: UDP, length 150",
        ))
        .unwrap();
        assert_eq!(s.proto, Proto::Ssdp);
        let u = parse_tcpdump_line(&line(
            ME,
            GW,
            "IPv4 (0x0800)",
            80,
            "192.168.0.173.40000 > 192.168.0.1.53: UDP, length 38",
        ))
        .unwrap();
        assert_eq!(u.proto, Proto::Udp);
    }

    #[test]
    fn icmp_arp_ipv6_and_unknown_protocols() {
        let i = parse_tcpdump_line(&line(
            ME,
            GW,
            "IPv4 (0x0800)",
            98,
            "192.168.0.173 > 192.168.0.1: ICMP echo request, id 1, seq 0, length 64",
        ))
        .unwrap();
        assert_eq!(i.proto, Proto::Icmp);
        let a = parse_tcpdump_line(&line(
            PC,
            "ff:ff:ff:ff:ff:ff",
            "ARP (0x0806)",
            42,
            "Request who-has 192.168.0.1 tell 192.168.0.7, length 28",
        ))
        .unwrap();
        assert_eq!((a.proto, a.ips), (Proto::Arp, None));
        let v6 = parse_tcpdump_line(&line(
            TV,
            "33:33:00:00:00:fb",
            "IPv6 (0x86dd)",
            110,
            "fe80::1.5353 > ff02::fb.5353: UDP, length 48",
        ))
        .unwrap();
        assert_eq!(v6.proto, Proto::Mdns);
        assert_eq!(
            v6.ips,
            Some(("fe80::1".parse().unwrap(), "ff02::fb".parse().unwrap()))
        );
        let v6icmp = parse_tcpdump_line(&line(
            TV,
            ME,
            "IPv6 (0x86dd)",
            86,
            "fe80::1 > fe80::2: ICMP6, neighbor solicitation, who has fe80::2, length 32",
        ))
        .unwrap();
        assert_eq!(v6icmp.proto, Proto::Icmp);
        let other = parse_tcpdump_line(&line(
            ME,
            GW,
            "IPv4 (0x0800)",
            60,
            "192.168.0.173 > 192.168.0.1: igmp",
        ))
        .unwrap();
        assert_eq!(other.proto, Proto::Other);
        let lldp = parse_tcpdump_line(&line(
            GW,
            "01:80:c2:00:00:0e",
            "LLDP (0x88cc)",
            200,
            "LLDP, name x",
        ))
        .unwrap();
        assert_eq!((lldp.proto, lldp.ips), (Proto::Other, None));
    }

    #[test]
    fn junk_and_truncated_lines_are_ignored_without_panicking() {
        for junk in [
            "",
            "tcpdump: listening on en8, link-type EN10MB (Ethernet), snapshot length 96 bytes",
            "1696612345.1 zz:zz > yy:yy, ethertype IPv4 (0x0800), length 5: x",
            "1696612345.1 aa:bb:cc:00:00:01 > aa:bb:cc:00:00:02, 802.3, length 60: LLC",
            "1696612345.1 aa:bb:cc:00:00:01 > aa:bb:cc:00:00:02, ethertype IPv4 (0x0800), length abc: x",
            "\0\0\0",
        ] {
            assert_eq!(parse_tcpdump_line(junk), None, "{junk:?}");
        }
        let good = line(
            GW,
            ME,
            "IPv4 (0x0800)",
            66,
            "192.168.0.1.443 > 192.168.0.173.52000: tcp 0",
        );
        for n in 0..good.len() {
            let _ = parse_tcpdump_line(&good[..n]);
        }
    }

    // ---- classification and privacy ----

    fn att(l: &str) -> Option<Attribution> {
        let ids = ids();
        classify_frame(&parse_tcpdump_line(l)?, &ctx(&ids))
    }

    #[test]
    fn unicast_lan_traffic_between_this_machine_and_a_device_is_a_flow_and_a_device_rate() {
        let rx = att(&line(
            TV,
            ME,
            "IPv4 (0x0800)",
            1500,
            "192.168.0.82.8009 > 192.168.0.173.50000: tcp 1448",
        ))
        .unwrap();
        assert_eq!(
            rx.key,
            FlowKey {
                src: "tv".into(),
                dst: End::Device("me".into()),
                proto: Proto::Tcp
            }
        );
        assert_eq!(rx.device, Some(("tv".into(), Direction::FromDevice)));
        assert_eq!(rx.bytes, 1500);
        let tx = att(&line(
            ME,
            TV,
            "IPv4 (0x0800)",
            100,
            "192.168.0.173.50000 > 192.168.0.82.8009: tcp 0",
        ))
        .unwrap();
        assert_eq!(tx.key.src, "me");
        assert_eq!(tx.device, Some(("tv".into(), Direction::ToDevice)));
    }

    #[test]
    fn broadcast_and_multicast_are_attributed_to_their_sender() {
        let b = att(&line(
            PC,
            "ff:ff:ff:ff:ff:ff",
            "ARP (0x0806)",
            42,
            "Request who-has 192.168.0.1 tell 192.168.0.7, length 28",
        ))
        .unwrap();
        assert_eq!(
            b.key,
            FlowKey {
                src: "pc".into(),
                dst: End::Broadcast,
                proto: Proto::Arp
            }
        );
        assert_eq!(
            b.device, None,
            "chatter is not a measurement between us and the sender"
        );
        let m = att(&line(
            TV,
            "01:00:5e:00:00:fb",
            "IPv4 (0x0800)",
            90,
            "192.168.0.82.5353 > 224.0.0.251.5353: UDP, length 48",
        ))
        .unwrap();
        assert_eq!(
            m.key,
            FlowKey {
                src: "tv".into(),
                dst: End::Multicast,
                proto: Proto::Mdns
            }
        );
        let v6 = att(&line(
            TV,
            "33:33:00:00:00:fb",
            "IPv6 (0x86dd)",
            110,
            "fe80::1.5353 > ff02::fb.5353: UDP, length 48",
        ))
        .unwrap();
        assert_eq!(v6.key.dst, End::Multicast);
    }

    #[test]
    fn traffic_to_or_from_off_subnet_hosts_collapses_into_one_other_flow_on_this_machine() {
        // Out to a remote host, via the gateway's MAC
        let out = att(&line(
            ME,
            GW,
            "IPv4 (0x0800)",
            1400,
            "192.168.0.173.52000 > 142.250.80.46.443: tcp 1340",
        ))
        .unwrap();
        assert_eq!(
            out.key,
            FlowKey {
                src: "me".into(),
                dst: End::Device("me".into()),
                proto: Proto::Other
            }
        );
        assert_eq!(
            out.device, None,
            "not attributed to the gateway or to any device"
        );
        // And back in
        let inn = att(&line(
            GW,
            ME,
            "IPv4 (0x0800)",
            1500,
            "151.101.1.69.443 > 192.168.0.173.52001: tcp 1448",
        ))
        .unwrap();
        assert_eq!(
            inn.key, out.key,
            "remote traffic in either direction is the same single bucket"
        );
        // Global IPv6 destinations are not LAN either
        let v6 = att(&line(
            ME,
            GW,
            "IPv6 (0x86dd)",
            90,
            "fd00::1.5000 > 2a00:1450::1.443: tcp 20",
        ))
        .unwrap();
        assert_eq!(v6.key.proto, Proto::Other);
    }

    #[test]
    fn nothing_the_classifier_returns_can_name_a_remote_host() {
        let a = att(&line(
            ME,
            GW,
            "IPv4 (0x0800)",
            100,
            "192.168.0.173.1 > 93.184.216.34.80: tcp 0",
        ))
        .unwrap();
        let dump = format!("{a:?}");
        assert!(!dump.contains("93.184"), "{dump}");
        assert!(!dump.contains("80"), "no ports either: {dump}");
    }

    #[test]
    fn unknown_senders_and_traffic_that_does_not_involve_us_are_dropped() {
        assert_eq!(
            att(&line(
                "de:ad:be:ef:00:01",
                ME,
                "IPv4 (0x0800)",
                100,
                "192.168.0.99.1 > 192.168.0.173.2: tcp 0"
            )),
            None,
            "unknown MAC"
        );
        assert_eq!(
            att(&line(
                TV,
                PC,
                "IPv4 (0x0800)",
                100,
                "192.168.0.82.1 > 192.168.0.7.2: tcp 0"
            )),
            None,
            "device to device, not us"
        );
        assert_eq!(
            att(&line(
                TV,
                "de:ad:be:ef:00:02",
                "IPv4 (0x0800)",
                100,
                "192.168.0.82.1 > 192.168.0.99.2: tcp 0"
            )),
            None,
            "unknown destination"
        );
    }

    #[test]
    fn link_local_and_dhcp_are_lan_traffic() {
        let dhcp = att(&line(
            ME,
            "ff:ff:ff:ff:ff:ff",
            "IPv4 (0x0800)",
            342,
            "0.0.0.0.68 > 255.255.255.255.67: UDP, length 300",
        ))
        .unwrap();
        assert_eq!(dhcp.key.dst, End::Broadcast);
        let ll = att(&line(
            PC,
            ME,
            "IPv4 (0x0800)",
            100,
            "169.254.5.5.1 > 192.168.0.173.2: UDP, length 20",
        ))
        .unwrap();
        assert_eq!(ll.key.proto, Proto::Udp);
    }

    // ---- summarising ----

    fn a(
        src: &str,
        dst: End,
        proto: Proto,
        bytes: u32,
        device: Option<(&str, Direction)>,
    ) -> Attribution {
        Attribution {
            key: FlowKey {
                src: src.into(),
                dst,
                proto,
            },
            bytes,
            device: device.map(|(d, dir)| (d.to_string(), dir)),
        }
    }

    #[test]
    fn frames_become_bits_and_packets_per_second() {
        let mut acc = FlowAccumulator::default();
        for _ in 0..10 {
            acc.add(&a(
                "tv",
                End::Device("me".into()),
                Proto::Tcp,
                1250,
                Some(("tv", Direction::FromDevice)),
            ));
        }
        for _ in 0..4 {
            acc.add(&a(
                "me",
                End::Device("tv".into()),
                Proto::Tcp,
                100,
                Some(("tv", Direction::ToDevice)),
            ));
        }
        let d = acc.drain(1.0);
        assert_eq!(d.flows.len(), 2);
        assert_eq!(
            d.flows[0],
            FlowOut {
                src: "tv".into(),
                dst: "me".into(),
                proto: "tcp",
                bps: 100_000,
                pps: 10
            }
        );
        assert_eq!(
            d.devices["tv"],
            (100_000, 3_200),
            "(rx_bps from tv, tx_bps to tv)"
        );
        let d2 = acc.drain(1.0);
        assert!(
            d2.flows.is_empty() && d2.devices.is_empty(),
            "drain empties the window"
        );
    }

    #[test]
    fn rates_are_scaled_by_the_window_length() {
        let mut acc = FlowAccumulator::default();
        acc.add(&a("pc", End::Broadcast, Proto::Arp, 500, None));
        let d = acc.drain(2.0);
        assert_eq!((d.flows[0].bps, d.flows[0].pps), (2_000, 1)); // 500 B * 8 / 2 s, one packet over two seconds rounds up to 1 pps
        assert_eq!(d.flows[0].dst, "broadcast");
        let mut acc = FlowAccumulator::default();
        acc.add(&a("pc", End::Broadcast, Proto::Arp, 500, None));
        assert!(
            acc.drain(0.0).flows[0].bps > 0,
            "a zero window must not divide by zero"
        );
    }

    #[test]
    fn the_flow_list_is_capped_and_sorted_largest_first() {
        let mut acc = FlowAccumulator::default();
        for i in 0..(MAX_FLOWS + 40) {
            acc.add(&a(
                &format!("dev{i:03}"),
                End::Multicast,
                Proto::Udp,
                100 + i as u32,
                None,
            ));
        }
        let d = acc.drain(1.0);
        assert_eq!(d.flows.len(), MAX_FLOWS);
        assert!(d.flows.windows(2).all(|w| w[0].bps >= w[1].bps));
        assert_eq!(d.flows[0].src, format!("dev{:03}", MAX_FLOWS + 39));
    }

    #[test]
    fn same_endpoints_and_protocol_sum_into_one_flow() {
        let mut acc = FlowAccumulator::default();
        for _ in 0..3 {
            acc.add(&a("me", End::Device("me".into()), Proto::Other, 1000, None));
        }
        let d = acc.drain(1.0);
        assert_eq!(d.flows.len(), 1);
        assert_eq!((d.flows[0].bps, d.flows[0].pps), (24_000, 3));
    }

    // ---- invocation safety and reasons ----

    #[test]
    fn interface_arguments_cannot_inject_options() {
        for ok in [
            "en0", "en8", "eth0", "enp3s0", "wlan0", "br-1a2b", "eth0.100", "lo",
        ] {
            assert!(valid_iface_arg(ok), "{ok}");
        }
        for bad in [
            "",
            "-i",
            "--help",
            "-w",
            "en0 -w x",
            "en0;ls",
            "a b",
            "$(x)",
            "en0\n",
            &"x".repeat(40),
        ] {
            assert!(!valid_iface_arg(bad), "{bad:?}");
        }
    }

    #[test]
    fn macos_permission_denied_names_the_narrow_grant_and_never_asks_for_root() {
        let r = unavailable_reason(
            Os::Mac,
            true,
            "tcpdump: en8: You don't have permission to capture on that device\n((cannot open BPF device) /dev/bpf0: Permission denied)",
        );
        assert!(r.contains("/dev/bpf"), "{r}");
        assert!(r.contains("access_bpf") || r.contains("ChmodBPF"), "{r}");
        assert!(
            !r.to_lowercase().contains("run rhizome as root") && !r.contains("sudo rhizome"),
            "{r}"
        );
    }

    #[test]
    fn linux_permission_denied_names_the_capability_for_tcpdump_only() {
        let r = unavailable_reason(
            Os::Linux,
            true,
            "tcpdump: eth0: You don't have permission to capture on that device\n(socket: Operation not permitted)",
        );
        assert!(r.contains("cap_net_raw"), "{r}");
        assert!(r.contains("tcpdump"), "{r}");
        assert!(!r.to_lowercase().contains("run rhizome as root"), "{r}");
    }

    #[test]
    fn windows_and_missing_tool_and_unknown_errors() {
        let w = unavailable_reason(Os::Windows, false, "");
        assert!(w.contains("Windows") && w.contains("Npcap"), "{w}");
        let missing = unavailable_reason(Os::Linux, false, "");
        assert!(
            missing.contains("tcpdump") && missing.contains("not found"),
            "{missing}"
        );
        let nodev = unavailable_reason(Os::Mac, true, "tcpdump: en99: No such device exists");
        assert!(nodev.contains("interface"), "{nodev}");
        let other = unavailable_reason(Os::Linux, true, "tcpdump: weird\u{1b}[31m failure");
        assert!(
            other.contains("weird") && !other.contains('\u{1b}'),
            "stderr is sanitised: {other:?}"
        );
    }
}
