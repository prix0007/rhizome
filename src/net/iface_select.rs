//! Pure interface selection. Prefers `--iface`, then the default route if it
//! is a broadcast-capable `en*` with a private IPv4 and a MAC, then the first
//! active `en*` that qualifies.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::MacAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfaceInfo {
    pub name: String,
    pub ipv4: Option<Ipv4Net>,
    pub mac: Option<MacAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_point_to_point: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub iface: String,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected {
    pub name: String,
    pub ip: Ipv4Addr,
    pub net: Ipv4Net,
    pub mac: MacAddr,
    pub gateway_ip: Option<Ipv4Addr>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    #[error("interface {0:?} was requested with --iface but does not exist")]
    UnknownOverride(String),
    #[error(
        "interface {0:?} cannot be scanned: it needs to be up with a private IPv4 address and a MAC"
    )]
    UnusableOverride(String),
    #[error(
        "no usable network interface found: need an active en* interface with a private IPv4 address"
    )]
    NoCandidate,
}

/// Usable = up, not loopback, with a private IPv4 and a MAC.
fn usable(i: &IfaceInfo) -> Option<(Ipv4Net, MacAddr)> {
    let net = i.ipv4?;
    let mac = i.mac?;
    (i.is_up && !i.is_loopback && net.addr().is_private() && !mac.is_zero()).then_some((net, mac))
}

/// Whether an interface name looks like a physical LAN adapter on any OS:
/// macOS `en0`, Linux `eth0` / `enp3s0` / `eno1` / `wlan0` / `wlp2s0`, and the
/// Windows friendly names `Ethernet`, `Ethernet 2`, `Wi-Fi`. Virtual, tunnel,
/// bridge, container and VM adapters are rejected first, whatever else the
/// name contains.
pub fn is_lan_nic_name(name: &str) -> bool {
    const REJECT_PREFIX: &[&str] = &[
        "utun",
        "awdl",
        "llw",
        "bridge",
        "docker",
        "veth",
        "br-",
        "virbr",
        "vboxnet",
        "vmnet",
        "tun",
        "tap",
        "wg",
        "gif",
        "stf",
        "ap",
        "anpi",
        "vethernet",
        "isatap",
        "teredo",
        "ppp",
    ];
    const REJECT_CONTAINS: &[&str] = &[
        "loopback",
        "virtual",
        "vmware",
        "hyper-v",
        "bluetooth",
        "vpn",
        "tunnel",
        "wsl",
        "pseudo",
    ];
    const ACCEPT_PREFIX: &[&str] = &["en", "eth", "wl", "ww"];
    const ACCEPT_CONTAINS: &[&str] = &[
        "wi-fi",
        "wifi",
        "wlan",
        "wireless",
        "ethernet",
        "local area connection",
    ];
    let lower = name.to_lowercase();
    // loopback: `lo`, `lo0` (but not e.g. "Local Area Connection")
    if lower
        .strip_prefix("lo")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    if REJECT_PREFIX.iter().any(|p| lower.starts_with(p))
        || REJECT_CONTAINS.iter().any(|c| lower.contains(c))
    {
        return false;
    }
    ACCEPT_PREFIX.iter().any(|p| lower.starts_with(p))
        || ACCEPT_CONTAINS.iter().any(|c| lower.contains(c))
}

fn is_lan_candidate(i: &IfaceInfo) -> bool {
    is_lan_nic_name(&i.name) && !i.is_point_to_point
}

/// MACs of this machine's interfaces that are up with an address on `net`.
pub fn local_macs_on(ifaces: &[IfaceInfo], net: Ipv4Net) -> std::collections::BTreeSet<MacAddr> {
    ifaces
        .iter()
        .filter(|i| i.is_up && !i.is_loopback && i.ipv4.is_some_and(|n| net.contains(&n.addr())))
        .filter_map(|i| i.mac)
        .collect()
}

/// One consistent snapshot decision: the interface to scan plus the MACs of
/// every live local interface on its subnet (this is what production uses).
pub fn select_with_locals(
    ifaces: &[IfaceInfo],
    default: Option<&DefaultRoute>,
    cli_override: Option<&str>,
) -> Result<(Selected, std::collections::BTreeSet<MacAddr>), SelectError> {
    let sel = select_interface(ifaces, default, cli_override)?;
    let locals = local_macs_on(ifaces, sel.net);
    Ok((sel, locals))
}

pub fn select_interface(
    ifaces: &[IfaceInfo],
    default: Option<&DefaultRoute>,
    cli_override: Option<&str>,
) -> Result<Selected, SelectError> {
    let build = |i: &IfaceInfo, net: Ipv4Net, mac: MacAddr| Selected {
        name: i.name.clone(),
        ip: net.addr(),
        net: net.trunc(),
        mac,
        gateway_ip: default
            .filter(|d| d.iface == i.name)
            .and_then(|d| d.gateway),
    };

    if let Some(name) = cli_override {
        let i = ifaces
            .iter()
            .find(|i| i.name == name)
            .ok_or_else(|| SelectError::UnknownOverride(name.to_string()))?;
        let (net, mac) =
            usable(i).ok_or_else(|| SelectError::UnusableOverride(name.to_string()))?;
        return Ok(build(i, net, mac));
    }

    if let Some(d) = default
        && let Some(i) = ifaces
            .iter()
            .find(|i| i.name == d.iface && is_lan_candidate(i))
        && let Some((net, mac)) = usable(i)
    {
        return Ok(build(i, net, mac));
    }

    let mut cands: Vec<&IfaceInfo> = ifaces
        .iter()
        .filter(|i| is_lan_candidate(i) && usable(i).is_some())
        .collect();
    cands.sort_by(|a, b| a.name.cmp(&b.name));
    let i = cands.first().ok_or(SelectError::NoCandidate)?;
    let (net, mac) = usable(i).ok_or(SelectError::NoCandidate)?;
    Ok(build(i, net, mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefix: u8, mac: Option<&str>) -> IfaceInfo {
        IfaceInfo {
            name: name.into(),
            ipv4: Some(Ipv4Net::new(ip.parse().unwrap(), prefix).unwrap()),
            mac: mac.map(|m| m.parse().unwrap()),
            is_up: true,
            is_loopback: false,
            is_point_to_point: false,
        }
    }

    fn route(name: &str, gw: &str) -> DefaultRoute {
        DefaultRoute {
            iface: name.into(),
            gateway: Some(gw.parse().unwrap()),
        }
    }

    fn en0() -> IfaceInfo {
        iface("en0", "192.168.0.172", 24, Some("32:00:00:00:00:84"))
    }

    #[test]
    fn default_en0_with_private_ip_is_chosen() {
        let s = select_interface(&[en0()], Some(&route("en0", "192.168.0.1")), None).unwrap();
        assert_eq!(s.name, "en0");
        assert_eq!(s.ip, "192.168.0.172".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s.net.to_string(), "192.168.0.0/24");
        assert_eq!(s.gateway_ip, Some("192.168.0.1".parse().unwrap()));
        assert_eq!(s.mac.to_string(), "32:00:00:00:00:84");
    }

    #[test]
    fn vpn_default_is_skipped_for_en_interface() {
        let mut utun = iface("utun3", "10.8.0.2", 32, None);
        utun.is_point_to_point = true;
        let s = select_interface(&[utun, en0()], Some(&route("utun3", "10.8.0.1")), None).unwrap();
        assert_eq!(s.name, "en0");
        assert_eq!(
            s.gateway_ip, None,
            "gateway of a different interface must not leak in"
        );
    }

    #[test]
    fn non_private_en_interface_is_not_a_candidate() {
        let public = iface("en0", "8.8.8.8", 24, Some("0:1:2:3:4:5"));
        assert_eq!(
            select_interface(&[public], None, None),
            Err(SelectError::NoCandidate)
        );
    }

    #[test]
    fn down_or_macless_interfaces_are_skipped() {
        let mut down = en0();
        down.is_up = false;
        let nomac = iface("en1", "192.168.1.5", 24, None);
        assert_eq!(
            select_interface(&[down, nomac], None, None),
            Err(SelectError::NoCandidate)
        );
    }

    #[test]
    fn falls_back_to_first_active_en_sorted_by_name() {
        let en5 = iface("en5", "10.0.0.5", 24, Some("0:1:2:3:4:5"));
        let en1 = iface("en1", "10.0.1.5", 24, Some("0:1:2:3:4:6"));
        let s = select_interface(&[en5, en1], None, None).unwrap();
        assert_eq!(s.name, "en1");
    }

    #[test]
    fn override_unknown_is_an_error() {
        assert_eq!(
            select_interface(&[en0()], None, Some("en9")),
            Err(SelectError::UnknownOverride("en9".into()))
        );
    }

    #[test]
    fn override_wins_over_default_and_may_be_non_en() {
        let br = iface("bridge0", "172.16.0.1", 16, Some("0:1:2:3:4:5"));
        let s = select_interface(
            &[en0(), br],
            Some(&route("en0", "192.168.0.1")),
            Some("bridge0"),
        )
        .unwrap();
        assert_eq!(s.name, "bridge0");
        assert_eq!(s.gateway_ip, None);
    }

    #[test]
    fn override_that_is_unusable_is_an_error() {
        let lo = IfaceInfo {
            is_loopback: true,
            ..iface("lo0", "127.0.0.1", 8, None)
        };
        assert_eq!(
            select_interface(&[lo], None, Some("lo0")),
            Err(SelectError::UnusableOverride("lo0".into()))
        );
    }

    #[test]
    fn no_candidates_is_a_clear_error() {
        let err = select_interface(&[], None, None).unwrap_err();
        assert_eq!(err, SelectError::NoCandidate);
        assert!(err.to_string().contains("no usable network interface"));
    }

    #[test]
    fn point_to_point_en_is_skipped() {
        let mut p = en0();
        p.is_point_to_point = true;
        assert_eq!(
            select_interface(&[p], Some(&route("en0", "192.168.0.1")), None),
            Err(SelectError::NoCandidate)
        );
    }

    // ---- several interfaces on one subnet ----

    #[test]
    fn local_macs_are_live_interfaces_on_the_scanned_subnet_only() {
        let net: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        let mut down = iface("en5", "192.168.0.99", 24, Some("0:1:2:3:4:5"));
        down.is_up = false;
        let mut lo = iface("lo0", "192.168.0.1", 24, Some("0:1:2:3:4:7"));
        lo.is_loopback = true;
        let ifaces = vec![
            iface("en0", "192.168.0.172", 24, Some("32:00:00:00:00:84")),
            iface("en8", "192.168.0.173", 24, Some("3c:e1:a1:00:00:53")),
            down,
            iface("bridge100", "192.168.2.1", 24, Some("0:1:2:3:4:6")),
            lo,
        ];
        let macs = local_macs_on(&ifaces, net);
        assert_eq!(macs.len(), 2);
        assert!(macs.contains(&"32:00:00:00:00:84".parse().unwrap()));
        assert!(macs.contains(&"3c:e1:a1:00:00:53".parse().unwrap()));
    }

    #[test]
    fn production_selection_returns_the_selected_interface_and_its_subnet_locals_together() {
        let mut down = iface("en5", "192.168.0.99", 24, Some("0:1:2:3:4:5"));
        down.is_up = false;
        let ifaces = vec![
            iface("en0", "192.168.0.172", 24, Some("32:00:00:00:00:84")),
            iface("en8", "192.168.0.173", 24, Some("3c:e1:a1:00:00:53")),
            down,
            iface("en6", "10.9.0.2", 24, Some("0:1:2:3:4:9")),
        ];
        let (sel, locals) =
            select_with_locals(&ifaces, Some(&route("en8", "192.168.0.1")), None).unwrap();
        assert_eq!(sel.name, "en8");
        assert_eq!(
            locals.len(),
            2,
            "the down interface and the other subnet are excluded: {locals:?}"
        );
        assert!(locals.contains(&sel.mac));
    }

    #[test]
    fn production_selection_propagates_selection_errors() {
        assert_eq!(
            select_with_locals(&[], None, None),
            Err(SelectError::NoCandidate)
        );
    }

    #[test]
    fn lan_adapter_names_on_every_os() {
        for ok in [
            "en0",
            "en8",
            "eth0",
            "eth1",
            "enp3s0",
            "eno1",
            "ens160",
            "wlan0",
            "wlp2s0",
            "wwan0",
            "Wi-Fi",
            "Wi-Fi 2",
            "WiFi",
            "Ethernet",
            "Ethernet 3",
            "Local Area Connection",
            "WLAN",
        ] {
            assert!(is_lan_nic_name(ok), "{ok} should be a candidate");
        }
        for bad in [
            "lo",
            "lo0",
            "utun3",
            "awdl0",
            "llw0",
            "bridge100",
            "docker0",
            "veth12ab",
            "br-1a2b3c",
            "virbr0",
            "tun0",
            "tap0",
            "wg0",
            "ap1",
            "anpi0",
            "ppp0",
            "vEthernet (Default Switch)",
            "vEthernet (WSL)",
            "Loopback Pseudo-Interface 1",
            "Bluetooth Network Connection",
            "VMware Network Adapter VMnet8",
            "VirtualBox Host-Only Network",
            "Teredo Tunneling Pseudo-Interface",
            "OpenVPN TAP-Windows6",
        ] {
            assert!(!is_lan_nic_name(bad), "{bad} must not be a candidate");
        }
    }

    #[test]
    fn a_linux_or_windows_machine_selects_its_nic_by_name_too() {
        let linux = iface("enp3s0", "192.168.1.20", 24, Some("0:1:2:3:4:5"));
        let docker = iface("docker0", "172.17.0.1", 16, Some("0:1:2:3:4:6"));
        let s = select_interface(
            &[docker, linux],
            Some(&route("enp3s0", "192.168.1.1")),
            None,
        )
        .unwrap();
        assert_eq!(s.name, "enp3s0");
        let wifi = iface("Wi-Fi", "192.168.1.30", 24, Some("0:1:2:3:4:7"));
        let hyperv = iface(
            "vEthernet (Default Switch)",
            "172.20.0.1",
            20,
            Some("0:1:2:3:4:8"),
        );
        let s = select_interface(&[hyperv, wifi], None, None).unwrap();
        assert_eq!(s.name, "Wi-Fi");
    }
}
