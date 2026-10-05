//! I/O adapter: read interfaces and the default route from the OS via `netdev`.

use super::iface_select::{DefaultRoute, IfaceInfo, SelectError, Selected, select_interface};
use crate::model::MacAddr;

pub fn list_ifaces() -> Vec<IfaceInfo> {
    netdev::get_interfaces()
        .into_iter()
        .map(|i| IfaceInfo {
            is_up: i.is_up(),
            is_loopback: i.is_loopback(),
            is_point_to_point: i.is_point_to_point(),
            ipv4: i.ipv4.first().copied(),
            mac: i.mac_addr.map(|m| MacAddr(m.octets())),
            name: i.name,
        })
        .collect()
}

pub fn default_route() -> Option<DefaultRoute> {
    let i = netdev::get_default_interface().ok()?;
    let gateway = i.gateway.as_ref().and_then(|g| g.ipv4.first().copied());
    Some(DefaultRoute {
        iface: i.name,
        gateway,
    })
}

/// Select the interface to scan right now (called every cycle so that
/// sleep/wake or a Wi-Fi switch is picked up).
/// One OS snapshot -> (interface to scan, MACs of this machine's live interfaces on its subnet).
pub fn select_with_locals_now(
    cli_override: Option<&str>,
) -> Result<(Selected, std::collections::BTreeSet<MacAddr>), SelectError> {
    super::iface_select::select_with_locals(&list_ifaces(), default_route().as_ref(), cli_override)
}

pub fn select_now(cli_override: Option<&str>) -> Result<Selected, SelectError> {
    select_interface(&list_ifaces(), default_route().as_ref(), cli_override)
}
