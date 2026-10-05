//! Link information for the selected interface: kind, negotiated rate, and
//! Wi-Fi signal details. Pure parsers on top, small readers below.
//!
//! Sources (none needs elevated rights):
//! * macOS: `networksetup -listallhardwareports` (which device is Wi-Fi),
//!   `ifconfig` media line for Ethernet speed, and `system_profiler
//!   SPAirPortDataType` for Wi-Fi rate, RSSI, noise, channel and PHY. The
//!   profiler takes about seven seconds, so it only ever runs in the slow
//!   background poller.
//! * Linux: `/sys/class/net/<if>/speed` and `/sys/class/net/<if>/wireless` plus
//!   `/proc/net/wireless` for signal and noise.
//! * Windows: `netsh wlan show interfaces` for Wi-Fi (English labels only;
//!   other languages give nulls) and the adapter speed from the OS.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::enrich::sanitize::sanitize;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct LinkInfo {
    /// `"wifi"` or `"ethernet"`; null when it could not be determined.
    pub kind: Option<String>,
    pub rate_mbps: Option<f64>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub channel: Option<String>,
    pub phy: Option<String>,
}

/// Wi-Fi details read from one of the OS tools.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WifiDetails {
    pub rate_mbps: Option<f64>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub channel: Option<String>,
    pub phy: Option<String>,
}

impl WifiDetails {
    pub fn into_link(self) -> LinkInfo {
        LinkInfo {
            kind: Some("wifi".into()),
            rate_mbps: self.rate_mbps,
            rssi_dbm: self.rssi_dbm,
            noise_dbm: self.noise_dbm,
            channel: self.channel,
            phy: self.phy,
        }
    }
}

/// macOS `system_profiler SPAirPortDataType`: the connected network's block under
/// `<iface>:` -> `Current Network Information:`. Nearby networks listed after it
/// are ignored. `None` when the interface is not in the output or not connected.
pub fn parse_system_profiler_wifi(text: &str, iface: &str) -> Option<WifiDetails> {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let lines: Vec<&str> = text.lines().collect();
    let header = format!("{iface}:");
    let at = lines.iter().position(|l| l.trim() == header)?;
    let iface_indent = indent(lines[at]);
    // The interface's own section ends at the next line that is not indented further.
    let section: Vec<&str> = lines[at + 1..]
        .iter()
        .copied()
        // Values can wrap onto unindented continuation lines; only a sibling or parent
        // *header* (a line ending in `:` at or above this indent) ends the section.
        .take_while(|l| {
            l.trim().is_empty() || indent(l) > iface_indent || !l.trim_end().ends_with(':')
        })
        .collect();
    let cur = section
        .iter()
        .position(|l| l.trim() == "Current Network Information:")?;
    let cur_indent = indent(section[cur]);
    let mut w = WifiDetails::default();
    let mut any = false;
    for l in section[cur + 1..]
        .iter()
        .take_while(|l| l.trim().is_empty() || indent(l) > cur_indent)
    {
        let Some((k, v)) = l.trim().split_once(": ") else {
            continue;
        };
        let v = v.trim();
        match k {
            "PHY Mode" => w.phy = Some(sanitize(v)).filter(|s| !s.is_empty()),
            "Channel" => w.channel = Some(sanitize(v)).filter(|s| !s.is_empty()),
            "Transmit Rate" => w.rate_mbps = v.parse().ok(),
            "Signal / Noise" => {
                let mut parts = v.split('/').map(|p| {
                    p.split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<i32>().ok())
                });
                w.rssi_dbm = parts.next().flatten();
                w.noise_dbm = parts.next().flatten();
            }
            _ => continue,
        }
        any = true;
    }
    // `Current Network Information:` exists only while connected, but an empty
    // block would still tell us nothing.
    let _ = any;
    Some(w)
}

/// macOS/BSD `ifconfig <iface>`: speed from the media line, e.g.
/// `media: autoselect (1000baseT <full-duplex>)` -> 1000.
pub fn parse_ifconfig_speed(text: &str) -> Option<f64> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("media:"))?;
    let lower = line.to_lowercase();
    let at = lower.find("base")?;
    let mut pre = &lower[..at];
    let mut unit = 1.0;
    if let Some(p) = pre.strip_suffix('g') {
        pre = p;
        unit = 1000.0;
    }
    let digits: String = pre
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits
        .parse::<f64>()
        .ok()
        .filter(|v| *v > 0.0)
        .map(|v| v * unit)
}

/// `networksetup -listallhardwareports`: device name to hardware port name.
pub fn parse_hardware_ports(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut port: Option<String> = None;
    for l in text.lines() {
        if let Some(p) = l.strip_prefix("Hardware Port:") {
            port = Some(sanitize(p));
        } else if let Some(d) = l.strip_prefix("Device:")
            && let Some(p) = port.take()
        {
            out.insert(d.trim().to_string(), p);
        }
    }
    out
}

/// Linux `/proc/net/wireless`: (level dBm, noise dBm) for `iface`. Values
/// without the trailing `.` are not dBm and noise of -256 means unknown.
pub fn parse_proc_net_wireless(text: &str, iface: &str) -> Option<(Option<i32>, Option<i32>)> {
    for l in text.lines() {
        let Some((name, rest)) = l.split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let t: Vec<&str> = rest.split_whitespace().collect();
        // status link level noise ...; `level`/`noise` are dBm only with a trailing dot
        let dbm = |s: Option<&&str>| {
            s.and_then(|s| s.strip_suffix('.'))
                .and_then(|n| n.parse::<i32>().ok())
        };
        let level = dbm(t.get(2));
        let noise = dbm(t.get(3)).filter(|n| *n > -256);
        return Some((level, noise));
    }
    None
}

/// Linux `/sys/class/net/<if>/speed`: Mbit/s, `-1` (or 0) when unknown.
pub fn parse_sysfs_speed(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok().filter(|v| *v > 0.0)
}

/// Windows `netsh wlan show interfaces`: the block whose `Name` is `iface`
/// (or the only connected block). Signal is a percentage; it is converted with
/// the usual `dBm = pct / 2 - 100` approximation, so treat it as approximate.
pub fn parse_netsh_wlan(text: &str, iface: &str) -> Option<WifiDetails> {
    // One block per interface, each starting at its `Name` line.
    let mut blocks: Vec<BTreeMap<String, String>> = Vec::new();
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let key = k.trim().to_lowercase();
        if key == "name" {
            blocks.push(BTreeMap::new());
        }
        if let Some(b) = blocks.last_mut() {
            b.entry(key).or_insert_with(|| v.trim().to_string());
        }
    }
    let block = blocks.into_iter().find(|b| {
        b.get("state")
            .is_some_and(|s| s.eq_ignore_ascii_case("connected"))
            && (iface.is_empty() || b.get("name").is_some_and(|n| n.eq_ignore_ascii_case(iface)))
    })?;
    let signal = block
        .get("signal")
        .and_then(|s| s.trim_end_matches('%').trim().parse::<i32>().ok())
        .filter(|p| (0..=100).contains(p));
    Some(WifiDetails {
        rate_mbps: block
            .get("transmit rate (mbps)")
            .and_then(|v| v.parse().ok()),
        rssi_dbm: signal.map(|p| p / 2 - 100),
        noise_dbm: None,
        channel: block
            .get("channel")
            .map(|c| sanitize(c))
            .filter(|c| !c.is_empty()),
        phy: block
            .get("radio type")
            .map(|c| sanitize(c))
            .filter(|c| !c.is_empty()),
    })
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

use std::path::PathBuf;
use std::time::Duration;

use crate::discovery::cmd::run_full;
use crate::net::iface_select::Selected;
use crate::platform::{Os, system_root, system32};

/// Read link information for the selected interface. Returns it together with
/// how long to wait before reading again: the macOS Wi-Fi profiler takes about
/// seven seconds, so Wi-Fi is polled slowly and only from the background task.
pub async fn read_link(sel: &Selected) -> (LinkInfo, Duration) {
    let name = sel.name.as_str();
    if !crate::traffic::capture::valid_iface_arg(name) && Os::current() != Os::Windows {
        return (LinkInfo::default(), Duration::from_secs(30));
    }
    match Os::current() {
        Os::Mac => read_mac(name).await,
        Os::Linux => (read_linux(name), Duration::from_secs(10)),
        Os::Windows => read_windows(name).await,
    }
}

async fn tool(path: PathBuf, args: &[&str], timeout: Duration) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let out = run_full(path, &args, timeout)
        .await
        .ok()
        .filter(|o| o.success)?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Adapter speed as the OS reports it (bits/s -> Mbit/s).
async fn netdev_speed(name: &str) -> Option<f64> {
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        netdev::get_interfaces()
            .into_iter()
            .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name.as_str()))
            .and_then(|i| i.transmit_speed)
            .map(|bps| bps as f64 / 1e6)
            .filter(|m| *m > 0.0)
    })
    .await
    .ok()
    .flatten()
}

async fn read_mac(name: &str) -> (LinkInfo, Duration) {
    let ports = tool(
        "/usr/sbin/networksetup".into(),
        &["-listallhardwareports"],
        Duration::from_secs(10),
    )
    .await
    .map(|t| parse_hardware_ports(&t))
    .unwrap_or_default();
    let is_wifi = ports
        .get(name)
        .is_some_and(|p| p.contains("Wi-Fi") || p.contains("AirPort"));
    if is_wifi {
        let text = tool(
            "/usr/sbin/system_profiler".into(),
            &["SPAirPortDataType"],
            Duration::from_secs(30),
        )
        .await;
        let info = text
            .and_then(|t| parse_system_profiler_wifi(&t, name))
            .map(WifiDetails::into_link)
            .unwrap_or_else(|| LinkInfo {
                kind: Some("wifi".into()),
                ..LinkInfo::default()
            });
        return (info, Duration::from_secs(60));
    }
    let speed = match tool("/sbin/ifconfig".into(), &[name], Duration::from_secs(5))
        .await
        .and_then(|t| parse_ifconfig_speed(&t))
    {
        Some(s) => Some(s),
        None => netdev_speed(name).await,
    };
    (
        LinkInfo {
            kind: Some("ethernet".into()),
            rate_mbps: speed,
            ..LinkInfo::default()
        },
        Duration::from_secs(30),
    )
}

fn read_linux(name: &str) -> LinkInfo {
    let sys = PathBuf::from("/sys/class/net").join(name);
    let is_wifi = sys.join("wireless").exists() || sys.join("phy80211").exists();
    if is_wifi {
        let (rssi, noise) = std::fs::read_to_string("/proc/net/wireless")
            .ok()
            .and_then(|t| parse_proc_net_wireless(&t, name))
            .unwrap_or((None, None));
        // The negotiated rate is not exposed without `iw`/netlink; left null.
        return LinkInfo {
            kind: Some("wifi".into()),
            rssi_dbm: rssi,
            noise_dbm: noise,
            ..LinkInfo::default()
        };
    }
    let speed = std::fs::read_to_string(sys.join("speed"))
        .ok()
        .and_then(|t| parse_sysfs_speed(&t));
    LinkInfo {
        kind: Some("ethernet".into()),
        rate_mbps: speed,
        ..LinkInfo::default()
    }
}

async fn read_windows(name: &str) -> (LinkInfo, Duration) {
    let netsh = system32(&system_root(), "netsh.exe");
    if let Some(w) = tool(
        netsh,
        &["wlan", "show", "interfaces"],
        Duration::from_secs(10),
    )
    .await
    .and_then(|t| parse_netsh_wlan(&t, name))
    {
        return (w.into_link(), Duration::from_secs(30));
    }
    (
        LinkInfo {
            kind: Some("ethernet".into()),
            rate_mbps: netdev_speed(name).await,
            ..LinkInfo::default()
        },
        Duration::from_secs(30),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILER: &str = "\
Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Firmware Version: wl0: Jan 1 2024 00:00:00 version 20.10.1 FWID 01-00000000
          MAC Address: aa:bb:cc:00:00:99
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax
          Supported Channels: 1 (2GHz), 36 (5GHz), 40 (5GHz)
          AirDrop: Supported
          Status: Connected
          Current Network Information:
            TestNet:
              PHY Mode: 802.11ax
              Channel: 40 (5GHz, 80MHz)
              Country Code: ZZ
              Network Type: Infrastructure
              Security: WPA3 Personal
              Signal / Noise: -57 dBm / -91 dBm
              Transmit Rate: 720
              MCS Index: 7
          Other Local Wi-Fi Networks:
            NeighbourNet:
              PHY Mode: 802.11a/n/ac/ax
              Channel: 149 (5GHz, 160MHz)
              Signal / Noise: -51 dBm / -93 dBm
            Another:
              PHY Mode: 802.11b/g/n
              Channel: 6 (2GHz, 20MHz)
              Signal / Noise: -74 dBm / -91 dBm
";

    const PROFILER_OFF: &str = "\
Wi-Fi:

      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Status: Not Connected
";

    #[test]
    fn profiler_reads_only_the_connected_network_block() {
        let w = parse_system_profiler_wifi(PROFILER, "en0").unwrap();
        assert_eq!(w.rate_mbps, Some(720.0));
        assert_eq!(w.rssi_dbm, Some(-57));
        assert_eq!(w.noise_dbm, Some(-91));
        assert_eq!(w.channel.as_deref(), Some("40 (5GHz, 80MHz)"));
        assert_eq!(w.phy.as_deref(), Some("802.11ax"));
    }

    #[test]
    fn profiler_survives_wrapped_values_at_column_zero_and_redacted_network_names() {
        // Real output wraps the firmware string onto an unindented continuation line,
        // and shows the network name as <redacted> without Location permission.
        let t = PROFILER
            .replace(
                "          Firmware Version: wl0: Jan 1 2024 00:00:00 version 20.10.1 FWID 01-00000000\n",
                "          Firmware Version: wl0: Jan 1 2024 00:00:00 version 20.10.1 FWID 01-00000000\nIO80211_driverkit-1.0 \"IO80211_driverkit-1.0\" Jan 1 2024 00:00:00\n",
            )
            .replace("            TestNet:\n", "            <redacted>:\n");
        assert!(
            t.contains("\nIO80211_driverkit"),
            "the fixture really has the column-0 line"
        );
        let w = parse_system_profiler_wifi(&t, "en0").unwrap();
        assert_eq!(w.rate_mbps, Some(720.0));
        assert_eq!(w.rssi_dbm, Some(-57));
        assert_eq!(w.phy.as_deref(), Some("802.11ax"));
    }

    #[test]
    fn profiler_not_connected_unknown_interface_and_garbage() {
        assert_eq!(parse_system_profiler_wifi(PROFILER_OFF, "en0"), None);
        assert_eq!(
            parse_system_profiler_wifi(PROFILER, "en8"),
            None,
            "not a Wi-Fi interface"
        );
        assert_eq!(parse_system_profiler_wifi("", "en0"), None);
        assert_eq!(
            parse_system_profiler_wifi("\0\0 nonsense: \n x", "en0"),
            None
        );
    }

    #[test]
    fn profiler_partial_blocks_give_partial_details() {
        let t = "      Interfaces:\n        en0:\n          Current Network Information:\n            N:\n              PHY Mode: 802.11n\n";
        let w = parse_system_profiler_wifi(t, "en0").unwrap();
        assert_eq!(w.phy.as_deref(), Some("802.11n"));
        assert_eq!((w.rssi_dbm, w.rate_mbps), (None, None));
    }

    #[test]
    fn profiler_values_are_sanitised() {
        let t = "        en0:\n          Current Network Information:\n            N:\n              Channel: 6\u{1b}[31m (2GHz)\n";
        assert_eq!(
            parse_system_profiler_wifi(t, "en0")
                .unwrap()
                .channel
                .as_deref(),
            Some("6[31m (2GHz)")
        );
    }

    #[test]
    fn ifconfig_media_gives_ethernet_speed() {
        let t = "en8: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether aa:bb:cc:00:00:08\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: active\n";
        assert_eq!(parse_ifconfig_speed(t), Some(1000.0));
        assert_eq!(
            parse_ifconfig_speed("\tmedia: autoselect (100baseTX <full-duplex>)"),
            Some(100.0)
        );
        assert_eq!(
            parse_ifconfig_speed("\tmedia: autoselect (2500Base-T <full-duplex>)"),
            Some(2500.0)
        );
        assert_eq!(
            parse_ifconfig_speed("\tmedia: autoselect (10Gbase-T <full-duplex>)"),
            Some(10_000.0)
        );
        assert_eq!(
            parse_ifconfig_speed("\tmedia: autoselect\n\tstatus: inactive"),
            None
        );
        assert_eq!(parse_ifconfig_speed("\tmedia: autoselect (none)"), None);
        assert_eq!(parse_ifconfig_speed(""), None);
    }

    #[test]
    fn hardware_ports_map_devices_to_port_names() {
        let t = "\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:00:00:99\n\nHardware Port: USB 10/100/1000 LAN\nDevice: en8\nEthernet Address: aa:bb:cc:00:00:08\n\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: N/A\n";
        let m = parse_hardware_ports(t);
        assert_eq!(m["en0"], "Wi-Fi");
        assert_eq!(m["en8"], "USB 10/100/1000 LAN");
        assert_eq!(m.len(), 3);
        assert!(parse_hardware_ports("").is_empty());
    }

    const WIRELESS: &str = "\
Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
 wlan0: 0000   70.  -40.  -256        0      0      0      0     18        0
 wlp3s0: 0000   55.  -62.  -95.        0      0      0      0      0        0
";

    #[test]
    fn proc_net_wireless_levels_and_unknown_noise() {
        assert_eq!(
            parse_proc_net_wireless(WIRELESS, "wlan0"),
            Some((Some(-40), None)),
            "noise -256 is unknown"
        );
        assert_eq!(
            parse_proc_net_wireless(WIRELESS, "wlp3s0"),
            Some((Some(-62), Some(-95)))
        );
        assert_eq!(parse_proc_net_wireless(WIRELESS, "eth0"), None);
        assert_eq!(parse_proc_net_wireless("", "wlan0"), None);
        assert_eq!(
            parse_proc_net_wireless(" wlan0: 0000 70 200 -256 0 0 0 0 0 0", "wlan0"),
            Some((None, None)),
            "raw values without a dot are not dBm"
        );
    }

    #[test]
    fn sysfs_speed() {
        assert_eq!(parse_sysfs_speed("1000\n"), Some(1000.0));
        assert_eq!(parse_sysfs_speed("2500"), Some(2500.0));
        assert_eq!(parse_sysfs_speed("-1\n"), None);
        assert_eq!(parse_sysfs_speed("0"), None);
        assert_eq!(parse_sysfs_speed(""), None);
        assert_eq!(parse_sysfs_speed("fast"), None);
    }

    const NETSH: &str = "\r
There is 1 interface on the system:\r
\r
    Name                   : Wi-Fi\r
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz\r
    GUID                   : 00000000-0000-0000-0000-000000000000\r
    Physical address       : aa:bb:cc:00:00:99\r
    State                  : connected\r
    SSID                   : TestNet\r
    BSSID                  : aa:bb:cc:00:00:01\r
    Network type           : Infrastructure\r
    Radio type             : 802.11ax\r
    Authentication         : WPA3-Personal\r
    Channel                : 36\r
    Receive rate (Mbps)    : 1200\r
    Transmit rate (Mbps)   : 960\r
    Signal                 : 90%\r
";

    #[test]
    fn netsh_wlan_connected_interface() {
        let w = parse_netsh_wlan(NETSH, "Wi-Fi").unwrap();
        assert_eq!(w.rate_mbps, Some(960.0));
        assert_eq!(w.channel.as_deref(), Some("36"));
        assert_eq!(w.phy.as_deref(), Some("802.11ax"));
        assert_eq!(w.rssi_dbm, Some(-55), "90% -> -55 dBm (approximation)");
        assert_eq!(w.noise_dbm, None);
    }

    #[test]
    fn netsh_wlan_disconnected_other_name_localised_and_empty() {
        let off = NETSH.replace("connected", "disconnected");
        assert_eq!(parse_netsh_wlan(&off, "Wi-Fi"), None);
        assert_eq!(
            parse_netsh_wlan(NETSH, "Ethernet"),
            None,
            "a different interface"
        );
        assert!(
            parse_netsh_wlan(NETSH, "").is_some(),
            "no name given: the connected block"
        );
        let de = "    Name                   : WLAN\r\n    Status                 : Verbunden\r\n    Signal                 : 80%\r\n";
        assert_eq!(
            parse_netsh_wlan(de, "WLAN"),
            None,
            "non-English labels are not recognised, and that is fine"
        );
        assert_eq!(parse_netsh_wlan("", "Wi-Fi"), None);
    }

    #[test]
    fn netsh_wlan_signal_edge_values() {
        let t =
            |s: &str| format!("    Name : Wi-Fi\r\n    State : connected\r\n    Signal : {s}\r\n");
        assert_eq!(
            parse_netsh_wlan(&t("100%"), "Wi-Fi").unwrap().rssi_dbm,
            Some(-50)
        );
        assert_eq!(
            parse_netsh_wlan(&t("0%"), "Wi-Fi").unwrap().rssi_dbm,
            Some(-100)
        );
        assert_eq!(parse_netsh_wlan(&t("abc"), "Wi-Fi").unwrap().rssi_dbm, None);
        assert_eq!(
            parse_netsh_wlan(&t("250%"), "Wi-Fi").unwrap().rssi_dbm,
            None
        );
    }

    #[test]
    fn link_info_serialises_with_nulls_for_everything_unknown() {
        let j = serde_json::to_value(LinkInfo::default()).unwrap();
        for k in [
            "kind",
            "rate_mbps",
            "rssi_dbm",
            "noise_dbm",
            "channel",
            "phy",
        ] {
            assert!(j.get(k).is_some_and(|v| v.is_null()), "{k}");
        }
        let _ = sanitize("keeps the import used");
    }
}
