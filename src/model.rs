//! Core domain types shared by every module. Serializable for the JSON API.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// A 48-bit MAC address. Serialized as lowercase, zero-padded `aa:bb:cc:dd:ee:ff`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct MacAddr(pub [u8; 6]);

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Gateway,
    ThisMachine,
    Printer,
    Tv,
    Speaker,
    Phone,
    Computer,
    NetworkGear,
    Iot,
    #[default]
    Unknown,
}

impl DeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::ThisMachine => "this_machine",
            Self::Printer => "printer",
            Self::Tv => "tv",
            Self::Speaker => "speaker",
            Self::Phone => "phone",
            Self::Computer => "computer",
            Self::NetworkGear => "network_gear",
            Self::Iot => "iot",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "gateway" => Self::Gateway,
            "this_machine" => Self::ThisMachine,
            "printer" => Self::Printer,
            "tv" => Self::Tv,
            "speaker" => Self::Speaker,
            "phone" => Self::Phone,
            "computer" => Self::Computer,
            "network_gear" => Self::NetworkGear,
            "iot" => Self::Iot,
            _ => Self::Unknown,
        }
    }
}

/// One device on the LAN, as shown in the UI. Times are unix milliseconds.
///
/// `last_seen` is the last time positive liveness evidence was observed
/// (the plan's `last_alive`; the two fields were folded into one).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub hostname_source: Option<String>,
    pub kind: DeviceKind,
    pub services: Vec<String>,
    pub ssdp_server: Option<String>,
    /// Distinct SSDP search targets seen for this host (e.g. `urn:...:MediaRenderer:1`).
    pub ssdp_types: Vec<String>,
    /// SSDP LOCATION, kept as text only and never fetched.
    pub ssdp_location: Option<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    pub randomized_mac: bool,
    pub shared_mac: bool,
    pub online: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub is_new: bool,
}

pub type DeviceMap = BTreeMap<String, Device>;

/// Per-cycle status pushed to clients and served at `/api/status`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct ScanStatus {
    pub scan_started_at: i64,
    pub scan_finished_at: i64,
    pub devices: usize,
    pub online: usize,
    pub iface: String,
    pub net: String,
    pub gateway: Option<String>,
    pub interval_s: u64,
    pub ping_method: String,
    pub mdns_available: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeviceEvent {
    Upsert(Box<Device>),
    Removed(String),
    Scan(Box<ScanStatus>),
}

/// One mDNS observation about an IPv4 host.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MdnsHit {
    pub ip: std::net::Ipv4Addr,
    pub hostname: Option<String>,
    /// Service labels such as `_ipp` (no `._tcp.local.` suffix).
    pub service_types: Vec<String>,
    /// Observed within the current scan window (counts as liveness); cached
    /// older entries only enrich hostname and services.
    pub fresh: bool,
}

/// The interesting headers of one SSDP response.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SsdpHit {
    pub server: Option<String>,
    pub st: Option<String>,
    pub usn: Option<String>,
    pub location: Option<String>,
}

/// An SSDP response together with the address it came from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SsdpObservation {
    pub ip: std::net::Ipv4Addr,
    pub hit: SsdpHit,
}
