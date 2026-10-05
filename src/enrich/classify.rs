//! Ordered rule table that guesses what kind of device something is.

use crate::model::DeviceKind;

#[derive(Default, Clone, Debug)]
pub struct ClassifyInput<'a> {
    pub vendor: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub services: &'a [String],
    pub ssdp_server: Option<&'a str>,
    pub ssdp_types: &'a [String],
    pub is_gw: bool,
    pub is_self: bool,
}

const PRINTER_VENDORS: &[&str] = &[
    "brother", "epson", "lexmark", "xerox", "kyocera", "ricoh", "konica",
];
const NETWORK_VENDORS: &[&str] = &[
    "ubiquiti",
    "tp-link",
    "netgear",
    "d-link",
    "cisco",
    "aruba",
    "mikrotik",
    "routerboard",
    "zyxel",
    "linksys",
    "tenda",
    "arris",
    "technicolor",
    "eero",
    "juniper",
];
const SPEAKER_VENDORS: &[&str] = &["sonos", "bose"];
const TV_VENDORS: &[&str] = &["roku", "vizio"];
const IOT_VENDORS: &[&str] = &["espressif", "tuya", "shelly", "signify", "philips lighting"];

const PHONE_HOSTNAMES: &[&str] = &["iphone", "ipad", "android", "pixel", "galaxy"];
const COMPUTER_HOSTNAMES: &[&str] = &[
    "macbook", "imac", "mac-mini", "macmini", "desktop-", "laptop",
];

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn has(services: &[String], names: &[&str]) -> bool {
    services.iter().any(|s| names.contains(&s.as_str()))
}

/// Rules run in order; the first match wins:
/// this machine, gateway, strong service hints, vendor, weak service hints,
/// hostname hint, unknown.
pub fn classify(i: &ClassifyInput<'_>) -> DeviceKind {
    if i.is_self {
        return DeviceKind::ThisMachine;
    }
    if i.is_gw {
        return DeviceKind::Gateway;
    }
    let sv = i.services;
    // Strong hints: services only that kind of device announces. Order matters:
    // a Mac advertises AirPlay too, but `_workstation` gives it away first.
    for (names, kind) in [
        (&["_apple-mobdev2"][..], DeviceKind::Phone),
        (&["_workstation"], DeviceKind::Computer),
        (
            &["_ipp", "_ipps", "_printer", "_pdl-datastream"],
            DeviceKind::Printer,
        ),
        (&["_googlecast", "_airplay"], DeviceKind::Tv),
        (&["_raop"], DeviceKind::Speaker),
        (&["_companion-link"], DeviceKind::Phone),
        (&["_hap", "_homekit"], DeviceKind::Iot),
    ] {
        if has(sv, names) {
            return kind;
        }
    }
    // SSDP: what the device says about itself (server banner and device types).
    let ssdp = i
        .ssdp_server
        .iter()
        .copied()
        .chain(i.ssdp_types.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if !ssdp.is_empty() {
        for (needles, kind) in [
            (&["sonos", "zoneplayer"][..], DeviceKind::Speaker),
            (
                &["internetgatewaydevice", "wanconnectiondevice"],
                DeviceKind::NetworkGear,
            ),
            (&["device:printer"], DeviceKind::Printer),
            (&["mediarenderer", "roku"], DeviceKind::Tv),
        ] {
            if contains_any(&ssdp, needles) {
                return kind;
            }
        }
    }
    if let Some(v) = i.vendor {
        let v = v.to_lowercase();
        for (list, kind) in [
            (PRINTER_VENDORS, DeviceKind::Printer),
            (NETWORK_VENDORS, DeviceKind::NetworkGear),
            (SPEAKER_VENDORS, DeviceKind::Speaker),
            (TV_VENDORS, DeviceKind::Tv),
            (IOT_VENDORS, DeviceKind::Iot),
        ] {
            if contains_any(&v, list) {
                return kind;
            }
        }
    }
    // Weak hints: plenty of devices run SSH or SMB, so the vendor gets the first word.
    if has(sv, &["_ssh", "_sftp-ssh", "_smb", "_afpovertcp"]) {
        return DeviceKind::Computer;
    }
    if let Some(h) = i.hostname {
        let h = h.to_lowercase();
        if contains_any(&h, PHONE_HOSTNAMES) {
            return DeviceKind::Phone;
        }
        if contains_any(&h, COMPUTER_HOSTNAMES) {
            return DeviceKind::Computer;
        }
    }
    DeviceKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(vendor: &str) -> ClassifyInput<'_> {
        ClassifyInput {
            vendor: Some(vendor),
            ..Default::default()
        }
    }

    #[test]
    fn gateway_and_self_win_over_everything() {
        let i = ClassifyInput {
            is_gw: true,
            vendor: Some("Brother Industries"),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Gateway);
        let i = ClassifyInput {
            is_self: true,
            is_gw: true,
            vendor: Some("Brother Industries"),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::ThisMachine);
    }

    #[test]
    fn printer_vendors() {
        for n in [
            "Brother Industries, LTD.",
            "SEIKO EPSON CORPORATION",
            "Lexmark International, Inc.",
            "Xerox Corporation",
        ] {
            assert_eq!(classify(&v(n)), DeviceKind::Printer, "{n}");
        }
    }

    #[test]
    fn network_gear_vendors() {
        for n in [
            "Ubiquiti Networks Inc.",
            "TP-LINK TECHNOLOGIES CO.,LTD.",
            "NETGEAR",
            "MikroTik",
            "Cisco Systems, Inc",
        ] {
            assert_eq!(classify(&v(n)), DeviceKind::NetworkGear, "{n}");
        }
    }

    #[test]
    fn speaker_tv_and_iot_vendors() {
        assert_eq!(classify(&v("Sonos, Inc.")), DeviceKind::Speaker);
        assert_eq!(classify(&v("Roku, Inc")), DeviceKind::Tv);
        assert_eq!(classify(&v("Espressif Inc.")), DeviceKind::Iot);
    }

    #[test]
    fn unknown_falls_through() {
        assert_eq!(classify(&v("Apple, Inc.")), DeviceKind::Unknown);
        assert_eq!(classify(&ClassifyInput::default()), DeviceKind::Unknown);
    }

    #[test]
    fn hostname_hints_are_a_weaker_signal_than_vendor() {
        let i = ClassifyInput {
            hostname: Some("Anuragis-iPhone"),
            vendor: Some("Apple, Inc."),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Phone);
        let i = ClassifyInput {
            hostname: Some("Anuragis-iPhone"),
            vendor: Some("Brother Industries"),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Printer);
        let i = ClassifyInput {
            hostname: Some("work-MacBook-Pro"),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Computer);
    }

    // ---- slice 6: mDNS service hints ----

    fn svc(list: &'static [&'static str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn with_services(services: &[String]) -> ClassifyInput<'_> {
        ClassifyInput {
            services,
            ..Default::default()
        }
    }

    #[test]
    fn service_rules() {
        for (s, want) in [
            ("_ipp", DeviceKind::Printer),
            ("_ipps", DeviceKind::Printer),
            ("_printer", DeviceKind::Printer),
            ("_pdl-datastream", DeviceKind::Printer),
            ("_googlecast", DeviceKind::Tv),
            ("_airplay", DeviceKind::Tv),
            ("_raop", DeviceKind::Speaker),
            ("_apple-mobdev2", DeviceKind::Phone),
            ("_companion-link", DeviceKind::Phone),
            ("_ssh", DeviceKind::Computer),
            ("_smb", DeviceKind::Computer),
            ("_workstation", DeviceKind::Computer),
            ("_hap", DeviceKind::Iot),
        ] {
            let services = vec![s.to_string()];
            assert_eq!(classify(&with_services(&services)), want, "{s}");
        }
    }

    #[test]
    fn a_mac_with_airplay_receiver_is_a_computer_not_a_tv() {
        let s = svc(&[
            "_airplay",
            "_raop",
            "_companion-link",
            "_workstation",
            "_smb",
        ]);
        assert_eq!(classify(&with_services(&s)), DeviceKind::Computer);
    }

    #[test]
    fn an_iphone_is_a_phone() {
        let s = svc(&["_companion-link", "_apple-mobdev2"]);
        assert_eq!(classify(&with_services(&s)), DeviceKind::Phone);
    }

    #[test]
    fn airplay_beats_raop_and_companion_link_for_an_apple_tv() {
        let s = svc(&["_raop", "_airplay", "_companion-link"]);
        assert_eq!(classify(&with_services(&s)), DeviceKind::Tv);
    }

    #[test]
    fn strong_services_beat_vendor_but_vendor_beats_weak_services() {
        let s = svc(&["_ipp"]);
        let i = ClassifyInput {
            services: &s,
            vendor: Some("Apple, Inc."),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Printer);
        let s = svc(&["_ssh"]);
        let i = ClassifyInput {
            services: &s,
            vendor: Some("Ubiquiti Networks Inc."),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::NetworkGear);
        let i = ClassifyInput {
            services: &s,
            vendor: Some("Brother Industries"),
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Printer);
    }

    #[test]
    fn gateway_still_beats_services() {
        let s = svc(&["_ipp"]);
        let i = ClassifyInput {
            services: &s,
            is_gw: true,
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Gateway);
    }

    #[test]
    fn unknown_services_do_not_classify() {
        let s = svc(&["_something-odd", "_http"]);
        assert_eq!(classify(&with_services(&s)), DeviceKind::Unknown);
    }

    // ---- slice 7: SSDP hints ----

    fn ssdp<'a>(server: Option<&'a str>, types: &'a [String]) -> ClassifyInput<'a> {
        ClassifyInput {
            ssdp_server: server,
            ssdp_types: types,
            ..Default::default()
        }
    }

    #[test]
    fn ssdp_server_and_type_rules() {
        let igd = svc(&["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]);
        assert_eq!(classify(&ssdp(None, &igd)), DeviceKind::NetworkGear);
        let mr = svc(&["urn:schemas-upnp-org:device:MediaRenderer:1"]);
        assert_eq!(classify(&ssdp(None, &mr)), DeviceKind::Tv);
        assert_eq!(
            classify(&ssdp(Some("Linux UPnP/1.0 Sonos/70.3-88200 (ZPS9)"), &[])),
            DeviceKind::Speaker
        );
        let zp = svc(&["urn:schemas-upnp-org:device:ZonePlayer:1"]);
        assert_eq!(classify(&ssdp(None, &zp)), DeviceKind::Speaker);
        let pr = svc(&["urn:schemas-upnp-org:device:Printer:1"]);
        assert_eq!(classify(&ssdp(None, &pr)), DeviceKind::Printer);
        assert_eq!(
            classify(&ssdp(Some("Roku/9.4 UPnP/1.0 Roku/9.4"), &[])),
            DeviceKind::Tv
        );
    }

    #[test]
    fn sonos_beats_the_generic_media_renderer_type() {
        let mr = svc(&["urn:schemas-upnp-org:device:MediaRenderer:1"]);
        assert_eq!(
            classify(&ssdp(Some("Linux UPnP/1.0 Sonos/70.3"), &mr)),
            DeviceKind::Speaker
        );
    }

    #[test]
    fn ssdp_is_case_insensitive_and_unknown_types_do_nothing() {
        let t = svc(&["URN:SCHEMAS-UPNP-ORG:DEVICE:MEDIARENDERER:1"]);
        assert_eq!(classify(&ssdp(None, &t)), DeviceKind::Tv);
        let boring = svc(&["upnp:rootdevice", "uuid:abc"]);
        assert_eq!(
            classify(&ssdp(Some("Linux UPnP/1.0"), &boring)),
            DeviceKind::Unknown
        );
    }

    #[test]
    fn gateway_flag_still_wins_over_ssdp_and_services_win_over_ssdp() {
        let mr = svc(&["urn:schemas-upnp-org:device:MediaRenderer:1"]);
        let i = ClassifyInput {
            is_gw: true,
            ssdp_types: &mr,
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Gateway);
        let s = svc(&["_ipp"]);
        let i = ClassifyInput {
            services: &s,
            ssdp_types: &mr,
            ..Default::default()
        };
        assert_eq!(classify(&i), DeviceKind::Printer);
    }
}
