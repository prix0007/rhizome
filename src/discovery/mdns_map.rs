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
    /// Service instance name, e.g. `Living Room` from `Living Room._airplay._tcp.local.`
    pub instance: String,
    /// TXT record key/value pairs.
    pub txt: Vec<(String, String)>,
}

/// What a service's TXT records and instance name say about the device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxtInfo {
    pub friendly_name: Option<String>,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
}

/// `Living Room._airplay._tcp.local.` + `_airplay._tcp.local.` -> `Living Room`.
pub fn instance_from_fullname(fullname: &str, ty_domain: &str) -> Option<String> {
    let inst = sanitize(fullname.strip_suffix(ty_domain)?.strip_suffix('.')?);
    (!inst.is_empty()).then_some(inst)
}

/// Pick friendly name, model and manufacturer out of TXT records (case-insensitive
/// keys: `fn`; `md`/`model`/`ty`/`am`; `usb_MFG`/`mfg`/`manufacturer`). For a few
/// services whose instance name is the device's own name the instance is the
/// fallback friendly name. Everything is sanitised.
pub fn txt_info(service_label: &str, instance: &str, txt: &[(String, String)]) -> TxtInfo {
    // Services whose instance name is the device's own display name.
    const NAMED_INSTANCES: &[&str] = &[
        "_airplay",
        "_googlecast",
        "_ipp",
        "_ipps",
        "_printer",
        "_companion-link",
        "_hap",
    ];
    let get_where = |keys: &[&str], ok: &dyn Fn(&str) -> bool| {
        keys.iter().find_map(|k| {
            txt.iter()
                .find(|(tk, _)| tk.eq_ignore_ascii_case(k))
                .map(|(_, v)| sanitize(v))
                .filter(|v| !v.is_empty() && ok(v))
        })
    };
    let get = |keys: &[&str]| get_where(keys, &|_| true);
    let from_instance = || {
        let inst = sanitize(instance);
        (NAMED_INSTANCES.contains(&service_label) && !inst.is_empty()).then_some(inst)
    };
    TxtInfo {
        friendly_name: get(&["fn"]).or_else(from_instance),
        // `md` means "metadata types" (e.g. `0,1,2`) for AirPlay audio, not a model;
        // and a model name always contains a letter (so `123` or `0,1,2` never qualifies).
        model: get_where(
            if service_label == "_raop" {
                &["model", "ty", "am"][..]
            } else {
                &["md", "model", "ty", "am"][..]
            },
            &|v| v.chars().any(|c| c.is_ascii_alphabetic()),
        ),
        manufacturer: get(&["usb_MFG", "mfg", "manufacturer"]),
    }
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
    let info = txt_info(
        service_types.first().map(String::as_str).unwrap_or(""),
        &r.instance,
        &r.txt,
    );
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
            friendly_name: info.friendly_name.clone(),
            model: info.model.clone(),
            manufacturer: info.manufacturer.clone(),
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
            instance: String::new(),
            txt: vec![],
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

    fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn chromecast_txt_gives_friendly_name_and_model() {
        let i = txt_info(
            "_googlecast",
            "Chromecast-abc123",
            &kv(&[
                ("fn", "Living Room TV"),
                ("md", "Chromecast Ultra"),
                ("id", "x"),
            ]),
        );
        assert_eq!(i.friendly_name.as_deref(), Some("Living Room TV"));
        assert_eq!(i.model.as_deref(), Some("Chromecast Ultra"));
        assert_eq!(i.manufacturer, None);
    }

    #[test]
    fn printer_txt_gives_model_and_manufacturer() {
        let i = txt_info(
            "_ipp",
            "HP LaserJet Pro M404 [A1B2C3]",
            &kv(&[
                ("ty", "HP LaserJet Pro M404dn"),
                ("usb_MFG", "HP"),
                ("note", "Office"),
            ]),
        );
        assert_eq!(i.model.as_deref(), Some("HP LaserJet Pro M404dn"));
        assert_eq!(i.manufacturer.as_deref(), Some("HP"));
        assert_eq!(
            i.friendly_name.as_deref(),
            Some("HP LaserJet Pro M404 [A1B2C3]"),
            "ipp instance names are the device's name"
        );
    }

    #[test]
    fn apple_model_and_key_precedence() {
        let i = txt_info(
            "_airplay",
            "Bedroom",
            &kv(&[
                ("am", "AppleTV11,1"),
                ("model", "AppleTV11,1"),
                ("md", "Real Model"),
            ]),
        );
        assert_eq!(
            i.model.as_deref(),
            Some("Real Model"),
            "md beats model beats am"
        );
        assert_eq!(i.friendly_name.as_deref(), Some("Bedroom"));
        let i = txt_info("_airplay", "Bedroom", &kv(&[("am", "AppleTV11,1")]));
        assert_eq!(i.model.as_deref(), Some("AppleTV11,1"));
    }

    #[test]
    fn raop_md_is_a_metadata_capability_list_not_a_model() {
        // Seen live on a Mac: `_raop` advertises md=0,1,2 next to its real model in `am`.
        let i = txt_info(
            "_raop",
            "AABBCC@Mac",
            &kv(&[("md", "0,1,2"), ("am", "MacBookPro18,3")]),
        );
        assert_eq!(i.model.as_deref(), Some("MacBookPro18,3"));
        let i = txt_info("_raop", "x", &kv(&[("md", "0,1,2")]));
        assert_eq!(i.model, None);
    }

    #[test]
    fn model_values_must_look_like_names_not_numbers_or_lists() {
        for junk in ["0,1,2", "123", "1.2.3", "0", "  "] {
            assert_eq!(
                txt_info("_foo", "", &kv(&[("md", junk)])).model,
                None,
                "{junk:?}"
            );
        }
        assert_eq!(
            txt_info("_foo", "", &kv(&[("md", "Model 3")]))
                .model
                .as_deref(),
            Some("Model 3")
        );
    }

    #[test]
    fn keys_are_case_insensitive_and_empty_values_ignored() {
        let i = txt_info(
            "_googlecast",
            "x",
            &kv(&[("FN", "Kitchen"), ("MD", ""), ("Model", "  ")]),
        );
        assert_eq!(i.friendly_name.as_deref(), Some("Kitchen"));
        assert_eq!(i.model, None);
    }

    #[test]
    fn the_instance_name_is_only_a_fallback_for_services_that_name_the_device() {
        assert_eq!(
            txt_info("_airplay", "Kitchen", &[])
                .friendly_name
                .as_deref(),
            Some("Kitchen")
        );
        assert_eq!(txt_info("_ssh", "Kitchen", &[]).friendly_name, None);
        assert_eq!(
            txt_info("_workstation", "pc [aa:bb:cc]", &[]).friendly_name,
            None
        );
        assert_eq!(
            txt_info("_raop", "AABBCCDDEEFF@Kitchen", &[]).friendly_name,
            None
        );
        assert_eq!(txt_info("_airplay", "", &[]).friendly_name, None);
    }

    #[test]
    fn txt_values_are_sanitised_and_capped() {
        let i = txt_info(
            "_googlecast",
            "x",
            &kv(&[("fn", "A\u{202e}B\u{1b}[0m"), ("md", &"m".repeat(600))]),
        );
        assert_eq!(i.friendly_name.as_deref(), Some("AB[0m"));
        assert_eq!(i.model.unwrap().chars().count(), 255);
    }

    #[test]
    fn instance_names_come_from_the_full_service_name() {
        assert_eq!(
            instance_from_fullname("Living Room._airplay._tcp.local.", "_airplay._tcp.local.")
                .as_deref(),
            Some("Living Room")
        );
        assert_eq!(
            instance_from_fullname("a.b._ipp._tcp.local.", "_ipp._tcp.local.").as_deref(),
            Some("a.b")
        );
        assert_eq!(
            instance_from_fullname("_ipp._tcp.local.", "_ipp._tcp.local."),
            None
        );
        assert_eq!(instance_from_fullname("nonsense", "_ipp._tcp.local."), None);
        assert_eq!(
            instance_from_fullname("x\u{1b}._ipp._tcp.local.", "_ipp._tcp.local.").as_deref(),
            Some("x")
        );
    }

    #[test]
    fn map_resolution_carries_txt_info_into_every_hit() {
        let mut r = raw(
            "Cast.local.",
            &["192.168.0.82", "192.168.0.83"],
            "_googlecast._tcp.local.",
        );
        r.txt = kv(&[("fn", "Den TV"), ("md", "Chromecast")]);
        let hits = map_resolution(&r);
        assert_eq!(hits.len(), 2);
        assert!(
            hits.iter()
                .all(|h| h.friendly_name.as_deref() == Some("Den TV")
                    && h.model.as_deref() == Some("Chromecast"))
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
            ..Default::default()
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
