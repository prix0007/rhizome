//! Pure SSDP: build the M-SEARCH request and parse unicast responses.

use crate::enrich::sanitize::sanitize;
use crate::model::SsdpHit;

pub const MULTICAST_ADDR: &str = "239.255.255.250:1900";
/// Responses larger than this are rejected outright.
pub const MAX_RESPONSE: usize = 8 * 1024;

pub fn build_msearch() -> Vec<u8> {
    format!("M-SEARCH * HTTP/1.1\r\nHOST: {MULTICAST_ADDR}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").into_bytes()
}

/// Parse a response datagram. `None` unless it is a well-formed `HTTP/1.1 200`
/// response of at most 8 KB. Header values are sanitised.
pub fn parse_response(bytes: &[u8]) -> Option<SsdpHit> {
    if bytes.len() > MAX_RESPONSE {
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let mut status = lines.next()?.split_whitespace();
    let proto = status.next()?;
    if !proto.starts_with("HTTP/1.") || status.next()? != "200" {
        return None;
    }
    let mut hit = SsdpHit::default();
    for line in lines {
        if line.is_empty() {
            break; // end of headers; anything after is ignored
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = Some(sanitize(value)).filter(|v| !v.is_empty());
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => hit.server = value,
            "st" => hit.st = value,
            "usn" => hit.usn = value,
            "location" => hit.location = value,
            _ => {}
        }
    }
    (hit != SsdpHit::default()).then_some(hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IGD: &[u8] = include_bytes!("../../tests/fixtures/ssdp_igd.txt");
    const SONOS: &[u8] = include_bytes!("../../tests/fixtures/ssdp_sonos.txt");
    const HOSTILE: &[u8] = include_bytes!("../../tests/fixtures/ssdp_hostile.txt");

    #[test]
    fn msearch_bytes_are_exact() {
        let expected = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
        assert_eq!(build_msearch(), expected.as_bytes());
    }

    #[test]
    fn parses_an_igd_response() {
        let h = parse_response(IGD).unwrap();
        assert_eq!(
            h.server.as_deref(),
            Some("Linux/4.14 UPnP/1.1 MiniUPnPd/2.1")
        );
        assert_eq!(
            h.st.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
        assert!(h.usn.as_deref().unwrap().starts_with("uuid:11111111"));
        assert_eq!(
            h.location.as_deref(),
            Some("http://192.168.0.1:5000/rootDesc.xml")
        );
    }

    #[test]
    fn headers_are_case_insensitive() {
        let h = parse_response(SONOS).unwrap();
        assert!(h.server.as_deref().unwrap().contains("Sonos"));
        assert!(h.st.as_deref().unwrap().contains("MediaRenderer"));
        assert!(h.location.is_some());
    }

    #[test]
    fn missing_or_wrong_status_line_is_rejected() {
        assert!(parse_response(b"ST: upnp:rootdevice\r\nSERVER: x\r\n\r\n").is_none());
        assert!(
            parse_response(b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nSERVER: x\r\n\r\n")
                .is_none()
        );
        assert!(parse_response(b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n").is_none());
        assert!(parse_response(b"HTTP/1.1 500 Oops\r\nSERVER: x\r\n\r\n").is_none());
        assert!(parse_response(b"").is_none());
        assert!(parse_response(b"\r\n\r\n").is_none());
    }

    #[test]
    fn http_1_0_ok_is_accepted() {
        assert!(parse_response(b"HTTP/1.0 200 OK\r\nSERVER: x\r\n\r\n").is_some());
    }

    #[test]
    fn oversize_bodies_are_rejected() {
        let mut big = b"HTTP/1.1 200 OK\r\nSERVER: x\r\n\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_RESPONSE));
        assert!(big.len() > MAX_RESPONSE);
        assert!(parse_response(&big).is_none());
        let mut ok = b"HTTP/1.1 200 OK\r\nSERVER: x\r\n\r\n".to_vec();
        ok.extend(std::iter::repeat_n(b'a', MAX_RESPONSE - ok.len()));
        assert!(parse_response(&ok).is_some());
    }

    #[test]
    fn non_utf8_is_handled_lossily() {
        let h = parse_response(
            b"HTTP/1.1 200 OK\r\nSERVER: caf\xe9 UPnP\xff/1.0\r\nST: upnp:rootdevice\r\n\r\n",
        )
        .unwrap();
        assert!(h.server.unwrap().contains('\u{fffd}'));
    }

    #[test]
    fn header_values_are_sanitised() {
        let h = parse_response(HOSTILE).unwrap();
        let server = h.server.unwrap();
        assert!(!server.contains('\x1b') && !server.contains('\x07'));
        assert_eq!(server, "<img src=x onerror=alert(1)>[31m UPnP/1.0");
        assert_eq!(h.location.as_deref(), Some("http://192.168.0.9/desc.xml"));
    }

    #[test]
    fn long_values_are_capped() {
        let line = format!("HTTP/1.1 200 OK\r\nSERVER: {}\r\n\r\n", "z".repeat(5000));
        assert_eq!(
            parse_response(line.as_bytes())
                .unwrap()
                .server
                .unwrap()
                .chars()
                .count(),
            255
        );
    }

    #[test]
    fn a_response_with_no_useful_headers_is_dropped() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1\r\n\r\n").is_none());
    }

    #[test]
    fn bare_lf_line_endings_and_junk_never_panic() {
        assert!(parse_response(b"HTTP/1.1 200 OK\nSERVER: x\n\n").is_some());
        for junk in [
            &b"HTTP/1.1 200 OK"[..],
            b"HTTP/1.1 200 OK\r\n:::\r\n",
            b"\xff\xfe\x00\x01",
            b"HTTP/1.1 200 OK\r\nSERVER\r\n\r\n",
        ] {
            let _ = parse_response(junk);
        }
    }

    #[test]
    fn fuzz_style_every_truncation_is_safe() {
        for n in 0..IGD.len() {
            let _ = parse_response(&IGD[..n]);
        }
        for n in 0..HOSTILE.len() {
            let _ = parse_response(&HOSTILE[..n]);
        }
    }
}
