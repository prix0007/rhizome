//! Pure parsing for the UPnP device description fetch: the LOCATION policy,
//! the HTTP response, and the XML itself.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::enrich::sanitize::sanitize;
use crate::net::subnet::is_scan_target;

/// What we keep from a device description.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpnpInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
}

impl UpnpInfo {
    /// `modelName`, else `modelNumber`.
    pub fn model(&self) -> Option<String> {
        self.model_name
            .clone()
            .or_else(|| self.model_number.clone())
    }
}

/// Where a LAN host asked us to fetch from, after the policy check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub path: String,
}

/// The only URLs we will ever fetch: `http://<IPv4 literal>[:port]/path` where
/// the literal is the very address the SSDP reply came from and passes
/// `is_scan_target` for `net`. No userinfo, no names, no other schemes.
pub fn validate_location(url: &str, from: Ipv4Addr, net: Ipv4Net) -> Option<Target> {
    if url.chars().any(|c| c.is_control() || c == ' ') {
        return None;
    }
    let scheme = url.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &url[7..];
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let path = if tail.is_empty() {
        "/"
    } else if tail.starts_with('/') {
        // The query string and fragment are dropped: real descriptions are plain paths,
        // and a LAN host gets no say in what extra request data we send.
        tail.split(['?', '#']).next().unwrap_or("/")
    } else {
        return None; // a bare query or fragment right after the host
    };
    if authority.contains('@') || path.len() > MAX_PATH_LEN {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (authority, 80),
    };
    let ip: Ipv4Addr = host.parse().ok()?;
    if port == 0 || ip != from || !is_scan_target(ip, net) {
        return None;
    }
    Some(Target {
        ip,
        port,
        path: path.to_string(),
    })
}

pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Extract the body of a `200` response. Redirects and every other status are
/// `None`. Supports `Content-Length`-less (close-delimited) and chunked bodies.
pub fn parse_http_response(raw: &[u8]) -> Option<Vec<u8>> {
    let window = &raw[..raw.len().min(MAX_HEADER_BYTES + 4)];
    let (head_end, sep) = find_header_end(window)?;
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let mut lines = head.lines();
    let mut status = lines.next()?.split_whitespace();
    if !status.next()?.starts_with("HTTP/1.") || status.next()? != "200" {
        return None; // includes every redirect: they are never followed
    }
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("transfer-encoding:") {
            chunked |= v.contains("chunked");
        } else if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
    }
    let body = &raw[head_end + sep..];
    if chunked {
        return dechunk(body);
    }
    let body = match content_length {
        Some(n) if n <= body.len() => &body[..n],
        _ => body,
    };
    (body.len() <= MAX_RESPONSE_BYTES).then(|| body.to_vec())
}

fn find_header_end(b: &[u8]) -> Option<(usize, usize)> {
    (0..b.len()).find_map(|i| {
        if b[i..].starts_with(b"\r\n\r\n") {
            Some((i, 4))
        } else if b[i..].starts_with(b"\n\n") {
            Some((i, 2))
        } else {
            None
        }
    })
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.iter().position(|c| *c == b'\n')?;
        if eol > 20 {
            return None;
        }
        let line = std::str::from_utf8(&b[..eol]).ok()?.trim_end_matches('\r');
        let size_hex = line.split(';').next()?.trim();
        if size_hex.is_empty() || size_hex.len() > 8 {
            return None;
        }
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        b = &b[eol + 1..];
        if size == 0 {
            return Some(out);
        }
        if size > MAX_RESPONSE_BYTES || out.len() + size > MAX_RESPONSE_BYTES || b.len() < size {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size..];
        b = b
            .strip_prefix(b"\r\n")
            .or_else(|| b.strip_prefix(b"\n"))
            .unwrap_or(b);
    }
}

/// Read the root device's `friendlyName`, `manufacturer`, `modelName` and
/// `modelNumber`. Entities are never expanded, a DOCTYPE is rejected outright,
/// nested (embedded) devices are ignored, and values are sanitised.
pub fn parse_description(xml: &[u8]) -> Option<UpnpInfo> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut info = UpnpInfo::default();
    let mut capture: Option<Field> = None;
    let mut text = String::new();
    let mut root_device_closed = false;
    for _ in 0..MAX_XML_EVENTS {
        buf.clear();
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) => {
                if stack.len() >= MAX_XML_DEPTH {
                    return None;
                }
                stack.push(e.local_name().as_ref().to_string());
                // Only the direct children of the first top-level device count;
                // embedded devices (inside deviceList) are deeper.
                capture = if stack.len() == 3 && stack[1] == "device" && !root_device_closed {
                    Field::from_name(&stack[2])
                } else {
                    None
                };
                text.clear();
            }
            Event::End(_) => {
                if let Some(f) = capture.take() {
                    f.store(&mut info, &text);
                }
                if stack.len() == 2 && stack[1] == "device" {
                    root_device_closed = true;
                }
                stack.pop();
                text.clear();
            }
            Event::Text(t) if capture.is_some() => {
                text.push_str(&t);
            }
            Event::CData(c) if capture.is_some() => {
                text.push_str(&c);
            }
            Event::GeneralRef(r) if capture.is_some() => {
                // Only the five predefined entities and numeric character
                // references; anything else is dropped, never expanded.
                if let Ok(Some(ch)) = r.resolve_char_ref() {
                    text.push(ch);
                } else {
                    match &*r {
                        "amp" => text.push('&'),
                        "lt" => text.push('<'),
                        "gt" => text.push('>'),
                        "quot" => text.push('"'),
                        "apos" => text.push('\''),
                        _ => {}
                    }
                }
            }
            // A DOCTYPE is where entities and external DTDs are declared.
            Event::DocType(_) => return None,
            Event::Eof => {
                if !stack.is_empty() {
                    return None; // truncated document
                }
                return (info != UpnpInfo::default()).then_some(info);
            }
            _ => {}
        }
    }
    None // event budget exhausted
}

const MAX_XML_DEPTH: usize = 32;
const MAX_XML_EVENTS: usize = 20_000;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_PATH_LEN: usize = 512;

#[derive(Clone, Copy)]
enum Field {
    FriendlyName,
    Manufacturer,
    ModelName,
    ModelNumber,
}

impl Field {
    fn from_name(n: &str) -> Option<Self> {
        match n {
            "friendlyName" => Some(Self::FriendlyName),
            "manufacturer" => Some(Self::Manufacturer),
            "modelName" => Some(Self::ModelName),
            "modelNumber" => Some(Self::ModelNumber),
            _ => None,
        }
    }

    /// First non-empty value wins.
    fn store(self, info: &mut UpnpInfo, raw: &str) {
        let clean = sanitize(raw);
        if clean.is_empty() {
            return;
        }
        let slot = match self {
            Self::FriendlyName => &mut info.friendly_name,
            Self::Manufacturer => &mut info.manufacturer,
            Self::ModelName => &mut info.model_name,
            Self::ModelNumber => &mut info.model_number,
        };
        slot.get_or_insert(clean);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> Ipv4Net {
        "192.168.0.0/24".parse().unwrap()
    }
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // ---- LOCATION policy ----

    #[test]
    fn accepts_a_plain_http_ipv4_location_from_the_same_host() {
        let t = validate_location(
            "http://192.168.0.82:8008/ssdp/device-desc.xml",
            ip("192.168.0.82"),
            net(),
        )
        .unwrap();
        assert_eq!(
            t,
            Target {
                ip: ip("192.168.0.82"),
                port: 8008,
                path: "/ssdp/device-desc.xml".into()
            }
        );
        let t = validate_location("http://192.168.0.1/", ip("192.168.0.1"), net()).unwrap();
        assert_eq!((t.port, t.path.as_str()), (80, "/"));
        let t = validate_location(
            "HTTP://192.168.0.1:1900/abcde/rootDesc.xml?x=1",
            ip("192.168.0.1"),
            net(),
        )
        .unwrap();
        assert_eq!(t.path, "/abcde/rootDesc.xml", "the query is stripped");
        let t = validate_location("http://192.168.0.1", ip("192.168.0.1"), net()).unwrap();
        assert_eq!(t.path, "/");
    }

    #[test]
    fn query_and_fragment_parts_are_stripped_from_the_path() {
        let from = ip("192.168.0.82");
        for (url, want) in [
            ("http://192.168.0.82:8008/d.xml?a=b&c=d", "/d.xml"),
            ("http://192.168.0.82:8008/d.xml#frag", "/d.xml"),
            ("http://192.168.0.82/d.xml?x#y", "/d.xml"),
            ("http://192.168.0.82/a/b.xml", "/a/b.xml"),
            ("http://192.168.0.82/?q", "/"),
        ] {
            assert_eq!(
                validate_location(url, from, net()).unwrap().path,
                want,
                "{url}"
            );
        }
        // the two real devices on this network still resolve
        let r = validate_location(
            "http://192.168.0.1:1900/abcde/rootDesc.xml",
            ip("192.168.0.1"),
            net(),
        )
        .unwrap();
        assert_eq!((r.port, r.path.as_str()), (1900, "/abcde/rootDesc.xml"));
        let tv = validate_location("http://192.168.0.82:8008/ssdp/device-desc.xml", from, net())
            .unwrap();
        assert_eq!((tv.port, tv.path.as_str()), (8008, "/ssdp/device-desc.xml"));
    }

    #[test]
    fn rejects_everything_else() {
        let from = ip("192.168.0.82");
        for bad in [
            "https://192.168.0.82/desc.xml",
            "ftp://192.168.0.82/x",
            "file:///etc/passwd",
            "//192.168.0.82/x",
            "192.168.0.82/x",
            "http://example.com/desc.xml",
            "http://localhost/desc.xml",
            "http://192.168.0.83/desc.xml", // a different LAN host: no redirecting our request
            "http://8.8.8.8/desc.xml",
            "http://127.0.0.1/desc.xml",
            "http://169.254.169.254/latest/meta-data",
            "http://192.168.1.82/desc.xml", // other subnet
            "http://192.168.0.255/x",
            "http://user@192.168.0.82/x",
            "http://user:pw@192.168.0.82/x",
            "http://192.168.0.82@evil.com/x",
            "http://192.168.0.82:0/x",
            "http://192.168.0.82:99999/x",
            "http://192.168.0.82:80:80/x",
            "http://192.168.0.82:abc/x",
            "http://[::1]/x",
            "http://0xc0a80052/x",
            "http://3232235602/x",
            "http://192.168.000.082/x",
            "http://192.168.0.82/a b",
            "http://192.168.0.82/\r\nHost: evil",
            "http://192.168.0.82/\u{0}",
            "http://192.168.0.82#frag@evil.com",
            "",
            "http://",
        ] {
            assert_eq!(validate_location(bad, from, net()), None, "{bad:?}");
        }
        let long = format!("http://192.168.0.82/{}", "a".repeat(600));
        assert_eq!(
            validate_location(&long, from, net()),
            None,
            "path length is capped"
        );
    }

    // ---- HTTP response ----

    #[test]
    fn extracts_the_body_of_a_200() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\n<root/>";
        assert_eq!(parse_http_response(raw).unwrap(), b"<root/>");
        let raw = b"HTTP/1.1 200 OK\ncontent-length: 7\n\n<root/>trailing";
        assert!(parse_http_response(raw).is_some());
    }

    #[test]
    fn redirects_and_errors_are_not_followed_or_accepted() {
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "307 Temporary Redirect",
            "404 Not Found",
            "500 Oops",
            "204 No Content",
        ] {
            let raw = format!("HTTP/1.1 {status}\r\nLocation: http://evil.example/\r\n\r\n<root/>");
            assert_eq!(parse_http_response(raw.as_bytes()), None, "{status}");
        }
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<roo\r\n3\r\nt/>\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), b"<root/>");
    }

    #[test]
    fn malformed_responses_never_panic() {
        for raw in [
            &b""[..],
            b"garbage",
            b"HTTP/1.1 200 OK",
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/2 200\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffff\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort",
        ] {
            let _ = parse_http_response(raw);
        }
        // a header block that never ends is refused
        let mut endless = b"HTTP/1.1 200 OK\r\n".to_vec();
        endless.extend(std::iter::repeat_n(b'x', 40_000));
        assert_eq!(parse_http_response(&endless), None);
    }

    // ---- XML ----

    const SONY: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room TV</friendlyName>
    <manufacturer>Sony Corporation</manufacturer>
    <modelName>BRAVIA</modelName>
    <modelNumber>KD-55X80J</modelNumber>
    <deviceList>
      <device><friendlyName>Embedded thing</friendlyName><manufacturer>Other</manufacturer><modelName>Inner</modelName></device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn reads_the_root_device_and_ignores_embedded_devices() {
        let i = parse_description(SONY.as_bytes()).unwrap();
        assert_eq!(i.friendly_name.as_deref(), Some("Living Room TV"));
        assert_eq!(i.manufacturer.as_deref(), Some("Sony Corporation"));
        assert_eq!(i.model_name.as_deref(), Some("BRAVIA"));
        assert_eq!(i.model_number.as_deref(), Some("KD-55X80J"));
        assert_eq!(i.model().as_deref(), Some("BRAVIA"));
    }

    #[test]
    fn model_falls_back_to_the_model_number() {
        let i = parse_description(b"<root><device><modelNumber>X1</modelNumber></device></root>")
            .unwrap();
        assert_eq!(i.model().as_deref(), Some("X1"));
    }

    #[test]
    fn prefixed_names_cdata_and_character_references_work() {
        let xml = "<d:root xmlns:d=\"urn:x\"><d:device><d:friendlyName><![CDATA[Tom & Jerry <TV>]]></d:friendlyName>\
                   <d:manufacturer>Caf&#233; &amp; Co &lt;3</d:manufacturer></d:device></d:root>";
        let i = parse_description(xml.as_bytes()).unwrap();
        assert_eq!(i.friendly_name.as_deref(), Some("Tom & Jerry <TV>"));
        assert_eq!(i.manufacturer.as_deref(), Some("Caf\u{e9} & Co <3"));
    }

    #[test]
    fn a_doctype_is_rejected_so_entities_can_never_be_declared_or_fetched() {
        let xxe = r#"<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><device><friendlyName>&xxe;</friendlyName></device></root>"#;
        assert_eq!(parse_description(xxe.as_bytes()), None);
        let external = r#"<!DOCTYPE root SYSTEM "http://evil.example/x.dtd"><root><device><friendlyName>a</friendlyName></device></root>"#;
        assert_eq!(parse_description(external.as_bytes()), None);
        let laughs = r#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><root><device><friendlyName>&lol2;</friendlyName></device></root>"#;
        assert_eq!(parse_description(laughs.as_bytes()), None);
    }

    #[test]
    fn an_undeclared_entity_reference_is_not_expanded() {
        let xml = b"<root><device><friendlyName>a &foo; b</friendlyName><manufacturer>M</manufacturer></device></root>";
        let i = parse_description(xml);
        // either rejected or the reference is dropped: never substituted
        if let Some(i) = i {
            assert!(!i.friendly_name.unwrap_or_default().contains("foo-value"));
        }
    }

    #[test]
    fn values_are_sanitised_trimmed_and_capped() {
        let xml = format!(
            "<root><device><friendlyName>  A\u{202e}B\u{1b}[31m\n C  </friendlyName><manufacturer>{}</manufacturer></device></root>",
            "m".repeat(1000)
        );
        let i = parse_description(xml.as_bytes()).unwrap();
        assert_eq!(i.friendly_name.as_deref(), Some("AB[31m C"));
        assert_eq!(i.manufacturer.unwrap().chars().count(), 255);
    }

    #[test]
    fn the_first_value_wins_and_empty_values_are_none() {
        let xml = b"<root><device><friendlyName>First</friendlyName><friendlyName>Second</friendlyName><manufacturer>  </manufacturer><modelName>M</modelName></device></root>";
        let i = parse_description(xml).unwrap();
        assert_eq!(i.friendly_name.as_deref(), Some("First"));
        assert_eq!(i.manufacturer, None);
    }

    #[test]
    fn documents_without_a_device_or_without_useful_fields_are_none() {
        assert_eq!(parse_description(b""), None);
        assert_eq!(parse_description(b"not xml at all"), None);
        assert_eq!(parse_description(b"<root></root>"), None);
        assert_eq!(
            parse_description(b"<root><device><deviceType>x</deviceType></device></root>"),
            None
        );
        assert_eq!(
            parse_description(b"<html><body><friendlyName>x</friendlyName></body></html>"),
            None,
            "must be inside a device"
        );
        assert_eq!(parse_description(&[0xff, 0xfe, 0x00]), None);
    }

    #[test]
    fn broken_or_hostile_xml_is_rejected_without_panicking() {
        assert_eq!(
            parse_description(b"<root><device><friendlyName>x</friendlyName>"),
            None,
            "truncated"
        );
        assert_eq!(
            parse_description(b"<root><device></root>"),
            None,
            "mismatched end tag"
        );
        let deep = format!("{}{}", "<a>".repeat(5000), "</a>".repeat(5000));
        assert_eq!(parse_description(deep.as_bytes()), None, "absurd nesting");
        let wide = format!("<root><device>{}</device></root>", "<x/>".repeat(100_000));
        assert_eq!(parse_description(wide.as_bytes()), None, "event budget");
        for n in 0..SONY.len() {
            let _ = parse_description(&SONY.as_bytes()[..n]);
        }
    }
}
