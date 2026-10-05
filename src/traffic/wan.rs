//! WAN throughput from the gateway's UPnP IGD byte counters
//! (`WANCommonInterfaceConfig`: `GetTotalBytesReceived` / `GetTotalBytesSent`).
//!
//! This is a SOAP POST to an address a LAN device advertised, so it obeys the
//! same restrictions as the description fetch: plain `http://` to the router's
//! own in-subnet IPv4 (already checked when the control URL was resolved), a
//! hand-written HTTP/1.0 request, no redirects, short timeouts, capped reads,
//! and strict XML (DOCTYPE rejected, entities never expanded). It is skipped
//! entirely with `--no-upnp`.

use std::net::SocketAddrV4;
use std::time::Duration;

use quick_xml::Reader;
use quick_xml::events::Event;

use super::rate::{CounterRate, Width};
use crate::discovery::upnp::{CONNECT_TIMEOUT, TOTAL_TIMEOUT, http_exchange};
use crate::discovery::upnp_parse::{IgdControl, parse_http_response};

pub const GET_RX: (&str, &str) = ("GetTotalBytesReceived", "NewTotalBytesReceived");
pub const GET_TX: (&str, &str) = ("GetTotalBytesSent", "NewTotalBytesSent");

/// The POST for one counter action. `action` is one of our own constants; the
/// service type was validated when the control URL was resolved.
pub fn soap_request(ctl: &IgdControl, action: &str) -> Vec<u8> {
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{svc}\"/></s:Body></s:Envelope>",
        svc = ctl.service_type
    );
    format!(
        "POST {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: rhizome\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{svc}#{action}\"\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        path = ctl.path,
        ip = ctl.ip,
        port = ctl.port,
        svc = ctl.service_type,
        len = body.len(),
    )
    .into_bytes()
}

/// Read the integer inside `<tag>` of a SOAP response. A SOAP fault, a DOCTYPE,
/// malformed XML, or a value that is not a plain unsigned integer is `None`.
pub fn parse_soap_counter(xml: &[u8], tag: &str) -> Option<u64> {
    const MAX_DEPTH: usize = 32;
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut capturing = false;
    let mut value = String::new();
    let mut found: Option<u64> = None;
    for _ in 0..20_000 {
        buf.clear();
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return None;
                }
                if found.is_none() && e.local_name().as_ref() == tag {
                    capturing = true;
                    value.clear();
                }
            }
            Event::End(_) => {
                if capturing {
                    capturing = false;
                    let v = value.trim();
                    if !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()) {
                        found = v.parse().ok();
                    }
                }
                depth = depth.saturating_sub(1);
            }
            Event::Text(t) if capturing => value.push_str(&t),
            Event::DocType(_) => return None,
            Event::Eof => return if depth == 0 { found } else { None },
            _ => {}
        }
    }
    None
}

/// Read one counter from the router. `None` on any failure.
pub async fn fetch_counter(
    ctl: &IgdControl,
    action: (&str, &str),
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Option<u64> {
    let addr = SocketAddrV4::new(ctl.ip, ctl.port);
    let raw = http_exchange(
        addr,
        &soap_request(ctl, action.0),
        connect_timeout,
        total_timeout,
    )
    .await?;
    parse_soap_counter(&parse_http_response(&raw)?, action.1)
}

/// Rates (bits per second) from successive reads of both counters.
pub struct WanMonitor {
    rx: CounterRate,
    tx: CounterRate,
    failures: u32,
    zero_reads: u32,
}

/// After this many consecutive failed polls the router is treated as not
/// supporting the counters (until the control URL changes).
pub const GIVE_UP_AFTER: u32 = 3;
/// Consecutive reads where both counters are exactly zero before the router is
/// treated as not implementing them (some report 0 forever).
pub const ZERO_READS_UNSUPPORTED: u32 = 5;

impl Default for WanMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl WanMonitor {
    pub fn new() -> Self {
        // Router counters are 32-bit on many models and 64-bit on others.
        Self {
            rx: CounterRate::new(Width::Auto),
            tx: CounterRate::new(Width::Auto),
            failures: 0,
            zero_reads: 0,
        }
    }

    pub fn reset(&mut self) {
        self.rx.reset();
        self.tx.reset();
        self.failures = 0;
        self.zero_reads = 0;
    }

    /// Whether to keep polling this router.
    pub fn gave_up(&self) -> bool {
        self.failures >= GIVE_UP_AFTER || self.zero_reads >= ZERO_READS_UNSUPPORTED
    }

    /// Feed one poll's result: both counters read at `ts_ms`, or `None` when the
    /// read failed. Returns `(rx_bps, tx_bps)` once two good reads exist.
    pub fn feed(&mut self, reading: Option<(u64, u64)>, ts_ms: i64) -> Option<(f64, f64)> {
        let Some((rx, tx)) = reading else {
            self.failures += 1;
            return None;
        };
        self.failures = 0;
        if (rx, tx) == (0, 0) {
            // A real, busy router never reads exactly zero repeatedly; one that does
            // is not implementing the counters, so there is no rate to report.
            self.zero_reads += 1;
            self.rx.reset();
            self.tx.reset();
            return None;
        }
        self.zero_reads = 0;
        let (r, t) = (self.rx.update(rx, ts_ms), self.tx.update(tx, ts_ms));
        r.zip(t)
    }

    /// Poll the router once.
    pub async fn poll(&mut self, ctl: &IgdControl, ts_ms: i64) -> Option<(f64, f64)> {
        let (rx, tx) = tokio::join!(
            fetch_counter(ctl, GET_RX, CONNECT_TIMEOUT, TOTAL_TIMEOUT),
            fetch_counter(ctl, GET_TX, CONNECT_TIMEOUT, TOTAL_TIMEOUT)
        );
        self.feed(rx.zip(tx), ts_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn ctl() -> IgdControl {
        IgdControl {
            ip: Ipv4Addr::new(192, 168, 0, 1),
            port: 5000,
            path: "/ctl/CmnIfCfg".into(),
            service_type: "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1".into(),
        }
    }

    fn envelope(tag: &str, value: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetTotalBytesReceivedResponse xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\"><{tag}>{value}</{tag}></u:GetTotalBytesReceivedResponse></s:Body></s:Envelope>"
        )
    }

    #[test]
    fn the_request_is_a_well_formed_http10_soap_post() {
        let r = String::from_utf8(soap_request(&ctl(), "GetTotalBytesReceived")).unwrap();
        assert!(r.starts_with("POST /ctl/CmnIfCfg HTTP/1.0\r\n"), "{r}");
        assert!(r.contains("Host: 192.168.0.1:5000\r\n"));
        assert!(r.contains("SOAPAction: \"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetTotalBytesReceived\"\r\n"));
        assert!(r.contains("Content-Type: text/xml; charset=\"utf-8\"\r\n"));
        assert!(r.contains("Connection: close\r\n"));
        let (head, body) = r.split_once("\r\n\r\n").unwrap();
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            declared,
            body.len(),
            "Content-Length matches the body exactly"
        );
        assert!(body.contains("<u:GetTotalBytesReceived xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\"/>"));
        assert!(
            !r.to_lowercase().contains("cookie") && !r.to_lowercase().contains("authorization")
        );
    }

    #[test]
    fn counters_are_read_from_the_response_and_everything_else_is_refused() {
        assert_eq!(
            parse_soap_counter(
                envelope("NewTotalBytesReceived", "123456789").as_bytes(),
                "NewTotalBytesReceived"
            ),
            Some(123_456_789)
        );
        assert_eq!(
            parse_soap_counter(
                envelope("NewTotalBytesReceived", "  42\n").as_bytes(),
                "NewTotalBytesReceived"
            ),
            Some(42),
            "whitespace is trimmed"
        );
        assert_eq!(
            parse_soap_counter(
                envelope("NewTotalBytesReceived", "18446744073709551615").as_bytes(),
                "NewTotalBytesReceived"
            ),
            Some(u64::MAX)
        );
        for bad in [
            "",
            "abc",
            "-5",
            "1.5",
            "99999999999999999999999",
            "0x10",
            "1e9",
            "12 34",
        ] {
            assert_eq!(
                parse_soap_counter(
                    envelope("NewTotalBytesReceived", bad).as_bytes(),
                    "NewTotalBytesReceived"
                ),
                None,
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_soap_counter(
                envelope("NewTotalBytesSent", "5").as_bytes(),
                "NewTotalBytesReceived"
            ),
            None,
            "wrong element"
        );
    }

    #[test]
    fn faults_doctypes_and_garbage_are_none() {
        let fault = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><detail><UPnPError><errorCode>401</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(
            parse_soap_counter(fault.as_bytes(), "NewTotalBytesReceived"),
            None
        );
        let xxe = format!(
            "<!DOCTYPE x [<!ENTITY e \"9\">]>{}",
            envelope("NewTotalBytesReceived", "&e;")
        );
        assert_eq!(
            parse_soap_counter(xxe.as_bytes(), "NewTotalBytesReceived"),
            None
        );
        assert_eq!(
            parse_soap_counter(b"not xml", "NewTotalBytesReceived"),
            None
        );
        assert_eq!(parse_soap_counter(b"", "NewTotalBytesReceived"), None);
        let ok = envelope("NewTotalBytesReceived", "7");
        for n in 0..ok.len() {
            let _ = parse_soap_counter(&ok.as_bytes()[..n], "NewTotalBytesReceived");
        }
        let deep = format!("{}1{}", "<a>".repeat(5000), "</a>".repeat(5000));
        assert_eq!(
            parse_soap_counter(deep.as_bytes(), "a"),
            None,
            "absurd nesting"
        );
    }

    async fn serve(
        replies: Vec<(String, String)>,
    ) -> (SocketAddrV4, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        // replies: (substring expected in SOAPAction, body)
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let seen = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let s2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                let replies = replies.clone();
                let s3 = s2.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let body = replies
                        .iter()
                        .find(|(k, _)| req.contains(k.as_str()))
                        .map(|(_, b)| b.clone());
                    s3.lock().unwrap().push(req);
                    let out = match body {
                        Some(b) => format!("HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\n{b}"),
                        None => "HTTP/1.0 500 Internal Server Error\r\n\r\n".to_string(),
                    };
                    let _ = sock.write_all(out.as_bytes()).await;
                });
            }
        });
        (addr, seen)
    }

    fn ctl_at(addr: SocketAddrV4) -> IgdControl {
        IgdControl {
            ip: *addr.ip(),
            port: addr.port(),
            ..ctl()
        }
    }

    #[tokio::test]
    async fn counters_are_fetched_over_http_and_a_router_error_is_none() {
        let (addr, seen) = serve(vec![
            (
                "#GetTotalBytesReceived".into(),
                envelope("NewTotalBytesReceived", "1000"),
            ),
            (
                "#GetTotalBytesSent".into(),
                envelope("NewTotalBytesSent", "2000"),
            ),
        ])
        .await;
        let t = Duration::from_millis(800);
        assert_eq!(fetch_counter(&ctl_at(addr), GET_RX, t, t).await, Some(1000));
        assert_eq!(fetch_counter(&ctl_at(addr), GET_TX, t, t).await, Some(2000));
        assert_eq!(
            fetch_counter(&ctl_at(addr), ("GetSomethingElse", "X"), t, t).await,
            None,
            "HTTP 500 is not a counter"
        );
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn redirects_are_not_followed_and_silent_routers_time_out() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\n\r\n")
                    .await;
            }
        });
        let t = Duration::from_millis(500);
        assert_eq!(fetch_counter(&ctl_at(addr), GET_RX, t, t).await, None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let saddr = match silent.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let (_s, _) = silent.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let started = std::time::Instant::now();
        assert_eq!(fetch_counter(&ctl_at(saddr), GET_RX, t, t).await, None);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    // ---- rates ----

    #[test]
    fn the_monitor_needs_two_good_reads_for_a_rate() {
        let mut m = WanMonitor::new();
        assert_eq!(m.feed(Some((1_000, 500)), 0), None);
        let (rx, tx) = m.feed(Some((126_000, 62_500 + 500)), 1000).unwrap();
        assert_eq!(rx, 1_000_000.0);
        assert_eq!(tx, 500_000.0);
    }

    #[test]
    fn a_32_bit_router_counter_that_wraps_keeps_working() {
        let mut m = WanMonitor::new();
        let top = u32::MAX as u64;
        m.feed(Some((top - 62_499, top - 1_000)), 0);
        let (rx, tx) = m.feed(Some((62_500, 124_000 - 1_000 + 1)), 1000).unwrap();
        assert_eq!(rx, 1_000_000.0, "wrapped past 2^32");
        assert!(tx > 0.0);
    }

    #[test]
    fn a_router_reboot_resets_the_counters_without_a_bogus_spike() {
        let mut m = WanMonitor::new();
        m.feed(Some((1_000_000_000, 1_000_000_000)), 0);
        assert_eq!(
            m.feed(Some((5_000, 5_000)), 1000),
            None,
            "counters went backwards from a small value: reset, no rate"
        );
        assert!(
            m.feed(Some((130_000, 130_000)), 2000).is_some(),
            "recovers on the next read"
        );
    }

    #[test]
    fn repeated_failures_make_the_monitor_give_up_and_success_resets_the_count() {
        let mut m = WanMonitor::new();
        for _ in 0..GIVE_UP_AFTER - 1 {
            assert_eq!(m.feed(None, 0), None);
        }
        assert!(!m.gave_up());
        m.feed(Some((1, 1)), 1000);
        for _ in 0..GIVE_UP_AFTER {
            m.feed(None, 2000);
        }
        assert!(m.gave_up());
        m.reset();
        assert!(!m.gave_up());
    }

    #[test]
    fn a_router_whose_counters_stay_at_zero_is_treated_as_unsupported_not_as_zero_traffic() {
        // Seen on a real gateway: the IGD answers, but both counters are always 0.
        let mut m = WanMonitor::new();
        for i in 0..ZERO_READS_UNSUPPORTED {
            assert_eq!(
                m.feed(Some((0, 0)), i64::from(i) * 1000),
                None,
                "never a rate of 0 bps"
            );
        }
        assert!(
            m.gave_up(),
            "after repeated all-zero reads the counters are considered unimplemented"
        );
    }

    #[test]
    fn a_counter_that_moves_off_zero_clears_the_suspicion() {
        let mut m = WanMonitor::new();
        for i in 0..ZERO_READS_UNSUPPORTED - 1 {
            m.feed(Some((0, 0)), i64::from(i) * 1000);
        }
        m.feed(Some((1_000, 500)), 10_000);
        assert!(!m.gave_up());
        assert!(m.feed(Some((126_000, 62_500 + 500)), 11_000).is_some());
    }
}
