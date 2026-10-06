//! I/O adapter: fetch a UPnP device description.
//!
//! This is the one place the agent makes an HTTP request to an address that a
//! LAN host chose (the SSDP `LOCATION`). So it is locked down: plain `http://`
//! to the IPv4 literal the SSDP reply came from (which must be an in-subnet
//! scan target), a hand-written HTTP/1.0 GET, redirects are never followed,
//! short connect and total timeouts, and a hard cap on the bytes read.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use ipnet::Ipv4Net;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::upnp_parse::{
    IgdService, MAX_RESPONSE_BYTES, UpnpInfo, parse_description, parse_http_response,
    parse_igd_service, resolve_control, validate_location,
};
use crate::model::SsdpObservation;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(3);
/// A successful description is kept this long before it is fetched again.
pub const SUCCESS_TTL_MS: i64 = 6 * 60 * 60 * 1000;
/// A failure is remembered for a shorter time so a dead endpoint is not hammered.
pub const FAILURE_TTL_MS: i64 = 30 * 60 * 1000;
pub const MAX_FETCHES_PER_CYCLE: usize = 16;
pub const FETCH_CONCURRENCY: usize = 4;

/// One plain-HTTP exchange with a host on the LAN: connect (short timeout),
/// write `request`, read at most `MAX_RESPONSE_BYTES` plus headers, all under a
/// total timeout. No redirects, no proxies, no TLS, no environment. Returns the
/// raw response bytes, or `None` on any failure. The caller has already applied
/// the address policy.
pub async fn http_exchange(
    addr: SocketAddrV4,
    request: &[u8],
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Option<Vec<u8>> {
    let work = async {
        let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .ok()?
            .ok()?;
        stream.write_all(request).await.ok()?;
        // Cap everything we are willing to read (headers + body).
        let mut raw = Vec::new();
        let limit = (MAX_RESPONSE_BYTES + 20 * 1024) as u64;
        stream.take(limit).read_to_end(&mut raw).await.ok()?;
        Some(raw)
    };
    tokio::time::timeout(total_timeout, work)
        .await
        .ok()
        .flatten()
}

/// A fetched description: what it says about the device, and the raw WAN
/// counter service entry (not yet policy-checked) if it has one.
pub struct Fetched {
    pub info: UpnpInfo,
    pub igd: Option<IgdService>,
}

/// Fetch and parse the description at `addr` + `path`, applying no address
/// policy (callers go through `fetch_location`). `None` on any failure.
pub async fn fetch_full_at(
    addr: SocketAddrV4,
    path: &str,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Option<Fetched> {
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {}:{}\r\nUser-Agent: rhizomon\r\nAccept: text/xml\r\nConnection: close\r\n\r\n",
        addr.ip(),
        addr.port()
    );
    let raw = http_exchange(addr, request.as_bytes(), connect_timeout, total_timeout).await?;
    let body = parse_http_response(&raw)?;
    let info = parse_description(&body);
    let igd = parse_igd_service(&body);
    if info.is_none() && igd.is_none() {
        return None;
    }
    Some(Fetched {
        info: info.unwrap_or_default(),
        igd,
    })
}

/// Like `fetch_full_at` but only the descriptive fields.
pub async fn fetch_description_at(
    addr: SocketAddrV4,
    path: &str,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Option<UpnpInfo> {
    fetch_full_at(addr, path, connect_timeout, total_timeout)
        .await
        .map(|f| f.info)
}

/// The policy-checked entry point: `location` must be an `http://` IPv4 URL for
/// exactly `from`, an in-subnet scan target. The router's WAN counter endpoint,
/// if present, is resolved under the same policy and returned in `info.igd`.
pub async fn fetch_location(location: &str, from: Ipv4Addr, net: Ipv4Net) -> Option<UpnpInfo> {
    let target = validate_location(location, from, net)?;
    let f = fetch_full_at(
        SocketAddrV4::new(target.ip, target.port),
        &target.path,
        CONNECT_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await?;
    let mut info = f.info;
    info.igd = f.igd.and_then(|svc| resolve_control(&target, &svc, net));
    Some(info)
}

/// One LOCATION per host (the lexicographically first, so the choice is stable),
/// only for hosts in `allowed`.
pub fn choose_locations(
    ssdp: &[SsdpObservation],
    allowed: &dyn Fn(Ipv4Addr) -> bool,
) -> BTreeMap<Ipv4Addr, String> {
    let mut out: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
    for o in ssdp.iter().filter(|o| allowed(o.ip)) {
        let Some(loc) = o.hit.location.as_deref() else {
            continue;
        };
        out.entry(o.ip)
            .and_modify(|cur| {
                if loc < cur.as_str() {
                    *cur = loc.to_string();
                }
            })
            .or_insert_with(|| loc.to_string());
    }
    out
}

/// Of `candidates`, those not cached at `now`, at most `cap`, in order.
pub fn due<V: Clone>(
    cache: &super::ttlcache::TtlCache<Ipv4Addr, V>,
    candidates: impl IntoIterator<Item = Ipv4Addr>,
    now: i64,
    cap: usize,
) -> Vec<Ipv4Addr> {
    candidates
        .into_iter()
        .filter(|ip| cache.get(ip, now).is_none())
        .take(cap)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::ttlcache::TtlCache;
    use crate::model::SsdpHit;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    const XML: &str = "<root><device><friendlyName>Den TV</friendlyName><manufacturer>Acme</manufacturer><modelName>X1</modelName></device></root>";

    /// A one-shot-per-connection server that answers with `reply` bytes.
    async fn serve(reply: Vec<u8>) -> (SocketAddrV4, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                h.fetch_add(1, Ordering::SeqCst);
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(&reply).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        (addr, hits)
    }

    async fn fetch(addr: SocketAddrV4) -> Option<UpnpInfo> {
        fetch_description_at(
            addr,
            "/d.xml",
            Duration::from_millis(500),
            Duration::from_millis(800),
        )
        .await
    }

    #[tokio::test]
    async fn fetches_and_parses_a_description() {
        let (addr, _) = serve(format!("HTTP/1.0 200 OK\r\n\r\n{XML}").into_bytes()).await;
        let i = fetch(addr).await.unwrap();
        assert_eq!(i.friendly_name.as_deref(), Some("Den TV"));
        assert_eq!(i.model().as_deref(), Some("X1"));
    }

    #[tokio::test]
    async fn the_request_is_a_plain_http_10_get_with_the_validated_path() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let got = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            let _ = s
                .write_all(format!("HTTP/1.0 200 OK\r\n\r\n{XML}").as_bytes())
                .await;
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        assert!(fetch(addr).await.is_some());
        let req = got.await.unwrap();
        assert!(req.starts_with("GET /d.xml HTTP/1.0\r\n"), "{req}");
        assert!(req.contains(&format!("Host: {}:{}", addr.ip(), addr.port())));
        assert!(
            !req.to_ascii_lowercase().contains("cookie")
                && !req.to_ascii_lowercase().contains("authorization")
        );
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (addr, hits) =
            serve(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/x\r\n\r\n".to_vec()).await;
        assert_eq!(fetch(addr).await, None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "exactly one request, nothing chased"
        );
    }

    #[tokio::test]
    async fn oversized_responses_are_cut_off_and_rejected() {
        let mut big = b"HTTP/1.0 200 OK\r\n\r\n<root><device><friendlyName>x".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_BYTES * 2));
        big.extend(b"</friendlyName></device></root>");
        let (addr, _) = serve(big).await;
        assert_eq!(fetch(addr).await, None);
    }

    #[tokio::test]
    async fn a_server_that_never_answers_times_out() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let (_s, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let t = std::time::Instant::now();
        assert_eq!(fetch(addr).await, None);
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn a_refused_connection_is_none() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        drop(l);
        assert_eq!(fetch(addr).await, None);
    }

    #[tokio::test]
    async fn chunked_and_garbage_replies_are_handled() {
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{XML}\r\n0\r\n\r\n",
            XML.len()
        );
        let (addr, _) = serve(chunked.into_bytes()).await;
        assert!(fetch(addr).await.is_some());
        let (addr, _) = serve(b"\x00\x01\x02 not http".to_vec()).await;
        assert_eq!(fetch(addr).await, None);
    }

    #[tokio::test]
    async fn the_public_entry_point_refuses_anything_outside_the_policy_without_connecting() {
        let (addr, hits) = serve(format!("HTTP/1.0 200 OK\r\n\r\n{XML}").into_bytes()).await;
        let net: Ipv4Net = "127.0.0.0/8".parse().unwrap();
        // loopback is not a scan target, so even a perfectly formed URL is refused
        let url = format!("http://{}:{}/d.xml", addr.ip(), addr.port());
        assert_eq!(fetch_location(&url, *addr.ip(), net).await, None);
        assert_eq!(
            fetch_location(
                "http://192.168.0.9/x",
                "192.168.0.8".parse().unwrap(),
                "192.168.0.0/24".parse().unwrap()
            )
            .await,
            None
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "no connection may be attempted"
        );
    }

    fn obs(ip: &str, loc: Option<&str>) -> SsdpObservation {
        SsdpObservation {
            ip: ip.parse().unwrap(),
            hit: SsdpHit {
                location: loc.map(String::from),
                ..Default::default()
            },
        }
    }

    #[test]
    fn one_stable_location_per_allowed_host() {
        let v = vec![
            obs("192.168.0.82", Some("http://192.168.0.82:8008/b.xml")),
            obs("192.168.0.82", Some("http://192.168.0.82:8008/a.xml")),
            obs("192.168.0.82", None),
            obs("192.168.0.9", Some("http://192.168.0.9/x.xml")),
            obs("192.168.0.7", Some("http://192.168.0.7/x.xml")),
        ];
        let allowed = |ip: Ipv4Addr| ip != "192.168.0.7".parse::<Ipv4Addr>().unwrap();
        let m = choose_locations(&v, &allowed);
        assert_eq!(m.len(), 2);
        assert_eq!(
            m[&"192.168.0.82".parse().unwrap()],
            "http://192.168.0.82:8008/a.xml"
        );
    }

    #[test]
    fn due_skips_cached_hosts_and_respects_the_cap() {
        let mut c: TtlCache<Ipv4Addr, u8> = TtlCache::new(16);
        let ip = |n: u8| Ipv4Addr::new(10, 0, 0, n);
        c.put(ip(1), 0, 0, 1000);
        let d = due(&c, [ip(1), ip(2), ip(3), ip(4)], 500, 2);
        assert_eq!(d, vec![ip(2), ip(3)]);
        let d = due(&c, [ip(1), ip(2)], 2000, 10);
        assert_eq!(d, vec![ip(1), ip(2)], "expired entries are due again");
    }
}
