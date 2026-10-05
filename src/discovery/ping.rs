//! ICMP sweep. Unprivileged `SOCK_DGRAM` ICMP first, `/sbin/ping` as fallback.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub const EPERM: i32 = 1;
pub const EACCES: i32 = 13;
pub const EHOSTUNREACH: i32 = 65;
pub const EPROTONOSUPPORT: i32 = 43;
pub const EAFNOSUPPORT: i32 = 47;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Socket,
    Send,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PingFailure {
    pub phase: Phase,
    pub errno: Option<i32>,
    pub target_is_gateway: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// macOS Local Network privacy is probably denying LAN traffic.
    LocalNetworkDenied,
    /// Cannot open an unprivileged ICMP socket: use `/sbin/ping`.
    FallbackToPingBinary,
    Ignore,
}

pub fn classify_failure(f: PingFailure) -> Verdict {
    match (f.phase, f.errno) {
        (Phase::Socket, Some(EPERM | EACCES | EPROTONOSUPPORT | EAFNOSUPPORT)) => {
            Verdict::FallbackToPingBinary
        }
        (Phase::Send, Some(EHOSTUNREACH)) if f.target_is_gateway => Verdict::LocalNetworkDenied,
        _ => Verdict::Ignore,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingMethod {
    SurgeDgram,
    PingBinary,
}

impl PingMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SurgeDgram => "icmp-dgram",
            Self::PingBinary => "/sbin/ping",
        }
    }
}

#[derive(Debug, Default)]
pub struct SweepResult {
    pub alive: BTreeSet<Ipv4Addr>,
    pub failures: Vec<PingFailure>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(phase: Phase, errno: Option<i32>, gw: bool) -> PingFailure {
        PingFailure {
            phase,
            errno,
            target_is_gateway: gw,
        }
    }

    #[test]
    fn ehostunreach_sending_to_gateway_means_local_network_denied() {
        assert_eq!(
            classify_failure(f(Phase::Send, Some(EHOSTUNREACH), true)),
            Verdict::LocalNetworkDenied
        );
    }

    #[test]
    fn ehostunreach_to_ordinary_host_is_ignored() {
        assert_eq!(
            classify_failure(f(Phase::Send, Some(EHOSTUNREACH), false)),
            Verdict::Ignore
        );
    }

    #[test]
    fn socket_creation_eperm_or_eacces_falls_back_to_ping_binary() {
        assert_eq!(
            classify_failure(f(Phase::Socket, Some(EPERM), false)),
            Verdict::FallbackToPingBinary
        );
        assert_eq!(
            classify_failure(f(Phase::Socket, Some(EACCES), false)),
            Verdict::FallbackToPingBinary
        );
        assert_eq!(
            classify_failure(f(Phase::Socket, Some(EPROTONOSUPPORT), false)),
            Verdict::FallbackToPingBinary
        );
    }

    #[test]
    fn eperm_on_send_is_not_a_fallback_trigger() {
        assert_eq!(
            classify_failure(f(Phase::Send, Some(EPERM), true)),
            Verdict::Ignore
        );
    }

    #[test]
    fn ping_binary_no_route_to_gateway_is_a_local_network_denial() {
        let gw: Ipv4Addr = "192.168.0.1".parse().unwrap();
        let f = binary_failure(gw, Some(gw), "ping: sendto: No route to host\n").unwrap();
        assert_eq!(
            f,
            PingFailure {
                phase: Phase::Send,
                errno: Some(EHOSTUNREACH),
                target_is_gateway: true
            }
        );
        assert_eq!(classify_failure(f), Verdict::LocalNetworkDenied);
    }

    #[test]
    fn ping_binary_failures_for_other_reasons_or_hosts_are_not_denials() {
        let gw: Ipv4Addr = "192.168.0.1".parse().unwrap();
        let other: Ipv4Addr = "192.168.0.9".parse().unwrap();
        let f = binary_failure(other, Some(gw), "ping: sendto: No route to host").unwrap();
        assert_eq!(classify_failure(f), Verdict::Ignore);
        assert!(binary_failure(gw, Some(gw), "").is_none());
        assert!(binary_failure(gw, Some(gw), "Request timeout for icmp_seq 0").is_none());
    }

    #[test]
    fn unknown_errors_are_ignored() {
        assert_eq!(
            classify_failure(f(Phase::Send, None, true)),
            Verdict::Ignore
        );
        assert_eq!(
            classify_failure(f(Phase::Socket, None, false)),
            Verdict::Ignore
        );
        assert_eq!(
            classify_failure(f(Phase::Socket, Some(9999), false)),
            Verdict::Ignore
        );
    }
}

// ---------------------------------------------------------------------------
// I/O below this line
// ---------------------------------------------------------------------------

use std::net::IpAddr;
use std::time::Duration;

use futures_util::StreamExt;
use ipnet::Ipv4Net;
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};

use super::cmd::run_full;
use crate::net::subnet::is_scan_target;

pub const CONCURRENCY: usize = 64;

/// Map a failed `/sbin/ping` run to a failure the classifier understands:
/// "No route to host" is macOS's Local Network denial signature.
pub fn binary_failure(
    ip: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    stderr: &str,
) -> Option<PingFailure> {
    stderr.contains("No route to host").then_some(PingFailure {
        phase: Phase::Send,
        errno: Some(EHOSTUNREACH),
        target_is_gateway: Some(ip) == gateway,
    })
}
const IDENT: u16 = 0x7268;

fn os_errno(e: &SurgeError) -> Option<i32> {
    match e {
        SurgeError::IOError(io) => io.raw_os_error(),
        _ => None,
    }
}

/// Unprivileged ICMP sweep over a `SOCK_DGRAM` socket (no root needed on macOS).
/// `Err` means the socket could not even be created.
pub async fn sweep_dgram(
    net: Ipv4Net,
    targets: &[Ipv4Addr],
    gateway: Option<Ipv4Addr>,
    timeout: Duration,
) -> Result<SweepResult, PingFailure> {
    let config = Config::builder()
        .kind(ICMP::V4)
        .sock_type_hint(socket2::Type::DGRAM)
        .build();
    let client = Client::new(&config).map_err(|e| PingFailure {
        phase: Phase::Socket,
        errno: e.raw_os_error(),
        target_is_gateway: false,
    })?;
    let payload = [0u8; 16];
    let client = &client;
    let results: Vec<(Ipv4Addr, Result<(), PingFailure>)> = futures_util::stream::iter(
        targets
            .iter()
            .copied()
            .filter(|ip| is_scan_target(*ip, net)),
    )
    .map(|ip| async move {
        let mut p = client.pinger(IpAddr::V4(ip), PingIdentifier(IDENT)).await;
        p.timeout(timeout);
        let r = match p.ping(PingSequence(0), &payload).await {
            Ok(_) => Ok(()),
            Err(e @ SurgeError::IOError(_)) => Err(PingFailure {
                phase: Phase::Send,
                errno: os_errno(&e),
                target_is_gateway: Some(ip) == gateway,
            }),
            Err(_) => Err(PingFailure {
                phase: Phase::Send,
                errno: None,
                target_is_gateway: false,
            }),
        };
        (ip, r)
    })
    .buffer_unordered(CONCURRENCY)
    .collect()
    .await;
    let mut out = SweepResult::default();
    for (ip, r) in results {
        match r {
            Ok(()) => {
                out.alive.insert(ip);
            }
            Err(f) if f.errno.is_some() => out.failures.push(f),
            Err(_) => {}
        }
    }
    Ok(out)
}

/// Fallback: `/sbin/ping -c1 -W 500 -q <ip>` (absolute path, no shell, typed address).
pub async fn sweep_binary(
    net: Ipv4Net,
    targets: &[Ipv4Addr],
    gateway: Option<Ipv4Addr>,
) -> SweepResult {
    let results: Vec<(Ipv4Addr, bool, Option<PingFailure>)> = futures_util::stream::iter(
        targets
            .iter()
            .copied()
            .filter(|ip| is_scan_target(*ip, net)),
    )
    .map(|ip| async move {
        let args = [
            "-c".to_string(),
            "1".into(),
            "-W".into(),
            "500".into(),
            "-q".into(),
            ip.to_string(),
        ];
        match run_full("/sbin/ping", &args, Duration::from_secs(3)).await {
            Ok(o) if o.success => (ip, true, None),
            Ok(o) => (
                ip,
                false,
                binary_failure(ip, gateway, &String::from_utf8_lossy(&o.stderr)),
            ),
            Err(_) => (ip, false, None),
        }
    })
    .buffer_unordered(32)
    .collect()
    .await;
    let mut out = SweepResult::default();
    for (ip, ok, failure) in results {
        if ok {
            out.alive.insert(ip);
        }
        out.failures.extend(failure);
    }
    out
}

#[cfg(test)]
mod live {
    use super::*;

    #[tokio::test]
    #[ignore = "needs a real network stack (loopback ICMP)"]
    async fn dgram_ping_to_loopback_works_without_root() {
        let config = Config::builder()
            .kind(ICMP::V4)
            .sock_type_hint(socket2::Type::DGRAM)
            .build();
        let client = Client::new(&config).expect("unprivileged DGRAM ICMP socket");
        let mut p = client
            .pinger(IpAddr::V4(Ipv4Addr::LOCALHOST), PingIdentifier(IDENT))
            .await;
        p.timeout(Duration::from_secs(2));
        let r = p.ping(PingSequence(0), &[0u8; 16]).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    #[ignore = "needs the real LAN: set RHIZOME_TEST_NET and RHIZOME_TEST_GW"]
    async fn dgram_sweep_finds_the_gateway() {
        let net: Ipv4Net = std::env::var("RHIZOME_TEST_NET").unwrap().parse().unwrap();
        let gw: Ipv4Addr = std::env::var("RHIZOME_TEST_GW").unwrap().parse().unwrap();
        let t =
            crate::net::subnet::enumerate_targets(net, Ipv4Addr::new(0, 0, 0, 0), Some(gw), 1024);
        let start = std::time::Instant::now();
        let r = sweep_dgram(net, &t, Some(gw), Duration::from_millis(1000))
            .await
            .unwrap();
        eprintln!(
            "DGRAM sweep: {} targets in {:?}; alive={:?}; failures={}",
            t.len(),
            start.elapsed(),
            r.alive,
            r.failures.len()
        );
        assert!(r.alive.contains(&gw));
    }

    #[tokio::test]
    #[ignore = "needs the real LAN: set RHIZOME_TEST_NET and RHIZOME_TEST_GW"]
    async fn binary_sweep_finds_the_gateway() {
        let net: Ipv4Net = std::env::var("RHIZOME_TEST_NET").unwrap().parse().unwrap();
        let gw: Ipv4Addr = std::env::var("RHIZOME_TEST_GW").unwrap().parse().unwrap();
        let t =
            crate::net::subnet::enumerate_targets(net, Ipv4Addr::new(0, 0, 0, 0), Some(gw), 1024);
        let start = std::time::Instant::now();
        let r = sweep_binary(net, &t, Some(gw)).await;
        eprintln!(
            "ping(8) sweep: {} targets in {:?}; alive={:?}",
            t.len(),
            start.elapsed(),
            r.alive
        );
        assert!(r.alive.contains(&gw));
    }
}
