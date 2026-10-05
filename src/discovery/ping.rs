//! ICMP sweep, per OS:
//!
//! * macOS and Linux: unprivileged `SOCK_DGRAM` ICMP first. On Linux that needs
//!   `net.ipv4.ping_group_range` to include the user's group; when the socket
//!   cannot be opened the system `ping` binary is used instead.
//! * Windows: `ping.exe` under `%SystemRoot%\System32` (no elevation needed;
//!   gives RTT and TTL). Raw sockets would need administrator rights.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub const EPERM: i32 = 1;
pub const EACCES: i32 = 13;
pub const EHOSTUNREACH: i32 = 65;
pub const EPROTONOSUPPORT: i32 = 43;
pub const EAFNOSUPPORT: i32 = 47;
// Linux numbers for the same conditions.
pub const EPROTONOSUPPORT_LINUX: i32 = 93;
pub const EAFNOSUPPORT_LINUX: i32 = 97;
// Winsock equivalents.
pub const WSAEACCES: i32 = 10013;
pub const WSAEPROTONOSUPPORT: i32 = 10043;

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
    /// Cannot open an unprivileged ICMP socket: use the system ping binary.
    FallbackToPingBinary,
    Ignore,
}

pub fn classify_failure(f: PingFailure) -> Verdict {
    match (f.phase, f.errno) {
        (
            Phase::Socket,
            Some(
                EPERM
                | EACCES
                | EPROTONOSUPPORT
                | EAFNOSUPPORT
                | EPROTONOSUPPORT_LINUX
                | EAFNOSUPPORT_LINUX
                | WSAEACCES
                | WSAEPROTONOSUPPORT,
            ),
        ) => Verdict::FallbackToPingBinary,
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
            Self::PingBinary => "ping-binary",
        }
    }
}

#[derive(Debug, Default)]
pub struct SweepResult {
    pub alive: BTreeSet<Ipv4Addr>,
    /// Round-trip time (and, when the OS hands us the IP header, the reply TTL)
    /// of each answering host.
    pub replies: std::collections::BTreeMap<Ipv4Addr, PingReply>,
    pub failures: Vec<PingFailure>,
    /// Set when the sweep could not run at all (e.g. no ping binary was found).
    pub unavailable: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingReply {
    pub rtt_ms: f64,
    pub ttl: Option<u8>,
}

/// Coarse OS family from a reply TTL. On a LAN there are no hops to subtract,
/// so the TTL is the sender's initial value: 64 (Linux, Unix, macOS, Android,
/// iOS), 128 (Windows) or 255 (routers and much embedded gear).
pub fn os_hint_from_ttl(ttl: u8) -> Option<&'static str> {
    match ttl {
        0 => None,
        1..=64 => Some("Linux/Unix/macOS-like"),
        65..=128 => Some("Windows-like"),
        129..=255 => Some("network gear/embedded"),
    }
}

/// Average round-trip from `ping -q` output
/// (`round-trip min/avg/max/stddev = 0.8/0.9/1.0/0.0 ms`).
pub fn parse_ping_rtt(stdout: &str) -> Option<f64> {
    let line = stdout.lines().find(|l| l.contains("min/avg/max"))?;
    let values = line.split('=').nth(1)?.split_whitespace().next()?;
    let parts: Vec<&str> = values.split('/').collect();
    if parts.len() < 3 {
        return None;
    }
    let avg: f64 = parts[1].parse().ok()?;
    (avg.is_finite() && avg >= 0.0).then_some(avg)
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
    fn parses_replies_from_every_pings_output() {
        let mac = "PING 192.168.0.1 (192.168.0.1): 56 data bytes\n64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=3.123 ms\n\n--- 192.168.0.1 ping statistics ---\n";
        assert_eq!(
            parse_ping_output(mac),
            Some(PingReply {
                rtt_ms: 3.123,
                ttl: Some(64)
            })
        );
        let linux = "PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.\n64 bytes from 10.0.0.2: icmp_seq=1 ttl=63 time=0.345 ms\n";
        assert_eq!(
            parse_ping_output(linux),
            Some(PingReply {
                rtt_ms: 0.345,
                ttl: Some(63)
            })
        );
        let busybox = "64 bytes from 10.0.0.2: seq=0 ttl=64 time=0.5 ms\n";
        assert_eq!(parse_ping_output(busybox).unwrap().ttl, Some(64));
        let win = "\r\nPinging 192.168.0.1 with 32 bytes of data:\r\nReply from 192.168.0.1: bytes=32 time=3ms TTL=128\r\n";
        assert_eq!(
            parse_ping_output(win),
            Some(PingReply {
                rtt_ms: 3.0,
                ttl: Some(128)
            })
        );
        let fast = "Reply from 192.168.0.1: bytes=32 time<1ms TTL=64\r\n";
        assert_eq!(
            parse_ping_output(fast),
            Some(PingReply {
                rtt_ms: 0.5,
                ttl: Some(64)
            })
        );
    }

    #[test]
    fn localised_windows_output_still_parses() {
        let de = "Antwort von 192.168.0.1: Bytes=32 Zeit=4ms TTL=64\r\n";
        assert_eq!(
            parse_ping_output(de),
            Some(PingReply {
                rtt_ms: 4.0,
                ttl: Some(64)
            })
        );
        let fr = "R\u{e9}ponse de 192.168.0.1\u{a0}: octets=32 temps<1ms TTL=128\r\n";
        assert_eq!(parse_ping_output(fr).unwrap().ttl, Some(128));
        let es = "Respuesta desde 192.168.0.1: bytes=32 tiempo=2ms TTL=64\r\n";
        assert_eq!(parse_ping_output(es).unwrap().rtt_ms, 2.0);
    }

    #[test]
    fn unreachable_and_timeout_output_is_not_a_reply() {
        for out in [
            "",
            "Request timeout for icmp_seq 0\n",
            "Reply from 192.168.0.5: Destination host unreachable.\r\n",
            "From 10.0.0.1 icmp_seq=1 Destination Host Unreachable\n",
            "Request timed out.\r\n",
            "ping: sendto: No route to host\n",
            "time=5 ms but no ttl\n",
            "ttl=64 but no time\n",
            "ttl=abc time=5 ms\n",
        ] {
            assert_eq!(parse_ping_output(out), None, "{out:?}");
        }
    }

    #[test]
    fn ttl_maps_to_a_coarse_os_family() {
        for (ttl, want) in [
            (64, Some("Linux/Unix/macOS-like")),
            (63, Some("Linux/Unix/macOS-like")),
            (1, Some("Linux/Unix/macOS-like")),
            (65, Some("Windows-like")),
            (128, Some("Windows-like")),
            (129, Some("network gear/embedded")),
            (255, Some("network gear/embedded")),
            (0, None),
        ] {
            assert_eq!(os_hint_from_ttl(ttl), want, "ttl {ttl}");
        }
    }

    #[test]
    fn ping_binary_rtt_is_parsed_from_the_summary_line() {
        let out = "PING 192.168.0.1 (192.168.0.1): 56 data bytes\n\n--- 192.168.0.1 ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 1.234/1.500/1.766/0.000 ms\n";
        assert_eq!(parse_ping_rtt(out), Some(1.5));
        assert_eq!(
            parse_ping_rtt("round-trip min/avg/max/stddev = 0.8/0.9/1.0/0.0 ms"),
            Some(0.9)
        );
        for bad in [
            "",
            "no summary here",
            "round-trip min/avg/max/stddev = a/b/c/d ms",
            "round-trip min/avg/max/stddev = 1/2 ms",
            "round-trip min/avg/max = -1/NaN/3 ms",
        ] {
            assert_eq!(parse_ping_rtt(bad), None, "{bad:?}");
        }
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
    fn linux_and_windows_socket_failures_also_fall_back_to_the_ping_binary() {
        for errno in [
            EACCES,
            EPERM,
            EPROTONOSUPPORT_LINUX,
            EAFNOSUPPORT_LINUX,
            WSAEACCES,
            WSAEPROTONOSUPPORT,
        ] {
            assert_eq!(
                classify_failure(f(Phase::Socket, Some(errno), false)),
                Verdict::FallbackToPingBinary,
                "errno {errno}"
            );
        }
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
use crate::platform::{Os, first_existing, ping_args, ping_candidates, system_root};

pub const CONCURRENCY: usize = 64;

/// Read one echo reply out of the system `ping` output, structurally so that
/// localised Windows text still works: the reply line carries `ttl=<n>` (any
/// case) and a time as `=<n>ms` or `<<n>ms`. A line without both (for example
/// "Reply from x: Destination host unreachable.") is not a reply. `time<1ms`
/// is reported as 0.5 ms.
pub fn parse_ping_output(out: &str) -> Option<PingReply> {
    for line in out.lines() {
        let lower = line.to_lowercase();
        let Some(at) = lower.find("ttl=") else {
            continue;
        };
        let digits: String = lower[at + 4..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let Ok(ttl) = digits.parse::<u8>() else {
            continue;
        };
        if let Some(rtt_ms) = find_time_ms(&lower) {
            return Some(PingReply {
                rtt_ms,
                ttl: Some(ttl),
            });
        }
    }
    None
}

/// The first `=<n>ms` / `<<n>ms` (optionally with spaces) in a line.
fn find_time_ms(line: &str) -> Option<f64> {
    for (i, c) in line.char_indices() {
        if c != '=' && c != '<' {
            continue;
        }
        let rest = line[i + 1..].trim_start();
        let num: String = rest
            .chars()
            .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
            .collect();
        let after = rest[num.len()..].trim_start();
        if after.starts_with("ms")
            && let Ok(v) = num.parse::<f64>()
        {
            return Some(if c == '<' { v * 0.5 } else { v });
        }
    }
    None
}

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
    let results: Vec<(Ipv4Addr, Result<PingReply, PingFailure>)> = futures_util::stream::iter(
        targets
            .iter()
            .copied()
            .filter(|ip| is_scan_target(*ip, net)),
    )
    .map(|ip| async move {
        let mut p = client.pinger(IpAddr::V4(ip), PingIdentifier(IDENT)).await;
        p.timeout(timeout);
        let r = match p.ping(PingSequence(0), &payload).await {
            Ok((packet, rtt)) => Ok(PingReply {
                rtt_ms: rtt.as_secs_f64() * 1000.0,
                // On macOS the DGRAM socket hands us the IP header, so the TTL is there.
                ttl: match packet {
                    surge_ping::IcmpPacket::V4(v4) => v4.get_ttl(),
                    _ => None,
                },
            }),
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
            Ok(reply) => {
                out.alive.insert(ip);
                out.replies.insert(ip, reply);
            }
            Err(f) if f.errno.is_some() => out.failures.push(f),
            Err(_) => {}
        }
    }
    Ok(out)
}

/// The system `ping` binary, one process per host (absolute path from a fixed
/// list, no shell, minimal environment, typed address). Gives RTT and, because it
/// prints the reply line, the TTL as well.
pub async fn sweep_binary(
    net: Ipv4Net,
    targets: &[Ipv4Addr],
    gateway: Option<Ipv4Addr>,
) -> SweepResult {
    let os = Os::current();
    let Some(exe) = first_existing(&ping_candidates(os, &system_root())) else {
        return SweepResult {
            unavailable: Some(format!(
                "no ping program found in the standard locations on {}; host discovery by ping is unavailable",
                os.name()
            )),
            ..SweepResult::default()
        };
    };
    let exe = &exe;
    let results: Vec<(Ipv4Addr, Option<PingReply>, Option<PingFailure>)> =
        futures_util::stream::iter(
            targets
                .iter()
                .copied()
                .filter(|ip| is_scan_target(*ip, net)),
        )
        .map(|ip| async move {
            let args = ping_args(os, ip, 500);
            match run_full(exe, &args, Duration::from_secs(3)).await {
                Ok(o) => {
                    // A reply is recognised by its content, not the exit status:
                    // ping.exe exits 0 even for "Destination host unreachable".
                    match parse_ping_output(&String::from_utf8_lossy(&o.stdout)) {
                        Some(r) => (ip, Some(r), None),
                        None => (
                            ip,
                            None,
                            binary_failure(ip, gateway, &String::from_utf8_lossy(&o.stderr)),
                        ),
                    }
                }
                Err(_) => (ip, None, None),
            }
        })
        .buffer_unordered(32)
        .collect()
        .await;
    let mut out = SweepResult::default();
    for (ip, reply, failure) in results {
        if let Some(r) = reply {
            out.alive.insert(ip);
            out.replies.insert(ip, r);
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
