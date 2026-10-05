//! TCP connect probe for ARP-known hosts that ignore ICMP.
//! A refused connection proves the host is up just as well as an accepted one.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use ipnet::Ipv4Net;
use tokio::net::TcpStream;

use crate::net::subnet::is_scan_target;

pub const PORTS: [u16; 6] = [80, 443, 22, 445, 62078, 8080];
pub const TIMEOUT: Duration = Duration::from_millis(300);
const HOST_CONCURRENCY: usize = 32;

/// True if something answered at `addr` (accepted or actively refused).
pub async fn probe_one(addr: SocketAddr, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => e.kind() == ErrorKind::ConnectionRefused,
        Err(_) => false,
    }
}

async fn probe_host(ip: Ipv4Addr) -> bool {
    let mut attempts: FuturesUnordered<_> = PORTS
        .iter()
        .map(|p| probe_one(SocketAddr::from((ip, *p)), TIMEOUT))
        .collect();
    while let Some(alive) = attempts.next().await {
        if alive {
            return true;
        }
    }
    false
}

/// Probe `targets` (each must pass `is_scan_target`) and return the ones that answered.
pub async fn probe(net: Ipv4Net, targets: &[Ipv4Addr]) -> BTreeSet<Ipv4Addr> {
    futures_util::stream::iter(
        targets
            .iter()
            .copied()
            .filter(|ip| is_scan_target(*ip, net)),
    )
    .map(|ip| async move { (ip, probe_host(ip).await) })
    .buffer_unordered(HOST_CONCURRENCY)
    .filter_map(|(ip, alive)| async move { alive.then_some(ip) })
    .collect()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn accepted_connection_is_alive() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        assert!(probe_one(addr, Duration::from_millis(500)).await);
    }

    #[tokio::test]
    async fn refused_connection_counts_as_alive() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        assert!(probe_one(addr, Duration::from_millis(500)).await);
    }

    #[tokio::test]
    async fn non_target_addresses_are_never_probed() {
        let net: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        let r = probe(
            net,
            &[
                "127.0.0.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "192.168.0.255".parse().unwrap(),
            ],
        )
        .await;
        assert!(r.is_empty());
    }
}
