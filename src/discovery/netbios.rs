//! NetBIOS node status (NBSTAT) over UDP 137, unicast to in-subnet hosts.
//!
//! Pure packet building and a bounds-checked parser; sockets are below.

use crate::enrich::sanitize::sanitize;

/// A node-status query for the wildcard name `*`.
pub fn build_nbstat_query(id: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(50);
    m.extend(id.to_be_bytes());
    m.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // flags 0, one question
    m.push(0x20);
    // first-level encoding of the wildcard name "*" padded with NULs: "CK" + 30 x "A"
    m.extend(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    m.push(0);
    m.extend([0, 0x21, 0, 1]); // NBSTAT, IN
    m
}

/// Parse a node-status reply to the query with transaction id `id`. Returns
/// the machine's workstation (suffix 0x00) unique name, sanitised, or `None`.
pub fn parse_nbstat_response(msg: &[u8], id: u16) -> Option<String> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id {
        return None;
    }
    if msg[2] & 0x80 == 0 || msg[3] & 0x0f != 0 {
        return None; // not a response, or an error rcode
    }
    if u16::from_be_bytes([msg[6], msg[7]]) < 1 {
        return None;
    }
    // Skip the owner name of the first answer: a pointer, or a label sequence.
    let mut pos = 12usize;
    loop {
        let l = *msg.get(pos)? as usize;
        if l == 0 {
            pos += 1;
            break;
        }
        if l & 0xc0 == 0xc0 {
            pos += 2;
            break;
        }
        if l > 63 {
            return None;
        }
        pos = pos.checked_add(1 + l)?;
    }
    let fixed = msg.get(pos..pos.checked_add(10)?)?;
    if u16::from_be_bytes([fixed[0], fixed[1]]) != 0x21 {
        return None;
    }
    let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    let rdata = msg.get(pos + 10..(pos + 10).checked_add(rdlen)?)?;
    let count = *rdata.first()? as usize;
    for i in 0..count {
        let entry = rdata.get(1 + i * 18..1 + (i + 1) * 18)?;
        let suffix = entry[15];
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        let group = flags & 0x8000 != 0;
        if suffix == 0x00 && !group {
            let name = sanitize(&String::from_utf8_lossy(&entry[..15]));
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// I/O: unicast node-status queries to in-subnet hosts.
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::dns_ptr::random_ids;

pub const NETBIOS_PORT: u16 = 137;

/// Query each `(address, port)` and collect workstation names until `window`
/// has passed. A reply only counts if it comes from the address it was asked of
/// and echoes that query's transaction id. No address policy here: callers
/// pass in-subnet scan targets (with `NETBIOS_PORT`).
pub async fn probe(
    bind_ip: Ipv4Addr,
    targets: &[SocketAddrV4],
    window: Duration,
) -> std::io::Result<BTreeMap<Ipv4Addr, String>> {
    let mut found = BTreeMap::new();
    if targets.is_empty() {
        return Ok(found);
    }
    let sock = UdpSocket::bind((bind_ip, 0)).await?;
    let ids = random_ids(targets.len());
    let by_id: BTreeMap<u16, SocketAddrV4> =
        ids.iter().copied().zip(targets.iter().copied()).collect();
    for (id, t) in &by_id {
        sock.send_to(&build_nbstat_query(*id), *t).await?;
    }
    let deadline = Instant::now() + window;
    let mut buf = [0u8; 1500];
    while found.len() < targets.len() {
        let Ok(r) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await else {
            break;
        };
        let Ok((n, SocketAddr::V4(from))) = r else {
            continue;
        };
        if n < 2 {
            continue;
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let Some(asked) = by_id.get(&id) else {
            continue;
        };
        if from.ip() != asked.ip() || from.port() != asked.port() {
            continue; // not from the address *and port* we asked
        }
        if let Some(name) = parse_nbstat_response(&buf[..n], id) {
            found.insert(*asked.ip(), name);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_wildcard() -> Vec<u8> {
        let mut v = vec![0x20, b'C', b'K'];
        v.extend(std::iter::repeat_n(b'A', 30));
        v.push(0);
        v
    }

    fn entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut n = name.as_bytes().to_vec();
        n.resize(15, b' ');
        n.push(suffix);
        n.extend(flags.to_be_bytes());
        n
    }

    fn reply(id: u16, entries: &[Vec<u8>], declared: Option<u8>) -> Vec<u8> {
        let mut m = vec![];
        m.extend(id.to_be_bytes());
        m.extend([0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        m.extend(encoded_wildcard());
        m.extend([0, 0x21, 0, 1, 0, 0, 0, 0]);
        let mut rd = vec![declared.unwrap_or(entries.len() as u8)];
        for e in entries {
            rd.extend(e);
        }
        rd.extend([0u8; 46]); // statistics
        m.extend((rd.len() as u16).to_be_bytes());
        m.extend(rd);
        m
    }

    #[test]
    fn the_query_bytes_are_exact() {
        let q = build_nbstat_query(0x1234);
        let mut want = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        want.extend(encoded_wildcard());
        want.extend([0, 0x21, 0, 1]);
        assert_eq!(q.len(), 50);
        assert_eq!(q, want);
    }

    #[test]
    fn picks_the_workstation_unique_name() {
        let m = reply(
            9,
            &[
                entry("WORKGROUP", 0x00, 0x8400),
                entry("DESKTOP-ABC", 0x00, 0x0400),
                entry("DESKTOP-ABC", 0x20, 0x0400),
            ],
            None,
        );
        assert_eq!(parse_nbstat_response(&m, 9).as_deref(), Some("DESKTOP-ABC"));
    }

    #[test]
    fn group_names_and_other_suffixes_do_not_count() {
        let only_group = reply(
            9,
            &[
                entry("WORKGROUP", 0x00, 0x8400),
                entry("DESKTOP", 0x20, 0x0400),
                entry("__MSBROWSE__", 0x01, 0x8400),
            ],
            None,
        );
        assert_eq!(parse_nbstat_response(&only_group, 9), None);
    }

    #[test]
    fn wrong_id_and_non_responses_are_rejected() {
        let m = reply(9, &[entry("PC", 0x00, 0x0400)], None);
        assert!(parse_nbstat_response(&m, 10).is_none());
        let mut query = m.clone();
        query[2] = 0x00; // QR=0
        assert!(parse_nbstat_response(&query, 9).is_none());
        let mut err = m.clone();
        err[3] = 0x03; // rcode
        assert!(parse_nbstat_response(&err, 9).is_none());
    }

    #[test]
    fn names_are_trimmed_and_sanitised() {
        let m = reply(9, &[entry("PC\u{7}1", 0x00, 0x0400)], None);
        // bytes >= 0x80 or controls must not leak through
        assert_eq!(parse_nbstat_response(&m, 9).as_deref(), Some("PC1"));
        let mut e = entry("", 0x00, 0x0400);
        e[..15].copy_from_slice(b"                ".get(..15).unwrap());
        assert_eq!(
            parse_nbstat_response(&reply(9, &[e], None), 9),
            None,
            "blank names are useless"
        );
    }

    #[test]
    fn a_lying_name_count_or_truncation_is_safe() {
        let m = reply(9, &[entry("PC", 0x00, 0x0400)], Some(250));
        let _ = parse_nbstat_response(&m, 9);
        let ok = reply(9, &[entry("PC", 0x00, 0x0400)], None);
        for n in 0..ok.len() {
            let _ = parse_nbstat_response(&ok[..n], 9);
        }
        for g in [&b""[..], &[0u8; 12], &[0xff; 80]] {
            assert!(parse_nbstat_response(g, 9).is_none());
        }
    }

    #[test]
    fn accepts_a_compressed_answer_name() {
        let mut m = vec![];
        m.extend(9u16.to_be_bytes());
        m.extend([0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        m.extend([0xc0, 0x0c, 0, 0x21, 0, 1, 0, 0, 0, 0]); // pointer owner (to offset 12, past the header)
        let mut rd = vec![1];
        rd.extend(entry("PC-1", 0x00, 0x0400));
        rd.extend([0u8; 46]);
        m.extend((rd.len() as u16).to_be_bytes());
        m.extend(rd);
        assert_eq!(parse_nbstat_response(&m, 9).as_deref(), Some("PC-1"));
    }

    #[tokio::test]
    async fn probe_collects_names_and_ignores_wrong_ids() {
        use tokio::net::UdpSocket;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = match server.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                assert_eq!(n, 50, "the query is a 50-byte NBSTAT");
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let wrong = reply(id.wrapping_add(1), &[entry("SPOOF", 0x00, 0x0400)], None);
                let _ = server.send_to(&wrong, from).await;
                let right = reply(id, &[entry("DESKTOP-1", 0x00, 0x0400)], None);
                let _ = server.send_to(&right, from).await;
            }
        });
        let got = probe(Ipv4Addr::LOCALHOST, &[saddr], Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(
            got.get(&Ipv4Addr::LOCALHOST).map(String::as_str),
            Some("DESKTOP-1")
        );
    }

    #[tokio::test]
    async fn a_reply_from_a_different_port_of_the_asked_host_is_ignored() {
        use tokio::net::UdpSocket;
        let asked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // same host, wrong port
        let aaddr = match asked.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((_, from)) = asked.recv_from(&mut buf).await {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let r = reply(id, &[entry("IMPOSTOR", 0x00, 0x0400)], None);
                let _ = other.send_to(&r, from).await; // answers from another port
            }
        });
        let got = probe(Ipv4Addr::LOCALHOST, &[aaddr], Duration::from_millis(400))
            .await
            .unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    #[tokio::test]
    async fn probe_with_no_targets_or_a_silent_host_yields_nothing() {
        assert!(
            probe(Ipv4Addr::LOCALHOST, &[], Duration::from_millis(50))
                .await
                .unwrap()
                .is_empty()
        );
        let silent = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
        let got = probe(Ipv4Addr::LOCALHOST, &[silent], Duration::from_millis(150))
            .await
            .unwrap_or_default();
        assert!(got.is_empty());
    }
}
