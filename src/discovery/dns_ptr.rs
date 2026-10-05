//! Reverse (PTR) lookups sent only to the gateway's DNS on UDP 53.
//!
//! The query and the strict, bounds-checked response parser are pure; the
//! socket code is below. The system resolver is never used, so a lookup can
//! never leave the LAN.

use std::net::Ipv4Addr;

pub const MAX_NAME_LEN: usize = 253;
/// Upper bound on distinct transaction ids.
pub const MAX_IDS: usize = 65_535;

/// `5.0.168.192.in-addr.arpa`
pub fn arpa_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// A standard recursive PTR/IN query for `ip`.
pub fn build_ptr_query(id: u16, ip: Ipv4Addr) -> Vec<u8> {
    let mut m = Vec::with_capacity(48);
    m.extend(id.to_be_bytes());
    // Standard query with RD=0: the gateway answers from its own lease/hosts
    // tables and must not forward our LAN addresses to an upstream resolver.
    m.extend([0x00, 0x00]);
    m.extend([0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    for label in arpa_name(ip).split('.') {
        m.push(label.len() as u8);
        m.extend(label.as_bytes());
    }
    m.push(0);
    m.extend([0, 12, 0, 1]); // PTR, IN
    m
}

/// Parse a reply to a query we sent for `ip` with transaction id `id`.
/// Returns the first usable PTR name (sanitised, no trailing dot) or `None`:
/// wrong id, not a response, error rcode, question mismatch, malformed or
/// looping compression, over-long names, and answers that merely echo the
/// address back are all rejected.
pub fn parse_ptr_response(msg: &[u8], id: u16, ip: Ipv4Addr) -> Option<String> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None; // not a response, or an error rcode
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    if qd != 1 {
        return None;
    }
    // The question must be the one we asked.
    let (qname, mut pos) = read_name(msg, 12)?;
    if !qname.eq_ignore_ascii_case(&arpa_name(ip)) {
        return None;
    }
    pos = pos.checked_add(4)?; // qtype + qclass
    if pos > msg.len() {
        return None;
    }
    for _ in 0..an.min(32) {
        let (_, after_owner) = read_name(msg, pos)?;
        let fixed = msg.get(after_owner..after_owner.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata = after_owner.checked_add(10)?;
        let end = rdata.checked_add(rdlen)?;
        if end > msg.len() {
            return None;
        }
        if rtype == 12 && rclass == 1 {
            let (name, _) = read_name(msg, rdata)?;
            if let Some(clean) = usable_ptr_name(&name, ip) {
                return Some(clean);
            }
        }
        pos = end;
    }
    None
}

/// Decode a (possibly compressed) domain name at `start`. Returns the dotted
/// name and the offset just past it in the *original* position (not following
/// pointers). Bounded: at most 16 pointer jumps, labels <= 63, name <= 253.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut end_after_first_pointer: Option<usize> = None;
    let mut jumps = 0;
    let mut name = String::new();
    loop {
        let len = *msg.get(pos)? as usize;
        match len {
            0 => {
                let next = end_after_first_pointer.unwrap_or(pos + 1);
                return Some((name, next));
            }
            l if l & 0xc0 == 0xc0 => {
                let low = *msg.get(pos + 1)? as usize;
                let target = ((l & 0x3f) << 8) | low;
                jumps += 1;
                if jumps > 16 || target >= msg.len() {
                    return None;
                }
                end_after_first_pointer.get_or_insert(pos + 2);
                pos = target;
            }
            l if l > 63 => return None, // reserved label types / over-long labels
            l => {
                let label = msg.get(pos + 1..pos + 1 + l)?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label));
                if name.len() > MAX_NAME_LEN {
                    return None;
                }
                pos += 1 + l;
            }
        }
    }
}

/// Sanitise and filter a PTR target; `None` for names that tell us nothing.
fn usable_ptr_name(raw: &str, ip: Ipv4Addr) -> Option<String> {
    let name = crate::enrich::sanitize::sanitize(raw.trim_end_matches('.'));
    let lower = name.to_ascii_lowercase();
    let o = ip.octets();
    let dotted = format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]);
    let dashed = format!("{}-{}-{}-{}", o[0], o[1], o[2], o[3]);
    if name.is_empty()
        || lower.ends_with(".in-addr.arpa")
        || lower == dotted
        || lower.starts_with(&format!("{dashed}."))
        || lower == dashed
    {
        return None;
    }
    Some(name)
}

// ---------------------------------------------------------------------------
// I/O: ask one DNS server (the gateway) over a connected UDP socket.
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

/// Unique, unpredictable 16-bit transaction ids (from the OS RNG; falls back to
/// the std hasher's per-process random keys if `/dev/urandom` cannot be read).
pub fn random_ids(n: usize) -> Vec<u16> {
    use std::io::Read;
    // Only 65536 distinct ids exist; asking for more must not loop forever.
    let n = n.min(MAX_IDS);
    let mut raw = vec![0u8; n.saturating_mul(2).max(2)];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .is_ok();
    if !ok {
        use std::hash::{BuildHasher, Hasher};
        let state = std::collections::hash_map::RandomState::new();
        for (i, b) in raw.iter_mut().enumerate() {
            let mut h = state.build_hasher();
            h.write_usize(i);
            *b = h.finish() as u8;
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    let mut bump = 0u16;
    while out.len() < n {
        let base = u16::from_be_bytes([raw[(i * 2) % raw.len()], raw[(i * 2 + 1) % raw.len()]]);
        let id = base.wrapping_add(bump);
        if seen.insert(id) {
            out.push(id);
        }
        i += 1;
        if i >= n {
            bump = bump.wrapping_add(1);
        }
    }
    out
}

/// Send one PTR query per address to `server` and collect usable answers until
/// `window` has passed. The socket is `connect()`ed, so the OS drops datagrams
/// from any other source; ids and the echoed question are checked on top.
/// No address policy here: callers restrict `server` and `ips` to the subnet.
pub async fn lookup_ptrs(
    bind_ip: Ipv4Addr,
    server: SocketAddrV4,
    ips: &[Ipv4Addr],
    window: Duration,
) -> std::io::Result<BTreeMap<Ipv4Addr, String>> {
    let mut found = BTreeMap::new();
    if ips.is_empty() {
        return Ok(found);
    }
    let sock = UdpSocket::bind((bind_ip, 0)).await?;
    sock.connect(server).await?;
    let ids = random_ids(ips.len());
    let by_id: BTreeMap<u16, Ipv4Addr> = ids.iter().copied().zip(ips.iter().copied()).collect();
    for (id, ip) in &by_id {
        sock.send(&build_ptr_query(*id, *ip)).await?;
    }
    let deadline = Instant::now() + window;
    let mut buf = [0u8; 1500];
    while found.len() < ips.len() {
        let Ok(r) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await else {
            break;
        };
        let n = match r {
            Ok(n) => n,
            // Windows: an earlier ICMP port-unreachable surfaces as ConnectionReset.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(_) => break,
        };
        if n < 2 {
            continue;
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let Some(ip) = by_id.get(&id) else { continue };
        if let Some(name) = parse_ptr_response(&buf[..n], id, *ip) {
            found.insert(*ip, name);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn enc_name(name: &str) -> Vec<u8> {
        let mut v = vec![];
        for l in name.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v
    }

    /// Header + question for `ip`, then raw answer bytes.
    fn response(id: u16, flags: u16, qip: Ipv4Addr, ancount: u16, answers: &[u8]) -> Vec<u8> {
        let mut m = vec![];
        m.extend(id.to_be_bytes());
        m.extend(flags.to_be_bytes());
        m.extend([0, 1]);
        m.extend(ancount.to_be_bytes());
        m.extend([0, 0, 0, 0]);
        m.extend(enc_name(&arpa_name(qip)));
        m.extend([0, 12, 0, 1]);
        m.extend(answers);
        m
    }

    /// An answer whose owner is a pointer to the question name (offset 12).
    fn ptr_answer(target: &[u8]) -> Vec<u8> {
        let mut a = vec![0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60];
        a.extend((target.len() as u16).to_be_bytes());
        a.extend(target);
        a
    }

    const OK: u16 = 0x8180;

    #[test]
    fn arpa_name_is_reversed() {
        assert_eq!(arpa_name(ip("192.168.0.5")), "5.0.168.192.in-addr.arpa");
    }

    #[test]
    fn the_query_bytes_are_exact() {
        let q = build_ptr_query(0x1234, ip("192.168.0.5"));
        let mut want = vec![0x12, 0x34, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        want.extend(enc_name("5.0.168.192.in-addr.arpa"));
        want.extend([0, 12, 0, 1]);
        assert_eq!(q, want);
    }

    #[test]
    fn the_query_never_asks_for_recursion_so_the_gateway_cannot_forward_lan_addresses() {
        for last in [1u8, 5, 254] {
            let q = build_ptr_query(0xbeef, Ipv4Addr::new(192, 168, 0, last));
            let flags = u16::from_be_bytes([q[2], q[3]]);
            assert_eq!(flags & 0x0100, 0, "RD must be 0");
            assert_eq!(flags, 0, "a plain non-recursive standard query");
        }
    }

    #[test]
    fn parses_a_simple_answer() {
        let m = response(
            7,
            OK,
            ip("192.168.0.5"),
            1,
            &ptr_answer(&enc_name("iphone.lan")),
        );
        assert_eq!(
            parse_ptr_response(&m, 7, ip("192.168.0.5")).as_deref(),
            Some("iphone.lan")
        );
    }

    #[test]
    fn follows_a_compression_pointer_inside_the_rdata() {
        // rdata: label "host" then a pointer to "in-addr.arpa" inside the question (offset of "in-addr")
        let q = enc_name(&arpa_name(ip("192.168.0.5")));
        let off = 12 + q.len() - (1 + 7 + 1 + 4 + 1); // start of the "in-addr" label
        let mut rd = vec![4];
        rd.extend(b"host");
        rd.extend([0xc0, off as u8]);
        let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&rd));
        // "host.in-addr.arpa" is just the address form of nonsense: it ends in in-addr.arpa so it is dropped
        assert_eq!(parse_ptr_response(&m, 7, ip("192.168.0.5")), None);
    }

    #[test]
    fn rejects_the_wrong_id_non_responses_and_error_codes() {
        let good = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&enc_name("a.lan")));
        assert!(parse_ptr_response(&good, 8, ip("192.168.0.5")).is_none());
        let query_flag = response(
            7,
            0x0100,
            ip("192.168.0.5"),
            1,
            &ptr_answer(&enc_name("a.lan")),
        );
        assert!(parse_ptr_response(&query_flag, 7, ip("192.168.0.5")).is_none());
        let nxdomain = response(7, 0x8183, ip("192.168.0.5"), 0, &[]);
        assert!(parse_ptr_response(&nxdomain, 7, ip("192.168.0.5")).is_none());
        let servfail = response(
            7,
            0x8182,
            ip("192.168.0.5"),
            1,
            &ptr_answer(&enc_name("a.lan")),
        );
        assert!(parse_ptr_response(&servfail, 7, ip("192.168.0.5")).is_none());
    }

    #[test]
    fn rejects_an_answer_to_a_different_question() {
        let m = response(
            7,
            OK,
            ip("192.168.0.99"),
            1,
            &ptr_answer(&enc_name("a.lan")),
        );
        assert!(parse_ptr_response(&m, 7, ip("192.168.0.5")).is_none());
    }

    #[test]
    fn answers_that_just_echo_the_address_are_dropped() {
        for echo in [
            "5.0.168.192.in-addr.arpa",
            "192.168.0.5",
            "192-168-0-5.lan.in-addr.arpa",
            "x.IN-ADDR.ARPA",
        ] {
            let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&enc_name(echo)));
            assert_eq!(parse_ptr_response(&m, 7, ip("192.168.0.5")), None, "{echo}");
        }
    }

    #[test]
    fn skips_non_ptr_answers_and_takes_the_next_usable_one() {
        let mut a = vec![0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]; // an A record
        a.extend(ptr_answer(&enc_name("printer.lan.")));
        let m = response(7, OK, ip("192.168.0.5"), 2, &a);
        assert_eq!(
            parse_ptr_response(&m, 7, ip("192.168.0.5")).as_deref(),
            Some("printer.lan")
        );
    }

    #[test]
    fn compression_loops_and_bad_pointers_are_rejected() {
        // rdata is a pointer to itself
        let q_len = enc_name(&arpa_name(ip("192.168.0.5"))).len();
        let rdata_off = 12 + q_len + 4 + 12; // after question, owner ptr(2)+type/class/ttl(8)+rdlen(2)
        let looped = vec![0xc0, rdata_off as u8];
        let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&looped));
        assert!(parse_ptr_response(&m, 7, ip("192.168.0.5")).is_none());
        // pointer past the end of the packet
        let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&[0xc0, 0xff]));
        assert!(parse_ptr_response(&m, 7, ip("192.168.0.5")).is_none());
        // two pointers pointing at each other
        let a_off = rdata_off;
        let b_off = rdata_off + 2;
        let mut rd = vec![0xc0, b_off as u8];
        rd.extend([0xc0, a_off as u8]);
        let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&rd));
        assert!(parse_ptr_response(&m, 7, ip("192.168.0.5")).is_none());
    }

    #[test]
    fn over_long_names_and_labels_are_rejected() {
        let long_label = {
            let mut v = vec![64];
            v.extend(std::iter::repeat_n(b'a', 64));
            v.push(0);
            v
        };
        let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&long_label));
        assert!(
            parse_ptr_response(&m, 7, ip("192.168.0.5")).is_none(),
            "label over 63"
        );
        let mut many = vec![];
        for _ in 0..40 {
            many.push(10);
            many.extend(std::iter::repeat_n(b'b', 10));
        }
        many.push(0);
        let m = response(7, OK, ip("192.168.0.5"), 1, &ptr_answer(&many));
        assert!(
            parse_ptr_response(&m, 7, ip("192.168.0.5")).is_none(),
            "name over 253"
        );
    }

    #[test]
    fn names_are_sanitised() {
        let m = response(
            7,
            OK,
            ip("192.168.0.5"),
            1,
            &ptr_answer(&enc_name("ev\u{202e}il\u{1b}[0m.lan")),
        );
        assert_eq!(
            parse_ptr_response(&m, 7, ip("192.168.0.5")).as_deref(),
            Some("evil[0m.lan")
        );
    }

    #[test]
    fn truncated_and_garbage_packets_never_panic() {
        let m = response(
            7,
            OK,
            ip("192.168.0.5"),
            1,
            &ptr_answer(&enc_name("host.lan")),
        );
        for n in 0..m.len() {
            let _ = parse_ptr_response(&m[..n], 7, ip("192.168.0.5"));
        }
        let lying = response(
            7,
            OK,
            ip("192.168.0.5"),
            60000,
            &ptr_answer(&enc_name("host.lan")),
        );
        let _ = parse_ptr_response(&lying, 7, ip("192.168.0.5"));
        for g in [&b""[..], &[0u8; 12], &[0xff; 64]] {
            assert!(parse_ptr_response(g, 7, ip("192.168.0.5")).is_none());
        }
    }

    #[tokio::test]
    async fn lookup_asks_the_server_and_collects_matching_answers_only() {
        use tokio::net::UdpSocket;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = match server.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let asked = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let a2 = asked.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                // recover the address from the question: labels are the reversed octets
                let q = &buf[12..n];
                let mut o = vec![];
                let mut p = 0;
                for _ in 0..4 {
                    let l = q[p] as usize;
                    o.push(
                        std::str::from_utf8(&q[p + 1..p + 1 + l])
                            .unwrap()
                            .parse::<u8>()
                            .unwrap(),
                    );
                    p += 1 + l;
                }
                let qip = Ipv4Addr::new(o[3], o[2], o[1], o[0]);
                a2.lock().unwrap().push(qip);
                if qip.octets()[3] == 9 {
                    continue; // this one never answers
                }
                // first a reply with the wrong id, then the right one
                let wrong = response(
                    id.wrapping_add(1),
                    OK,
                    qip,
                    1,
                    &ptr_answer(&enc_name("spoof.lan")),
                );
                let _ = server.send_to(&wrong, from).await;
                let right = response(
                    id,
                    OK,
                    qip,
                    1,
                    &ptr_answer(&enc_name(&format!("host{}.lan", qip.octets()[3]))),
                );
                let _ = server.send_to(&right, from).await;
            }
        });
        let ips = [ip("192.168.0.5"), ip("192.168.0.6"), ip("192.168.0.9")];
        let got = lookup_ptrs(Ipv4Addr::LOCALHOST, saddr, &ips, Duration::from_millis(600))
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[&ip("192.168.0.5")], "host5.lan");
        assert_eq!(got[&ip("192.168.0.6")], "host6.lan");
        assert_eq!(
            asked.lock().unwrap().len(),
            3,
            "one query per address, nothing more"
        );
    }

    #[tokio::test]
    async fn lookup_with_no_addresses_sends_nothing_and_a_silent_server_just_yields_nothing() {
        let dead = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
        assert!(
            lookup_ptrs(Ipv4Addr::LOCALHOST, dead, &[], Duration::from_millis(50))
                .await
                .unwrap()
                .is_empty()
        );
        let got = lookup_ptrs(
            Ipv4Addr::LOCALHOST,
            dead,
            &[ip("192.168.0.5")],
            Duration::from_millis(100),
        )
        .await
        .unwrap_or_default();
        assert!(got.is_empty());
    }

    #[test]
    fn random_ids_cannot_loop_forever_for_huge_requests() {
        let t = std::time::Instant::now();
        let ids = random_ids(1_000_000);
        assert_eq!(ids.len(), MAX_IDS);
        let set: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(set.len(), MAX_IDS);
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(random_ids(0).is_empty());
    }

    #[test]
    fn random_ids_are_unique() {
        for n in [1, 2, 64, 500] {
            let ids = random_ids(n);
            assert_eq!(ids.len(), n);
            let set: std::collections::BTreeSet<_> = ids.iter().collect();
            assert_eq!(set.len(), n);
        }
        assert_ne!(random_ids(8), random_ids(8), "unpredictable between calls");
    }
}
