//! I/O adapter: run `/usr/sbin/arp -an` and parse its output.
//! `-n` keeps it from doing reverse DNS lookups.

use std::time::Duration;

use super::arp_parse::{ArpEntry, parse_arp, parse_proc_net_arp, parse_windows_arp};
use super::cmd::{CmdError, MAX_OUTPUT, run_capped};
use crate::net::iface_select::Selected;
use crate::platform::{Os, arp_candidates, first_existing, system_root};

/// Turn a finished `arp -an` into entries. A non-zero exit is an error, and
/// output that hit the size cap loses its (possibly torn) last line.
pub fn arp_result(success: bool, stdout: &[u8], iface: &str) -> Result<Vec<ArpEntry>, CmdError> {
    if !success {
        return Err(CmdError::Failed(
            "/usr/sbin/arp".into(),
            "exited with a non-zero status".into(),
        ));
    }
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    if stdout.len() as u64 >= MAX_OUTPUT {
        // The read stopped at the cap: the last line may be cut in half.
        if let Some(cut) = text.rfind('\n') {
            text.truncate(cut + 1);
        }
    }
    Ok(parse_arp(&text, Some(iface)))
}

/// Read this machine's neighbour (ARP) table for the selected interface.
///
/// * macOS: `arp -an` (absolute path, minimal environment).
/// * Linux: `/proc/net/arp` directly. No subprocess, no dependency on `ip`
///   being installed (minimal containers lack it), and the format is a stable
///   kernel interface.
/// * Windows: `arp -a` under `%SystemRoot%\System32`, parsed by structure.
pub async fn read_arp(sel: &Selected) -> Result<Vec<ArpEntry>, CmdError> {
    match Os::current() {
        Os::Linux => {
            let text = tokio::fs::read_to_string("/proc/net/arp")
                .await
                .map_err(|e| CmdError::Failed("/proc/net/arp".into(), e.to_string()))?;
            Ok(parse_proc_net_arp(&text, Some(&sel.name)))
        }
        Os::Mac => {
            let exe = first_existing(&arp_candidates(Os::Mac, ""))
                .ok_or_else(|| CmdError::Failed("arp".into(), "/usr/sbin/arp not found".into()))?;
            let (ok, out) = run_capped(exe, &["-an".to_string()], Duration::from_secs(5)).await?;
            arp_result(ok, &out, &sel.name)
        }
        Os::Windows => {
            let exe =
                first_existing(&arp_candidates(Os::Windows, &system_root())).ok_or_else(|| {
                    CmdError::Failed("arp".into(), "ARP.EXE not found in System32".into())
                })?;
            let (ok, out) = run_capped(exe, &["-a".to_string()], Duration::from_secs(5)).await?;
            if !ok {
                return Err(CmdError::Failed(
                    "arp".into(),
                    "exited with a non-zero status".into(),
                ));
            }
            Ok(parse_windows_arp(
                &String::from_utf8_lossy(&out),
                Some(sel.ip),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "? (192.168.0.1) at 68:7f:f0:00:00:01 on en0 ifscope [ethernet]\n";

    #[test]
    fn success_parses_entries_for_the_interface() {
        let r = arp_result(true, LINE.as_bytes(), "en0").unwrap();
        assert_eq!(r.len(), 1);
        assert!(arp_result(true, LINE.as_bytes(), "en5").unwrap().is_empty());
    }

    #[test]
    fn nonzero_exit_is_an_error_even_with_output() {
        let e = arp_result(false, LINE.as_bytes(), "en0").unwrap_err();
        assert!(matches!(e, CmdError::Failed(..)));
        assert!(arp_result(false, b"", "en0").is_err());
    }

    #[test]
    fn truncated_output_drops_the_torn_last_line() {
        let mut bytes = Vec::new();
        while (bytes.len() as u64) < MAX_OUTPUT {
            bytes.extend_from_slice(LINE.as_bytes());
        }
        bytes.truncate(MAX_OUTPUT as usize); // the reader stopped at the cap, mid-line
        let torn = bytes.last() != Some(&b'\n');
        let r = arp_result(true, &bytes, "en0").unwrap();
        assert!(!r.is_empty());
        assert!(
            r.iter()
                .all(|e| e.mac.is_some() && e.ip.to_string() == "192.168.0.1")
        );
        if torn {
            let complete = bytes.iter().filter(|b| **b == b'\n').count();
            assert_eq!(r.len(), complete, "the torn trailing line is not parsed");
        }
    }
}
