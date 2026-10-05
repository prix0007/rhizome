//! Per-OS facts, kept pure and parameterised by `Os` so that every OS's rules
//! are unit-tested on every machine (CI builds all three).
//!
//! Executables are only ever resolved from a fixed list of absolute paths
//! (never through `PATH`, which another user or a stray directory could
//! control) and are run with a minimal environment.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Mac,
    Linux,
    Windows,
}

impl Os {
    pub const fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::Mac
        } else if cfg!(windows) {
            Os::Windows
        } else {
            // Linux and the other Unixes share the Linux layout closely enough
            // for the paths below; anything missing is simply reported.
            Os::Linux
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Os::Mac => "macOS",
            Os::Linux => "Linux",
            Os::Windows => "Windows",
        }
    }
}

/// `%SystemRoot%` on Windows (read once from the process's own environment,
/// not from `PATH`), with the stock default if it is missing.
pub fn system_root() -> String {
    std::env::var("SystemRoot")
        .ok()
        .filter(|s| !s.is_empty() && Path::new(s).is_absolute())
        .unwrap_or_else(|| r"C:\Windows".to_string())
}

/// `<SystemRoot>\\System32\\<exe>`.
pub fn system32(system_root: &str, exe: &str) -> PathBuf {
    PathBuf::from(format!(
        r"{}\System32\{}",
        system_root.trim_end_matches('\\'),
        exe
    ))
}

/// Where the system `ping` may live.
pub fn ping_candidates(os: Os, system_root: &str) -> Vec<PathBuf> {
    match os {
        Os::Mac => vec!["/sbin/ping".into()],
        Os::Linux => ["/bin/ping", "/usr/bin/ping", "/sbin/ping", "/usr/sbin/ping"]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        Os::Windows => vec![system32(system_root, "PING.EXE")],
    }
}

/// Where `arp` may live. Linux reads `/proc/net/arp` instead and needs none.
pub fn arp_candidates(os: Os, system_root: &str) -> Vec<PathBuf> {
    match os {
        Os::Mac => vec!["/usr/sbin/arp".into()],
        Os::Linux => vec![],
        Os::Windows => vec![system32(system_root, "ARP.EXE")],
    }
}

/// Where `tcpdump` may live (capture is opt-in; Windows has none).
pub fn tcpdump_candidates(os: Os) -> Vec<PathBuf> {
    match os {
        Os::Mac => vec!["/usr/sbin/tcpdump".into()],
        Os::Linux => [
            "/usr/bin/tcpdump",
            "/usr/sbin/tcpdump",
            "/sbin/tcpdump",
            "/bin/tcpdump",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect(),
        Os::Windows => vec![],
    }
}

/// The first candidate that exists as a file.
pub fn first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.is_file()).cloned()
}

/// Arguments for one echo request to `ip`, waiting `timeout_ms` for the reply.
/// The address is a typed `Ipv4Addr`, never a string from the network.
pub fn ping_args(os: Os, ip: Ipv4Addr, timeout_ms: u32) -> Vec<String> {
    let ip = ip.to_string();
    match os {
        // macOS: -W is milliseconds.
        Os::Mac => vec![
            "-c".into(),
            "1".into(),
            "-W".into(),
            timeout_ms.to_string(),
            ip,
        ],
        // iputils and busybox: -W is whole seconds (at least 1).
        Os::Linux => vec![
            "-c".into(),
            "1".into(),
            "-W".into(),
            timeout_ms.div_ceil(1000).max(1).to_string(),
            ip,
        ],
        // Windows: -n count, -w milliseconds, -4 forces IPv4.
        Os::Windows => vec![
            "-4".into(),
            "-n".into(),
            "1".into(),
            "-w".into(),
            timeout_ms.to_string(),
            ip,
        ],
    }
}

/// The only environment a subprocess gets.
pub fn minimal_env(os: Os, system_root: &str) -> Vec<(String, String)> {
    match os {
        Os::Mac | Os::Linux => vec![("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into())],
        Os::Windows => vec![
            ("SystemRoot".into(), system_root.to_string()),
            (
                "PATH".into(),
                format!(r"{0}\System32;{0}", system_root.trim_end_matches('\\')),
            ),
        ],
    }
}

/// Whether unprivileged datagram ICMP sockets are worth trying on this OS.
/// (Windows has no equivalent without elevation; it uses `ping.exe`.)
pub fn dgram_icmp_supported(os: Os) -> bool {
    !matches!(os, Os::Windows)
}

/// Whether the reply TTL is available from the datagram ICMP socket. macOS
/// hands the IP header to the application; Linux strips it (the TTL would need
/// `IP_RECVTTL` ancillary data on a socket we do not own), so `os_hint` stays
/// empty there until the ping binary path is in use.
pub fn dgram_icmp_reports_ttl(os: Os) -> bool {
    matches!(os, Os::Mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> Ipv4Addr {
        "192.168.0.1".parse().unwrap()
    }

    #[test]
    fn every_executable_path_is_absolute_and_never_a_bare_name() {
        for os in [Os::Mac, Os::Linux, Os::Windows] {
            let all = [
                ping_candidates(os, r"C:\Windows"),
                arp_candidates(os, r"C:\Windows"),
                tcpdump_candidates(os),
            ]
            .concat();
            for p in all {
                let s = p.to_string_lossy().into_owned();
                let abs = s.starts_with('/')
                    || (s.len() > 2 && s.as_bytes()[1] == b':' && s.as_bytes()[2] == b'\\');
                assert!(abs, "{os:?}: {s} must be absolute");
            }
        }
    }

    #[test]
    fn per_os_candidates() {
        assert_eq!(ping_candidates(Os::Mac, "")[0], PathBuf::from("/sbin/ping"));
        assert!(ping_candidates(Os::Linux, "").contains(&PathBuf::from("/usr/bin/ping")));
        assert!(ping_candidates(Os::Linux, "").contains(&PathBuf::from("/bin/ping")));
        assert_eq!(
            ping_candidates(Os::Windows, r"C:\Windows")[0],
            PathBuf::from(r"C:\Windows\System32\PING.EXE")
        );
        assert_eq!(
            ping_candidates(Os::Windows, r"D:\WINNT\")[0],
            PathBuf::from(r"D:\WINNT\System32\PING.EXE")
        );
        assert!(
            arp_candidates(Os::Linux, "").is_empty(),
            "Linux reads /proc/net/arp"
        );
        assert_eq!(
            arp_candidates(Os::Mac, "")[0],
            PathBuf::from("/usr/sbin/arp")
        );
        assert!(tcpdump_candidates(Os::Windows).is_empty());
    }

    #[test]
    fn ping_arguments_per_os_use_the_right_timeout_unit() {
        assert_eq!(
            ping_args(Os::Mac, ip(), 500),
            ["-c", "1", "-W", "500", "192.168.0.1"]
        );
        assert_eq!(
            ping_args(Os::Linux, ip(), 500),
            ["-c", "1", "-W", "1", "192.168.0.1"],
            "seconds, at least 1"
        );
        assert_eq!(
            ping_args(Os::Linux, ip(), 2500),
            ["-c", "1", "-W", "3", "192.168.0.1"]
        );
        assert_eq!(
            ping_args(Os::Windows, ip(), 500),
            ["-4", "-n", "1", "-w", "500", "192.168.0.1"]
        );
    }

    #[test]
    fn the_subprocess_environment_is_minimal() {
        let unix = minimal_env(Os::Linux, "");
        assert_eq!(unix.len(), 1);
        assert_eq!(unix[0].0, "PATH");
        let w = minimal_env(Os::Windows, r"C:\Windows");
        assert!(
            w.iter()
                .any(|(k, v)| k == "SystemRoot" && v == r"C:\Windows")
        );
        assert!(
            w.iter().all(|(_, v)| !v.contains("Users")),
            "no user directories on PATH"
        );
    }

    #[test]
    fn datagram_icmp_facts() {
        assert!(dgram_icmp_supported(Os::Mac) && dgram_icmp_supported(Os::Linux));
        assert!(!dgram_icmp_supported(Os::Windows));
        assert!(dgram_icmp_reports_ttl(Os::Mac));
        assert!(!dgram_icmp_reports_ttl(Os::Linux));
    }

    #[test]
    fn first_existing_picks_only_real_files() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("tool");
        std::fs::write(&real, b"x").unwrap();
        let missing = dir.path().join("nope");
        assert_eq!(first_existing(&[missing.clone(), real.clone()]), Some(real));
        assert_eq!(first_existing(&[missing]), None);
        assert_eq!(
            first_existing(&[dir.path().to_path_buf()]),
            None,
            "a directory is not an executable"
        );
    }
}
