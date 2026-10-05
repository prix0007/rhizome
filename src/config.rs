//! CLI configuration with validation.

use std::path::PathBuf;

use clap::Parser;

pub const DEFAULT_PORT: u16 = 7878;
pub const MIN_INTERVAL_S: u64 = 10;

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(
    name = "rhizome",
    version,
    about = "Local, real-time 3D map of your LAN"
)]
pub struct Config {
    /// Port for the web UI (always bound to 127.0.0.1).
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
    /// Network interface to scan (default: the active en* interface).
    #[arg(long)]
    pub iface: Option<String>,
    /// Seconds between scans (minimum 10).
    #[arg(long, default_value_t = 30)]
    pub interval: u64,
    /// SQLite database path (default: ~/Library/Application Support/rhizome/rhizome.db).
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Do not TCP-probe ARP-known hosts that ignore ping.
    #[arg(long)]
    pub no_tcp_probe: bool,
    /// Maximum number of hosts to ping per scan.
    #[arg(long, default_value_t = 1024)]
    pub max_hosts: usize,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("--port must be between 1 and 65535")]
    Port,
    #[error("--interval must be at least {MIN_INTERVAL_S} seconds (got {0})")]
    Interval(u64),
    #[error("--max-hosts must be at least 1")]
    MaxHosts,
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::Port);
        }
        if self.interval < MIN_INTERVAL_S {
            return Err(ConfigError::Interval(self.interval));
        }
        if self.max_hosts == 0 {
            return Err(ConfigError::MaxHosts);
        }
        Ok(())
    }

    /// A device is offline after three missed intervals.
    pub fn offline_after_ms(&self) -> i64 {
        (self.interval as i64) * 3 * 1000
    }

    pub fn db_path(&self) -> Option<PathBuf> {
        self.db.clone().or_else(|| {
            directories::ProjectDirs::from("", "", "rhizome")
                .map(|d| d.data_dir().join("rhizome.db"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Config {
        let mut v = vec!["rhizome"];
        v.extend_from_slice(args);
        Config::try_parse_from(v).unwrap()
    }

    #[test]
    fn defaults() {
        let c = parse(&[]);
        assert_eq!(c.port, 7878);
        assert_eq!(c.interval, 30);
        assert_eq!(c.max_hosts, 1024);
        assert!(!c.no_tcp_probe);
        assert!(c.validate().is_ok());
        assert_eq!(c.offline_after_ms(), 90_000);
    }

    #[test]
    fn port_zero_is_rejected() {
        assert_eq!(parse(&["--port", "0"]).validate(), Err(ConfigError::Port));
    }

    #[test]
    fn port_out_of_range_fails_to_parse() {
        assert!(Config::try_parse_from(["rhizome", "--port", "70000"]).is_err());
    }

    #[test]
    fn interval_floor_is_enforced() {
        assert_eq!(
            parse(&["--interval", "9"]).validate(),
            Err(ConfigError::Interval(9))
        );
        assert!(parse(&["--interval", "10"]).validate().is_ok());
    }

    #[test]
    fn max_hosts_must_be_positive() {
        assert_eq!(
            parse(&["--max-hosts", "0"]).validate(),
            Err(ConfigError::MaxHosts)
        );
    }

    #[test]
    fn there_is_no_bind_address_flag() {
        assert!(Config::try_parse_from(["rhizome", "--bind", "0.0.0.0"]).is_err());
        assert!(Config::try_parse_from(["rhizome", "--host", "0.0.0.0"]).is_err());
    }

    #[test]
    fn explicit_db_path_wins() {
        let c = parse(&["--db", "/tmp/x.db"]);
        assert_eq!(c.db_path(), Some(PathBuf::from("/tmp/x.db")));
    }
}
