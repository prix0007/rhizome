use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use rhizome::config::Config;
use rhizome::net::iface::select_now;
use rhizome::net::iface_select::SelectError;
use rhizome::scanner::{LiveCollector, LiveOptions, Scanner, ScannerConfig};
use rhizome::state::hub::Hub;
use rhizome::store::Store;
use rhizome::traffic::{IgdSlot, TrafficHub, TrafficOptions};
use rhizome::web::{AppState, listen_url, loopback_addr, router};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cfg = Config::parse();
    cfg.validate()?;
    // A bad --iface is a usage error. No interface *yet* (e.g. no network at
    // launch) is not: the scanner re-selects every cycle and will pick one up.
    let sel = match select_now(cfg.iface.as_deref()) {
        Ok(sel) => Some(sel),
        Err(SelectError::NoCandidate) => {
            tracing::warn!("no usable network interface yet; will keep looking every scan");
            None
        }
        Err(e) => return Err(e.into()),
    };

    let addr = loopback_addr(cfg.port);
    let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| {
        format!(
            "cannot listen on {addr}: is another instance (or program) using port {}? try --port",
            cfg.port
        )
    })?;

    let hub = Arc::new(Hub::new(256));
    let traffic = Arc::new(TrafficHub::new(cfg.capture));
    let igd = Arc::new(IgdSlot::default());
    let shutdown = CancellationToken::new();
    let store = match cfg.db_path() {
        Some(path) => match Store::open(&path) {
            Ok(s) => {
                tracing::info!("history database: {}", path.display());
                Some(Arc::new(s))
            }
            Err(e) => {
                tracing::warn!("history disabled, cannot open {}: {e}", path.display());
                None
            }
        },
        None => None,
    };
    let mut scanner = Scanner::new(
        Box::new(LiveCollector::new(LiveOptions {
            iface_override: cfg.iface.clone(),
            max_hosts: cfg.max_hosts,
            tcp_probe: !cfg.no_tcp_probe,
            netbios: !cfg.no_netbios,
            dns: !cfg.no_dns,
            upnp: !cfg.no_upnp,
            igd: Some(igd.clone()),
            fresh_window: Duration::from_secs(cfg.interval + 10),
        })),
        hub.clone(),
        ScannerConfig {
            interval_s: cfg.interval,
            offline_after_ms: cfg.offline_after_ms(),
            new_window_ms: 10 * 60 * 1000,
            max_devices: rhizome::state::merge::DEFAULT_MAX_DEVICES,
        },
    );
    if let Some(store) = &store {
        scanner = scanner.with_store(store.clone());
    }
    scanner = scanner.with_traffic(traffic.clone());
    let scan_task = tokio::spawn(scanner.run(shutdown.clone()));
    // Host throughput, link info, WAN counters and (opt-in) packet-flow summaries.
    tokio::spawn(rhizome::traffic::run(
        traffic.clone(),
        hub.clone(),
        TrafficOptions {
            capture: cfg.capture,
            wan: !cfg.no_upnp,
            igd,
        },
        shutdown.clone(),
    ));

    match &sel {
        Some(sel) => tracing::info!(
            "listening on {} iface={} net={} gw={}",
            listen_url(cfg.port),
            sel.name,
            sel.net,
            sel.gateway_ip
                .map(|g| g.to_string())
                .unwrap_or_else(|| "unknown".into())
        ),
        None => tracing::info!("listening on {} iface=none", listen_url(cfg.port)),
    }

    // The same store backs the scanner's history and the PUT /api/devices/{id}/meta endpoint.
    let mut state = AppState::new(hub, cfg.port, shutdown.clone()).with_traffic(traffic);
    if let Some(store) = store {
        state = state.with_store(store);
    }
    let app = router(state);
    let serve = axum::serve(listener, app).with_graceful_shutdown({
        let s = shutdown.clone();
        async move { s.cancelled().await }
    });
    let sig = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        sig.cancel();
    });
    let served = tokio::time::timeout(Duration::from_secs(u64::MAX / 4), serve);
    tokio::pin!(served);
    // Wait for the server; once shutdown is requested give it a few seconds, then exit anyway.
    tokio::select! {
        r = &mut served => { r.context("server timed out")??; }
        _ = async { shutdown.cancelled().await; tokio::time::sleep(Duration::from_secs(3)).await } => {
            tracing::warn!("forcing exit after 3s");
        }
    }
    let _ = scan_task.await;
    Ok(())
}
