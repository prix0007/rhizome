//! HTTP surface: static UI plus JSON API. Always bound to 127.0.0.1.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, put};
use tokio_util::sync::CancellationToken;

use crate::state::hub::Hub;
use crate::store::Store;

pub mod api;
pub mod assets;
pub mod guard;
pub mod headers;
pub mod meta;

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<Hub>,
    pub port: u16,
    pub shutdown: CancellationToken,
    /// Where user metadata is persisted (none: kept in memory only).
    pub store: Option<Arc<Store>>,
    /// Serialises the read-modify-write-commit of `PUT .../meta`, so overlapping
    /// edits of different fields cannot revert each other.
    pub meta_lock: Arc<tokio::sync::Mutex<()>>,
    /// Live traffic measurements (`/api/traffic` and the SSE `traffic` event).
    pub traffic: Arc<crate::traffic::TrafficHub>,
}

impl AppState {
    pub fn new(hub: Arc<Hub>, port: u16, shutdown: CancellationToken) -> Self {
        Self {
            hub,
            port,
            shutdown,
            store: None,
            meta_lock: Arc::new(tokio::sync::Mutex::new(())),
            traffic: Arc::new(crate::traffic::TrafficHub::new(false)),
        }
    }

    pub fn with_traffic(mut self, traffic: Arc<crate::traffic::TrafficHub>) -> Self {
        self.traffic = traffic;
        self
    }

    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/devices", get(api::devices))
        .route("/api/status", get(api::status))
        .route("/api/events", get(api::events))
        .route("/api/traffic", get(api::traffic))
        .route(
            "/api/devices/{id}/meta",
            put(api::put_meta)
                .layer(DefaultBodyLimit::max(meta::MAX_BODY_BYTES))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    guard::mutation_guard,
                )),
        )
        .fallback(assets::serve)
        .layer(middleware::from_fn_with_state(state.clone(), guard::guard))
        // Outermost, so rejected requests also get the security headers.
        .layer(middleware::from_fn(headers::security_headers))
        .with_state(state)
}

/// The one URL we print and document. Never `localhost`: another local user
/// could squat `[::1]:<port>` and browsers resolve `localhost` to `::1` first.
pub fn listen_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// The only address the server ever binds to.
pub fn loopback_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_url_is_the_numeric_loopback_only() {
        assert_eq!(listen_url(7878), "http://127.0.0.1:7878");
        assert!(!listen_url(1).contains("localhost"));
        assert!(!listen_url(1).contains("[::1]"));
    }
}
