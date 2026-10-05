//! HTTP surface: static UI plus JSON API. Always bound to 127.0.0.1.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use tokio_util::sync::CancellationToken;

use crate::state::hub::Hub;

pub mod api;
pub mod assets;
pub mod guard;
pub mod headers;

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<Hub>,
    pub port: u16,
    pub shutdown: CancellationToken,
}

impl AppState {
    pub fn new(hub: Arc<Hub>, port: u16, shutdown: CancellationToken) -> Self {
        Self {
            hub,
            port,
            shutdown,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/devices", get(api::devices))
        .route("/api/status", get(api::status))
        .route("/api/events", get(api::events))
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
