#![allow(dead_code)]
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use rhizomon::model::{Device, DeviceKind, MacAddr};
use rhizomon::state::hub::Hub;
use rhizomon::web::{AppState, router};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

pub const PORT: u16 = 7878;
pub const HOST: &str = "127.0.0.1:7878";

pub fn device(ip: &str, mac: &str, gw: bool) -> Device {
    let m: MacAddr = mac.parse().unwrap();
    Device {
        kind: if gw {
            DeviceKind::Gateway
        } else {
            DeviceKind::Unknown
        },
        is_gateway: gw,
        online: true,
        ..Device::new(m, ip.parse().unwrap(), 1)
    }
}

pub fn app_with(hub: Arc<Hub>) -> Router {
    router(AppState::new(hub, PORT, CancellationToken::new()))
}

pub fn seeded_hub() -> Arc<Hub> {
    let hub = Arc::new(Hub::new(16));
    let mut map = rhizomon::model::DeviceMap::new();
    for d in [
        device("192.168.0.1", "68:7f:f0:00:00:01", true),
        device("192.168.0.82", "2:0:0:0:0:62", false),
    ] {
        map.insert(d.id.clone(), d);
    }
    hub.seed(&map);
    hub
}

pub struct Resp {
    pub status: StatusCode,
    pub content_type: String,
    pub body: String,
    pub headers: axum::http::HeaderMap,
}

pub async fn send(app: Router, req: Request<Body>) -> Resp {
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        content_type,
        body: String::from_utf8_lossy(&body).into_owned(),
        headers,
    }
}

pub fn get_req(path: &str, host: Option<&str>, origin: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path);
    if let Some(h) = host {
        b = b.header(header::HOST, h);
    }
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    b.body(Body::empty()).unwrap()
}

pub async fn get(path: &str) -> Resp {
    send(app_with(seeded_hub()), get_req(path, Some(HOST), None)).await
}
