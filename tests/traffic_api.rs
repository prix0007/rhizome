//! `GET /api/traffic` and the SSE `traffic` event: the contract shape, guards, and publishing.

mod common;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use common::*;
use http_body_util::BodyExt;
use rhizomon::state::hub::Hub;
use rhizomon::traffic::{DeviceTraffic, Sample, TrafficHub, WanTraffic};
use rhizomon::web::{AppState, router};
use tokio_util::sync::CancellationToken;

fn app(traffic: Arc<TrafficHub>) -> axum::Router {
    router(AppState::new(seeded_hub(), PORT, CancellationToken::new()).with_traffic(traffic))
}

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let r = send(app, get_req(path, Some(HOST), None)).await;
    let v = serde_json::from_str(&r.body).unwrap_or(serde_json::Value::Null);
    (r.status, v)
}

#[tokio::test]
async fn before_the_first_sample_the_contract_shape_is_returned_with_nulls() {
    let (status, v) = get_json(app(Arc::new(TrafficHub::new(false))), "/api/traffic").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["ts"].is_number());
    for k in ["iface", "rx_bps", "tx_bps"] {
        assert!(v["host"].get(k).is_some_and(|x| x.is_null()), "host.{k}");
    }
    for k in [
        "kind",
        "rate_mbps",
        "rssi_dbm",
        "noise_dbm",
        "channel",
        "phy",
    ] {
        assert!(
            v["host"]["link"].get(k).is_some_and(|x| x.is_null()),
            "host.link.{k}"
        );
    }
    assert!(v["wan"].is_null());
    assert_eq!(v["devices"], serde_json::json!({}));
    assert_eq!(v["capture"]["enabled"], false);
    assert_eq!(v["capture"]["available"], false);
    assert_eq!(v["capture"]["flows"], serde_json::json!([]));
    assert!(
        v["capture"]["reason"].is_string(),
        "off: says how to turn it on"
    );
}

#[tokio::test]
async fn a_published_sample_is_what_the_endpoint_returns() {
    let t = Arc::new(TrafficHub::new(true));
    let mut s = Sample::empty(true, 1_700_000_000_000);
    s.host.iface = Some("en8".into());
    s.host.rx_bps = Some(1_500_000);
    s.host.tx_bps = Some(250_000);
    s.host.link.kind = Some("ethernet".into());
    s.host.link.rate_mbps = Some(1000.0);
    s.wan = Some(WanTraffic {
        rx_bps: 9_000_000,
        tx_bps: 800_000,
        source: "upnp-igd",
    });
    s.devices.insert(
        "02:21:49:00:00:82".into(),
        DeviceTraffic {
            loss_pct: Some(0.0),
            jitter_ms: Some(1.2),
            rx_bps: Some(10),
            tx_bps: Some(20),
            measured: true,
        },
    );
    t.publish(s);
    let (_, v) = get_json(app(t), "/api/traffic").await;
    assert_eq!(v["ts"], 1_700_000_000_000i64);
    assert_eq!(v["host"]["iface"], "en8");
    assert_eq!(v["host"]["rx_bps"], 1_500_000);
    assert_eq!(v["host"]["link"]["kind"], "ethernet");
    assert_eq!(v["wan"]["source"], "upnp-igd");
    assert_eq!(v["wan"]["rx_bps"], 9_000_000);
    let d = &v["devices"]["02:21:49:00:00:82"];
    assert_eq!(
        (
            d["loss_pct"].as_f64(),
            d["jitter_ms"].as_f64(),
            d["measured"].as_bool()
        ),
        (Some(0.0), Some(1.2), Some(true))
    );
    assert_eq!(d["rx_bps"], 10);
}

#[tokio::test]
async fn the_traffic_route_has_the_same_guards_and_headers_as_the_other_api_routes() {
    let t = Arc::new(TrafficHub::new(false));
    for (host, origin) in [
        (Some("evil.com"), None),
        (None, None),
        (Some(HOST), Some("http://evil.com")),
    ] {
        let r = send(app(t.clone()), get_req("/api/traffic", host, origin)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{host:?} {origin:?}");
    }
    let r = send(app(t), get_req("/api/traffic", Some(HOST), None)).await;
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    assert!(r.headers.get("content-security-policy").is_some());
    assert!(r.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn traffic_is_read_only() {
    for m in [
        axum::http::Method::POST,
        axum::http::Method::PUT,
        axum::http::Method::DELETE,
    ] {
        let req = axum::http::Request::builder()
            .method(m)
            .uri("/api/traffic")
            .header("host", HOST)
            .header("origin", "http://127.0.0.1:7878")
            .header("x-rhizomon", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(app(Arc::new(TrafficHub::new(false))), req)
                .await
                .status,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}

async fn next_chunk(body: &mut Body) -> String {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("timed out waiting for SSE frame")
            .expect("stream ended")
            .unwrap();
        if let Ok(data) = frame.into_data() {
            let s = String::from_utf8_lossy(&data).into_owned();
            if !s.trim().is_empty() && !s.trim_start().starts_with(':') {
                return s;
            }
        }
    }
}

#[tokio::test]
async fn the_event_stream_carries_traffic_events_with_the_same_json() {
    let t = Arc::new(TrafficHub::new(false));
    let a =
        router(AppState::new(seeded_hub(), PORT, CancellationToken::new()).with_traffic(t.clone()));
    let res = tower::ServiceExt::oneshot(a, get_req("/api/events", Some(HOST), None))
        .await
        .unwrap();
    let mut body = res.into_body();
    let first = next_chunk(&mut body).await;
    assert!(first.contains("event: snapshot"), "{first}");
    let mut s = Sample::empty(false, 42);
    s.host.iface = Some("en0".into());
    t.publish(s);
    let ev = next_chunk(&mut body).await;
    assert!(
        ev.contains("event: traffic") && ev.contains("\"iface\":\"en0\""),
        "{ev}"
    );
    let data = ev.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
    let v: serde_json::Value = serde_json::from_str(data).unwrap();
    assert_eq!(v["ts"], 42);
}

#[tokio::test]
async fn device_events_still_flow_alongside_traffic_events() {
    let devices = Arc::new(Hub::new(16));
    let t = Arc::new(TrafficHub::new(false));
    let a = router(
        AppState::new(devices.clone(), PORT, CancellationToken::new()).with_traffic(t.clone()),
    );
    let res = tower::ServiceExt::oneshot(a, get_req("/api/events", Some(HOST), None))
        .await
        .unwrap();
    let mut body = res.into_body();
    let _ = next_chunk(&mut body).await;
    devices.publish(rhizomon::model::DeviceEvent::Upsert(Box::new(device(
        "192.168.0.9",
        "aa:bb:cc:dd:ee:09",
        false,
    ))));
    t.publish(Sample::empty(false, 7));
    let mut seen = String::new();
    for _ in 0..2 {
        seen.push_str(&next_chunk(&mut body).await);
    }
    assert!(
        seen.contains("event: device") && seen.contains("event: traffic"),
        "{seen}"
    );
}
