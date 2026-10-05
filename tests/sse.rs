mod common;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use common::*;
use http_body_util::BodyExt;
use rhizome::model::{DeviceEvent, ScanStatus};
use rhizome::state::hub::Hub;

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

async fn open(hub: Arc<Hub>) -> Body {
    let res = tower::ServiceExt::oneshot(app_with(hub), get_req("/api/events", Some(HOST), None))
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    res.into_body()
}

#[tokio::test]
async fn first_event_is_a_snapshot_of_current_devices() {
    let mut body = open(seeded_hub()).await;
    let first = next_chunk(&mut body).await;
    assert!(first.contains("event: snapshot"), "{first}");
    assert!(first.contains("192.168.0.82"));
}

#[tokio::test]
async fn published_upsert_arrives_as_device_event() {
    let hub = seeded_hub();
    let mut body = open(hub.clone()).await;
    let _ = next_chunk(&mut body).await;
    hub.publish(DeviceEvent::Upsert(Box::new(device(
        "192.168.0.99",
        "aa:bb:cc:dd:ee:99",
        false,
    ))));
    let ev = next_chunk(&mut body).await;
    assert!(ev.contains("event: device"), "{ev}");
    assert!(ev.contains("192.168.0.99"));
}

#[tokio::test]
async fn removed_and_scan_events_are_named() {
    let hub = seeded_hub();
    let mut body = open(hub.clone()).await;
    let _ = next_chunk(&mut body).await;
    hub.publish(DeviceEvent::Removed("aa:bb:cc:dd:ee:99".into()));
    assert!(next_chunk(&mut body).await.contains("event: removed"));
    hub.publish(DeviceEvent::Scan(Box::new(ScanStatus {
        iface: "en0".into(),
        ..Default::default()
    })));
    let s = next_chunk(&mut body).await;
    assert!(s.contains("event: scan") && s.contains("en0"), "{s}");
}

#[tokio::test]
async fn lagged_receiver_gets_a_fresh_snapshot() {
    let hub = Arc::new(Hub::new(4));
    let mut body = open(hub.clone()).await;
    let _ = next_chunk(&mut body).await;
    for i in 0..40u8 {
        hub.publish(DeviceEvent::Upsert(Box::new(device(
            &format!("192.168.0.{}", 100 + i),
            &format!("aa:bb:cc:dd:ee:{i:02x}"),
            false,
        ))));
    }
    let ev = next_chunk(&mut body).await;
    assert!(ev.contains("event: snapshot"), "{ev}");
    assert!(
        ev.contains("192.168.0.139"),
        "snapshot must contain the latest state"
    );
}

#[tokio::test]
async fn stream_ends_on_shutdown() {
    use rhizome::web::{AppState, router};
    let token = tokio_util::sync::CancellationToken::new();
    let app = router(AppState::new(seeded_hub(), PORT, token.clone()));
    let res = tower::ServiceExt::oneshot(app, get_req("/api/events", Some(HOST), None))
        .await
        .unwrap();
    let mut body = res.into_body();
    let _ = next_chunk(&mut body).await;
    token.cancel();
    let end = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(f) = body.frame().await {
            f.unwrap();
        }
    })
    .await;
    assert!(
        end.is_ok(),
        "SSE stream must terminate when shutdown is requested"
    );
}
