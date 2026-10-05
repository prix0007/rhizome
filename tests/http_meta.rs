//! `PUT /api/devices/{id}/meta`: user-set names and notes.

mod common;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::*;
use rhizome::model::DeviceEvent;
use rhizome::state::hub::Hub;
use rhizome::store::Store;
use rhizome::web::{AppState, router};
use tokio_util::sync::CancellationToken;

const ORIGIN: &str = "http://127.0.0.1:7878";
const PHONE: &str = "02:00:00:00:00:62";
const NET: &str = "68:7f:f0:00:00:01";

struct Rig {
    hub: Arc<Hub>,
    store: Arc<Store>,
    app: Router,
}

fn rig() -> Rig {
    let hub = seeded_hub();
    hub.set_network_id(Some(NET.to_string()));
    let store = Arc::new(Store::open_in_memory().unwrap());
    let devs: Vec<_> = hub.snapshot().devices;
    store.upsert_many(NET, &devs).unwrap();
    let app = router(
        AppState::new(hub.clone(), PORT, CancellationToken::new()).with_store(store.clone()),
    );
    Rig { hub, store, app }
}

fn put(id: &str, body: &str, origin: Option<&str>, x: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/devices/{id}/meta"))
        .header("host", HOST)
        .header("content-type", "application/json");
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    if let Some(x) = x {
        b = b.header("x-rhizome", x);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn good(id: &str, body: &str) -> Request<Body> {
    put(id, body, Some(ORIGIN), Some("1"))
}

fn enc(id: &str) -> String {
    id.replace(':', "%3A").replace('@', "%40")
}

#[tokio::test]
async fn success_returns_the_updated_device_and_a_get_shows_it() {
    let r = rig();
    let res = send(
        r.app.clone(),
        good(
            &enc(PHONE),
            r#"{"custom_name":"Dad's phone","notes":"Pixel 8"}"#,
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v: serde_json::Value = serde_json::from_str(&res.body).unwrap();
    assert_eq!(v["id"], PHONE);
    assert_eq!(v["custom_name"], "Dad's phone");
    assert_eq!(v["notes"], "Pixel 8");
    let list = get_via(&r.app, "/api/devices").await;
    let phone = list
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == PHONE)
        .unwrap();
    assert_eq!(phone["custom_name"], "Dad's phone");
    let gw = list
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["is_gateway"] == true)
        .unwrap();
    assert!(
        gw.get("custom_name").is_none(),
        "unknown fields are omitted"
    );
}

async fn get_via(app: &Router, path: &str) -> serde_json::Value {
    let res = send(app.clone(), get_req(path, Some(HOST), None)).await;
    serde_json::from_str(&res.body).unwrap()
}

#[tokio::test]
async fn the_change_is_published_to_sse_clients_and_persisted() {
    let r = rig();
    let mut rx = r.hub.subscribe();
    let res = send(
        r.app.clone(),
        good(&enc(PHONE), r#"{"custom_name":"Kitchen"}"#),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match ev {
        DeviceEvent::Upsert(d) => {
            assert_eq!(d.id, PHONE);
            assert_eq!(d.custom_name.as_deref(), Some("Kitchen"));
        }
        other => panic!("expected an upsert, got {other:?}"),
    }
    let row = r
        .store
        .load(NET)
        .unwrap()
        .into_iter()
        .find(|x| x.id == PHONE)
        .unwrap();
    assert_eq!(row.custom_name.as_deref(), Some("Kitchen"));
}

#[tokio::test]
async fn null_and_empty_clear_and_absent_keys_are_kept() {
    let r = rig();
    send(
        r.app.clone(),
        good(&enc(PHONE), r#"{"custom_name":"A","notes":"B"}"#),
    )
    .await;
    let res = send(r.app.clone(), good(&enc(PHONE), r#"{"notes":null}"#)).await;
    let v: serde_json::Value = serde_json::from_str(&res.body).unwrap();
    assert_eq!(v["custom_name"], "A", "absent key untouched");
    assert!(v.get("notes").is_none());
    let res = send(r.app.clone(), good(&enc(PHONE), r#"{"custom_name":""}"#)).await;
    let v: serde_json::Value = serde_json::from_str(&res.body).unwrap();
    assert!(v.get("custom_name").is_none());
    let row = r
        .store
        .load(NET)
        .unwrap()
        .into_iter()
        .find(|x| x.id == PHONE)
        .unwrap();
    assert_eq!((row.custom_name, row.notes), (None, None));
}

#[tokio::test]
async fn ids_with_at_signs_work_url_encoded() {
    let r = rig();
    let id = "aa:bb:cc:dd:ee:01@10.0.0.2";
    let mut d = device("10.0.0.2", "aa:bb:cc:dd:ee:01", false);
    d.id = id.to_string();
    r.hub.publish(DeviceEvent::Upsert(Box::new(d)));
    let res = send(r.app.clone(), good(&enc(id), r#"{"custom_name":"shared"}"#)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v: serde_json::Value = serde_json::from_str(&res.body).unwrap();
    assert_eq!(v["id"], id);
}

#[tokio::test]
async fn missing_x_rhizome_or_origin_or_a_foreign_origin_is_forbidden_and_changes_nothing() {
    let r = rig();
    let body = r#"{"custom_name":"hacked"}"#;
    let cases = [
        put(&enc(PHONE), body, Some(ORIGIN), None),
        put(&enc(PHONE), body, Some(ORIGIN), Some("0")),
        put(&enc(PHONE), body, None, Some("1")),
        put(&enc(PHONE), body, Some("http://evil.com"), Some("1")),
        put(&enc(PHONE), body, Some("null"), Some("1")),
        put(&enc(PHONE), body, Some("http://127.0.0.1:9999"), Some("1")),
    ];
    for req in cases {
        let res = send(r.app.clone(), req).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN);
    }
    let list = get_via(&r.app, "/api/devices").await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|d| d.get("custom_name").is_none())
    );
}

#[tokio::test]
async fn forbidden_even_with_valid_headers_when_the_host_or_fetch_site_is_wrong() {
    let r = rig();
    let mut req = good(&enc(PHONE), r#"{"custom_name":"x"}"#);
    req.headers_mut()
        .insert("host", "evil.com".parse().unwrap());
    assert_eq!(send(r.app.clone(), req).await.status, StatusCode::FORBIDDEN);
    let mut req = good(&enc(PHONE), r#"{"custom_name":"x"}"#);
    req.headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    assert_eq!(send(r.app.clone(), req).await.status, StatusCode::FORBIDDEN);
    let mut req = good(&enc(PHONE), r#"{"custom_name":"x"}"#);
    req.headers_mut()
        .insert("sec-fetch-site", "same-origin".parse().unwrap());
    assert_eq!(send(r.app.clone(), req).await.status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_ids_are_404() {
    let r = rig();
    for id in ["de:ad:be:ef:00:01", "nope", "%2e%2e", "aa%3Abb%40x"] {
        let res = send(r.app.clone(), good(id, r#"{"custom_name":"x"}"#)).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{id}");
    }
}

#[tokio::test]
async fn oversized_bodies_are_413_and_malformed_ones_400() {
    let r = rig();
    let big = format!(r#"{{"notes":"{}"}}"#, "x".repeat(10_000));
    assert_eq!(
        send(r.app.clone(), good(&enc(PHONE), &big)).await.status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for bad in [
        "",
        "{",
        "[]",
        "null",
        r#"{"custom_name":5}"#,
        r#"{"hostname":"x"}"#,
        r#"{"custom_name":"a","custom_name2":"b"}"#,
    ] {
        assert_eq!(
            send(r.app.clone(), good(&enc(PHONE), bad)).await.status,
            StatusCode::BAD_REQUEST,
            "{bad:?}"
        );
    }
    let long_name = format!(r#"{{"custom_name":"{}"}}"#, "n".repeat(65));
    assert_eq!(
        send(r.app.clone(), good(&enc(PHONE), &long_name))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let long_notes = format!(r#"{{"notes":"{}"}}"#, "n".repeat(501));
    assert_eq!(
        send(r.app.clone(), good(&enc(PHONE), &long_notes))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn text_is_sanitised_before_it_is_stored_or_returned() {
    let r = rig();
    let res = send(
        r.app.clone(),
        good(
            &enc(PHONE),
            "{\"custom_name\":\"a\\u0000\\u202eb\",\"notes\":\"x\\r\\ny\"}",
        ),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&res.body).unwrap();
    assert_eq!(v["custom_name"], "ab");
    assert_eq!(v["notes"], "x\ny");
}

#[tokio::test]
async fn other_methods_on_the_route_are_not_allowed() {
    let r = rig();
    for m in [Method::GET, Method::POST, Method::DELETE, Method::PATCH] {
        let req = Request::builder()
            .method(m.clone())
            .uri(format!("/api/devices/{}/meta", enc(PHONE)))
            .header("host", HOST)
            .header("origin", ORIGIN)
            .header("x-rhizome", "1")
            .body(Body::from(r#"{"custom_name":"x"}"#))
            .unwrap();
        assert_eq!(
            send(r.app.clone(), req).await.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{m}"
        );
    }
}

#[tokio::test]
async fn without_a_known_network_the_change_is_refused_rather_than_stored_under_nothing() {
    let hub = seeded_hub(); // no network id set
    let store = Arc::new(Store::open_in_memory().unwrap());
    let app = router(AppState::new(hub, PORT, CancellationToken::new()).with_store(store));
    let res = send(app, good(&enc(PHONE), r#"{"custom_name":"x"}"#)).await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn without_a_store_the_change_still_applies_in_memory() {
    let hub = seeded_hub();
    let app = router(AppState::new(hub.clone(), PORT, CancellationToken::new()));
    let res = send(app, good(&enc(PHONE), r#"{"custom_name":"mem"}"#)).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        hub.snapshot()
            .devices
            .iter()
            .find(|d| d.id == PHONE)
            .unwrap()
            .custom_name
            .as_deref(),
        Some("mem")
    );
}

#[tokio::test]
async fn a_scan_that_replaces_the_device_map_keeps_the_user_metadata() {
    let r = rig();
    send(
        r.app.clone(),
        good(&enc(PHONE), r#"{"custom_name":"Keep me","notes":"n"}"#),
    )
    .await;
    // the scanner publishes a fresh map in which the device knows nothing of the edit
    let mut fresh = rhizome::model::DeviceMap::new();
    for d in r.hub.snapshot().devices {
        let mut d = d;
        d.custom_name = None;
        d.notes = None;
        fresh.insert(d.id.clone(), d);
    }
    r.hub.apply_scan(&fresh, vec![], Default::default());
    let d = r
        .hub
        .snapshot()
        .devices
        .into_iter()
        .find(|d| d.id == PHONE)
        .unwrap();
    assert_eq!(d.custom_name.as_deref(), Some("Keep me"));
    assert_eq!(d.notes.as_deref(), Some("n"));
}

#[tokio::test]
async fn overlapping_puts_setting_different_fields_do_not_revert_each_other() {
    for round in 0..25 {
        let r = rig();
        let a = send(
            r.app.clone(),
            good(&enc(PHONE), r#"{"custom_name":"Name"}"#),
        );
        let b = send(r.app.clone(), good(&enc(PHONE), r#"{"notes":"Note"}"#));
        let (ra, rb) = tokio::join!(a, b);
        assert_eq!(
            (ra.status, rb.status),
            (StatusCode::OK, StatusCode::OK),
            "round {round}"
        );
        let d = r
            .hub
            .snapshot()
            .devices
            .into_iter()
            .find(|d| d.id == PHONE)
            .unwrap();
        assert_eq!(
            d.custom_name.as_deref(),
            Some("Name"),
            "round {round}: name lost"
        );
        assert_eq!(
            d.notes.as_deref(),
            Some("Note"),
            "round {round}: notes lost"
        );
        let row = r
            .store
            .load(NET)
            .unwrap()
            .into_iter()
            .find(|x| x.id == PHONE)
            .unwrap();
        assert_eq!(
            (row.custom_name.as_deref(), row.notes.as_deref()),
            (Some("Name"), Some("Note")),
            "round {round}: DB and hub disagree"
        );
    }
}
