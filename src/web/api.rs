use std::convert::Infallible;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use futures_util::stream;
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;

use super::AppState;
use super::meta::parse_meta_update;
use crate::model::{Device, DeviceEvent, ScanStatus, UserMeta};
use crate::state::hub::Hub;

pub async fn devices(State(st): State<AppState>) -> Json<Vec<Device>> {
    Json(st.hub.snapshot().devices)
}

/// `GET /api/traffic`: the latest traffic sample.
pub async fn traffic(State(st): State<AppState>) -> Json<crate::traffic::Sample> {
    Json(st.traffic.latest())
}

pub async fn status(State(st): State<AppState>) -> Json<ScanStatus> {
    Json(st.hub.snapshot().status.unwrap_or_default())
}

fn json_event(name: &str, value: &impl serde::Serialize) -> Event {
    Event::default()
        .event(name)
        .json_data(value)
        .unwrap_or_else(|_| Event::default().comment("serialization error"))
}

fn traffic_event(s: &crate::traffic::Sample) -> Event {
    json_event("traffic", s)
}

fn snapshot_event(hub: &Hub) -> Event {
    let snap = hub.snapshot();
    json_event(
        "snapshot",
        &json!({ "devices": snap.devices, "status": snap.status }),
    )
}

fn live_event(ev: &DeviceEvent) -> Event {
    match ev {
        DeviceEvent::Upsert(d) => json_event("device", d),
        DeviceEvent::Removed(id) => json_event("removed", id),
        DeviceEvent::Scan(s) => json_event("scan", s),
    }
}

/// Server-sent events: a `snapshot` first, then `device` / `removed` / `scan`.
/// A receiver that falls behind is resynchronised with a fresh `snapshot`.
pub async fn events(State(st): State<AppState>) -> impl axum::response::IntoResponse {
    // Subscribe before taking the snapshot so nothing is missed (duplicates are idempotent).
    let rx = st.hub.subscribe();
    let first = snapshot_event(&st.hub);
    let hub = st.hub.clone();
    let live = BroadcastStream::new(rx).map(move |r| match r {
        Ok(ev) => live_event(&ev),
        Err(_lagged) => snapshot_event(&hub),
    });
    // Traffic samples ride the same stream (about one per second; `GET /api/traffic`
    // gives the latest immediately). A lagged receiver just skips ahead.
    let traffic_live = BroadcastStream::new(st.traffic.subscribe())
        .filter_map(|r| futures_util::future::ready(r.ok().map(|s| traffic_event(&s))));
    let s = stream::once(async move { first })
        .chain(stream::select(live, traffic_live))
        .take_until(st.shutdown.clone().cancelled_owned())
        .map(Ok::<_, Infallible>);
    Sse::new(s).keep_alive(KeepAlive::default())
}

/// `PUT /api/devices/{id}/meta`: the user's name and notes for one device.
/// (Origin and `X-Rhizome` are enforced by the route's middleware.)
pub async fn put_meta(
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    // One edit at a time from the read to the commit (the DB write is awaited inside).
    let _edit = st.meta_lock.lock().await;
    let Some(device) = st.hub.device_map().get(&id).cloned() else {
        return (StatusCode::NOT_FOUND, "unknown device").into_response();
    };
    let update = match parse_meta_update(&body) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let new = update.apply(&UserMeta {
        custom_name: device.custom_name.clone(),
        notes: device.notes.clone(),
    });

    if let Some(store) = st.store.clone() {
        let Some(nid) = st.hub.network_id() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "network not identified yet; try again after the next scan",
            )
                .into_response();
        };
        let mut to_save = device.clone();
        to_save.custom_name = new.custom_name.clone();
        to_save.notes = new.notes.clone();
        match tokio::task::spawn_blocking(move || store.set_user_meta(&nid, &to_save)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!("could not save device metadata: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "could not save").into_response();
            }
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "could not save").into_response(),
        }
    }
    match st.hub.commit_user_meta(&id, new) {
        Some(d) => Json(d).into_response(),
        None => (StatusCode::NOT_FOUND, "unknown device").into_response(), // removed meanwhile
    }
}
