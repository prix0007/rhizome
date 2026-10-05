use std::convert::Infallible;

use axum::Json;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::StreamExt;
use futures_util::stream;
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;

use super::AppState;
use crate::model::{Device, DeviceEvent, ScanStatus};
use crate::state::hub::Hub;

pub async fn devices(State(st): State<AppState>) -> Json<Vec<Device>> {
    Json(st.hub.snapshot().devices)
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
    let s = stream::once(async move { first })
        .chain(live)
        .take_until(st.shutdown.clone().cancelled_owned())
        .map(Ok::<_, Infallible>);
    Sse::new(s).keep_alive(KeepAlive::default())
}
