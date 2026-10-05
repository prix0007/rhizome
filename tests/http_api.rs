//! In-process HTTP tests using a seeded hub (no network).

mod common;
use axum::http::StatusCode;
use common::*;

#[tokio::test]
async fn root_serves_html() {
    let r = get("/").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.content_type.starts_with("text/html"),
        "{}",
        r.content_type
    );
    assert!(r.body.contains("<script"));
}

#[tokio::test]
async fn vendored_library_is_served_as_javascript() {
    let r = get("/vendor/3d-force-graph.min.js").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.content_type.contains("javascript"), "{}", r.content_type);
    assert!(r.body.contains("ForceGraph3D"));
}

#[tokio::test]
async fn app_modules_are_served() {
    for p in [
        "/app.js",
        "/graph-model.js",
        "/label-layout.js",
        "/labels.js",
        "/scene.js",
        "/style.css",
    ] {
        assert_eq!(get(p).await.status, StatusCode::OK, "{p}");
    }
}

#[tokio::test]
async fn brand_and_metadata_assets_are_served_with_the_right_types() {
    for (p, ty) in [
        ("/logo.svg", "image/svg+xml"),
        ("/manifest.webmanifest", "manifest+json"),
        ("/favicon-32.png", "image/png"),
        ("/apple-touch-icon.png", "image/png"),
        ("/icon-192.png", "image/png"),
        ("/icon-512.png", "image/png"),
        ("/og-image.png", "image/png"),
    ] {
        let r = get(p).await;
        assert_eq!(r.status, StatusCode::OK, "{p}");
        assert!(r.content_type.contains(ty), "{p}: {}", r.content_type);
    }
}

#[tokio::test]
async fn vendored_fonts_are_served_from_the_same_origin() {
    for p in [
        "/vendor/fonts/ibm-plex-mono-latin-400-normal.woff2",
        "/vendor/fonts/ibm-plex-mono-latin-500-normal.woff2",
    ] {
        let r = get(p).await;
        assert_eq!(r.status, StatusCode::OK, "{p}");
        assert!(r.content_type.contains("woff2"), "{p}: {}", r.content_type);
    }
}

#[tokio::test]
async fn devices_returns_json_array() {
    let r = get("/api/devices").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.content_type.starts_with("application/json"),
        "{}",
        r.content_type
    );
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    // Sorted by id (MAC): the locally administered 02:... entry sorts first.
    assert_eq!(arr[0]["mac"], "02:00:00:00:00:62");
    assert_eq!(arr[1]["ip"], "192.168.0.1");
    assert_eq!(arr[1]["is_gateway"], true);
}

#[tokio::test]
async fn status_endpoint_returns_json_object() {
    let r = get("/api/status").await;
    assert_eq!(r.status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert!(v.is_object());
}

#[tokio::test]
async fn unknown_paths_and_traversal_are_404() {
    for p in [
        "/nope",
        "/../Cargo.toml",
        "/vendor/../../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/tests/graph-model.test.js",
        "/package.json",
        "//etc/passwd",
    ] {
        assert_eq!(get(p).await.status, StatusCode::NOT_FOUND, "{p}");
    }
}

#[tokio::test]
async fn index_declares_icons_that_are_actually_served_so_no_favicon_404() {
    let r = get("/").await;
    assert!(
        r.body.contains(r#"rel="icon""#),
        "an explicit icon link is required"
    );
    // every declared icon target must exist (a 404 would show up as a console error)
    let mut checked = 0;
    for part in r.body.split("<link").skip(1) {
        let tag = part.split('>').next().unwrap_or("");
        if !tag.contains("icon") {
            continue;
        }
        let href = tag
            .split("href=\"")
            .nth(1)
            .and_then(|h| h.split('"').next())
            .unwrap_or("");
        if href.is_empty() || href.starts_with("data:") {
            continue;
        }
        let path = format!("/{}", href.trim_start_matches('/'));
        assert_eq!(get(&path).await.status, StatusCode::OK, "{path}");
        checked += 1;
    }
    assert!(checked >= 1 || r.body.contains(r#"href="data:,""#));
}
