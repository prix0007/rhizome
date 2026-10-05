mod common;
use axum::http::StatusCode;
use common::*;

async fn status(path: &str, host: Option<&str>, origin: Option<&str>) -> StatusCode {
    send(app_with(seeded_hub()), get_req(path, host, origin))
        .await
        .status
}

#[tokio::test]
async fn evil_host_is_forbidden_on_every_route() {
    for p in [
        "/",
        "/app.js",
        "/vendor/3d-force-graph.min.js",
        "/api/devices",
        "/api/status",
        "/api/events",
        "/nope",
    ] {
        assert_eq!(
            status(p, Some("evil.com"), None).await,
            StatusCode::FORBIDDEN,
            "{p}"
        );
        assert_eq!(
            status(p, Some("127.0.0.1.evil.com:7878"), None).await,
            StatusCode::FORBIDDEN,
            "{p}"
        );
        assert_eq!(
            status(p, Some("127.0.0.1:9999"), None).await,
            StatusCode::FORBIDDEN,
            "{p}"
        );
        assert_eq!(
            status(p, None, None).await,
            StatusCode::FORBIDDEN,
            "{p} missing host"
        );
    }
}

#[tokio::test]
async fn good_hosts_pass() {
    assert_eq!(
        status("/", Some("127.0.0.1:7878"), None).await,
        StatusCode::OK
    );
    assert_eq!(
        status("/", Some("localhost:7878"), None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn foreign_origin_is_forbidden_even_with_good_host() {
    for p in ["/api/events", "/api/devices", "/"] {
        assert_eq!(
            status(p, Some(HOST), Some("http://evil.com")).await,
            StatusCode::FORBIDDEN,
            "{p}"
        );
        assert_eq!(
            status(p, Some(HOST), Some("null")).await,
            StatusCode::FORBIDDEN,
            "{p}"
        );
    }
}

#[tokio::test]
async fn same_origin_passes_and_no_cors_headers_are_sent() {
    let r = send(
        app_with(seeded_hub()),
        get_req("/api/devices", Some(HOST), Some("http://127.0.0.1:7878")),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn forbidden_responses_still_carry_security_headers() {
    let r = send(app_with(seeded_hub()), get_req("/", Some("evil.com"), None)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.headers.get("content-security-policy").is_some());
}

#[tokio::test]
async fn security_headers_on_all_responses() {
    let r = get("/").await;
    let csp = r
        .headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(csp, rhizome::web::headers::CSP);
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("script-src 'self'"));
    assert!(!csp.contains("script-src 'self' 'unsafe"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("base-uri 'none'"));
    assert_eq!(r.headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(r.headers.get("referrer-policy").unwrap(), "no-referrer");
}

#[tokio::test]
async fn api_responses_are_not_cacheable_but_assets_are_unaffected() {
    assert_eq!(
        get("/api/devices")
            .await
            .headers
            .get("cache-control")
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        get("/api/status")
            .await
            .headers
            .get("cache-control")
            .unwrap(),
        "no-store"
    );
    assert!(get("/").await.headers.get("cache-control").is_none());
}

fn req_with(headers: &[(&str, &str)]) -> axum::http::Request<axum::body::Body> {
    let mut b = axum::http::Request::get("/api/devices").header("host", HOST);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(axum::body::Body::empty()).unwrap()
}

#[tokio::test]
async fn cross_site_fetch_metadata_is_forbidden_on_every_route() {
    for path in ["/", "/api/devices", "/api/events", "/app.js"] {
        for site in ["cross-site", "same-site"] {
            let mut b = axum::http::Request::get(path)
                .header("host", HOST)
                .header("sec-fetch-site", site);
            b = b.header("sec-fetch-mode", "no-cors");
            let r = send(
                app_with(seeded_hub()),
                b.body(axum::body::Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{path} {site}");
        }
    }
}

#[tokio::test]
async fn cross_site_navigation_loads_the_page_but_never_the_api() {
    for (path, want) in [
        ("/", StatusCode::OK),
        ("/api/devices", StatusCode::FORBIDDEN),
    ] {
        let b = axum::http::Request::get(path)
            .header("host", HOST)
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document");
        let r = send(
            app_with(seeded_hub()),
            b.body(axum::body::Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(r.status, want, "{path}");
    }
}

#[tokio::test]
async fn same_origin_and_none_fetch_metadata_pass() {
    for site in ["same-origin", "none"] {
        let r = send(
            app_with(seeded_hub()),
            req_with(&[("sec-fetch-site", site)]),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{site}");
    }
}

#[tokio::test]
async fn duplicate_sec_fetch_site_headers_are_forbidden() {
    let r = send(
        app_with(seeded_hub()),
        req_with(&[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-site", "cross-site"),
        ]),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn extra_isolation_headers_and_form_action_are_present() {
    let r = get("/").await;
    assert_eq!(
        r.headers.get("cross-origin-resource-policy").unwrap(),
        "same-origin"
    );
    assert_eq!(r.headers.get("x-frame-options").unwrap(), "DENY");
    let csp = r
        .headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("form-action 'none'"), "{csp}");
    // and on rejected responses too
    let bad = send(app_with(seeded_hub()), get_req("/", Some("evil.com"), None)).await;
    assert_eq!(
        bad.headers.get("cross-origin-resource-policy").unwrap(),
        "same-origin"
    );
    assert_eq!(bad.headers.get("x-frame-options").unwrap(), "DENY");
}
