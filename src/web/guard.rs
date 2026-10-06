//! Host and Origin checks against DNS rebinding and cross-origin access.

/// `Host` must be exactly `127.0.0.1:<port>` or `localhost:<port>`.
pub fn host_allowed(host: Option<&str>, port: u16) -> bool {
    let Some(h) = host else { return false };
    h == format!("127.0.0.1:{port}") || h.eq_ignore_ascii_case(&format!("localhost:{port}"))
}

/// Fetch-metadata defence: when the browser says where the request came from,
/// only our own pages (`same-origin`) or direct navigation (`none`) are allowed.
/// Absent (curl, old browsers) is fine; anything else, including duplicates
/// and empty values, is not.
pub fn fetch_site_allowed(values: &[&str]) -> bool {
    match values {
        [] => true,
        [one] => *one == "same-origin" || *one == "none",
        _ => false,
    }
}

/// A top-level document navigation (link, bookmark, typed URL) to a non-API
/// path. These are exempt from the fetch-site check: the page itself holds no
/// device data, and its own requests to `/api/` are `same-origin`.
pub fn is_page_navigation(
    is_get: bool,
    path: &str,
    mode: Option<&str>,
    dest: Option<&str>,
) -> bool {
    is_get && !path.starts_with("/api/") && mode == Some("navigate") && dest == Some("document")
}

/// State-changing requests need more than a plain GET does: an `Origin` that is
/// present and exactly ours (not merely absent), and the custom `X-Rhizomon: 1`
/// header, which a cross-origin page cannot send without a preflight we refuse.
pub fn mutation_allowed(origin: Option<&str>, x_rhizomon: &[&str], port: u16) -> bool {
    origin.is_some() && origin_allowed(origin, port) && x_rhizomon == ["1"]
}

/// Route-level middleware for state-changing routes (runs before the body is read).
pub async fn mutation_guard(
    axum::extract::State(st): axum::extract::State<super::AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let headers = req.headers();
    let origins: Vec<&str> = headers
        .get_all("origin")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let xs: Vec<&str> = headers
        .get_all("x-rhizomon")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let origin = match origins.as_slice() {
        [one] => Some(*one),
        _ => None, // absent or duplicated
    };
    if !mutation_allowed(origin, &xs, st.port) {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: same-origin request with X-Rhizomon required",
        )
            .into_response();
    }
    next.run(req).await
}

/// An absent `Origin` is fine (same-origin GETs and curl); a present one must
/// be exactly our own origin. `null` and everything else is rejected.
pub fn origin_allowed(origin: Option<&str>, port: u16) -> bool {
    match origin {
        None => true,
        Some(o) => {
            o == format!("http://127.0.0.1:{port}")
                || o.eq_ignore_ascii_case(&format!("http://localhost:{port}"))
        }
    }
}

/// Middleware applied to every route, including static assets and 404s.
pub async fn guard(
    axum::extract::State(st): axum::extract::State<super::AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let headers = req.headers();
    // Exactly one Host header, and it must be ours.
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = hosts.next().and_then(|v| v.to_str().ok());
    let single = hosts.next().is_none();
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin_raw = origins.next();
    let origin = match origin_raw {
        None => None,
        Some(v) => match v.to_str() {
            Ok(s) => Some(s),
            Err(_) => return (StatusCode::FORBIDDEN, "forbidden origin").into_response(),
        },
    };
    if !single || !host_allowed(host, st.port) {
        return (StatusCode::FORBIDDEN, "forbidden host").into_response();
    }
    if origins.next().is_some() || !origin_allowed(origin, st.port) {
        return (StatusCode::FORBIDDEN, "forbidden origin").into_response();
    }
    // Fetch metadata (sent by every modern browser): refuse cross-site and
    // same-site requests, including non-UTF-8 or duplicated values.
    let sites: Option<Vec<&str>> = headers
        .get_all("sec-fetch-site")
        .iter()
        .map(|v| v.to_str().ok())
        .collect();
    let single_value = |name: &str| {
        let mut it = headers.get_all(name).iter();
        let first = it.next().and_then(|v| v.to_str().ok());
        if it.next().is_none() { first } else { None }
    };
    // Following a link or bookmark to a page is a cross-site top-level
    // navigation; it must load. The API never is one.
    let page_navigation = is_page_navigation(
        req.method() == axum::http::Method::GET,
        req.uri().path(),
        single_value("sec-fetch-mode"),
        single_value("sec-fetch-dest"),
    );
    if !page_navigation && !sites.is_some_and(|s| fetch_site_allowed(&s)) {
        return (StatusCode::FORBIDDEN, "forbidden fetch site").into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_table() {
        let p = 7878;
        for (h, ok) in [
            (Some("127.0.0.1:7878"), true),
            (Some("localhost:7878"), true),
            (Some("LOCALHOST:7878"), true),
            (Some("127.0.0.1:7879"), false),
            (Some("127.0.0.1"), false),
            (Some("localhost"), false),
            (Some("evil.com"), false),
            (Some("evil.com:7878"), false),
            (Some("127.0.0.1.evil.com"), false),
            (Some("127.0.0.1.evil.com:7878"), false),
            (Some("localhost.evil.com:7878"), false),
            (Some("evil.com@127.0.0.1:7878"), false),
            (Some("127.0.0.1:7878.evil.com"), false),
            (Some(" 127.0.0.1:7878"), false),
            (Some("[::1]:7878"), false),
            (Some("0.0.0.0:7878"), false),
            (Some(""), false),
            (None, false),
        ] {
            assert_eq!(host_allowed(h, p), ok, "{h:?}");
        }
    }

    #[test]
    fn mutation_table() {
        let p = 7878;
        let ok = Some("http://127.0.0.1:7878");
        assert!(mutation_allowed(ok, &["1"], p));
        assert!(mutation_allowed(Some("http://localhost:7878"), &["1"], p));
        assert!(!mutation_allowed(None, &["1"], p), "Origin must be present");
        assert!(!mutation_allowed(Some("http://evil.com"), &["1"], p));
        assert!(!mutation_allowed(Some("null"), &["1"], p));
        assert!(!mutation_allowed(Some("http://127.0.0.1:9"), &["1"], p));
        assert!(!mutation_allowed(ok, &[], p), "X-Rhizomon missing");
        assert!(!mutation_allowed(ok, &["0"], p));
        assert!(!mutation_allowed(ok, &["true"], p));
        assert!(
            !mutation_allowed(ok, &["1", "1"], p),
            "duplicates are refused"
        );
        assert!(!mutation_allowed(ok, &[""], p));
    }

    #[test]
    fn fetch_site_table() {
        assert!(fetch_site_allowed(&[]), "absent is allowed");
        assert!(fetch_site_allowed(&["same-origin"]));
        assert!(fetch_site_allowed(&["none"]));
        for bad in [
            &["cross-site"][..],
            &["same-site"],
            &[""],
            &["Same-Origin "],
            &["same-origin", "same-origin"],
            &["same-origin", "cross-site"],
        ] {
            assert!(!fetch_site_allowed(bad), "{bad:?}");
        }
    }

    #[test]
    fn page_navigation_table() {
        let nav = (Some("navigate"), Some("document"));
        assert!(is_page_navigation(true, "/", nav.0, nav.1));
        assert!(is_page_navigation(true, "/index.html", nav.0, nav.1));
        assert!(!is_page_navigation(true, "/api/devices", nav.0, nav.1));
        assert!(!is_page_navigation(false, "/", nav.0, nav.1), "GET only");
        assert!(!is_page_navigation(true, "/", Some("no-cors"), nav.1));
        assert!(!is_page_navigation(true, "/", nav.0, Some("iframe")));
        assert!(!is_page_navigation(true, "/", None, None));
    }

    #[test]
    fn origin_table() {
        let p = 7878;
        for (o, ok) in [
            (None, true),
            (Some("http://127.0.0.1:7878"), true),
            (Some("http://localhost:7878"), true),
            (Some("null"), false),
            (Some("http://evil.com"), false),
            (Some("http://evil.com:7878"), false),
            (Some("https://127.0.0.1:7878"), false),
            (Some("http://127.0.0.1:7879"), false),
            (Some("http://127.0.0.1.evil.com:7878"), false),
            (Some("http://127.0.0.1:7878/"), false),
            (Some(""), false),
        ] {
            assert_eq!(origin_allowed(o, p), ok, "{o:?}");
        }
    }
}
