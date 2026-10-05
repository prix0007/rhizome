//! Static UI served from `ui/` (read from disk in debug builds, embedded in release).

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, Uri, header};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "ui/"]
#[exclude = "tests/*"]
#[exclude = "package.json"]
struct Ui;

pub async fn serve(uri: Uri) -> Response<Body> {
    let raw = uri.path().trim_start_matches('/');
    let path = if raw.is_empty() { "index.html" } else { raw };
    // Reject anything that is not a plain relative path.
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == ".." || seg == "." || seg.contains('\\'))
    {
        return not_found();
    }
    match Ui::get(path) {
        Some(file) => {
            let mime = file.metadata.mimetype().to_string();
            let mut res = Response::new(Body::from(file.data.into_owned()));
            if let Ok(v) = HeaderValue::from_str(&mime) {
                res.headers_mut().insert(header::CONTENT_TYPE, v);
            }
            res
        }
        None => not_found(),
    }
}

fn not_found() -> Response<Body> {
    let mut res = Response::new(Body::from("not found"));
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}
