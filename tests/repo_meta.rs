//! Repository metadata that matters for an open-source repo.

use std::path::Path;

fn read(p: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(p)).unwrap()
}

#[test]
fn readme_opens_with_the_logo_and_a_plain_description() {
    let readme = read("README.md");
    let first_lines: String = readme.lines().take(12).collect::<Vec<_>>().join("\n");
    assert!(first_lines.contains(r#"<img src="ui/logo.svg" width="96" alt="Rhizomon logo">"#));
    assert!(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ui/logo.svg")
            .exists(),
        "the logo file must exist"
    );
    assert!(readme.contains("# Rhizomon"));
    assert!(readme.contains("local network mapper"));
}

#[test]
fn readme_documents_the_new_sources_flag_and_endpoint() {
    let readme = read("README.md");
    for needle in [
        "--no-netbios",
        "PUT /api/devices/{id}/meta",
        "X-Rhizomon",
        "UPnP",
        "NetBIOS",
        "gateway",
        "os_hint",
        "rtt_ms",
        "Known limitations",
    ] {
        assert!(readme.contains(needle), "README should mention {needle}");
    }
    assert!(
        !readme.contains("never fetched"),
        "the old claim that LOCATION is never fetched is no longer true"
    );
    assert!(!readme.contains("No reverse DNS"), "stale claim");
}

#[test]
fn readme_only_documents_the_numeric_loopback_url() {
    let readme = read("README.md");
    assert!(readme.contains("http://127.0.0.1:7878"));
    assert!(
        !readme.contains("http://localhost"),
        "only the 127.0.0.1 URL is documented"
    );
}

#[test]
fn cargo_metadata_is_filled_in_and_the_license_matches_the_license_file() {
    let toml = read("Cargo.toml");
    assert!(toml.contains("description = "));
    assert!(toml.contains(r#"readme = "README.md""#));
    let kw = toml
        .lines()
        .find(|l| l.starts_with("keywords"))
        .expect("keywords");
    let count = kw.matches('"').count() / 2;
    assert!(
        (1..=5).contains(&count),
        "crates.io allows at most five keywords: {kw}"
    );
    assert!(toml.lines().any(|l| l.starts_with("categories")));
    assert!(
        toml.lines().any(|l| l.trim() == r#"license = "MIT""#),
        "Cargo.toml must declare the MIT license"
    );
    assert!(
        read("LICENSE").contains("MIT License"),
        "the LICENSE file is the MIT license"
    );
    assert!(!toml.contains("repository"), "no remote exists");
}

#[test]
fn readme_states_the_license() {
    let readme = read("README.md");
    assert!(readme.contains("MIT"), "README must name the license");
    assert!(readme.contains("[LICENSE](LICENSE)"));
}
