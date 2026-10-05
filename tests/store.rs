mod common;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use common::device;
use rhizome::store::Store;

fn dev(ip: &str, mac: &str, first: i64, last: i64) -> rhizome::model::Device {
    let mut d = device(ip, mac, false);
    d.first_seen = first;
    d.last_seen = last;
    d
}

#[test]
fn migrate_is_idempotent_and_sets_user_version() {
    let s = Store::open_in_memory().unwrap();
    let v1 = s.user_version().unwrap();
    assert_eq!(v1, 2);
    s.migrate().unwrap();
    s.migrate().unwrap();
    assert_eq!(s.user_version().unwrap(), v1);
}

#[test]
fn upsert_keeps_first_seen_and_advances_last_seen() {
    let s = Store::open_in_memory().unwrap();
    s.upsert_many("net", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 100, 100)])
        .unwrap();
    s.upsert_many("net", &[dev("10.0.0.3", "aa:bb:cc:dd:ee:01", 999, 500)])
        .unwrap();
    let rows = s.load("net").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].first_seen, 100);
    assert_eq!(rows[0].last_seen, 500);
    assert_eq!(rows[0].last_ip, "10.0.0.3", "latest IP wins");
}

#[test]
fn last_seen_never_moves_backwards() {
    let s = Store::open_in_memory().unwrap();
    s.upsert_many("net", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 100, 500)])
        .unwrap();
    s.upsert_many("net", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 100, 200)])
        .unwrap();
    assert_eq!(s.load("net").unwrap()[0].last_seen, 500);
}

#[test]
fn load_is_scoped_by_network_id() {
    let s = Store::open_in_memory().unwrap();
    s.upsert_many("home", &[dev("192.168.0.2", "aa:bb:cc:dd:ee:01", 1, 1)])
        .unwrap();
    s.upsert_many(
        "office",
        &[
            dev("10.0.0.2", "aa:bb:cc:dd:ee:02", 1, 1),
            dev("10.0.0.3", "aa:bb:cc:dd:ee:03", 1, 1),
        ],
    )
    .unwrap();
    assert_eq!(s.load("home").unwrap().len(), 1);
    assert_eq!(s.load("office").unwrap().len(), 2);
    assert!(s.load("elsewhere").unwrap().is_empty());
}

#[test]
fn same_mac_on_two_networks_is_two_rows() {
    let s = Store::open_in_memory().unwrap();
    s.upsert_many("a", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1)])
        .unwrap();
    s.upsert_many("b", &[dev("10.9.0.2", "aa:bb:cc:dd:ee:01", 5, 5)])
        .unwrap();
    assert_eq!(s.load("a").unwrap()[0].first_seen, 1);
    assert_eq!(s.load("b").unwrap()[0].first_seen, 5);
}

#[test]
fn hostile_strings_round_trip_verbatim() {
    let s = Store::open_in_memory().unwrap();
    let evil = "'); DROP TABLE devices;--";
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1);
    d.hostname = Some(evil.into());
    d.vendor = Some("Robert'); DROP TABLE meta;--".into());
    s.upsert_many(evil, &[d]).unwrap();
    s.set_meta(evil, evil, evil).unwrap();
    let rows = s.load(evil).unwrap();
    assert_eq!(rows[0].hostname.as_deref(), Some(evil));
    assert_eq!(
        rows[0].vendor.as_deref(),
        Some("Robert'); DROP TABLE meta;--")
    );
    assert_eq!(s.get_meta(evil, evil).unwrap().as_deref(), Some(evil));
    // tables still exist
    assert_eq!(s.load("other").unwrap().len(), 0);
}

#[test]
fn meta_get_set_overwrite() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.get_meta("n", "baseline_at").unwrap(), None);
    s.set_meta("n", "baseline_at", "123").unwrap();
    s.set_meta("n", "baseline_at", "456").unwrap();
    assert_eq!(
        s.get_meta("n", "baseline_at").unwrap().as_deref(),
        Some("456")
    );
    assert_eq!(s.get_meta("m", "baseline_at").unwrap(), None);
}

#[cfg(unix)]
#[test]
fn file_is_0600_and_new_directory_is_0700() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("rhizome.db");
    let s = Store::open(&path).unwrap();
    s.upsert_many("n", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1)])
        .unwrap();
    let fmode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(fmode, 0o600, "{fmode:o}");
    let dmode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dmode, 0o700, "{dmode:o}");
}

#[cfg(unix)]
#[test]
fn existing_parent_directory_permissions_are_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let _s = Store::open(&dir.path().join("x.db")).unwrap();
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn loose_existing_file_is_tightened() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.db");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _s = Store::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn data_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rhizome.db");
    {
        let s = Store::open(&path).unwrap();
        s.upsert_many("n", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 10, 20)])
            .unwrap();
        s.set_meta("n", "baseline_at", "10").unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.load("n").unwrap()[0].last_seen, 20);
    assert_eq!(
        s.get_meta("n", "baseline_at").unwrap().as_deref(),
        Some("10")
    );
    assert_eq!(s.user_version().unwrap(), 2);
}

#[test]
fn large_batches_are_one_transaction_and_fast() {
    let s = Store::open_in_memory().unwrap();
    let devs: Vec<_> = (0..10_000u32)
        .map(|i| {
            dev(
                "10.0.0.2",
                &format!(
                    "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                    (i >> 24) & 255,
                    (i >> 16) & 255,
                    (i >> 8) & 255,
                    i & 255
                ),
                1,
                1,
            )
        })
        .collect();
    let t = std::time::Instant::now();
    s.upsert_many("big", &devs).unwrap();
    assert_eq!(s.load("big").unwrap().len(), 10_000);
    assert!(t.elapsed().as_secs() < 10);
}
