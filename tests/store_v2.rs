//! Schema v2: learned device fields and user metadata, plus migration from v1.

mod common;
use common::device;
use rhizome::store::Store;

fn dev(ip: &str, mac: &str, first: i64, last: i64) -> rhizome::model::Device {
    let mut d = device(ip, mac, false);
    d.first_seen = first;
    d.last_seen = last;
    d
}

const V1_SCHEMA: &str = "
CREATE TABLE devices (
    network_id TEXT NOT NULL, id TEXT NOT NULL, mac TEXT NOT NULL, last_ip TEXT NOT NULL,
    hostname TEXT, vendor TEXT, kind TEXT NOT NULL, randomized INTEGER NOT NULL,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY (network_id, id)
);
CREATE TABLE meta (network_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (network_id, key));
PRAGMA user_version = 1;
";

fn make_v1_db(path: &std::path::Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(V1_SCHEMA).unwrap();
    c.execute(
        "INSERT INTO devices VALUES ('net1','aa:bb:cc:dd:ee:01','aa:bb:cc:dd:ee:01','10.0.0.2','old-host','Acme','printer',0,100,200)",
        [],
    )
    .unwrap();
    c.execute("INSERT INTO meta VALUES ('net1','baseline_at','50')", [])
        .unwrap();
}

#[test]
fn a_database_created_by_the_previous_schema_migrates_in_place_and_keeps_its_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    make_v1_db(&path);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.user_version().unwrap(), 2);
    let rows = s.load("net1").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].hostname.as_deref(), Some("old-host"));
    assert_eq!((rows[0].first_seen, rows[0].last_seen), (100, 200));
    assert_eq!(rows[0].custom_name, None);
    assert_eq!(rows[0].friendly_name, None);
    assert_eq!(
        s.get_meta("net1", "baseline_at").unwrap().as_deref(),
        Some("50")
    );
    // the new columns are usable
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 100, 300);
    d.friendly_name = Some("Office printer".into());
    d.model = Some("LaserJet".into());
    s.upsert_many("net1", &[d]).unwrap();
    assert_eq!(
        s.load("net1").unwrap()[0].friendly_name.as_deref(),
        Some("Office printer")
    );
}

#[test]
fn migration_is_idempotent_across_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    make_v1_db(&path);
    for _ in 0..3 {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.user_version().unwrap(), 2);
        s.migrate().unwrap();
        assert_eq!(s.load("net1").unwrap().len(), 1);
    }
}

#[test]
fn a_fresh_database_gets_the_same_final_schema() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.user_version().unwrap(), 2);
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1);
    d.model = Some("m".into());
    s.upsert_many("n", &[d]).unwrap();
    assert_eq!(s.load("n").unwrap()[0].model.as_deref(), Some("m"));
}

#[test]
fn learned_fields_round_trip_and_show_for_restored_devices() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 5);
    d.friendly_name = Some("Living Room".into());
    d.manufacturer = Some("Google Inc.".into());
    d.model = Some("Chromecast".into());
    d.dns_name = Some("chromecast.lan".into());
    d.netbios_name = Some("CAST".into());
    d.os_hint = Some("Linux/Unix/macOS-like".into());
    d.rtt_ms = Some(1.5); // transient: never stored
    s.upsert_many("n", &[d]).unwrap();
    let back = s.load("n").unwrap().remove(0).into_device().unwrap();
    assert_eq!(back.friendly_name.as_deref(), Some("Living Room"));
    assert_eq!(back.manufacturer.as_deref(), Some("Google Inc."));
    assert_eq!(back.model.as_deref(), Some("Chromecast"));
    assert_eq!(back.dns_name.as_deref(), Some("chromecast.lan"));
    assert_eq!(back.netbios_name.as_deref(), Some("CAST"));
    assert_eq!(back.os_hint.as_deref(), Some("Linux/Unix/macOS-like"));
    assert_eq!(back.rtt_ms, None);
    assert!(!back.online);
}

#[test]
fn user_metadata_persists_and_is_never_clobbered_by_device_upserts() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 5);
    s.upsert_many("n", &[d.clone()]).unwrap();
    d.custom_name = Some("Dad's phone".into());
    d.notes = Some("do not remove".into());
    s.set_user_meta("n", &d).unwrap();
    // later scans upsert a copy of the device that knows nothing about the user's edits
    let plain = dev("10.0.0.9", "aa:bb:cc:dd:ee:01", 1, 99);
    s.upsert_many("n", &[plain]).unwrap();
    let row = s.load("n").unwrap().remove(0);
    assert_eq!(row.custom_name.as_deref(), Some("Dad's phone"));
    assert_eq!(row.notes.as_deref(), Some("do not remove"));
    assert_eq!(row.last_ip, "10.0.0.9");
    let back = row.into_device().unwrap();
    assert_eq!(back.custom_name.as_deref(), Some("Dad's phone"));
}

#[test]
fn user_metadata_can_be_cleared_and_is_scoped_per_network() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 5);
    d.custom_name = Some("x".into());
    s.set_user_meta("a", &d).unwrap(); // also inserts the row if the device is not stored yet
    s.upsert_many("b", &[dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 5)])
        .unwrap();
    assert_eq!(s.load("a").unwrap()[0].custom_name.as_deref(), Some("x"));
    assert_eq!(s.load("b").unwrap()[0].custom_name, None);
    d.custom_name = None;
    s.set_user_meta("a", &d).unwrap();
    assert_eq!(s.load("a").unwrap()[0].custom_name, None);
}

#[test]
fn hostile_user_text_round_trips_verbatim() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 5);
    d.custom_name = Some("'); DROP TABLE devices;--".into());
    d.notes = Some("\" OR 1=1 --".into());
    s.set_user_meta("n", &d).unwrap();
    let r = s.load("n").unwrap().remove(0);
    assert_eq!(r.custom_name.as_deref(), Some("'); DROP TABLE devices;--"));
    assert_eq!(r.notes.as_deref(), Some("\" OR 1=1 --"));
}

// ---- review fixes ----

#[test]
fn a_database_from_a_newer_binary_is_refused_with_a_clear_error_and_left_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.db");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE devices (x INTEGER); INSERT INTO devices VALUES (7); PRAGMA user_version = 3;",
        )
        .unwrap();
    }
    let err = match Store::open(&path) {
        Ok(_) => panic!("must refuse a newer database"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("newer") && err.contains('3'), "{err}");
    let c = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3, "not downgraded or modified");
    let n: i64 = c
        .query_row("SELECT x FROM devices", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 7);
}

#[test]
fn migration_runs_in_one_immediate_transaction_so_two_openers_cannot_both_migrate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    make_v1_db(&path);
    let p1 = path.clone();
    let p2 = path.clone();
    let a = std::thread::spawn(move || Store::open(&p1).map(|s| s.user_version().unwrap()));
    let b = std::thread::spawn(move || Store::open(&p2).map(|s| s.user_version().unwrap()));
    let (ra, rb) = (a.join().unwrap(), b.join().unwrap());
    // neither may die on "duplicate column"; at worst one waits for the other's lock
    for r in [ra, rb] {
        assert_eq!(r.expect("both openers succeed"), 2);
    }
}

#[test]
fn a_newer_observation_replaces_the_stored_learned_value() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1);
    d.model = Some("Forged".into());
    d.dns_name = Some("old.lan".into());
    d.os_hint = Some("Windows-like".into());
    s.upsert_many("n", &[d.clone()]).unwrap();
    d.model = Some("Real".into());
    d.dns_name = Some("new.lan".into());
    d.os_hint = Some("Linux/Unix/macOS-like".into());
    s.upsert_many("n", &[d]).unwrap();
    let r = s.load("n").unwrap().remove(0);
    assert_eq!(
        r.model.as_deref(),
        Some("Real"),
        "a forged value is not pinned forever"
    );
    assert_eq!(r.dns_name.as_deref(), Some("new.lan"));
    assert_eq!(r.os_hint.as_deref(), Some("Linux/Unix/macOS-like"));
}

#[test]
fn a_value_the_device_no_longer_has_is_cleared_in_the_database_too() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1);
    d.netbios_name = Some("OLDPC".into());
    d.friendly_name = Some("Old".into());
    s.upsert_many("n", &[d.clone()]).unwrap();
    d.netbios_name = None;
    d.friendly_name = None;
    s.upsert_many("n", &[d]).unwrap();
    let r = s.load("n").unwrap().remove(0);
    assert_eq!((r.netbios_name, r.friendly_name), (None, None));
}

#[test]
fn replacing_or_clearing_learned_values_never_touches_the_users_name_or_notes() {
    let s = Store::open_in_memory().unwrap();
    let mut d = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 1);
    d.custom_name = Some("Mine".into());
    d.notes = Some("n".into());
    d.model = Some("A".into());
    s.set_user_meta("n", &d).unwrap();
    let mut scan = dev("10.0.0.2", "aa:bb:cc:dd:ee:01", 1, 2); // knows nothing of the user's edits
    scan.model = None;
    s.upsert_many("n", &[scan]).unwrap();
    let r = s.load("n").unwrap().remove(0);
    assert_eq!(r.model, None);
    assert_eq!(
        (r.custom_name.as_deref(), r.notes.as_deref()),
        (Some("Mine"), Some("n"))
    );
}
