//! IEEE OUI (MA-L) vendor lookup. The registry CSV is embedded at compile time.

use std::sync::OnceLock;

use crate::enrich::sanitize::sanitize;
use crate::model::MacAddr;

pub struct OuiDb {
    entries: Vec<(u32, Box<str>)>,
    duplicate_rows: usize,
}

impl std::fmt::Debug for OuiDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OuiDb({} entries)", self.entries.len())
    }
}

impl OuiDb {
    pub fn from_csv(csv: &str) -> Self {
        let mut rows: Vec<(u32, Box<str>)> = Vec::new();
        for rec in parse_csv(csv) {
            if rec.len() < 3 {
                continue;
            }
            let prefix = rec[1].trim();
            if prefix.len() != 6 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let Ok(key) = u32::from_str_radix(prefix, 16) else {
                continue;
            };
            let name = sanitize(&rec[2]);
            if name.is_empty() {
                continue;
            }
            rows.push((key, name.into_boxed_str()));
        }
        let total = rows.len();
        rows.sort_by_key(|r| r.0); // stable: the first row for a prefix wins
        rows.dedup_by_key(|r| r.0);
        let duplicate_rows = total - rows.len();
        Self {
            entries: rows,
            duplicate_rows,
        }
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        let key = mac.oui();
        self.entries
            .binary_search_by_key(&key, |e| e.0)
            .ok()
            .map(|i| &*self.entries[i].1)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// True when every prefix appears exactly once (the lookup invariant).
    pub fn has_unique_sorted_prefixes(&self) -> bool {
        self.entries.windows(2).all(|w| w[0].0 < w[1].0)
    }
    /// Rows dropped because their prefix had already appeared.
    pub fn duplicate_rows(&self) -> usize {
        self.duplicate_rows
    }
    pub fn embedded() -> &'static OuiDb {
        static DB: OnceLock<OuiDb> = OnceLock::new();
        DB.get_or_init(|| OuiDb::from_csv(include_str!("../../data/oui.csv")))
    }
}

/// Minimal RFC 4180 reader: quoted fields may contain commas, doubled quotes
/// and newlines. An unterminated quote swallows the rest of the input.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut rec: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => in_quotes = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            ',' => rec.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                rec.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut rec));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !rec.is_empty() {
        rec.push(field);
        records.push(rec);
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: &str = include_str!("../../tests/fixtures/oui_small.csv");

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fixture_hit_and_miss() {
        let db = OuiDb::from_csv(SMALL);
        assert_eq!(
            db.lookup(mac("68:7f:f0:00:00:01")),
            Some("Acme Networks, Inc.")
        );
        assert_eq!(db.lookup(mac("8c:fd:49:0:0:4")), Some("Plain Vendor Ltd"));
        assert_eq!(db.lookup(mac("de:ad:be:ef:00:01")), None);
    }

    #[test]
    fn lookup_is_insensitive_to_case_and_separator() {
        let db = OuiDb::from_csv(SMALL);
        for s in [
            "68:7F:F0:00:00:01",
            "68-7f-f0-00-00-01",
            "687FF0:00:00:01".replace("687FF0", "68:7f:f0").as_str(),
        ] {
            assert_eq!(db.lookup(mac(s)), Some("Acme Networks, Inc."), "{s}");
        }
        assert_eq!(
            db.lookup(mac("0:a0:c9:1:2:3")),
            Some("Quote \"Corp\""),
            "lowercase hex in the CSV and escaped quotes"
        );
    }

    #[test]
    fn quoted_fields_with_commas_and_newlines_parse() {
        let db = OuiDb::from_csv(SMALL);
        assert_eq!(
            db.lookup(mac("68:7f:f0:0:0:0")),
            Some("Acme Networks, Inc.")
        );
    }

    #[test]
    fn malformed_and_empty_rows_are_skipped_and_duplicates_counted() {
        let db = OuiDb::from_csv(SMALL);
        // 687FF0, 8CFD49, 00A0C9, AABBCC kept; bad hex, short prefix and empty name skipped.
        assert_eq!(db.len(), 4);
        assert_eq!(db.duplicate_rows(), 1);
        assert_eq!(db.lookup(mac("0:11:22:0:0:0")), None);
    }

    #[test]
    fn empty_and_garbage_input() {
        assert!(OuiDb::from_csv("").is_empty());
        assert!(OuiDb::from_csv("\"unterminated,quote\nMA-L,AABBCC").len() <= 1);
    }

    #[test]
    fn embedded_registry_is_large_and_has_no_duplicate_prefixes() {
        let db = OuiDb::embedded();
        assert!(db.len() > 30_000, "only {} entries", db.len());
        assert!(
            db.has_unique_sorted_prefixes(),
            "no duplicate prefixes in the lookup table"
        );
        // The raw IEEE file itself contains a few legacy prefixes assigned twice
        // (e.g. 080030, 0001C8); the first row wins and the rest are dropped.
        assert!(
            db.duplicate_rows() <= 10,
            "{} duplicate rows in source",
            db.duplicate_rows()
        );
    }

    #[test]
    fn embedded_registry_knows_well_known_prefixes() {
        let db = OuiDb::embedded();
        assert!(db.lookup(mac("00:03:93:0:0:0")).unwrap().contains("Apple"));
    }
}
