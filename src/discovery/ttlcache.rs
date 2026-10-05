//! A small bounded cache with per-entry expiry. Slow sources (UPnP, DNS,
//! NetBIOS) are looked up through it so a scan cycle never waits on them twice.

use std::collections::BTreeMap;

pub struct TtlCache<K: Ord + Clone, V: Clone> {
    map: BTreeMap<K, (V, i64)>,
    cap: usize,
}

impl<K: Ord + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(cap: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The value if present and not expired at `now` (ms).
    pub fn get(&self, key: &K, now: i64) -> Option<&V> {
        self.map
            .get(key)
            .filter(|(_, exp)| *exp > now)
            .map(|(v, _)| v)
    }

    /// Store with a lifetime. Known keys are always replaced; a new key is
    /// refused when the cache is full of unexpired entries. Returns whether stored.
    pub fn put(&mut self, key: K, value: V, now: i64, ttl_ms: i64) -> bool {
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            self.map.retain(|_, (_, exp)| *exp > now);
            if self.map.len() >= self.cap {
                return false;
            }
        }
        self.map.insert(key, (value, now.saturating_add(ttl_ms)));
        true
    }

    /// All unexpired entries.
    pub fn live(&self, now: i64) -> Vec<(K, V)> {
        self.map
            .iter()
            .filter(|(_, (_, exp))| *exp > now)
            .map(|(k, (v, _))| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_expire() {
        let mut c: TtlCache<u32, &str> = TtlCache::new(8);
        assert!(c.put(1, "a", 1000, 500));
        assert_eq!(c.get(&1, 1499), Some(&"a"));
        assert_eq!(c.get(&1, 1500), None, "expired exactly at the deadline");
        assert_eq!(c.get(&2, 0), None);
    }

    #[test]
    fn replacing_a_key_resets_its_lifetime() {
        let mut c: TtlCache<u32, u32> = TtlCache::new(8);
        c.put(1, 10, 0, 100);
        c.put(1, 20, 90, 100);
        assert_eq!(c.get(&1, 150), Some(&20));
    }

    #[test]
    fn the_cache_is_bounded_and_expired_entries_make_room() {
        let mut c: TtlCache<u32, u32> = TtlCache::new(2);
        assert!(c.put(1, 1, 0, 1000));
        assert!(c.put(2, 2, 0, 100));
        assert!(!c.put(3, 3, 50, 1000), "full of live entries");
        assert!(c.put(1, 11, 50, 1000), "known keys can always be replaced");
        assert!(c.put(3, 3, 150, 1000), "entry 2 expired, so there is room");
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(&2, 150), None);
    }

    #[test]
    fn live_lists_only_unexpired() {
        let mut c: TtlCache<u32, u32> = TtlCache::new(8);
        c.put(1, 1, 0, 100);
        c.put(2, 2, 0, 1000);
        assert_eq!(c.live(500), vec![(2, 2)]);
    }
}
