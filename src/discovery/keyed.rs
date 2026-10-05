//! A value that is tied to a key (here: an interface name). Restarted when the
//! key changes; failures are never cached, so the next call retries.

use std::sync::Mutex;

pub struct Keyed<T: Clone> {
    slot: Mutex<Option<(String, T)>>,
}

impl<T: Clone> Default for Keyed<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Keyed<T> {
    pub fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// Return the value for `key`, calling `start` only when there is none yet
    /// or the key changed. The previous value (for another key) is dropped.
    pub fn get_or_start(
        &self,
        key: &str,
        start: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((k, v)) = slot.as_ref()
            && k == key
        {
            return Ok(v.clone());
        }
        // Different key (or nothing yet): drop the old value before starting the new one.
        *slot = None;
        let v = start()?;
        *slot = Some((key.to_string(), v.clone()));
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Arc;

    #[test]
    fn started_once_per_key() {
        let k: Keyed<u32> = Keyed::new();
        let calls = Cell::new(0);
        let start = || {
            calls.set(calls.get() + 1);
            Ok(7)
        };
        assert_eq!(k.get_or_start("en0", start), Ok(7));
        assert_eq!(k.get_or_start("en0", start), Ok(7));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn restarted_when_the_key_changes_and_old_value_is_dropped() {
        let k: Keyed<Arc<()>> = Keyed::new();
        let first = Arc::new(());
        let f = first.clone();
        k.get_or_start("en0", move || Ok(f)).unwrap();
        assert_eq!(Arc::strong_count(&first), 2);
        k.get_or_start("en8", || Ok(Arc::new(()))).unwrap();
        assert_eq!(
            Arc::strong_count(&first),
            1,
            "the en0 value must be dropped when en8 takes over"
        );
    }

    #[test]
    fn failures_are_not_cached() {
        let k: Keyed<u32> = Keyed::new();
        let calls = Rc::new(Cell::new(0));
        let c = calls.clone();
        assert_eq!(
            k.get_or_start("en0", || {
                c.set(c.get() + 1);
                Err("bind failed".into())
            }),
            Err("bind failed".to_string())
        );
        let c = calls.clone();
        assert_eq!(
            k.get_or_start("en0", || {
                c.set(c.get() + 1);
                Ok(1)
            }),
            Ok(1)
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn a_failure_after_a_success_for_a_new_key_leaves_no_stale_value() {
        let k: Keyed<u32> = Keyed::new();
        k.get_or_start("en0", || Ok(1)).unwrap();
        assert!(k.get_or_start("en8", || Err("nope".into())).is_err());
        let calls = Cell::new(0);
        k.get_or_start("en8", || {
            calls.set(1);
            Ok(2)
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
    }
}
