//! Per-device packet loss and jitter from a rolling window of ping results.
//! No extra probing: the scan cycle's own ping sweep supplies one sample per
//! device per cycle.

use std::collections::{BTreeMap, VecDeque};

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Samples kept per device (so the window spans this many scan cycles).
pub const WINDOW: usize = 20;
/// Fewer samples than this say nothing useful about loss or jitter.
pub const MIN_SAMPLES: usize = 3;

#[derive(Clone, Debug, Default)]
pub struct QualityWindow {
    samples: VecDeque<Option<f64>>,
}

impl QualityWindow {
    /// One ping attempt: `Some(rtt_ms)` for a reply, `None` for none.
    pub fn push(&mut self, rtt_ms: Option<f64>) {
        if self.samples.len() == WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt_ms);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Percentage of attempts without a reply (one decimal), once there are
    /// at least `MIN_SAMPLES` attempts.
    pub fn loss_pct(&self) -> Option<f64> {
        let n = self.samples.len();
        if n < MIN_SAMPLES {
            return None;
        }
        let lost = self.samples.iter().filter(|s| s.is_none()).count();
        Some(round1(lost as f64 * 100.0 / n as f64))
    }

    /// Mean absolute difference between the round-trip times of consecutive
    /// replies, in milliseconds (one decimal, in the spirit of RFC 3550
    /// interarrival jitter). `None` with fewer than `MIN_SAMPLES` attempts or
    /// without two adjacent replies.
    pub fn jitter_ms(&self) -> Option<f64> {
        if self.samples.len() < MIN_SAMPLES {
            return None;
        }
        let v: Vec<Option<f64>> = self.samples.iter().copied().collect();
        let diffs: Vec<f64> = v
            .windows(2)
            .filter_map(|w| match (w[0], w[1]) {
                (Some(a), Some(b)) => Some((b - a).abs()),
                _ => None,
            })
            .collect();
        (!diffs.is_empty()).then(|| round1(diffs.iter().sum::<f64>() / diffs.len() as f64))
    }
}

/// `(loss_pct, jitter_ms)` per device id.
pub type QualitySnapshot = BTreeMap<String, (Option<f64>, Option<f64>)>;

/// Loss and jitter for every device, by device id.
#[derive(Clone, Debug, Default)]
pub struct QualityBook {
    windows: BTreeMap<String, QualityWindow>,
}

impl QualityBook {
    pub fn record(&mut self, id: &str, rtt_ms: Option<f64>) {
        self.windows.entry(id.to_string()).or_default().push(rtt_ms);
    }

    /// Forget devices that are no longer known.
    pub fn retain_only(&mut self, keep: &dyn Fn(&str) -> bool) {
        self.windows.retain(|id, _| keep(id));
    }

    /// `(loss_pct, jitter_ms)` per device.
    pub fn snapshot(&self) -> QualitySnapshot {
        self.windows
            .iter()
            .map(|(id, w)| (id.clone(), (w.loss_pct(), w.jitter_ms())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(samples: &[Option<f64>]) -> QualityWindow {
        let mut w = QualityWindow::default();
        for s in samples {
            w.push(*s);
        }
        w
    }

    #[test]
    fn loss_needs_a_minimum_number_of_samples() {
        assert_eq!(win(&[]).loss_pct(), None);
        assert_eq!(win(&[None, None]).loss_pct(), None);
        assert_eq!(win(&[None, None, None]).loss_pct(), Some(100.0));
    }

    #[test]
    fn loss_is_the_share_of_missing_replies() {
        let w = win(&[Some(1.0), None, Some(1.0), Some(1.0)]);
        assert_eq!(w.loss_pct(), Some(25.0));
        assert_eq!(win(&[Some(1.0); 5]).loss_pct(), Some(0.0));
        assert_eq!(win(&[Some(1.0), Some(1.0), None]).loss_pct(), Some(33.3));
    }

    #[test]
    fn the_window_is_rolling() {
        let mut w = QualityWindow::default();
        for _ in 0..WINDOW {
            w.push(None);
        }
        assert_eq!(w.loss_pct(), Some(100.0));
        for _ in 0..WINDOW {
            w.push(Some(2.0));
        }
        assert_eq!(w.len(), WINDOW);
        assert_eq!(w.loss_pct(), Some(0.0), "old losses have rolled out");
    }

    #[test]
    fn jitter_is_the_mean_absolute_difference_of_consecutive_replies() {
        let w = win(&[Some(10.0), Some(12.0), Some(11.0), Some(15.0)]);
        // |12-10| = 2, |11-12| = 1, |15-11| = 4  ->  7 / 3
        assert_eq!(w.jitter_ms(), Some(2.3));
        assert_eq!(
            win(&[Some(5.0), Some(5.0), Some(5.0)]).jitter_ms(),
            Some(0.0)
        );
    }

    #[test]
    fn jitter_ignores_pairs_split_by_a_lost_reply_and_needs_two_adjacent_replies() {
        assert_eq!(win(&[Some(10.0)]).jitter_ms(), None);
        assert_eq!(
            win(&[Some(10.0), Some(12.0)]).jitter_ms(),
            None,
            "two samples are too few to call it jitter"
        );
        assert_eq!(
            win(&[Some(10.0), None, Some(50.0)]).jitter_ms(),
            None,
            "not adjacent, no pair"
        );
        let w = win(&[Some(10.0), None, Some(50.0), Some(52.0)]);
        assert_eq!(w.jitter_ms(), Some(2.0));
    }

    #[test]
    fn the_book_tracks_devices_independently_and_forgets_the_missing() {
        let mut b = QualityBook::default();
        for i in 0..4 {
            b.record("a", Some(1.0 + i as f64));
            b.record("b", if i % 2 == 0 { Some(1.0) } else { None });
        }
        let s = b.snapshot();
        assert_eq!(s["a"].0, Some(0.0));
        assert_eq!(s["a"].1, Some(1.0));
        assert_eq!(s["b"].0, Some(50.0));
        assert_eq!(s["b"].1, None);
        b.retain_only(&|id| id == "a");
        assert!(b.snapshot().contains_key("a") && !b.snapshot().contains_key("b"));
    }

    #[test]
    fn nothing_is_reported_for_a_device_with_too_little_history() {
        let mut b = QualityBook::default();
        b.record("a", Some(1.0));
        let s = b.snapshot();
        assert_eq!(s["a"], (None, None));
    }
}
