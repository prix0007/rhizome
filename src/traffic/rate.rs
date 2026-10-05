//! Turning cumulative byte counters into rates, correctly across counter wrap
//! and resets. Pure: no clock and no I/O.

/// How wide the OS counter is. macOS interface counters are 32-bit (they wrap
/// at 4 GiB, i.e. every few minutes on a busy link); Linux and Windows are
/// 64-bit; router (UPnP) counters can be either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Bits32,
    Bits64,
    /// Unknown: a drop is treated as a 32-bit wrap only if the previous value
    /// was within 2 GiB of the 32-bit limit, otherwise as a counter reset.
    Auto,
}

/// Bytes added between two readings, or `None` when the counter was reset
/// (a drop that cannot be a wrap) and no meaningful delta exists.
pub fn delta_with_wrap(prev: u64, cur: u64, width: Width) -> Option<u64> {
    const LIMIT: u64 = u32::MAX as u64;
    const WRAP_ZONE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB below the 32-bit limit
    if cur >= prev {
        return Some(cur - prev);
    }
    let wrapped = match width {
        Width::Bits32 => prev <= LIMIT,
        Width::Bits64 => false,
        Width::Auto => (LIMIT - WRAP_ZONE..=LIMIT).contains(&prev),
    };
    wrapped.then(|| (1u64 << 32) - prev + cur)
}

/// No real link carries more than this; a larger computed rate means a counter
/// reset that looked like a wrap, so the sample is discarded.
pub const MAX_PLAUSIBLE_BYTES_PER_SEC: f64 = 12.5e9; // 100 Gbit/s

/// Rate of one counter between successive readings.
#[derive(Clone, Debug)]
pub struct CounterRate {
    width: Width,
    last: Option<(u64, i64)>,
}

impl CounterRate {
    pub fn new(width: Width) -> Self {
        Self { width, last: None }
    }

    /// Forget the previous reading (e.g. the interface changed).
    pub fn reset(&mut self) {
        self.last = None;
    }

    /// Feed a reading taken at `ts_ms`; returns bits per second since the
    /// previous reading, or `None` for the first reading, a counter reset,
    /// a non-advancing clock, or an implausible jump.
    pub fn update(&mut self, value: u64, ts_ms: i64) -> Option<f64> {
        let prev = self.last;
        let dt_ms = prev.map(|(_, t)| ts_ms - t);
        if dt_ms.is_some_and(|d| d <= 0) {
            return None; // the clock did not advance: keep the old baseline
        }
        self.last = Some((value, ts_ms));
        let ((pv, _), dt_ms) = (prev?, dt_ms?);
        let bytes = delta_with_wrap(pv, value, self.width)?;
        let per_sec = bytes as f64 / (dt_ms as f64 / 1000.0);
        (per_sec <= MAX_PLAUSIBLE_BYTES_PER_SEC).then_some(per_sec * 8.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_increase() {
        assert_eq!(delta_with_wrap(100, 250, Width::Bits64), Some(150));
        assert_eq!(delta_with_wrap(0, 0, Width::Auto), Some(0));
    }

    #[test]
    fn a_32_bit_counter_that_wraps_adds_the_remainder() {
        let max = u32::MAX as u64;
        assert_eq!(
            delta_with_wrap(max - 99, 50, Width::Bits32),
            Some(150),
            "wrapped past 2^32"
        );
        assert_eq!(delta_with_wrap(max, 0, Width::Bits32), Some(1));
        assert_eq!(
            delta_with_wrap(10, 5, Width::Bits32),
            Some((1u64 << 32) - 5),
            "any drop is a wrap on a 32-bit counter"
        );
    }

    #[test]
    fn a_32_bit_reading_above_the_limit_is_nonsense_and_dropped() {
        assert_eq!(
            delta_with_wrap(100, (u32::MAX as u64) + 5, Width::Bits32),
            Some(u32::MAX as u64 + 5 - 100),
            "a larger value is just an increase"
        );
        assert_eq!(
            delta_with_wrap(u32::MAX as u64 + 10, 3, Width::Bits32),
            None,
            "previous reading cannot be a 32-bit counter"
        );
    }

    #[test]
    fn a_64_bit_drop_is_a_reset_not_a_wrap() {
        assert_eq!(delta_with_wrap(5_000_000_000, 100, Width::Bits64), None);
    }

    #[test]
    fn auto_width_treats_a_drop_near_the_32_bit_limit_as_a_wrap_and_other_drops_as_resets() {
        let max = u32::MAX as u64;
        assert_eq!(delta_with_wrap(max - 1000, 500, Width::Auto), Some(1501));
        assert_eq!(
            delta_with_wrap(1_000_000, 10, Width::Auto),
            None,
            "router reboot"
        );
        assert_eq!(
            delta_with_wrap(3_000_000_000, 10, Width::Auto),
            Some((1u64 << 32) - 3_000_000_000 + 10),
            "within 2 GiB of the top counts as a wrap"
        );
        assert_eq!(
            delta_with_wrap(5_000_000_000, 10, Width::Auto),
            None,
            "already above 32 bits: a 64-bit counter was reset"
        );
    }

    #[test]
    fn the_first_reading_gives_no_rate_and_the_second_gives_bits_per_second() {
        let mut r = CounterRate::new(Width::Bits64);
        assert_eq!(r.update(1_000, 0), None);
        assert_eq!(
            r.update(126_000, 1000),
            Some(1_000_000.0),
            "125 000 bytes in one second = 1 Mbit/s"
        );
    }

    #[test]
    fn rates_scale_with_the_elapsed_time() {
        let mut r = CounterRate::new(Width::Bits64);
        r.update(0, 0);
        assert_eq!(r.update(250_000, 2000), Some(1_000_000.0));
    }

    #[test]
    fn wrap_is_handled_across_updates() {
        let mut r = CounterRate::new(Width::Bits32);
        r.update(u32::MAX as u64 - 62_499, 0);
        // 62 500 bytes before the wrap + 62 500 after, in one second
        assert_eq!(r.update(62_500, 1000), Some(1_000_000.0));
        assert_eq!(
            r.update(62_500 + 125_000, 2000),
            Some(1_000_000.0),
            "and it keeps working afterwards"
        );
    }

    #[test]
    fn a_reset_skips_one_sample_and_then_recovers() {
        let mut r = CounterRate::new(Width::Bits64);
        r.update(1_000_000, 0);
        assert_eq!(r.update(10, 1000), None, "counter went backwards: no rate");
        assert_eq!(
            r.update(125_010, 2000),
            Some(1_000_000.0),
            "the new baseline is used"
        );
    }

    #[test]
    fn clock_problems_and_implausible_jumps_are_discarded() {
        let mut r = CounterRate::new(Width::Bits64);
        r.update(0, 1000);
        assert_eq!(r.update(100, 1000), None, "same timestamp");
        assert_eq!(r.update(200, 900), None, "clock went backwards");
        let mut r = CounterRate::new(Width::Auto);
        r.update(u32::MAX as u64 - 10, 0);
        // looks like a wrap but would be ~34 Gbit/s over 1 s -> still plausible; make it implausible
        assert_eq!(
            r.update(2_000_000_000, 1000),
            Some((2_000_000_000u64 + 11) as f64 * 8.0),
            "an increase is never questioned below the cap"
        );
        let mut r = CounterRate::new(Width::Auto);
        r.update(u32::MAX as u64 - 1_000_000_000, 0);
        // a drop to 1 byte read as a wrap = ~1 GB in 10 ms = 800 Gbit/s: a reset, not a wrap
        assert_eq!(r.update(1, 10), None);
    }

    #[test]
    fn reset_forgets_the_baseline() {
        let mut r = CounterRate::new(Width::Bits64);
        r.update(1_000, 0);
        r.reset();
        assert_eq!(r.update(2_000, 1000), None);
        assert!(r.update(127_000, 2000).is_some());
    }
}
