// wstrace - Hardware QueryPerformanceCounter (QPC) Timestamps & Microsecond Latency

use std::sync::OnceLock;
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

static QPC_FREQUENCY: OnceLock<i64> = OnceLock::new();

/// Initializes and returns the QPC hardware frequency in counts per second.
/// Caches the frequency atomically to avoid repeated syscalls.
pub fn get_qpc_frequency() -> i64 {
    *QPC_FREQUENCY.get_or_init(|| {
        let mut freq: i64 = 0;
        unsafe {
            if QueryPerformanceFrequency(&mut freq) != 0 && freq > 0 {
                freq
            } else {
                // Fallback frequency (10 MHz is typical on modern Windows systems)
                10_000_000
            }
        }
    })
}

/// Returns the current hardware performance counter value (ticks).
pub fn read_qpc_ticks() -> i64 {
    let mut counter: i64 = 0;
    unsafe {
        QueryPerformanceCounter(&mut counter);
    }
    counter
}

/// Calculates the elapsed duration between two QPC tick values in microseconds (us).
pub fn calculate_elapsed_us(start_ticks: i64, end_ticks: i64) -> u64 {
    if end_ticks <= start_ticks {
        return 0;
    }
    let freq = get_qpc_frequency();
    let delta = end_ticks - start_ticks;
    ((delta as u128 * 1_000_000) / freq as u128) as u64
}

/// Calculates the elapsed duration between two QPC tick values in nanoseconds (ns).
pub fn calculate_elapsed_ns(start_ticks: i64, end_ticks: i64) -> u64 {
    if end_ticks <= start_ticks {
        return 0;
    }
    let freq = get_qpc_frequency();
    let delta = end_ticks - start_ticks;
    ((delta as u128 * 1_000_000_000) / freq as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_qpc_frequency_is_positive() {
        let freq = get_qpc_frequency();
        assert!(freq > 0, "QPC frequency must be greater than zero");
    }

    #[test]
    fn test_qpc_ticks_are_monotonic() {
        let t1 = read_qpc_ticks();
        let t2 = read_qpc_ticks();
        assert!(t2 >= t1, "QPC ticks must be monotonically non-decreasing");
    }

    #[test]
    fn test_calculate_elapsed_us_sleep() {
        let t1 = read_qpc_ticks();
        thread::sleep(Duration::from_millis(5));
        let t2 = read_qpc_ticks();
        let elapsed_us = calculate_elapsed_us(t1, t2);

        // Expect approximately 5,000 us (allow 2,000 us to 50,000 us for scheduler jitter)
        assert!(
            elapsed_us >= 2_000,
            "Elapsed duration should be at least 2ms, got {} us",
            elapsed_us
        );
    }

    #[test]
    fn test_calculate_elapsed_us_when_end_before_start_returns_zero() {
        assert_eq!(calculate_elapsed_us(1000, 500), 0);
        assert_eq!(calculate_elapsed_us(1000, 1000), 0);
    }
}
