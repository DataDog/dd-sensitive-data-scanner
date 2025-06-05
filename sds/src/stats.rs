use lazy_static::lazy_static;
use metrics::{counter, gauge, Counter, Gauge};
use std::sync::atomic::{AtomicI64, Ordering};

lazy_static! {
    pub static ref GLOBAL_STATS: Stats = Stats::new();
}

pub struct Stats {
    pub scanner_creations: Counter,
    pub scanner_deletions: Counter,

    // Count of total scanners. The actual count is calculated with an atomic
    // since some metrics exporters don't support incrementing gauges (e.g. statsd)
    total_scanners_count: AtomicI64,
    total_scanners: Gauge,

    total_regexes: Gauge,

    total_regex_cache_size_count: AtomicI64,
    total_regex_cache_size: Gauge,

    pub regex_store_errors: Counter,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            scanner_creations: counter!("scanner.creations"),
            scanner_deletions: counter!("scanner.deletions"),
            total_scanners_count: AtomicI64::new(0),
            total_scanners: gauge!("scanner.total_count"),
            total_regexes: gauge!("scanner.total_regexes"),
            total_regex_cache_size_count: AtomicI64::new(0),
            total_regex_cache_size: gauge!("scanner.total_regex_cache_size"),
            regex_store_errors: counter!("scanner.regex_store_error"),
        }
    }

    pub fn increment_total_scanners(&self) {
        self.update_total_scanners(1);
    }

    pub fn decrement_total_scanners(&self) {
        self.update_total_scanners(-1);
    }

    fn update_total_scanners(&self, delta: i64) {
        let prev_value = self
            .total_scanners_count
            .fetch_add(delta, Ordering::Relaxed);
        self.total_scanners.set((prev_value + delta) as f64);
    }

    pub fn set_total_regexes(&self, total_regexes: usize) {
        self.total_regexes.set(total_regexes as f64)
    }

    pub fn add_total_regex_cache(&self, delta: i64) {
        let prev_value = self
            .total_regex_cache_size_count
            .fetch_add(delta, Ordering::Relaxed);
        self.total_regex_cache_size.set((prev_value + delta) as f64);
    }
}
