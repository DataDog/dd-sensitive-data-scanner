use lazy_static::lazy_static;
use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};
use std::sync::atomic::{AtomicI64, Ordering};

lazy_static! {
    pub static ref GLOBAL_STATS: Stats = Stats::new();
}

pub struct Stats {
    pub scanner_creations: Counter,
    pub scanner_deletions: Counter,

    // Count of total scanners. The actual count is calculated with an atomic
    // since some metrics exporters don't supporting incrementing gauges (e.g. statsd)
    total_scanners_count: AtomicI64,
    total_scanners: Gauge,

    // The total number of rules in a scanner
    pub number_of_rules_per_scanner: Histogram,

    // The total amount of memory used for a single set of regex caches for a single scanner
    pub regex_cache_per_scanner: Histogram,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            scanner_creations: counter!("scanner.creations"),
            scanner_deletions: counter!("scanner.deletions"),
            total_scanners_count: AtomicI64::new(0),
            total_scanners: gauge!("scanner.total_count"),
            number_of_rules_per_scanner: histogram!("scanner.num_rules"),
            regex_cache_per_scanner: histogram!("scanner.regex_cache_size"),
        }
    }

    pub fn increment_total_scanners(&self) {
        self.update_total_scanners(1);
    }

    pub fn decrement_total_scanners(&self) {
        self.update_total_scanners(-1);
    }

    fn update_total_scanners(&self, delta: i64) {
        let prev_value = self.total_scanners_count.fetch_add(delta, Ordering::SeqCst);
        self.total_scanners.set((prev_value + delta) as f64);
    }
}
