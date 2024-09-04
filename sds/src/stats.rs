use lazy_static::lazy_static;
use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};

lazy_static! {
    pub static ref GLOBAL_STATS: Stats = Stats::new();
}

pub struct Stats {
    pub scanner_creations: Counter,
    pub scanner_deletions: Counter,

    pub total_scanners: Gauge,

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
            total_scanners: gauge!("scanner.total_count"),
            number_of_rules_per_scanner: histogram!("scanner.num_rules"),
            regex_cache_per_scanner: histogram!("scanner.regex_cache_size"),
        }
    }
}
