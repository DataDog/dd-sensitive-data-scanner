use crate::Labels;
use metrics::{Counter, Histogram, counter, histogram};

pub struct RuleMetrics {
    pub false_positive_excluded_attributes: Counter,
}

impl RuleMetrics {
    pub fn new(labels: &Labels) -> Self {
        RuleMetrics {
            false_positive_excluded_attributes: counter!(
                "false_positive.multipass.excluded_match",
                labels.clone()
            ),
        }
    }
}

pub struct ScannerMetrics {
    pub num_scanned_events: Counter,
    pub duration_ns: Counter,
    pub match_count: Counter,
    pub suppressed_match_count: Counter,
    pub cpu_duration: Histogram,
}

impl ScannerMetrics {
    pub fn new(labels: &Labels, highcard_labels: &Labels) -> Self {
        ScannerMetrics {
            num_scanned_events: counter!("scanned_events", labels.clone()),
            duration_ns: counter!("scanning.duration", labels.clone()),
            match_count: counter!("scanning.match_count", labels.clone()),
            suppressed_match_count: counter!("scanning.suppressed_match_count", labels.clone()),
            cpu_duration: histogram!("scanning.cpu_duration", highcard_labels.clone()),
        }
    }
}
