use crate::Labels;
use metrics::{counter, Counter};

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
    pub num_matches: Counter,
    pub event_size_bytes: Counter,
}

impl ScannerMetrics {
    pub fn new(labels: &Labels) -> Self {
        ScannerMetrics {
            num_scanned_events: counter!("scanned_events", labels.clone()),
            duration_ns: counter!("scanning.duration", labels.clone()),
            num_matches: counter!("scanning.num_matches", labels.clone()),
            event_size_bytes: counter!("scanned_bytes", labels.clone()),
        }
    }
}
