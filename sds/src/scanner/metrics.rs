use crate::Labels;
use metrics::{Counter, counter};

#[derive(Clone)]
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
/*
 * Scanning metrics
 *
 * duration_ns: Total time from scan start to completion
 * num_scanned_events: Number of scanned events
 * match_count: Number of matches found
 * suppressed_match_count: Number of matches suppressed
 * cpu_duration: Time spent in CPU operations
 *
 * In case of too high cardinality, please refer to https://github.com/DataDog/logs-backend/blob/prod/domains/commons/shared/libs/telemetry/src/main/java/com/dd/metrics/RegistryCacheTags.java
 */
pub struct ScannerMetrics {
    pub num_scanned_events: Counter,
    pub match_count: Counter,
    pub suppressed_match_count: Counter,
    pub cpu_duration: Counter,
}

impl ScannerMetrics {
    pub fn new(labels: &Labels) -> Self {
        ScannerMetrics {
            num_scanned_events: counter!("scanned_events", labels.clone()),
            match_count: counter!("scanning.match_count", labels.clone()),
            suppressed_match_count: counter!("scanning.suppressed_match_count", labels.clone()),
            cpu_duration: counter!("scanning.cpu_duration", labels.clone()),
        }
    }
}
