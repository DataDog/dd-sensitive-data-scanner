use crate::Labels;
use metrics::{Counter, counter};

#[derive(Clone)]
pub struct RuleMetrics {
    pub false_positive_excluded_attributes: Counter,
    pub match_count: Counter,
    pub suppressed_match_count: Counter,
}

impl RuleMetrics {
    pub fn new(labels: &Labels) -> Self {
        RuleMetrics {
            false_positive_excluded_attributes: counter!(
                "false_positive.multipass.excluded_match",
                labels.clone()
            ),
            match_count: counter!("scanning.match_count", labels.clone()),
            suppressed_match_count: counter!("scanning.suppressed_match_count", labels.clone()),
        }
    }
}

/*
 * Scanning metrics
 *
 * Per-scanner (ScannerMetrics, scanner-level labels only):
 *   scanned_events: Number of scan calls
 *   scanning.cpu_duration: CPU time spent per scan (excludes async I/O wait)
 *
 * Per-rule (RuleMetrics, combined scanner+rule labels):
 *   scanning.match_count: Matches reported to the caller (post-suppression), per rule
 *   scanning.suppressed_match_count: Matches suppressed before reaching the caller, per rule
 *   false_positive.multipass.excluded_match: Multipass V0 false positives, per rule
 *
 * In case of too high cardinality, please refer to https://github.com/DataDog/logs-backend/blob/prod/domains/commons/shared/libs/telemetry/src/main/java/com/dd/metrics/RegistryCacheTags.java
 */
pub struct ScannerMetrics {
    pub num_scanned_events: Counter,
    pub cpu_duration: Counter,
}

impl ScannerMetrics {
    pub fn new(labels: &Labels) -> Self {
        ScannerMetrics {
            num_scanned_events: counter!("scanned_events", labels.clone()),
            cpu_duration: counter!("scanning.cpu_duration", labels.clone()),
        }
    }
}
