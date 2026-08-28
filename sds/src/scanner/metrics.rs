use crate::Labels;
use metrics::{Counter, counter};
use std::collections::BTreeMap;

/// Computes the `"{sensitive_data_category}/{sensitive_data}"` tag value for a rule from its
/// `tags`. Missing `sensitive_data_category` falls back to `"missing_category"`. Missing
/// `sensitive_data` yields `None`, since there's nothing meaningful to tag with.
pub fn compute_sds_rule_name(tags: &BTreeMap<String, String>) -> Option<String> {
    let sensitive_data = tags.get("sensitive_data")?;
    let sensitive_data_category = tags
        .get("sensitive_data_category")
        .map(String::as_str)
        .unwrap_or("missing_category");
    Some(format!("{sensitive_data_category}/{sensitive_data}"))
}

#[derive(Clone)]
pub struct RuleMetrics {
    /// Pre-initialized counter for the fast path (debug observability disabled).
    pub false_positive_excluded_attributes: Counter,
    /// Base labels when debug observability enabled,
    /// used to attach the `sds_namespace` tag dynamically.
    pub base_labels: Labels,
}

impl RuleMetrics {
    pub fn new(labels: &Labels) -> Self {
        RuleMetrics {
            false_positive_excluded_attributes: counter!(
                "false_positive.multipass.excluded_match",
                labels.clone()
            ),
            base_labels: labels.clone(),
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

#[cfg(test)]
mod test {
    use super::compute_sds_rule_name;
    use std::collections::BTreeMap;

    #[test]
    fn compute_sds_rule_name_returns_none_for_empty_tags() {
        assert_eq!(compute_sds_rule_name(&BTreeMap::new()), None);
    }

    #[test]
    fn compute_sds_rule_name_concatenates_category_and_data() {
        let tags = BTreeMap::from([
            (
                "sensitive_data_category".to_string(),
                "credentials".to_string(),
            ),
            (
                "sensitive_data".to_string(),
                "travis_ci_access_token".to_string(),
            ),
        ]);
        assert_eq!(
            compute_sds_rule_name(&tags),
            Some("credentials/travis_ci_access_token".to_string())
        );
    }

    #[test]
    fn compute_sds_rule_name_returns_none_when_category_present_but_data_missing() {
        let tags = BTreeMap::from([(
            "sensitive_data_category".to_string(),
            "credentials".to_string(),
        )]);
        assert_eq!(compute_sds_rule_name(&tags), None);
    }

    #[test]
    fn compute_sds_rule_name_falls_back_to_missing_category_when_category_absent() {
        let tags = BTreeMap::from([(
            "sensitive_data".to_string(),
            "travis_ci_access_token".to_string(),
        )]);
        assert_eq!(
            compute_sds_rule_name(&tags),
            Some("missing_category/travis_ci_access_token".to_string())
        );
    }
}
