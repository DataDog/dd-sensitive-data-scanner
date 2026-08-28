use crate::Labels;
use metrics::{Counter, counter};

/// Looks up the value of a `"key:value"` tag entry by key, matching the format used by
/// standard rule definitions (e.g. `sensitive_data:travis_ci_access_token`).
fn get_tag_value<'a>(tags: &'a [String], key: &str) -> Option<&'a str> {
    let prefix_len = key.len() + 1;
    tags.iter().find_map(|tag| {
        (tag.len() > prefix_len && tag.starts_with(key) && tag.as_bytes()[key.len()] == b':')
            .then(|| &tag[prefix_len..])
    })
}

/// Computes the `"{sensitive_data_category}/{sensitive_data}"` tag value for a rule from its
/// `tags`. Missing `sensitive_data_category` falls back to `"missing_category"`. Missing
/// `sensitive_data` yields `None`, since there's nothing meaningful to tag with.
pub fn compute_sds_rule_name(tags: &[String]) -> Option<String> {
    let sensitive_data = get_tag_value(tags, "sensitive_data")?;
    let sensitive_data_category =
        get_tag_value(tags, "sensitive_data_category").unwrap_or("missing_category");
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

    #[test]
    fn compute_sds_rule_name_returns_none_for_empty_tags() {
        assert_eq!(compute_sds_rule_name(&[]), None);
    }

    #[test]
    fn compute_sds_rule_name_concatenates_category_and_data() {
        let tags = vec![
            "sensitive_data_category:credentials".to_string(),
            "sensitive_data:travis_ci_access_token".to_string(),
        ];
        assert_eq!(
            compute_sds_rule_name(&tags),
            Some("credentials/travis_ci_access_token".to_string())
        );
    }

    #[test]
    fn compute_sds_rule_name_returns_none_when_category_present_but_data_missing() {
        let tags = vec!["sensitive_data_category:credentials".to_string()];
        assert_eq!(compute_sds_rule_name(&tags), None);
    }

    #[test]
    fn compute_sds_rule_name_falls_back_to_missing_category_when_category_absent() {
        let tags = vec!["sensitive_data:travis_ci_access_token".to_string()];
        assert_eq!(
            compute_sds_rule_name(&tags),
            Some("missing_category/travis_ci_access_token".to_string())
        );
    }

    #[test]
    fn compute_sds_rule_name_does_not_confuse_sensitive_data_category_with_sensitive_data() {
        // "sensitive_data_category" starts with the "sensitive_data" key, so the lookup
        // must not mistake one tag for the other.
        let tags = vec!["sensitive_data_category:credentials".to_string()];
        assert_eq!(compute_sds_rule_name(&tags), None);
    }

    #[test]
    fn compute_sds_rule_name_ignores_malformed_tags_without_a_colon() {
        let tags = vec!["sensitive_data".to_string()];
        assert_eq!(compute_sds_rule_name(&tags), None);
    }
}
