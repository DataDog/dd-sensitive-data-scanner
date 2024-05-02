use crate::labels::{Labels, NO_LABEL};
use metrics::{counter, Counter};

pub struct Metrics {
    pub false_positive_excluded_attributes: Counter,
}

const TYPE: &str = "type";

impl Metrics {
    pub fn new(labels: &Labels) -> Self {
        Metrics {
            false_positive_excluded_attributes: counter!(
                "false_positive.excluded_attributes",
                labels.clone_with_labels(Labels::new(&[(TYPE, "excluded_attributes".to_string())]))
            ),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new(&NO_LABEL)
    }
}
