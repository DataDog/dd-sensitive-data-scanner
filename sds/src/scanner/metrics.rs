use crate::labels::{Labels};
use metrics::{counter, Counter};

pub struct Metrics {
    pub false_positive_excluded_attributes: Counter,
}

impl Metrics {
    pub fn new(labels: &Labels) -> Self {
        Metrics {
            false_positive_excluded_attributes: counter!(
                "false_positive.multipass.excluded_match",
                labels.clone()
            ),
        }
    }
}
