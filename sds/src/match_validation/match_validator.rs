use crate::{CompiledRuleDyn, RuleMatch};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::vec::Vec;

#[async_trait]
pub trait MatchValidator: Send + Sync {
    async fn validate(
        &self,
        matches: &mut Vec<RuleMatch>,
        scanner_rules: &Vec<Box<dyn CompiledRuleDyn>>,
    );
}

pub struct MatchValidatorOptions {
    pub aws_sts_endpoint: String,
    pub forced_datetime_utc: Option<DateTime<Utc>>,
}

impl Default for MatchValidatorOptions {
    fn default() -> Self {
        Self {
            aws_sts_endpoint: "https://sts.amazonaws.com".to_string(),
            forced_datetime_utc: None,
        }
    }
}
