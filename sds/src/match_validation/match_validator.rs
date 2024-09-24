use crate::{CompiledRuleDyn, RuleMatch};
use async_trait::async_trait;
use std::vec::Vec;

#[async_trait]
pub trait MatchValidator: Send + Sync {
    async fn validate(
        &self,
        matches: &mut Vec<RuleMatch>,
        scanner_rules: &Vec<Box<dyn CompiledRuleDyn>>,
    );
}
