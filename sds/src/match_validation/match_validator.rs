use crate::{CompiledRuleDyn, RuleMatch};
use async_trait::async_trait;
use std::vec::Vec;

#[async_trait]
pub trait MatchValidator: Send + Sync {
    // Trait use to validate the matches and update the match status
    // It requires the matches found by the scans and the scanner rules to retrieve the match validation type
    async fn validate(
        &self,
        matches: &mut Vec<RuleMatch>,
        scanner_rules: &Vec<Box<dyn CompiledRuleDyn>>,
    );
}
