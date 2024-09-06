use async_trait::async_trait;

use crate::{CompiledRuleDyn, RuleMatch};

use super::match_validator::MatchValidator;

pub struct AwsValidator {
    // Otherwise struct is not allocated by compiler opt
    // will be removed in next PR
    _useless: bool,
}

impl AwsValidator {
    pub fn new() -> Self {
        AwsValidator { _useless: false }
    }
}

#[async_trait]
impl MatchValidator for AwsValidator {
    async fn validate(&self, _: &mut Vec<RuleMatch>, _: &Vec<Box<dyn CompiledRuleDyn>>) {}
}
