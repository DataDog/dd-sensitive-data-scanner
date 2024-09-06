use super::match_validator::MatchValidator;
use crate::{CompiledRuleDyn, RuleMatch};
use async_trait::async_trait;

pub struct HttpValidator {
    // Otherwise struct is not allocated by compiler opt
    // will be removed in next PR
    _useless: bool,
}

impl HttpValidator {
    pub fn new() -> Self {
        HttpValidator { _useless: false }
    }
}

#[async_trait]
impl MatchValidator for HttpValidator {
    async fn validate(&self, _: &mut Vec<RuleMatch>, _: &Vec<Box<dyn CompiledRuleDyn>>) {}
}
