use crate::{CompiledRuleDyn, RuleMatch};
use std::vec::Vec;

pub trait MatchValidator: Send + Sync {
    // Trait use to validate the matches and update the match status
    // It requires the matches found by the scans and the scanner rules to retrieve the match validation type
    fn validate(&self, matches: &mut Vec<RuleMatch>, scanner_rules: &[Box<dyn CompiledRuleDyn>]);
}
