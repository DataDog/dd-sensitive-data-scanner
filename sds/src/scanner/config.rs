use crate::scanner::error::CreateScannerError;
use crate::{CompiledRule, Labels, RegexRuleConfig};

pub trait RuleConfig: Send + Sync {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError>;

    fn as_regex_rule(&self) -> Option<&RegexRuleConfig> {
        None
    }

    /// Return a pattern that must match the field for this rule to produce a match.
    /// Opt in only if skipping a nonmatch has no observable effect on this or other rules.
    fn pattern_for_prefilter(&self) -> Option<&str> {
        None
    }
}
