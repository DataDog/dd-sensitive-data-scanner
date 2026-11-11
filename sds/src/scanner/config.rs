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

    /// Return a config only if its pattern and included keywords are necessary for every match
    /// and skipping a nonmatch has no observable effect on this rule or other rules.
    fn regex_config_for_prefilter(&self) -> Option<&RegexRuleConfig> {
        None
    }
}
