use crate::scanner::error::CreateScannerError;
use crate::{CompiledRule, Labels, MatchGroupingStrategy, RegexRuleConfig};

pub trait RuleConfig: Send + Sync {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError>;

    fn as_regex_rule(&self) -> Option<&RegexRuleConfig> {
        None
    }

    fn default_match_grouping(&self) -> MatchGroupingStrategy {
        MatchGroupingStrategy::Disabled
    }
}
