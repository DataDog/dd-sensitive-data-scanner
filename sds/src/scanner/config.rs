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

    /// Return a pattern in [`RegexRuleConfig`] syntax that must match the original field
    /// whenever this rule can match. Include any flags the rule requires, such as `(?i)`.
    ///
    /// If the prefilter rules out a field, the scanner skips `init_per_string_data`,
    /// `init_per_event_data`, and `get_string_matches` for that visit. Keep the default
    /// if this rule or another rule depends on those calls for nonmatching fields.
    fn pattern_for_prefilter(&self) -> Option<&str> {
        None
    }
}
