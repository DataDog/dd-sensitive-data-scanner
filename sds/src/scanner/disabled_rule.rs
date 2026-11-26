use crate::Path;
use crate::scanner::{CompiledRule, RuleResult, RuleStatus, StringMatchesCtx};

/// Stands in for a rule that could not be loaded, so that rule indices of the other rules stay
/// stable (match reporting and blocked rules are index based).
pub struct DisabledCompiledRule;

impl CompiledRule for DisabledCompiledRule {
    fn get_string_matches(
        &self,
        _content: &str,
        _path: &Path,
        _ctx: &mut StringMatchesCtx<'_>,
    ) -> RuleResult {
        Ok(RuleStatus::Done)
    }

    fn is_disabled(&self) -> bool {
        true
    }
}
