use crate::scanner::{AsyncStatus, RuleResult};
use crate::{
    CompiledRule, CreateScannerError, Labels, MatchAction, Path, RootRuleConfig, RuleConfig,
    ScannerBuilder, StringMatch, StringMatchesCtx,
};
use futures::FutureExt;
use std::sync::Arc;

pub struct AsyncRuleConfig {}

pub struct AsyncCompiledRule {}

impl CompiledRule for AsyncCompiledRule {
    fn get_string_matches(
        &self,
        _content: &str,
        _path: &Path,
        ctx: &mut StringMatchesCtx,
    ) -> RuleResult<()> {
        ctx.process_async(|ctx| {
            Box::pin(async move {
                ctx.emit_match(StringMatch { start: 10, end: 16 });
                Ok(())
            })
        })
    }
}

impl RuleConfig for AsyncRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        _content: usize,
        _: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        Ok(Box::new(AsyncCompiledRule {}))
    }
}

#[test]
fn run_async_rule() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        Arc::new(AsyncRuleConfig {}) as Arc<dyn RuleConfig>
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .build()
    .unwrap();

    let mut input = "this is a secret with random data".to_owned();

    let matched_rules = scanner.scan(&mut input).unwrap();

    assert_eq!(matched_rules.len(), 1);
    assert_eq!(input, "this is a [REDACTED] with random data");
}
