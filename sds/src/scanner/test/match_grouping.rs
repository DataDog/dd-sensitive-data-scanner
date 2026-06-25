use crate::{
    CompiledRule, CreateScannerError, Labels, MatchAction, MatchGroupingStrategy, Path,
    RootRuleConfig, RuleConfig, RuleResult, RuleStatus, ScannerBuilder, StringMatch,
    StringMatchesCtx,
};
use std::sync::Arc;

struct NameLikeRuleConfig {
    match_grouping: MatchGroupingStrategy,
}

struct NameLikeCompiledRule;

impl CompiledRule for NameLikeCompiledRule {
    fn get_string_matches(
        &self,
        content: &str,
        _path: &Path,
        ctx: &mut StringMatchesCtx,
    ) -> RuleResult {
        for word in ["John", "Smith"] {
            if let Some(start) = content.find(word) {
                ctx.match_emitter.emit(StringMatch {
                    start,
                    end: start + word.len(),
                    keyword: None,
                });
            }
        }
        Ok(RuleStatus::Done)
    }
}

impl RuleConfig for NameLikeRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        _rule_index: usize,
        _labels: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        Ok(Box::new(NameLikeCompiledRule))
    }

    fn default_match_grouping(&self) -> MatchGroupingStrategy {
        self.match_grouping
    }
}

fn build_scanner(match_grouping: MatchGroupingStrategy) -> crate::Scanner {
    let rule_config =
        RootRuleConfig::new(Arc::new(NameLikeRuleConfig { match_grouping }) as Arc<dyn RuleConfig>)
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            });

    ScannerBuilder::new(&[rule_config])
        .with_return_matches(true)
        .build()
        .unwrap()
}

#[test]
fn groups_whitespace_separated_matches_when_rule_opts_in() {
    let scanner = build_scanner(MatchGroupingStrategy::AdjacentWhitespace);
    let mut content = "John Smith".to_string();

    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(content, "[REDACTED]");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start_index, 0);
    assert_eq!(matches[0].end_index_exclusive, 10);
    assert_eq!(matches[0].match_value, Some("John Smith".to_string()));
}

#[test]
fn leaves_whitespace_separated_matches_split_by_default() {
    let scanner = build_scanner(MatchGroupingStrategy::Disabled);
    let mut content = "John Smith".to_string();

    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(content, "[REDACTED] [REDACTED]");
    assert_eq!(matches.len(), 2);
}

#[test]
fn does_not_group_non_whitespace_separated_matches() {
    let scanner = build_scanner(MatchGroupingStrategy::AdjacentWhitespace);
    let mut content = "John, Smith".to_string();

    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(content, "[REDACTED], [REDACTED]");
    assert_eq!(matches.len(), 2);
}
