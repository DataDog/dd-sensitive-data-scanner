use crate::scanner::RootRuleConfig;
use crate::{MatchAction, RegexRuleConfig, RuleMatch, Scanner, ScannerBuilder};
use serde_json::{Value, json};

pub(super) fn rule_with_validator(
    pattern: &str,
    validator: Value,
) -> RootRuleConfig<RegexRuleConfig> {
    serde_json::from_value(json!({
        "pattern": pattern,
        "validator": validator,
        "match_action": {"type": "Redact", "replacement": "[REDACTED]"},
    }))
    .unwrap()
}

pub(super) fn plain_rule(pattern: &str) -> RootRuleConfig<RegexRuleConfig> {
    RootRuleConfig::new(RegexRuleConfig::new(pattern)).match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })
}

pub(super) fn build_scanner(rules: Vec<RootRuleConfig<RegexRuleConfig>>) -> Scanner {
    let rules: Vec<_> = rules.into_iter().map(RootRuleConfig::into_dyn).collect();
    ScannerBuilder::new(&rules).build().unwrap()
}

pub(super) fn scan(scanner: &Scanner, input: &str) -> (String, Vec<RuleMatch>) {
    let mut content = input.to_string();
    let matches = scanner.scan(&mut content).unwrap();
    (content, matches)
}
