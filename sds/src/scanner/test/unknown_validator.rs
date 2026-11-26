use crate::scanner::RootRuleConfig;
use crate::{MatchAction, RegexRuleConfig, RuleMatch, Scanner, ScannerBuilder};
use metrics::{Key, Label};
use metrics_util::CompositeKey;
use metrics_util::MetricKind::Counter;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use serde_json::{Value, json};

fn rule_with_validator(pattern: &str, validator: Value) -> RootRuleConfig<RegexRuleConfig> {
    serde_json::from_value(json!({
        "pattern": pattern,
        "validator": validator,
        "match_action": {"type": "Redact", "replacement": "[REDACTED]"},
    }))
    .unwrap()
}

fn plain_rule(pattern: &str) -> RootRuleConfig<RegexRuleConfig> {
    RootRuleConfig::new(RegexRuleConfig::new(pattern)).match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })
}

fn build_scanner(rules: Vec<RootRuleConfig<RegexRuleConfig>>) -> Scanner {
    let rules: Vec<_> = rules.into_iter().map(RootRuleConfig::into_dyn).collect();
    ScannerBuilder::new(&rules).build().unwrap()
}

fn scan(scanner: &Scanner, input: &str) -> (String, Vec<RuleMatch>) {
    let mut content = input.to_string();
    let matches = scanner.scan(&mut content).unwrap();
    (content, matches)
}

#[test]
fn unknown_validator_with_pass_default_response_keeps_matches() {
    let scanner = build_scanner(vec![rule_with_validator(
        "secret",
        json!({"type": "FutureValidator", "default_response": "pass"}),
    )]);

    assert_eq!(scan(&scanner, "a secret").0, "a [REDACTED]");
}

#[test]
fn unknown_validator_with_fail_default_response_drops_matches() {
    let scanner = build_scanner(vec![rule_with_validator(
        "secret",
        json!({"type": "FutureValidator", "default_response": "fail", "config": {"any": 1}}),
    )]);

    assert_eq!(scan(&scanner, "a secret").0, "a secret");
}

#[test]
fn unknown_validator_without_default_response_disables_only_that_rule() {
    let scanner = build_scanner(vec![
        rule_with_validator("secret", json!({"type": "FutureValidator"})),
        plain_rule("foo"),
    ]);

    let (content, matches) = scan(&scanner, "secret foo");

    assert_eq!(content, "secret [REDACTED]");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_index, 1);
}

#[test]
fn disabled_rule_does_not_compile_its_regex() {
    // A rule written for a newer runtime may use regex syntax this runtime rejects.
    let scanner = build_scanner(vec![
        rule_with_validator("(unclosed", json!({"type": "FutureValidator"})),
        plain_rule("foo"),
    ]);

    assert_eq!(scan(&scanner, "foo").0, "[REDACTED]");
}

#[test]
fn known_validator_ignores_default_response() {
    let scanner = build_scanner(vec![rule_with_validator(
        "[0-9]+",
        json!({"type": "LuhnChecksum", "default_response": "fail"}),
    )]);

    assert_eq!(scan(&scanner, "4111111111111111").0, "[REDACTED]");
}

type Snapshot = std::collections::HashMap<
    CompositeKey,
    (
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    ),
>;

fn counter_value<'a>(
    snapshot: &'a Snapshot,
    name: &'static str,
    labels: Vec<Label>,
) -> Option<&'a DebugValue> {
    snapshot
        .get(&CompositeKey::new(Counter, Key::from_parts(name, labels)))
        .map(|(_, _, value)| value)
}

#[test]
fn disabled_rule_increments_disabled_rule_counter() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let mut rule = rule_with_validator("secret", json!({"type": "FutureValidator"}));
        rule.tags = vec!["sensitive_data:future_token".to_string()];
        build_scanner(vec![rule]);
    });

    let snapshot = snapshotter.snapshot().into_hashmap();
    assert_eq!(
        counter_value(
            &snapshot,
            "scanner.disabled_rule",
            vec![
                Label::new("reason", "secondary_validator"),
                Label::new("sds_rule_name", "missing_category/future_token"),
            ],
        ),
        Some(&DebugValue::Counter(1))
    );
}

#[test]
fn known_validator_with_future_config_falls_back_to_default_response() {
    let scanner = build_scanner(vec![rule_with_validator(
        "secret",
        json!({
            "type": "JwtClaimsValidator",
            "default_response": "pass",
            "config": {"required_claims": {"sub": {"type": "FutureRequirement"}}},
        }),
    )]);

    assert_eq!(scan(&scanner, "a secret").0, "a [REDACTED]");
}
