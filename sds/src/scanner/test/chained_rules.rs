//! Real-world credential rules, run end to end with a `ChainedStepValidator` against the rule's own
//! test samples.
//!
//! Unlike the rest of the suite, these fixtures hold production rule patterns and samples
//! verbatim: the point is to prove that each chain works with the real rule, which can't be
//! exercised end to end anywhere else until consumers ship a library that supports chains.
//!
//! The YAML tests only say "redacted or not", and almost every negative sample is rejected by the
//! pattern before the validator runs. Each negative therefore records what rejects it, and the
//! checksum and decoded-structure groups also check that corrupting one character of every
//! positive (the last checksum character, or `corrupt_at`) drops the match, so the chains are
//! exercised on more than the few negatives that reach them.
//!
//! Sample inputs are stored base64-encoded so that secret scanners, including this repository's
//! push protection, don't report the fixtures' test tokens as leaked credentials: the samples carry
//! valid checksums on purpose, which is what those scanners key on. Outputs are redacted, so they
//! stay readable.

use super::validator_rules::{build_scanner, scan};
use crate::scanner::RootRuleConfig;
use crate::{MatchAction, RegexRuleConfig, ValidatorConfig, validate_chain_strict};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFixture {
    id: String,
    pattern: String,
    pattern_capture_groups: Option<Vec<String>>,
    default_included_keywords: Vec<String>,
    /// The validator the rule uses today, for the parity groups.
    hand_written_validator: Option<Value>,
    validator: Value,
    /// Byte offset in the match of the character corrupted by
    /// [`check_corrupted_matches_are_dropped`]; the last character (the checksum) by default.
    corrupt_at: Option<usize>,
    positive: Vec<Sample>,
    negative: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    description: String,
    #[serde(rename = "input_base64", deserialize_with = "decode_base64")]
    input: String,
    /// Only for positives; a negative's expected output is its input.
    output: Option<String>,
    use_included_keywords: bool,
    rejected_by: Option<RejectedBy>,
}

/// What keeps a negative sample from being redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RejectedBy {
    Pattern,
    Keywords,
    Validator,
}

impl Sample {
    fn expected_output(&self) -> &str {
        self.output.as_deref().unwrap_or(&self.input)
    }
}

fn decode_base64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    use base64::Engine;
    let encoded = String::deserialize(deserializer)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;
    String::from_utf8(bytes).map_err(serde::de::Error::custom)
}

fn load(fixtures: &str) -> Vec<RuleFixture> {
    serde_json::from_str(fixtures).unwrap()
}

/// Builds the rule through the JSON rule config, the way rules are loaded in production, with the
/// included keywords only when the sample asks for them.
fn build_rule(
    fixture: &RuleFixture,
    validator: Option<&Value>,
    use_included_keywords: bool,
) -> RootRuleConfig<RegexRuleConfig> {
    let mut config = json!({
        "pattern": fixture.pattern,
        "match_action": {"type": "Redact", "replacement": "[REDACTED]"},
    });
    if let Some(validator) = validator {
        config["validator"] = validator.clone();
    }
    if let Some(groups) = &fixture.pattern_capture_groups {
        config["pattern_capture_groups"] = json!(groups);
    }
    let mut rule: RootRuleConfig<RegexRuleConfig> = serde_json::from_value(config)
        .unwrap_or_else(|error| panic!("{}: invalid rule config: {error}", fixture.id));
    if use_included_keywords {
        rule.inner = rule
            .inner
            .with_included_keywords(&fixture.default_included_keywords);
    }
    rule
}

/// The redacted content and the redacted spans.
fn redact(
    fixture: &RuleFixture,
    validator: Option<&Value>,
    sample: &Sample,
) -> (String, Vec<(usize, usize)>) {
    redact_text(
        fixture,
        validator,
        sample.use_included_keywords,
        &sample.input,
    )
}

fn redact_text(
    fixture: &RuleFixture,
    validator: Option<&Value>,
    use_included_keywords: bool,
    input: &str,
) -> (String, Vec<(usize, usize)>) {
    let scanner = build_scanner(vec![build_rule(fixture, validator, use_included_keywords)]);
    let (content, matches) = scan(&scanner, input);
    let spans = matches
        .iter()
        .map(|rule_match| (rule_match.start_index, rule_match.end_index_exclusive))
        .collect();
    (content, spans)
}

/// Byte spans of the matches in the original input (the redacted spans point into the output).
fn match_spans_in_input(fixture: &RuleFixture, sample: &Sample) -> Vec<(usize, usize)> {
    let rule =
        build_rule(fixture, None, sample.use_included_keywords).match_action(MatchAction::None);
    let (_, matches) = scan(&build_scanner(vec![rule]), &sample.input);
    matches
        .iter()
        .map(|rule_match| (rule_match.start_index, rule_match.end_index_exclusive))
        .collect()
}

/// Collects every failure of a group so one run names all the broken rules and samples.
#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn check(&mut self, condition: bool, fixture: &RuleFixture, message: impl FnOnce() -> String) {
        if !condition {
            self.0.push(format!("[{}] {}", fixture.id, message()));
        }
    }

    fn assert_none(self, group: &str) {
        assert!(
            self.0.is_empty(),
            "{group}: {} failure(s):\n{}",
            self.0.len(),
            self.0.join("\n")
        );
    }
}

fn check_strict_validation(fixture: &RuleFixture, failures: &mut Failures) {
    let result = validate_chain_strict(&fixture.validator["config"]);
    failures.check(result.is_ok(), fixture, || {
        format!(
            "strict validation rejected the chain: {}",
            result.unwrap_err()
        )
    });
}

fn check_samples(fixture: &RuleFixture, failures: &mut Failures) {
    let chain = Some(&fixture.validator);
    for sample in fixture.positive.iter().chain(&fixture.negative) {
        let (content, _) = redact(fixture, chain, sample);
        failures.check(content == sample.expected_output(), fixture, || {
            format!(
                "sample {:?}: expected {:?}, got {content:?}",
                sample.description,
                sample.expected_output()
            )
        });
    }
}

/// A negative rejected by the validator must match without it, otherwise the sample says nothing
/// about the chain; one rejected by the pattern or keywords must not.
fn check_negative_rejections(fixture: &RuleFixture, failures: &mut Failures) {
    for sample in &fixture.negative {
        let Some(rejected_by) = sample.rejected_by else {
            failures.check(false, fixture, || {
                format!("negative {:?} has no `rejected_by`", sample.description)
            });
            continue;
        };
        let without_validator = redact(fixture, None, sample).0 != sample.input;
        let without_keywords = redact_text(fixture, None, false, &sample.input).0 != sample.input;
        let observed = match (without_validator, without_keywords) {
            (true, _) => RejectedBy::Validator,
            (false, true) => RejectedBy::Keywords,
            (false, false) => RejectedBy::Pattern,
        };
        failures.check(observed == rejected_by, fixture, || {
            format!(
                "negative {:?}: declared rejected_by {rejected_by:?}, observed {observed:?}",
                sample.description
            )
        });
    }
}

fn check_parity_with_hand_written(fixture: &RuleFixture, failures: &mut Failures) {
    let Some(hand_written) = &fixture.hand_written_validator else {
        failures.check(false, fixture, || {
            "parity fixture has no `hand_written_validator`".to_string()
        });
        return;
    };
    for sample in fixture.positive.iter().chain(&fixture.negative) {
        let chained = redact(fixture, Some(&fixture.validator), sample);
        let reference = redact(fixture, Some(hand_written), sample);
        failures.check(chained == reference, fixture, || {
            format!(
                "sample {:?}: chain gives {chained:?}, {} gives {reference:?}",
                sample.description, hand_written["type"]
            )
        });
    }
    check_validator_parity_on_edge_inputs(fixture, hand_written, failures);
}

/// The samples never contain the inputs where the hand-written validators have subtle rules
/// (hex case, empty or short values, no separator, non-ASCII), so those are compared directly on
/// the validators, together with each matched token and its case-swapped form.
fn check_validator_parity_on_edge_inputs(
    fixture: &RuleFixture,
    hand_written: &Value,
    failures: &mut Failures,
) {
    let compile = |validator: &Value| {
        serde_json::from_value::<ValidatorConfig>(validator.clone())
            .unwrap()
            .compile()
            .unwrap()
    };
    let chained = compile(&fixture.validator);
    let reference = compile(hand_written);
    let matched_tokens = fixture
        .positive
        .iter()
        .chain(&fixture.negative)
        .flat_map(|sample| {
            match_spans_in_input(fixture, sample)
                .into_iter()
                .map(|(start, end)| sample.input[start..end].to_string())
        });
    let edge_inputs = [
        "",
        "a",
        "deadbeef",
        "DEADBEEF",
        "AbCdEf0123456789",
        "0g",
        "ff_FF",
        "日本",
        "x_",
        "_",
        "ghp_T4V4",
        "x_abcdef",
        "x_abcdefg",
        "no-separator",
        "=0000000A",
    ]
    .map(String::from);
    for token in matched_tokens.chain(edge_inputs) {
        let case_swapped: String = token
            .chars()
            .map(|c| match c.is_ascii_uppercase() {
                true => c.to_ascii_lowercase(),
                false => c.to_ascii_uppercase(),
            })
            .collect();
        for input in [&token, &case_swapped] {
            let (chain_says, reference_says) = (
                chained.is_valid_match(input),
                reference.is_valid_match(input),
            );
            failures.check(chain_says == reference_says, fixture, || {
                format!(
                    "validator input {input:?}: chain says {chain_says}, {} says {reference_says}",
                    hand_written["type"]
                )
            });
        }
    }
}

/// Swaps an ASCII alphanumeric (or `+`, `/`) for a neighbour of the same kind, so the token still
/// matches the rule pattern but its checksum or decoded structure is wrong.
fn corrupt(byte: u8) -> Option<u8> {
    match byte {
        b'0' | b'a' | b'A' => Some(byte + 1),
        b'1'..=b'9' | b'b'..=b'z' | b'B'..=b'Z' => Some(byte - 1),
        b'+' => Some(b'/'),
        b'/' => Some(b'+'),
        _ => None,
    }
}

fn check_corrupted_matches_are_dropped(fixture: &RuleFixture, failures: &mut Failures) {
    for sample in &fixture.positive {
        for (start, end) in match_spans_in_input(fixture, sample) {
            let mut corrupted = sample.input.clone().into_bytes();
            let position = fixture.corrupt_at.map_or(end - 1, |offset| start + offset);
            let Some(replacement) = corrupted.get(position).copied().and_then(corrupt) else {
                failures.check(false, fixture, || {
                    format!(
                        "sample {:?}: cannot corrupt byte {position}",
                        sample.description
                    )
                });
                continue;
            };
            corrupted[position] = replacement;
            let corrupted = String::from_utf8(corrupted).unwrap();
            let still_matches_pattern =
                redact_text(fixture, None, sample.use_included_keywords, &corrupted).0 != corrupted;
            failures.check(still_matches_pattern, fixture, || {
                format!("corrupted {corrupted:?} no longer matches the pattern")
            });
            let (content, _) = redact_text(
                fixture,
                Some(&fixture.validator),
                sample.use_included_keywords,
                &corrupted,
            );
            failures.check(content == corrupted, fixture, || {
                format!("corrupted {corrupted:?} was redacted: {content:?}")
            });
        }
    }
}

type Check = fn(&RuleFixture, &mut Failures);

const COMMON_CHECKS: [Check; 3] = [
    check_strict_validation,
    check_samples,
    check_negative_rejections,
];

fn assert_group(group: &str, fixtures: &str, extra_checks: &[Check]) {
    let fixtures = load(fixtures);
    assert!(!fixtures.is_empty(), "{group}: no fixtures");
    let mut failures = Failures::default();
    for fixture in &fixtures {
        for check in COMMON_CHECKS.iter().chain(extra_checks) {
            check(fixture, &mut failures);
        }
    }
    failures.assert_none(group);
}

#[test]
fn github_token_checksum_rules() {
    assert_group(
        "github_token_checksum",
        include_str!("chained_rules/github_token_checksum.json"),
        &[
            check_parity_with_hand_written,
            check_corrupted_matches_are_dropped,
        ],
    );
}

#[test]
fn atlassian_token_checksum_rules() {
    assert_group(
        "atlassian_token_checksum",
        include_str!("chained_rules/atlassian_token_checksum.json"),
        &[
            check_parity_with_hand_written,
            check_corrupted_matches_are_dropped,
        ],
    );
}

#[test]
fn non_hex_rules() {
    assert_group(
        "non_hex",
        include_str!("chained_rules/non_hex.json"),
        &[check_parity_with_hand_written],
    );
}

#[test]
fn github_style_crc_rules_without_a_validator_today() {
    assert_group(
        "github_style_crc",
        include_str!("chained_rules/github_style_crc.json"),
        &[check_corrupted_matches_are_dropped],
    );
}

#[test]
fn new_crc_scheme_rules() {
    assert_group(
        "crc_schemes",
        include_str!("chained_rules/crc_schemes.json"),
        &[check_corrupted_matches_are_dropped],
    );
}

#[test]
fn decoded_structure_rules() {
    assert_group(
        "decoded_structure",
        include_str!("chained_rules/decoded_structure.json"),
        &[check_corrupted_matches_are_dropped],
    );
}
