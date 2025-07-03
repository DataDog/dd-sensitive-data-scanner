mod included_keywords;
mod match_validation;
mod metrics;
mod overlapping_matches;
mod validators;

use super::*;
use super::{MatchEmitter, ScannerBuilder, StringMatch};
use crate::match_action::{MatchAction, MatchActionValidationError};

use crate::observability::labels::Labels;
use crate::scanner::regex_rule::config::{
    ProximityKeywordsConfig, RegexRuleConfig, SecondaryValidator::*,
};
use crate::scanner::scope::Scope;
use crate::scanner::{get_next_regex_start, CreateScannerError, Scanner};
use crate::scoped_ruleset::ExclusionCheck;
use crate::validation::RegexValidationError;

use crate::{simple_event::SimpleEvent, PartialRedactDirection, Path, PathSegment, RuleMatch};
use crate::{Encoding, Utf8Encoding};
use ahash::AHashSet;

use regex_automata::Match;
use std::collections::BTreeMap;

use super::CompiledRule;
use super::RuleConfig;

pub struct DumbRuleConfig {}

pub struct DumbCompiledRule {}

impl CompiledRule for DumbCompiledRule {
    fn get_string_matches(
        &self,
        _content: &str,
        _path: &Path,
        _regex_caches: &mut RegexCaches,
        _per_string_data: &mut SharedData,
        _per_scanner_data: &SharedData,
        _per_event_data: &mut SharedData,
        _exclusion_check: &ExclusionCheck<'_>,
        _excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        _: Option<&Vec<(usize, usize)>>,
    ) -> Result<(), ScannerError> {
        match_emitter.emit(StringMatch { start: 10, end: 16 });
        Ok(())
    }
}

impl RuleConfig for DumbRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        _content: usize,
        _: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        Ok(Box::new(DumbCompiledRule {}))
    }
}

#[test]
fn dumb_custom_rule() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        Arc::new(DumbRuleConfig {}) as Arc<dyn RuleConfig>
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .build()
    .unwrap();

    let mut input = "this is a secret with random data".to_owned();

    let matched_rules = scanner.scan(&mut input);

    assert_eq!(matched_rules.len(), 1);
    assert_eq!(input, "this is a [REDACTED] with random data");
}

#[test]
fn test_mixed_rules() {
    let scanner = ScannerBuilder::new(&[
        RootRuleConfig::new(Arc::new(DumbRuleConfig {}) as Arc<dyn RuleConfig>).match_action(
            MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            },
        ),
        RootRuleConfig::new(RegexRuleConfig::new("secret").build()).match_action(
            MatchAction::Redact {
                replacement: "[SECRET]".to_string(),
            },
        ),
    ])
    .build()
    .unwrap();

    let mut input = "this is a dumbss with random data and a secret".to_owned();

    let matched_rules = scanner.scan(&mut input);

    assert_eq!(matched_rules.len(), 2);
    assert_eq!(
        input,
        "this is a [REDACTED] with random data and a [SECRET]"
    );
}

#[test]
fn simple_redaction() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("secret").build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .build()
    .unwrap();

    let mut input = "text with secret".to_owned();

    let matched_rules = scanner.scan(&mut input);

    assert_eq!(matched_rules.len(), 1);
    assert_eq!(input, "text with [REDACTED]");
}

#[test]
fn simple_redaction_with_additional_labels() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("secret").build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .labels(Labels::new(&[("key".to_string(), "value".to_string())]))
    .build()
    .unwrap();

    let mut input = "text with secret".to_owned();

    let matched_rules = scanner.scan(&mut input);

    assert_eq!(matched_rules.len(), 1);
    assert_eq!(input, "text with [REDACTED]");
}

#[test]
fn should_fail_on_compilation_error() {
    let scanner_result =
        ScannerBuilder::new(&[RootRuleConfig::new(RegexRuleConfig::new("\\u").build())]).build();
    assert!(scanner_result.is_err());
    assert_eq!(
        scanner_result.err().unwrap(),
        CreateScannerError::InvalidRegex(RegexValidationError::InvalidSyntax)
    )
}

#[test]
fn should_validate_zero_char_count_partial_redact() {
    let scanner_result = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("secret").build(),
    )
    .match_action(MatchAction::PartialRedact {
        direction: PartialRedactDirection::LastCharacters,
        character_count: 0,
    })])
    .build();

    assert!(scanner_result.is_err());
    assert_eq!(
        scanner_result.err().unwrap(),
        CreateScannerError::InvalidMatchAction(
            MatchActionValidationError::PartialRedactionNumCharsZero
        )
    )
}

#[test]
fn multiple_replacements() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(RegexRuleConfig::new("\\d").build())
        .match_action(MatchAction::Redact {
            replacement: "[REDACTED]".to_string(),
        })])
    .build()
    .unwrap();

    let mut content = "testing 1 2 3".to_string();

    let matches = scanner.scan(&mut content);

    assert_eq!(content, "testing [REDACTED] [REDACTED] [REDACTED]");
    assert_eq!(matches.len(), 3);
}

#[test]
fn match_rule_index() {
    let scanner = ScannerBuilder::new(&[
        RootRuleConfig::new(RegexRuleConfig::new("a").build()),
        RootRuleConfig::new(RegexRuleConfig::new("b").build()),
    ])
    .build()
    .unwrap();

    let mut content = "a b".to_string();

    let matches = scanner.scan(&mut content);

    assert_eq!(content, "a b");
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].rule_index, 0);
    assert_eq!(
        (
            matches[0].start_index,
            matches[0].end_index_exclusive,
            matches[0].shift_offset
        ),
        (0, 1, 0)
    );
    assert_eq!(matches[1].rule_index, 1);
    assert_eq!(
        (
            matches[1].start_index,
            matches[1].end_index_exclusive,
            matches[1].shift_offset
        ),
        (2, 3, 0)
    );
}

#[test]
fn test_indices() {
    let test_builder = RegexRuleConfig::new("test");
    let detect_test_rule = RootRuleConfig::new(test_builder.build());
    let redact_test_rule =
        RootRuleConfig::new(test_builder.build()).match_action(MatchAction::Redact {
            replacement: "[test]".to_string(),
        });

    let redact_test_rule_2 =
        RootRuleConfig::new(RegexRuleConfig::new("ab").build()).match_action(MatchAction::Redact {
            replacement: "[ab]".to_string(),
        });

    let test_cases = vec![
        (vec![detect_test_rule.clone()], "test1", vec![(0, 4, 0)]),
        (vec![redact_test_rule.clone()], "test2", vec![(0, 6, 2)]),
        (vec![redact_test_rule.clone()], "xtestx", vec![(1, 7, 2)]),
        (
            vec![redact_test_rule.clone()],
            "xtestxtestx",
            vec![(1, 7, 2), (8, 14, 4)],
        ),
        (
            vec![redact_test_rule_2.clone()],
            "xtestxabx",
            vec![(6, 10, 2)],
        ),
        (
            vec![redact_test_rule_2.clone(), redact_test_rule.clone()],
            "xtestxabx",
            vec![(1, 7, 2), (8, 12, 4)],
        ),
        (
            vec![detect_test_rule.clone(), redact_test_rule_2.clone()],
            "ab-test",
            vec![(0, 4, 2), (5, 9, 2)],
        ),
    ];

    for (rule_config, input, expected_indices) in test_cases {
        let scanner = ScannerBuilder::new(rule_config.leak()).build().unwrap();
        let mut input = input.to_string();
        let matches = scanner.scan(&mut input);

        assert_eq!(matches.len(), expected_indices.len());
        for (rule_match, expected_range) in matches.iter().zip(expected_indices) {
            assert_eq!(
                (
                    rule_match.start_index,
                    rule_match.end_index_exclusive,
                    rule_match.shift_offset
                ),
                expected_range
            );
        }
    }
}

fn build_test_scanner() -> Scanner {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["awsAccess".to_string(), "access/key".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });
    Scanner::builder(&[redact_test_rule]).build().unwrap()
}

#[test]
fn test_included_keywords_match_path_case_insensitive() {
    let scanner = build_test_scanner();

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "access".to_string(),
        SimpleEvent::Map(BTreeMap::from([(
            "KEY".to_string(),
            SimpleEvent::String("hello world".to_string()),
        )])),
    )]));

    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_included_keywords_path_not_matching() {
    let scanner = build_test_scanner();

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "aws".to_string(),
        SimpleEvent::List(vec![
            SimpleEvent::Map(BTreeMap::from([(
                "key".to_string(),
                SimpleEvent::String("hello world".to_string()),
            )])),
            SimpleEvent::Map(BTreeMap::from([(
                "access".to_string(),
                SimpleEvent::String("hello".to_string()),
            )])),
        ]),
    )]));

    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_blocked_rules() {
    let redact_test_rule = RootRuleConfig::new(RegexRuleConfig::new("world").build()).match_action(
        MatchAction::Redact {
            replacement: "[REDACTED]".to_string(),
        },
    );

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();
    let mut content = "hello world".to_string();

    // Scan with no blocked rules
    let matches = scanner.scan(&mut content);
    assert_eq!(content, "hello [REDACTED]");
    assert_eq!(matches.len(), 1);

    // Scan with blocked rules
    let mut content = "hello world".to_string();
    println!("We're going to scan with options");
    let matches = scanner.scan_with_options(
        &mut content,
        ScanOptionBuilder::new()
            .with_blocked_rules_idx(vec![0])
            .build(),
    );
    println!("Matches: {:?}", matches);
    assert_eq!(content, "hello world");
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_excluded_keywords() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec![],
                excluded_keywords: vec!["hello".to_string()],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();
    let mut content = "hello world".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(content, "hello world");
    assert_eq!(matches.len(), 0);

    let mut content = "he**o world".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(content, "he**o [REDACTED]");
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_multiple_partial_redactions() {
    let rule = RootRuleConfig::new(RegexRuleConfig::new("...").build()).match_action(
        MatchAction::PartialRedact {
            direction: PartialRedactDirection::FirstCharacters,
            character_count: 1,
        },
    );

    let scanner = ScannerBuilder::new(&[rule.clone(), rule]).build().unwrap();
    let mut content = "hello world".to_string();
    let matches = scanner.scan(&mut content);

    assert_eq!(matches.len(), 3);
    assert_eq!(content, "*el*o *orld");

    assert_eq!(
        matches[0],
        RuleMatch {
            rule_index: 0,
            path: Path::root(),
            replacement_type: crate::ReplacementType::PartialStart,
            start_index: 0,
            end_index_exclusive: 3,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );

    assert_eq!(
        matches[1],
        RuleMatch {
            rule_index: 0,
            path: Path::root(),
            replacement_type: crate::ReplacementType::PartialStart,
            start_index: 3,
            end_index_exclusive: 6,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );

    assert_eq!(
        matches[2],
        RuleMatch {
            rule_index: 0,
            path: Path::root(),
            replacement_type: crate::ReplacementType::PartialStart,
            start_index: 6,
            end_index_exclusive: 9,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );
}

#[test]
fn assert_scanner_is_sync_send() {
    // This ensures that the scanner is safe to use from multiple threads.
    // This is needed because the Scanner can be used from unsafe FFI code which
    // prevents the compiler from enforcing this
    fn assert_send<T: Send + Sync>() {}

    assert_send::<Scanner>();
}

#[test]
fn should_skip_match_when_present_in_excluded_matches() {
    // If 2 matches have the same mutation and same start, the longer one is taken
    let rule_0 = RootRuleConfig::new(RegexRuleConfig::new("b.*").build())
        .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
            "test".into(),
        )])]))
        .match_action(MatchAction::Redact {
            replacement: "[scrub]".to_string(),
        });

    let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();

    let mut content = SimpleEvent::Map(BTreeMap::from([
        (
            "a-match".to_string(),
            SimpleEvent::String("bcdef".to_string()),
        ),
        (
            "z-match".to_string(),
            SimpleEvent::String("bcdef".to_string()),
        ),
        ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
    ]));

    let matches = scanner.scan(&mut content);

    // "test" is excluded because it matches the excluded scope.
    // Both "a-match" and "z-match" are excluded due to having the
    // same match value as "test" (multi-pass V0)
    assert_eq!(matches.len(), 0);
}

#[test]
fn should_be_able_to_disable_multipass_v0() {
    let rule_0 = RootRuleConfig::new(RegexRuleConfig::new("b.*").build())
        .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
            "test".into(),
        )])]))
        .match_action(MatchAction::Redact {
            replacement: "[scrub]".to_string(),
        });

    let scanner = ScannerBuilder::new(&[rule_0])
        .with_multipass_v0(false)
        .build()
        .unwrap();

    let mut content = SimpleEvent::Map(BTreeMap::from([
        (
            "a-match".to_string(),
            SimpleEvent::String("bcdef".to_string()),
        ),
        (
            "z-match".to_string(),
            SimpleEvent::String("bcdef".to_string()),
        ),
        ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
    ]));

    let matches = scanner.scan(&mut content);

    // "test" is excluded because it matches the excluded scope.
    // Both "a-match" and "z-match" are kept since multipass V0 is disabled
    assert_eq!(matches.len(), 2);
}

#[test]
fn should_not_exclude_false_positive_matches() {
    // If a match in an excluded scope is a false-positive due to keyword proximity matching,
    // it is not saved in the excluded matches.
    let rule_0 = RootRuleConfig::new(
        RegexRuleConfig::new("b.*")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["secret".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
        "test".into(),
    )])]))
    .match_action(MatchAction::Redact {
        replacement: "[scrub]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();

    let mut content = SimpleEvent::Map(BTreeMap::from([
        (
            "message".to_string(),
            SimpleEvent::String("secret abcdef".to_string()),
        ),
        ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
    ]));

    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_calculate_indices_is_called_with_sorted_start_index() {
    // A custom "Event" implementation is used here to use a different encoding that asserts the indices are in order
    struct OrderAssertEvent(SimpleEvent);

    impl crate::Event for OrderAssertEvent {
        type Encoding = AssertOrderEncoding;

        fn visit_event<'a>(&'a mut self, visitor: &mut impl crate::EventVisitor<'a>) {
            self.0.visit_event(visitor)
        }

        fn visit_string_mut(&mut self, path: &Path, visit: impl FnMut(&mut String) -> bool) {
            self.0.visit_string_mut(path, visit)
        }
    }

    struct AssertOrderEncoding;

    impl Encoding for AssertOrderEncoding {
        type Index = <Utf8Encoding as Encoding>::Index;
        type IndexShift = <Utf8Encoding as Encoding>::IndexShift;

        fn zero_index() -> Self::Index {
            <Utf8Encoding as Encoding>::zero_index()
        }

        fn zero_shift() -> Self::IndexShift {
            <Utf8Encoding as Encoding>::zero_shift()
        }

        fn get_index(value: &Self::Index, utf8_index: usize) -> usize {
            <Utf8Encoding as Encoding>::get_index(value, utf8_index)
        }

        fn calculate_indices<'a>(
            _content: &str,
            match_visitor: impl Iterator<Item = crate::EncodeIndices<'a, Self>>,
        ) {
            let mut prev_start = 0;
            for indices in match_visitor {
                assert!(
                    indices.utf8_start >= prev_start,
                    "Indices are not in order."
                );
                prev_start = indices.utf8_start;
            }
        }

        fn adjust_shift(shift: &mut Self::IndexShift, before: &str, after: &str) {
            <Utf8Encoding as Encoding>::adjust_shift(shift, before, after)
        }

        fn get_shift(value: &Self::IndexShift, utf8_shift: isize) -> isize {
            <Utf8Encoding as Encoding>::get_shift(value, utf8_shift)
        }
    }

    // `rule_0` has a match after `rule_1` (out of order)
    let rule_0 = RootRuleConfig::new(RegexRuleConfig::new("efg").build());
    let rule_1 = RootRuleConfig::new(RegexRuleConfig::new("abc").build());

    let scanner = ScannerBuilder::new(&[rule_0, rule_1]).build().unwrap();

    let mut content = OrderAssertEvent(SimpleEvent::Map(BTreeMap::from([(
        "message".to_string(),
        SimpleEvent::String("abc-efg".to_string()),
    )])));

    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_hash_with_leading_zero() {
    let rule_0 =
        RootRuleConfig::new(RegexRuleConfig::new(".+").build()).match_action(MatchAction::Hash);

    let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();

    let mut content =
        SimpleEvent::String("rand string that has a leading zero after hashing: y".to_string());

    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);

    // normally 09d99e4b6ad0d289, but the leading 0 is removed
    assert_eq!(content, SimpleEvent::String("9d99e4b6ad0d289".to_string()));
}

#[test]
fn test_hash_with_leading_zero_utf16() {
    #[allow(deprecated)]
    let rule_0 = RootRuleConfig::new(RegexRuleConfig::new(".+").build())
        .match_action(MatchAction::Utf16Hash);

    let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();

    let mut content = "rand string that has a leading zero after hashing: S".to_string();

    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);

    // normally 08c3ad1a22e2edb1, but the leading 0 is removed
    assert_eq!(content, "8c3ad1a22e2edb1");
}

#[test]
fn test_internal_overlapping_matches() {
    // A simple "credit-card rule is modified a bit to allow a multi-char character in the match
    let rule_0 = RootRuleConfig::new(
        RegexRuleConfig::new("([\\d€]+){1}(,\\d+){3}")
            .with_validator(Some(LuhnChecksum))
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[credit card]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();

    // The first 4 numbers match as a credit-card, but fail the luhn checksum.
    // The last 4 numbers (which overlap with the first match) pass the checksum.
    let mut content = "[5€184,5185,5252,5052,5005]".to_string();

    let matches = scanner.scan(&mut content);
    // This is mostly asserting that the scanner doesn't panic when encountering multibyte characters
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_next_regex_start_after_false_positive() {
    let content = "          testtest";
    let regex_match = Match::must(0, 10..14);
    assert_eq!(get_next_regex_start(content, &regex_match), Some(11));
}

#[test]
fn test_excluded_keyword_with_excluded_chars_in_content() {
    let rule_0 = RootRuleConfig::new(
        RegexRuleConfig::new("value")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec![],
                excluded_keywords: vec!["test".to_string()],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();

    // "test" should NOT be detected as an excluded keyword because "-" is ignored, so the word
    // boundary shouldn't match here
    let mut content = "x-test=value".to_string();

    let matches = scanner.scan(&mut content);
    // This should match because "test" is not found, so it's not a false-positive
    assert_eq!(matches.len(), 1);
}
