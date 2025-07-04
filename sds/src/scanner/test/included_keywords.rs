use crate::scanner::test::build_test_scanner;
use crate::scanner::RootRuleConfig;
use crate::{MatchAction, ProximityKeywordsConfig, RegexRuleConfig, ScannerBuilder, SimpleEvent};
use std::collections::BTreeMap;

#[test]
fn test_included_keywords_match_content() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();
    let mut content = "hello world".to_string();
    // These are regexes so we're safe to unwrap
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(content, "hello [REDACTED]");
    assert_eq!(matches.len(), 1);

    let mut content = "he**o world".to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(content, "he**o world");
    assert_eq!(matches.len(), 0);

    let mut content = "world hello world".to_string();
    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(content, "world hello [REDACTED]");
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_included_keywords_match_path() {
    let scanner = build_test_scanner();

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "aws".to_string(),
        SimpleEvent::Map(BTreeMap::from([(
            "access".to_string(),
            SimpleEvent::String("hello world".to_string()),
        )])),
    )]));

    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_included_keywords_match_path_camel_case() {
    let scanner = build_test_scanner();

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "accessKEY".to_string(),
        SimpleEvent::String("hello world".to_string()),
    )]));

    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "AccessKey".to_string(),
        SimpleEvent::String("hello world".to_string()),
    )]));

    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_included_keywords_path_with_uncaught_separator_symbol() {
    let scanner = build_test_scanner();

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "aws%access".to_string(),
        SimpleEvent::String("hello".to_string()),
    )]));

    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_included_keywords_path_deep() {
    let scanner = build_test_scanner();

    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "aws".to_string(),
        SimpleEvent::List(vec![
            SimpleEvent::Map(BTreeMap::from([(
                "key".to_string(),
                SimpleEvent::String("hello world".to_string()),
            )])),
            SimpleEvent::Map(BTreeMap::from([
                (
                    "access".to_string(),
                    SimpleEvent::Map(BTreeMap::from([(
                        "random_key".to_string(),
                        SimpleEvent::String("hello world".to_string()),
                    )])),
                ),
                (
                    "another_key".to_string(),
                    SimpleEvent::String("hello world".to_string()),
                ),
            ])),
        ]),
    )]));

    let matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_included_keyword_not_match_further_than_look_ahead_character_count() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();

    let mut content = "hello [this block is exactly 37 chars long] world".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(matches.len(), 0);
}

#[test]
fn test_included_keyword_multiple_matches_in_one_prefix() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();

    let mut content = "hello world world".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    // Both "world" matches fit within the 30 char prefix.
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_included_keyword_multiple_prefix_matches() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();

    let mut content =
        "hello world [this takes up enough space to separate the prefixes] world hello world"
            .to_string();
    let matches = scanner.scan(&mut content).unwrap();

    // Both "worlds" after a "hello" should match
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_multi_word_underscore_separator() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("secret")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello world".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();

    let mut content = "hello_world secret".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    // 1 match because "hello_world" matches "hello world" keyword
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_multi_word_underscore_word_boundaries_separator() {
    let redact_test_rule = RootRuleConfig::new(
        RegexRuleConfig::new("secret")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello world".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();

    let mut content = "a_hello_world_b secret".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    // 1 match because "hello_world" matches "hello world" keyword
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_included_keywords_on_start_boundary_with_space_including_word_boundary() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("ab")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["id".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )])
    .build()
    .unwrap();

    let mut content = "users id   ab".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start_index, 11);
    assert_eq!(matches[0].end_index_exclusive, 13);
}

#[test]
fn test_included_keywords_on_end_boundary() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("abc")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["id".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )])
    .build()
    .unwrap();

    let mut content = "users idabc".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(matches.len(), 0);
}

#[test]
fn should_not_look_ahead_too_far() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("x")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 10,
                included_keywords: vec!["host".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )])
    .build()
    .unwrap();

    let mut content = "host           x".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 0);

    let mut content = "host      x".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 1);

    let mut content = "host       x".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 0);

    let mut content = " host      x".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 1);
}

#[test]
fn should_verify_included_keywords_on_path_even_if_included_keywords_are_in_string() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 10,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )])
    .build()
    .unwrap();

    let mut event = SimpleEvent::Map(BTreeMap::from([(
        "hello".to_string(),
        SimpleEvent::String("hello [more than ten characters] world".to_string()),
    )]));

    // Even though the included keywords are too far from the match in the string
    // the keyword is present in the path and that should validate the match.
    assert_eq!(scanner.scan(&mut event).unwrap().len(), 1);
}

#[test]
fn test_included_and_excluded_keyword() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(
        RegexRuleConfig::new("world")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 11,
                included_keywords: vec!["hey".to_string()],
                excluded_keywords: vec!["hello".to_string()],
            })
            .build(),
    )])
    .build()
    .unwrap();

    // only the included keyword is present
    let mut content = "hey world".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 1);

    // only the excluded keyword is present
    let mut content = "hello world".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 0);

    // no keyword is present
    let mut content = "world".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 0);

    // included and excluded keywords are present
    let mut content = "hey, hello world".to_string();
    assert_eq!(scanner.scan(&mut content).unwrap().len(), 1);
}
