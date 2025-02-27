use crate::{MatchAction, MatchStatus, Path, RegexRuleConfig, RuleMatch, ScannerBuilder};

#[test]
fn matches_should_take_precedence_over_non_mutating_overlapping_matches() {
    let rule_0 = RegexRuleConfig::new("...")
        .match_action(MatchAction::None)
        .build();

    let rule_1 = RegexRuleConfig::new("...")
        .match_action(MatchAction::Redact {
            replacement: "***".to_string(),
        })
        .build();

    let scanner = ScannerBuilder::new(&[rule_0, rule_1]).build().unwrap();
    let mut content = "hello world".to_string();
    let mut matches = scanner.scan(&mut content);
    matches.sort();

    assert_eq!(matches.len(), 3);
    assert_eq!(content, "*********ld");

    assert_eq!(
        matches[0],
        RuleMatch {
            rule_index: 1,
            path: Path::root(),
            replacement_type: crate::ReplacementType::Placeholder,
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
            rule_index: 1,
            path: Path::root(),
            replacement_type: crate::ReplacementType::Placeholder,
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
            rule_index: 1,
            path: Path::root(),
            replacement_type: crate::ReplacementType::Placeholder,
            start_index: 6,
            end_index_exclusive: 9,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );
}

#[test]
fn test_overlapping_mutation_higher_priority() {
    // A mutating match is a higher priority even if it starts after a non-mutating match

    let rule_0 = RegexRuleConfig::new("abc")
        .match_action(MatchAction::None)
        .build();

    let rule_1 = RegexRuleConfig::new("bcd")
        .match_action(MatchAction::Redact {
            replacement: "***".to_string(),
        })
        .build();

    let scanner = ScannerBuilder::new(&[rule_0, rule_1]).build().unwrap();
    let mut content = "abcdef".to_string();
    let mut matches = scanner.scan(&mut content);
    matches.sort();

    assert_eq!(matches.len(), 1);
    assert_eq!(content, "a***ef");

    assert_eq!(
        matches[0],
        RuleMatch {
            rule_index: 1,
            path: Path::root(),
            replacement_type: crate::ReplacementType::Placeholder,
            start_index: 1,
            end_index_exclusive: 4,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );
}

#[test]
fn test_overlapping_start_offset() {
    // The match that starts first is used (if the mutation is the same)

    let rule_0 = RegexRuleConfig::new("abc")
        .match_action(MatchAction::None)
        .build();

    let rule_1 = RegexRuleConfig::new("bcd")
        .match_action(MatchAction::None)
        .build();

    let scanner = ScannerBuilder::new(&[rule_0, rule_1]).build().unwrap();
    let mut content = "abcdef".to_string();
    let mut matches = scanner.scan(&mut content);
    matches.sort();

    assert_eq!(matches.len(), 1);
    assert_eq!(content, "abcdef");

    assert_eq!(
        matches[0],
        RuleMatch {
            rule_index: 0,
            path: Path::root(),
            replacement_type: crate::ReplacementType::None,
            start_index: 0,
            end_index_exclusive: 3,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );
}

#[test]
fn test_overlapping_length() {
    // If 2 matches have the same mutation and same start, the longer one is taken

    let rule_0 = RegexRuleConfig::new("abc")
        .match_action(MatchAction::None)
        .build();

    let rule_1 = RegexRuleConfig::new("abcd")
        .match_action(MatchAction::None)
        .build();

    let scanner = ScannerBuilder::new(&[rule_0, rule_1]).build().unwrap();
    let mut content = "abcdef".to_string();
    let mut matches = scanner.scan(&mut content);
    matches.sort();

    assert_eq!(matches.len(), 1);
    assert_eq!(content, "abcdef");

    assert_eq!(
        matches[0],
        RuleMatch {
            rule_index: 1,
            path: Path::root(),
            replacement_type: crate::ReplacementType::None,
            start_index: 0,
            end_index_exclusive: 4,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );
}

#[test]
fn test_overlapping_rule_order() {
    // If 2 matches have the same mutation, same start, and the same length, the one with the lower rule index is used

    let rule_0 = RegexRuleConfig::new("abc")
        .match_action(MatchAction::None)
        .build();

    let rule_1 = RegexRuleConfig::new("abc")
        .match_action(MatchAction::None)
        .build();

    let scanner = ScannerBuilder::new(&[rule_0, rule_1]).build().unwrap();
    let mut content = "abcdef".to_string();
    let mut matches = scanner.scan(&mut content);
    matches.sort();

    assert_eq!(matches.len(), 1);
    assert_eq!(content, "abcdef");

    assert_eq!(
        matches[0],
        RuleMatch {
            rule_index: 0,
            path: Path::root(),
            replacement_type: crate::ReplacementType::None,
            start_index: 0,
            end_index_exclusive: 3,
            shift_offset: 0,

            match_value: None,

            match_status: MatchStatus::NotAvailable,
        }
    );
}

#[test]
fn test_overlapping_mutations() {
    // This reproduces a bug where overlapping mutations weren't filtered out, resulting in invalid
    // UTF-8 indices being calculated which resulted in a panic if they were used.

    let rule = RegexRuleConfig::new("hello")
        .match_action(MatchAction::Redact {
            replacement: "*".to_string(),
        })
        .build();

    let scanner = ScannerBuilder::new(&[rule.clone(), rule]).build().unwrap();
    let mut content = "hello world".to_string();
    let matches = scanner.scan(&mut content);
    assert_eq!(content, "* world");

    // The rule was cloned, so if this is only 1, the 2nd was filtered out
    assert_eq!(matches.len(), 1);
}
