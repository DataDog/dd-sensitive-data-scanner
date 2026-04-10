use crate::scanner::RootRuleConfig;
use crate::scanner::regex_rule::config::SecondaryValidator;
use crate::{MatchAction, RegexRuleConfig, ScannerBuilder, Suppressions};

/// Build two scanners (one with merged DFA enabled, one without) and assert they produce
/// identical match results on the given content.
fn assert_scan_equivalence(rules: &[RootRuleConfig<RegexRuleConfig>], content: &str) {
    let dyn_rules: Vec<_> = rules.iter().map(|r| r.clone().into_dyn()).collect();

    let scanner_with = ScannerBuilder::new(&dyn_rules)
        .with_merged_dfa(true)
        .build()
        .unwrap();
    let scanner_without = ScannerBuilder::new(&dyn_rules)
        .with_merged_dfa(false)
        .build()
        .unwrap();

    let mut content_with = content.to_string();
    let mut content_without = content.to_string();

    let mut matches_with = scanner_with.scan(&mut content_with).unwrap();
    let mut matches_without = scanner_without.scan(&mut content_without).unwrap();

    // Sort matches so comparison is order-independent
    matches_with.sort_by_key(|m| (m.rule_index, m.start_index));
    matches_without.sort_by_key(|m| (m.rule_index, m.start_index));

    assert_eq!(
        matches_with.len(),
        matches_without.len(),
        "Match count differs for content: {content:?}\n  with merged DFA: {matches_with:?}\n  without merged DFA: {matches_without:?}"
    );

    for (m_with, m_without) in matches_with.iter().zip(matches_without.iter()) {
        assert_eq!(
            m_with.rule_index, m_without.rule_index,
            "Rule index differs for content: {content:?}"
        );
        assert_eq!(
            m_with.start_index, m_without.start_index,
            "Start index differs for content: {content:?}"
        );
        assert_eq!(
            m_with.end_index_exclusive, m_without.end_index_exclusive,
            "End index differs for content: {content:?}"
        );
        assert_eq!(
            m_with.shift_offset, m_without.shift_offset,
            "Shift offset differs for content: {content:?}"
        );
    }

    // When redaction is involved, the mutated content should also match
    assert_eq!(
        content_with, content_without,
        "Mutated content differs for original content: {content:?}"
    );
}

// ---------------------------------------------------------------------------
// Unit tests for MergedDfa construction
// ---------------------------------------------------------------------------

#[test]
fn test_no_mergeable_rules() {
    // All rules have included keywords, so none should be merged.
    let rules: Vec<_> = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d{3}").with_included_keywords(["secret"])),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+").with_included_keywords(["password"])),
    ];
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner = ScannerBuilder::new(&dyn_rules).build().unwrap();
    assert!(
        !scanner.has_merged_dfa(),
        "Expected no merged DFA when all rules have included keywords"
    );
}

#[test]
fn test_single_mergeable_rule() {
    let rules: Vec<_> = vec![RootRuleConfig::new(RegexRuleConfig::new("\\d{3}"))];
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner = ScannerBuilder::new(&dyn_rules).build().unwrap();
    assert!(
        scanner.has_merged_dfa(),
        "Expected a merged DFA for a single keyword-free rule"
    );
}

#[test]
fn test_multiple_mergeable_rules() {
    let rules: Vec<_> = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d{3}")),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+")),
        RootRuleConfig::new(RegexRuleConfig::new("foo|bar")),
    ];
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner = ScannerBuilder::new(&dyn_rules).build().unwrap();
    assert!(
        scanner.has_merged_dfa(),
        "Expected a merged DFA for multiple keyword-free rules"
    );
}

#[test]
fn test_mixed_rules() {
    // Only keyword-free rules should be merged; rules with included keywords are excluded.
    let rules: Vec<_> = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d{3}")),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+").with_included_keywords(["token"])),
        RootRuleConfig::new(RegexRuleConfig::new("foo|bar")),
    ];
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner = ScannerBuilder::new(&dyn_rules).build().unwrap();
    assert!(
        scanner.has_merged_dfa(),
        "Expected a merged DFA for the keyword-free rules in a mixed set"
    );
}

#[test]
fn test_capture_group_rules_not_merged() {
    // Rules with capture groups should be excluded from the merged DFA.
    let rules: Vec<_> = vec![
        RootRuleConfig::new(
            RegexRuleConfig::new("(?P<sds_match>\\d{3})-\\d{2}")
                .with_pattern_capture_group("sds_match"),
        ),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+")),
    ];
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner = ScannerBuilder::new(&dyn_rules).build().unwrap();
    // The second rule (no capture group, no keywords) should still be mergeable.
    assert!(
        scanner.has_merged_dfa(),
        "Expected a merged DFA from the rule without capture groups"
    );
}

#[test]
fn test_merged_dfa_disabled() {
    let rules: Vec<_> = vec![RootRuleConfig::new(RegexRuleConfig::new("\\d{3}"))];
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner = ScannerBuilder::new(&dyn_rules)
        .with_merged_dfa(false)
        .build()
        .unwrap();
    assert!(
        !scanner.has_merged_dfa(),
        "Expected no merged DFA when explicitly disabled"
    );
}

// ---------------------------------------------------------------------------
// Equivalence tests: merged DFA on vs. off must produce identical results
// ---------------------------------------------------------------------------

#[test]
fn test_equivalence_no_matches() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d{16}")).match_action(MatchAction::None),
        RootRuleConfig::new(RegexRuleConfig::new("[A-Z]{10}")).match_action(MatchAction::None),
    ];

    assert_scan_equivalence(&rules, "hello world, no digits or uppercase runs here");
}

#[test]
fn test_equivalence_single_match() {
    let rules =
        vec![RootRuleConfig::new(RegexRuleConfig::new("secret")).match_action(MatchAction::None)];

    assert_scan_equivalence(&rules, "this contains a secret value");
}

#[test]
fn test_equivalence_multiple_matches() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d+")).match_action(MatchAction::None),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+@[a-z]+\\.[a-z]+"))
            .match_action(MatchAction::None),
    ];

    assert_scan_equivalence(&rules, "contact user@example.com or call 555-1234");
}

#[test]
fn test_equivalence_all_rules_match() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d+")).match_action(MatchAction::None),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+")).match_action(MatchAction::None),
    ];

    assert_scan_equivalence(&rules, "abc 123 def 456");
}

#[test]
fn test_equivalence_with_redaction() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d{3}-\\d{2}-\\d{4}")).match_action(
            MatchAction::Redact {
                replacement: "[SSN]".to_string(),
            },
        ),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+@[a-z]+\\.[a-z]+")).match_action(
            MatchAction::Redact {
                replacement: "[EMAIL]".to_string(),
            },
        ),
    ];

    assert_scan_equivalence(&rules, "SSN: 123-45-6789 email: user@example.com end");
}

#[test]
fn test_equivalence_with_excluded_keywords() {
    // Excluded keywords are a post-match filter, so merged DFA rules can still have them.
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("world").with_excluded_keywords(["hello"]))
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            }),
    ];

    // "hello" is near "world", so it should be excluded
    assert_scan_equivalence(&rules, "hello world");
    // No excluded keyword nearby, so it should match
    assert_scan_equivalence(&rules, "goodbye world");
}

#[test]
fn test_equivalence_with_secondary_validator() {
    let rules = vec![
        RootRuleConfig::new(
            RegexRuleConfig::new("(\\d{16})|((\\d{4} ){3}\\d{4})")
                .with_validator(Some(SecondaryValidator::LuhnChecksum)),
        )
        .match_action(MatchAction::Redact {
            replacement: "[CARD]".to_string(),
        }),
    ];

    // Valid Luhn number
    assert_scan_equivalence(&rules, "card: 4111 1111 1111 1111");
    // Invalid Luhn number
    assert_scan_equivalence(&rules, "card: 4111 1111 1111 1112");
}

#[test]
fn test_equivalence_mixed_mergeable_and_keyword_rules() {
    let rules = vec![
        // This rule has no keywords, so it is mergeable
        RootRuleConfig::new(RegexRuleConfig::new("\\d{3}")).match_action(MatchAction::Redact {
            replacement: "[NUM]".to_string(),
        }),
        // This rule has included keywords, so it is NOT mergeable
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+").with_included_keywords(["password"]))
            .match_action(MatchAction::Redact {
                replacement: "[WORD]".to_string(),
            }),
        // Another mergeable rule
        RootRuleConfig::new(RegexRuleConfig::new("foo")).match_action(MatchAction::Redact {
            replacement: "[FOO]".to_string(),
        }),
    ];

    assert_scan_equivalence(&rules, "password mytoken 123 and foo");
    assert_scan_equivalence(&rules, "no keywords here 456 foo bar");
}

#[test]
fn test_equivalence_overlapping_patterns() {
    // Patterns that can match overlapping regions of the input
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("abc")).match_action(MatchAction::None),
        RootRuleConfig::new(RegexRuleConfig::new("bcd")).match_action(MatchAction::None),
    ];

    assert_scan_equivalence(&rules, "abcde");
    assert_scan_equivalence(&rules, "xabcdx");
}

#[test]
fn test_equivalence_with_suppressions() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new(r"\b\w+@\w+\.com\b"))
            .match_action(MatchAction::Redact {
                replacement: "[EMAIL]".to_string(),
            })
            .suppressions(Suppressions {
                ends_with: vec!["@datadoghq.com".to_string()],
                exact_match: vec![],
                starts_with: vec![],
            }),
    ];

    // This match should be suppressed
    assert_scan_equivalence(&rules, "contact arthur@datadoghq.com");
    // This match should NOT be suppressed
    assert_scan_equivalence(&rules, "contact nathan@yahoo.com");
    // Mix of suppressed and non-suppressed
    assert_scan_equivalence(&rules, "emails: arthur@datadoghq.com and nathan@yahoo.com");
}

// ---------------------------------------------------------------------------
// Additional edge case equivalence tests
// ---------------------------------------------------------------------------

#[test]
fn test_equivalence_empty_content() {
    let rules =
        vec![RootRuleConfig::new(RegexRuleConfig::new("\\d+")).match_action(MatchAction::None)];

    assert_scan_equivalence(&rules, "");
}

#[test]
fn test_equivalence_many_rules() {
    let rules: Vec<_> = (0..10)
        .map(|i| {
            let pattern = format!("pattern{}", i);
            RootRuleConfig::new(RegexRuleConfig::new(&pattern)).match_action(MatchAction::None)
        })
        .collect();

    assert_scan_equivalence(&rules, "pattern0 pattern5 pattern9 other");
    assert_scan_equivalence(&rules, "no matches here at all");
}

#[test]
fn test_equivalence_repeated_matches_same_rule() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d")).match_action(MatchAction::Redact {
            replacement: "[D]".to_string(),
        }),
    ];

    assert_scan_equivalence(&rules, "a1b2c3d4e5f6g7h8i9j0");
}

#[test]
fn test_equivalence_unicode_content() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d+")).match_action(MatchAction::Redact {
            replacement: "[NUM]".to_string(),
        }),
    ];

    assert_scan_equivalence(&rules, "prix: 42\u{20ac} et 100\u{00a5}");
}

#[test]
fn test_equivalence_detection_only_multiple_rules() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("secret")).match_action(MatchAction::None),
        RootRuleConfig::new(RegexRuleConfig::new("token")).match_action(MatchAction::None),
        RootRuleConfig::new(RegexRuleConfig::new("key")).match_action(MatchAction::None),
    ];

    assert_scan_equivalence(&rules, "the secret token and the key are here");
    assert_scan_equivalence(&rules, "nothing sensitive in this text");
}

#[test]
fn test_equivalence_mixed_redact_and_detect() {
    let rules = vec![
        RootRuleConfig::new(RegexRuleConfig::new("\\d{4}")).match_action(MatchAction::Redact {
            replacement: "[REDACTED]".to_string(),
        }),
        RootRuleConfig::new(RegexRuleConfig::new("[a-z]+@[a-z]+\\.[a-z]+"))
            .match_action(MatchAction::None),
    ];

    assert_scan_equivalence(&rules, "card 1234 email user@test.com");
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

mod proptest_tests {
    use super::assert_scan_equivalence;
    use crate::scanner::RootRuleConfig;
    use crate::{MatchAction, RegexRuleConfig};
    use proptest::prelude::*;

    // A fixed set of valid regex patterns to sample from (generating arbitrary valid
    // regexes that pass SDS validation is impractical, so we use a curated pool).
    const PATTERN_POOL: &[&str] = &[
        r"\d+",
        r"[a-z]+",
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"secret",
        r"token",
        r"[A-Z]{3}-\d{6}",
        r"\b[a-fA-F0-9]{8}\b",
        r"foo|bar|baz",
    ];

    fn arb_rule() -> impl Strategy<Value = RootRuleConfig<RegexRuleConfig>> {
        (0..PATTERN_POOL.len(), any::<bool>()).prop_map(|(idx, redact)| {
            let pattern = PATTERN_POOL[idx];
            let rule = RootRuleConfig::new(RegexRuleConfig::new(pattern));
            if redact {
                rule.match_action(MatchAction::Redact {
                    replacement: "[X]".to_string(),
                })
            } else {
                rule.match_action(MatchAction::None)
            }
        })
    }

    fn arb_rules() -> impl Strategy<Value = Vec<RootRuleConfig<RegexRuleConfig>>> {
        proptest::collection::vec(arb_rule(), 1..8)
    }

    proptest! {
        #[test]
        fn prop_merged_dfa_equivalence(
            rules in arb_rules(),
            content in "[a-z0-9@. ]{0,200}"
        ) {
            assert_scan_equivalence(&rules, &content);
        }

        #[test]
        fn prop_merged_dfa_equivalence_with_realistic_content(
            rules in arb_rules(),
            // Mix of text, digits, emails, IPs to trigger various pattern matches
            content in "(hello |secret |token |foo |bar |[0-9]{1,4}|[a-z]+@[a-z]+\\.[a-z]+ |[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3} ){1,10}"
        ) {
            assert_scan_equivalence(&rules, &content);
        }
    }
}
