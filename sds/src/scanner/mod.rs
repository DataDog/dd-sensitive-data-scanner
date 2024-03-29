use crate::encoding::Encoding;
use crate::event::Event;
use crate::observability::labels::{Labels, NO_LABEL};

use crate::proximity_keywords::CompiledProximityKeywords;
use crate::rule::RuleConfig;
use crate::rule_match::{InternalRuleMatch, RuleMatch};
use crate::scoped_ruleset::{ContentVisitor, ExclusionCheck, ScopedRuleSet};
pub use crate::secondary_validation::Validator;
use crate::validation::validate_and_create_regex;
use crate::{CreateScannerError, EncodeIndices, MatchAction, Path, Scope};
use regex_automata::meta::Regex as MetaRegex;
use std::sync::Arc;

use self::cache_pool::{CachePool, CachePoolGuard};
use ahash::AHashSet;

mod cache_pool;
pub mod error;

/// This is the internal representation of a rule after it has been validated / compiled.
pub struct CompiledRule {
    pub rule_index: usize,
    pub regex: MetaRegex,
    pub match_action: MatchAction,
    pub scope: Scope,
    pub proximity_keywords: CompiledProximityKeywords,
    pub validator: Option<Arc<dyn Validator>>,
}

pub struct Scanner {
    rules: Arc<Vec<CompiledRule>>,
    scoped_ruleset: ScopedRuleSet,
    cache_pool: CachePool,
}

impl Scanner {
    pub fn new(rules: &[RuleConfig]) -> Result<Self, CreateScannerError> {
        Scanner::new_with_labels(rules, NO_LABEL)
    }

    pub fn new_with_labels(
        rules: &[RuleConfig],
        scanner_labels: Labels,
    ) -> Result<Self, CreateScannerError> {
        let compiled_rules = rules
            .iter()
            .enumerate()
            .map(|(rule_index, config)| {
                // This validates that the pattern is valid and normalizes behavior.
                let regex = validate_and_create_regex(&config.pattern)?;
                config.match_action.validate()?;

                let rule_labels = scanner_labels.clone_with_labels(config.labels.clone());

                let compiled_keywords = config
                    .proximity_keywords
                    .clone()
                    .map_or(Ok(CompiledProximityKeywords::default()), |keywords| {
                        CompiledProximityKeywords::try_new(keywords, &rule_labels)
                    })?;

                Ok(CompiledRule {
                    rule_index,
                    regex,
                    match_action: config.match_action.clone(),
                    scope: config.scope.clone(),
                    proximity_keywords: compiled_keywords,
                    validator: config
                        .validator
                        .clone()
                        .map(|x| Arc::new(x) as Arc<dyn Validator>),
                })
            })
            .collect::<Result<Vec<CompiledRule>, CreateScannerError>>()?;

        let scoped_ruleset = ScopedRuleSet::new(
            &compiled_rules
                .iter()
                .map(|rule| rule.scope.clone())
                .collect::<Vec<_>>(),
        );

        let rules = Arc::new(compiled_rules);

        Ok(Self {
            rules: rules.clone(),
            scoped_ruleset,
            cache_pool: CachePool::new(rules),
        })
    }

    pub fn scan<E: Event>(&self, event: &mut E) -> Vec<RuleMatch> {
        // This is a set of caches (1 for each rule) that can be used for scanning. This is obtained once per scan to reduce
        // lock contention. (Normally it has to be obtained for each regex scan individually)
        let caches: regex_automata::util::pool::PoolGuard<
            '_,
            Vec<regex_automata::meta::Cache>,
            Box<dyn Fn() -> Vec<regex_automata::meta::Cache> + Send + Sync>,
        > = self.cache_pool.get();

        // All matches, after some (but not all) false-positives have been removed.
        // This is a vec of vecs, where each inner vec is a set of matches for a single path.
        let mut rule_matches_list = vec![];

        let mut excluded_matches = AHashSet::new();

        self.scoped_ruleset.visit_string_rule_combinations(
            event,
            ScannerContentVisitor {
                scanner: self,
                caches,
                rule_matches: &mut rule_matches_list,
                excluded_matches: &mut excluded_matches,
            },
        );
        let mut output_rule_matches = vec![];

        for (path, rule_matches) in &mut rule_matches_list {
            // All rule matches in each inner list are for a single path, so they can be processed independently.
            event.visit_string_mut(path, |content| {
                // filter out any matches where the content is included in `excluded_matches`.
                rule_matches.retain(|rule_match| {
                    !excluded_matches.contains(&content[rule_match.utf8_start..rule_match.utf8_end])
                });

                self.sort_and_remove_overlapping_rules::<E::Encoding>(rule_matches);

                let will_mutate = rule_matches
                    .iter()
                    .any(|rule_match| self.rules[rule_match.rule_index].match_action.is_mutating());

                self.apply_match_actions(content, path, rule_matches, &mut output_rule_matches);

                will_mutate
            });
        }

        output_rule_matches
    }

    /// Apply mutations from actions, and shift indices to match the mutated values.
    /// This assumes the matches are all from the content given, and are sorted by start index.
    fn apply_match_actions<E: Encoding>(
        &self,
        content: &mut String,
        path: &Path<'static>,
        rule_matches: &mut [InternalRuleMatch<E>],
        output_rule_matches: &mut Vec<RuleMatch>,
    ) {
        let mut utf8_byte_delta: isize = 0;
        let mut custom_index_delta: <E>::IndexShift = <E>::zero_shift();

        for rule_match in rule_matches {
            output_rule_matches.push(self.apply_match_actions_for_string::<E>(
                content,
                path.clone(),
                rule_match,
                &mut utf8_byte_delta,
                &mut custom_index_delta,
            ));
        }
    }

    /// This will be called once for each match of a single string. The rules must be passed in in order of the start index. Mutating rules must not overlap.
    fn apply_match_actions_for_string<E: Encoding>(
        &self,
        content: &mut String,
        path: Path<'static>,
        rule_match: &InternalRuleMatch<E>,
        // The current difference in length between the original and mutated string
        utf8_byte_delta: &mut isize,

        // The difference between the custom index on the original string and the mutated string
        custom_index_delta: &mut <E>::IndexShift,
    ) -> RuleMatch {
        let rule = &self.rules[rule_match.rule_index];

        let custom_start =
            (<E>::get_index(&rule_match.custom_start, rule_match.utf8_start) as isize
                + <E>::get_shift(custom_index_delta, *utf8_byte_delta)) as usize;

        if rule.match_action.is_mutating() {
            let mutated_utf8_match_start =
                (rule_match.utf8_start as isize + *utf8_byte_delta) as usize;
            let mutated_utf8_match_end = (rule_match.utf8_end as isize + *utf8_byte_delta) as usize;

            // Matches for mutating rules must have valid indices
            debug_assert!(content.is_char_boundary(mutated_utf8_match_start));
            debug_assert!(content.is_char_boundary(mutated_utf8_match_end));

            let matched_content = &content[mutated_utf8_match_start..mutated_utf8_match_end];

            if let Some(replacement) = rule.match_action.get_replacement(matched_content) {
                let before_replacement = &matched_content[replacement.start..replacement.end];

                // update indices to match the new mutated content
                <E>::adjust_shift(
                    custom_index_delta,
                    before_replacement,
                    &replacement.replacement,
                );
                *utf8_byte_delta +=
                    replacement.replacement.len() as isize - before_replacement.len() as isize;

                let replacement_start = mutated_utf8_match_start + replacement.start;
                let replacement_end = mutated_utf8_match_start + replacement.end;
                content.replace_range(replacement_start..replacement_end, &replacement.replacement);
            }
        }

        let shift_offset = <E>::get_shift(custom_index_delta, *utf8_byte_delta);
        let custom_end = (<E>::get_index(&rule_match.custom_end, rule_match.utf8_end) as isize
            + shift_offset) as usize;

        RuleMatch {
            rule_index: rule_match.rule_index,
            path,
            replacement_type: rule.match_action.replacement_type(),
            start_index: custom_start,
            end_index_exclusive: custom_end,
            shift_offset,
        }
    }

    fn sort_and_remove_overlapping_rules<E: Encoding>(
        &self,
        rule_matches: &mut Vec<InternalRuleMatch<E>>,
    ) {
        // Some of the scanner code relies on the behavior here, such as the sort order and removal of overlapping mutating rules.
        // Be very careful if this function is modified.

        rule_matches.sort_unstable_by(|a, b| {
            // Mutating rules are a higher priority (earlier in the list)
            let ord = self.rules[a.rule_index]
                .match_action
                .is_mutating()
                .cmp(&self.rules[b.rule_index].match_action.is_mutating())
                .reverse();

            // Earlier start offset
            let ord = ord.then(a.utf8_start.cmp(&b.utf8_start));

            // Longer matches
            let ord = ord.then(a.len().cmp(&b.len()).reverse());

            // Matches from earlier rules
            let ord = ord.then(a.rule_index.cmp(&b.rule_index));

            // swap the order of everything so matches can be efficiently popped off the back as they are processed
            ord.reverse()
        });

        let mut retained_rules: Vec<InternalRuleMatch<E>> = vec![];

        'rule_matches: while let Some(rule_match) = rule_matches.pop() {
            if self.rules[rule_match.rule_index].match_action.is_mutating() {
                // Mutating rules are kept only if they don't overlap with a previous rule.
                if let Some(last) = retained_rules.last() {
                    if last.utf8_end > rule_match.utf8_start {
                        continue;
                    }
                }
            } else {
                // Only retain if it doesn't overlap with any other rule. Since mutating matches are sorted before non-mutated matches
                // this needs to check all retained matches (instead of just the last one)
                for retained_rule in &retained_rules {
                    if retained_rule.utf8_start < rule_match.utf8_end
                        && retained_rule.utf8_end > rule_match.utf8_start
                    {
                        continue 'rule_matches;
                    }
                }
            };
            retained_rules.push(rule_match);
        }

        // ensure rules are sorted by start index (other parts of the library required this to function correctly)
        retained_rules.sort_unstable_by_key(|rule_match| rule_match.utf8_start);

        *rule_matches = retained_rules;
    }
}

struct ScannerContentVisitor<'a, E: Encoding> {
    scanner: &'a Scanner,
    caches: CachePoolGuard<'a>,
    rule_matches: &'a mut Vec<(crate::Path<'static>, Vec<InternalRuleMatch<E>>)>,
    excluded_matches: &'a mut AHashSet<String>,
}

impl<'a, E: Encoding> ContentVisitor<'a> for ScannerContentVisitor<'a, E> {
    fn visit_content<'b>(
        &'b mut self,
        path: &crate::Path<'a>,
        content: &str,
        rule_visitor: crate::scoped_ruleset::RuleIndexVisitor,
        exclusion_check: ExclusionCheck<'b>,
    ) -> bool {
        // matches for a single path
        let mut path_rules_matches = vec![];

        rule_visitor.visit_rule_indices(|rule_index| {
            let rule = &self.scanner.rules[rule_index];
            let cache = &mut self.caches[rule_index];

            // `find_iter` already skips overlapping matches for the same rule,
            // so those don't need to be filtered out here
            let mut it = regex_automata::util::iter::Searcher::new(content.into());
            while let Some(regex_match) =
                it.advance(|input| Ok(rule.regex.search_with(cache, input)))
            {
                if rule
                    .proximity_keywords
                    .is_false_positive_match(content, regex_match.start())
                {
                    // proximity keywords consider this match as false positive, so it is dropped
                    continue;
                }
                if let Some(validator) = rule.validator.as_ref() {
                    if !validator.is_valid_match(&content[regex_match.range()]) {
                        continue;
                    };
                }

                if exclusion_check.is_excluded(rule_index) {
                    // Matches from excluded paths are saved and used to treat additional equal matches as false positives
                    self.excluded_matches
                        .insert(content[regex_match.range()].to_string());
                    continue;
                }

                path_rules_matches.push(InternalRuleMatch {
                    rule_index,
                    utf8_start: regex_match.start(),
                    utf8_end: regex_match.end(),
                    custom_start: E::zero_index(),
                    custom_end: E::zero_index(),
                });
            }
        });

        E::calculate_indices(
            content,
            path_rules_matches
                .iter_mut()
                .map(|rule_match: &mut InternalRuleMatch<E>| EncodeIndices {
                    utf8_start: rule_match.utf8_start,
                    utf8_end: rule_match.utf8_end,
                    custom_start: &mut rule_match.custom_start,
                    custom_end: &mut rule_match.custom_end,
                }),
        );

        // If there are any matches, the string will need to be accessed to check for false positives from
        // excluded matches, any to potentially mutate the string.
        let has_match = !path_rules_matches.is_empty();

        if has_match {
            self.rule_matches
                .push((path.into_static(), path_rules_matches));
        }

        has_match
    }
}

#[cfg(test)]
mod test {
    use crate::match_action::{MatchAction, MatchActionValidationError};
    use crate::observability::labels::Labels;
    use crate::rule::{
        ProximityKeywordsConfig, RuleConfig, RuleConfigBuilder, SecondaryValidator::LuhnChecksum,
    };
    use crate::scanner::{CreateScannerError, Scanner};
    use crate::validation::RegexValidationError;
    use crate::SecondaryValidator::ChineseIdChecksum;
    use crate::SecondaryValidator::GithubTokenChecksum;
    use crate::{
        simple_event::SimpleEvent, PartialRedactDirection, Path, PathSegment, RuleMatch, Scope,
    };
    use std::collections::BTreeMap;

    #[test]
    fn simple_redaction() {
        let scanner = Scanner::new(&[RuleConfig::builder("secret".to_string())
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build()])
        .unwrap();

        let mut input = "text with secret".to_owned();

        let matched_rules = scanner.scan(&mut input);

        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "text with [REDACTED]");
    }

    #[test]
    fn simple_redaction_with_additional_labels() {
        let scanner = Scanner::new_with_labels(
            &[RuleConfig::builder("secret".to_string())
                .match_action(MatchAction::Redact {
                    replacement: "[REDACTED]".to_string(),
                })
                .build()],
            Labels::new(&[("key".to_string(), "value".to_string())]),
        )
        .unwrap();

        let mut input = "text with secret".to_owned();

        let matched_rules = scanner.scan(&mut input);

        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "text with [REDACTED]");
    }

    #[test]
    fn should_fail_on_compilation_error() {
        let scanner_result = Scanner::new(&[RuleConfig::builder("\\u".to_owned()).build()]);
        assert!(scanner_result.is_err());
        assert_eq!(
            scanner_result.err().unwrap(),
            CreateScannerError::InvalidRegex(RegexValidationError::InvalidSyntax)
        )
    }

    #[test]
    fn should_validate_zero_char_count_partial_redact() {
        let scanner_result = Scanner::new(&[RuleConfig::builder("secret".to_owned())
            .match_action(MatchAction::PartialRedact {
                direction: PartialRedactDirection::LastCharacters,
                character_count: 0,
            })
            .build()]);

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
        let scanner = Scanner::new(&[RuleConfig::builder("\\d".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build()])
        .unwrap();

        let mut content = "testing 1 2 3".to_string();

        let matches = scanner.scan(&mut content);

        assert_eq!(content, "testing [REDACTED] [REDACTED] [REDACTED]");
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn match_rule_index() {
        let scanner = Scanner::new(&[
            RuleConfig::builder("a".to_owned()).build(),
            RuleConfig::builder("b".to_owned()).build(),
        ])
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
        let detect_test_rule = RuleConfig::builder("test".to_owned()).build();
        let redact_test_rule = RuleConfigBuilder::from(&detect_test_rule)
            .match_action(MatchAction::Redact {
                replacement: "[test]".to_string(),
            })
            .build();
        let redact_test_rule_2 = RuleConfig::builder("ab".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "[ab]".to_string(),
            })
            .build();

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
            let scanner = Scanner::new(rule_config.leak()).unwrap();
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

    #[test]
    fn test_included_keywords() {
        let redact_test_rule = RuleConfig::builder("world".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = Scanner::new(&[redact_test_rule]).unwrap();
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(content, "hello [REDACTED]");
        assert_eq!(matches.len(), 1);

        let mut content = "he**o world".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(content, "he**o world");
        assert_eq!(matches.len(), 0);

        let mut content = "world hello world".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(content, "world hello [REDACTED]");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_excluded_keywords() {
        let redact_test_rule = RuleConfig::builder("world".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec![],
                excluded_keywords: vec!["hello".to_string()],
            })
            .build();

        let scanner = Scanner::new(&[redact_test_rule]).unwrap();
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
    fn test_luhn_checksum() {
        let rule = RuleConfig::builder("\\b4\\d{3}(?:(?:\\s\\d{4}){3}|(?:\\.\\d{4}){3}|(?:-\\d{4}){3}|(?:\\d{9}(?:\\d{3}(?:\\d{3})?)?))\\b".to_string())
            .match_action(MatchAction::Redact {
                replacement: "[credit card]".to_string(),
            })
            .build();

        let rule_with_checksum = RuleConfigBuilder::from(&rule)
            .validator(LuhnChecksum)
            .build();

        let scanner = Scanner::new(&[rule]).unwrap();
        let mut content = "4556997807150071 4111 1111 1111 1111".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(matches.len(), 2);
        assert_eq!(content, "[credit card] [credit card]");

        let scanner = Scanner::new(&[rule_with_checksum]).unwrap();
        let mut content = "4556997807150071 4111 1111 1111 1111".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "4556997807150071 [credit card]");
    }

    #[test]
    fn test_chinese_id_checksum() {
        let pattern = "\\b[1-9]\\d{5}(?:(?:19|20)\\d{2}(?:(?:0[1-9]|1[0-2])(?:0[1-9]|[1-2]\\d|3[0-1]))\\d{3}[0-9Xx]|\\d{7,18})\\b";
        let rule = RuleConfig::builder(pattern.to_string())
            .match_action(MatchAction::Redact {
                replacement: "[IDCARD]".to_string(),
            })
            .build();

        let rule_with_checksum = RuleConfigBuilder::from(&rule)
            .validator(ChineseIdChecksum)
            .build();

        let scanner = Scanner::new(&[rule]).unwrap();
        let mut content = "513231200012121657 513231200012121651".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(matches.len(), 2);
        assert_eq!(content, "[IDCARD] [IDCARD]");

        let scanner = Scanner::new(&[rule_with_checksum]).unwrap();
        let mut content = "513231200012121657 513231200012121651".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "[IDCARD] 513231200012121651");
    }

    #[test]
    fn test_github_token_checksum() {
        let pattern = "\\bgh[opsu]_[0-9a-zA-Z]{36}\\b";
        let rule = RuleConfig::builder(pattern.to_string())
            .match_action(MatchAction::Redact {
                replacement: "[GITHUB]".to_string(),
            })
            .build();

        let rule_with_checksum = RuleConfigBuilder::from(&rule)
            .validator(GithubTokenChecksum)
            .build();

        let scanner = Scanner::new(&[rule]).unwrap();
        let mut content =
            "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
                .to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(matches.len(), 2);
        assert_eq!(content, "[GITHUB] [GITHUB]");

        let scanner = Scanner::new(&[rule_with_checksum]).unwrap();
        let mut content =
            "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
                .to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "[GITHUB] ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5");
    }

    #[test]
    fn test_overlapping_mutations() {
        // This reproduces a bug where overlapping mutations weren't filtered out, resulting in invalid
        // UTF-8 indices being calculated which resulted in a panic if they were used.

        let rule = RuleConfig::builder("hello".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "*".to_string(),
            })
            .build();

        let scanner = Scanner::new(&[rule.clone(), rule]).unwrap();
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content);
        assert_eq!(content, "* world");

        // The rule was cloned, so if this is only 1, the 2nd was filtered out
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_multiple_partial_redactions() {
        let rule = RuleConfig::builder("...".to_owned())
            .match_action(MatchAction::PartialRedact {
                direction: PartialRedactDirection::FirstCharacters,
                character_count: 1,
            })
            .build();

        let scanner = Scanner::new(&[rule.clone(), rule]).unwrap();
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
                shift_offset: 0
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
                shift_offset: 0
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
                shift_offset: 0
            }
        );
    }

    #[test]
    fn assert_scanner_is_sync_send() {
        // This ensures that the scanner is safe to use from multiple threads.
        fn assert_send<T: Send + Sync>() {}

        assert_send::<Scanner>();
    }

    #[test]
    fn matches_should_take_precedence_over_non_mutating_overlapping_matches() {
        let rule_0 = RuleConfig::builder("...".to_owned())
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RuleConfig::builder("...".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "***".to_string(),
            })
            .build();

        let scanner = Scanner::new(&[rule_0, rule_1]).unwrap();
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
                shift_offset: 0
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
                shift_offset: 0
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
                shift_offset: 0
            }
        );
    }

    #[test]
    fn test_overlapping_mutation_higher_priority() {
        // A mutating match is a higher priority even if it starts after a non-mutating match

        let rule_0 = RuleConfig::builder("abc".to_owned())
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RuleConfig::builder("bcd".to_owned())
            .match_action(MatchAction::Redact {
                replacement: "***".to_string(),
            })
            .build();

        let scanner = Scanner::new(&[rule_0, rule_1]).unwrap();
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
                shift_offset: 0
            }
        );
    }

    #[test]
    fn test_overlapping_start_offset() {
        // The match that starts first is used (if the mutation is the same)

        let rule_0 = RuleConfig::builder("abc".to_owned())
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RuleConfig::builder("bcd".to_owned())
            .match_action(MatchAction::None)
            .build();

        let scanner = Scanner::new(&[rule_0, rule_1]).unwrap();
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
                shift_offset: 0
            }
        );
    }

    #[test]
    fn test_overlapping_length() {
        // If 2 matches have the same mutation and same start, the longer one is taken

        let rule_0 = RuleConfig::builder("abc".to_owned())
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RuleConfig::builder("abcd".to_owned())
            .match_action(MatchAction::None)
            .build();

        let scanner = Scanner::new(&[rule_0, rule_1]).unwrap();
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
                shift_offset: 0
            }
        );
    }

    #[test]
    fn test_overlapping_rule_order() {
        // If 2 matches have the same mutation, same start, and the same length, the one with the lower rule index is used

        let rule_0 = RuleConfig::builder("abc".to_owned())
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RuleConfig::builder("abc".to_owned())
            .match_action(MatchAction::None)
            .build();

        let scanner = Scanner::new(&[rule_0, rule_1]).unwrap();
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
                shift_offset: 0
            }
        );
    }

    #[test]
    fn should_skip_match_when_present_in_excluded_matches() {
        // If 2 matches have the same mutation and same start, the longer one is taken

        let rule_0 = RuleConfig::builder("b.*".to_owned())
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                "test".into(),
            )])]))
            .match_action(MatchAction::Redact {
                replacement: "[scrub]".to_string(),
            })
            .build();

        let scanner = Scanner::new(&[rule_0]).unwrap();

        let mut content = SimpleEvent::Map(BTreeMap::from([
            (
                "message".to_string(),
                SimpleEvent::String("abcdef".to_string()),
            ),
            ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
        ]));

        let matches = scanner.scan(&mut content);

        // The match from the "test" field (which is excluded) is the same as the match from "message", so it is
        // treated as a false positive.
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn should_not_exclude_false_positive_matches() {
        // If a match in an excluded scope is a false-positive due to keyword proximity matching,
        // it is not saved in the excluded matches.

        let rule_0 = RuleConfig::builder("b.*".to_owned())
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["secret".to_string()],
                excluded_keywords: vec![],
            })
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                "test".into(),
            )])]))
            .match_action(MatchAction::Redact {
                replacement: "[scrub]".to_string(),
            })
            .build();

        let scanner = Scanner::new(&[rule_0]).unwrap();

        let mut content = SimpleEvent::Map(BTreeMap::from([
            (
                "message".to_string(),
                SimpleEvent::String("secret abcdef".to_string()),
            ),
            ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
        ]));

        let matches = scanner.scan(&mut content);

        // The match from the "test" field (which is excluded) is the same as the match from "message", so it is
        // treated as a false positive.
        assert_eq!(matches.len(), 1);
    }
}
