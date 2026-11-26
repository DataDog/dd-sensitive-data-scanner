use crate::{
    CompiledRule, CreateScannerError, Labels, MatchAction, Path, RegexRuleConfig, RootRuleConfig,
    RuleConfig, RuleResult, RuleStatus, ScanOptionBuilder, Scanner, Scope, StringMatchesCtx,
};
use serde_json::json;
use std::sync::{Arc, mpsc};

fn redact(pattern: &str) -> RootRuleConfig<Arc<dyn RuleConfig>> {
    RootRuleConfig::new_dyn(RegexRuleConfig::new(pattern)).match_action(MatchAction::Redact {
        replacement: "[R]".into(),
    })
}

fn build(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>], enabled: bool) -> Scanner {
    Scanner::builder(rules)
        .with_return_matches(true)
        .with_prefilter(enabled)
        .build()
        .unwrap()
}

#[test]
fn prefilter_preserves_matches_and_redactions() {
    let rules = [
        redact("foo(?:bar[0-9])?"),
        redact("(?:first|second)[0-9]"),
        redact("(?i)key"),
        redact("café"),
        redact("[0-9]{2}"),
    ];
    let filtered = build(&rules, true);
    let unfiltered = build(&rules, false);
    for value in ["foo", "foobar1", "first1", "second2", "Key", "café", "12"] {
        for len in [value.len(), 255, 256, 257, 4096] {
            let prefix = ".".repeat(len - value.len());
            let mut input = format!("{prefix}{value}");
            let mut reference = input.clone();
            let matches = filtered.scan(&mut input).unwrap();
            assert_eq!(matches, unfiltered.scan(&mut reference).unwrap());
            assert_eq!(matches.len(), 1, "{value}, {len} bytes");
            assert_eq!(matches[0].match_value.as_deref(), Some(value));
            assert_eq!(input, reference);
            assert_eq!(input, format!("{prefix}[R]"));
        }
    }
}

#[test]
fn prefilter_preserves_scopes_and_excluded_values() {
    let message = Path::from(vec!["message".into()]);
    let excluded = Path::from(vec!["ignore".into()]);
    let rules = [
        redact("id[0-9]").scope(Scope::include_and_exclude(
            vec![message.clone(), excluded.clone()],
            vec![excluded],
        )),
        redact("token").scope(Scope::include(vec![message])),
    ];
    let event = json!({"message":"id1 id2 token", "ignore":"id1", "other":"id2 token"});
    let scan = |enabled| {
        let mut result = event.clone();
        let options = ScanOptionBuilder::new()
            .with_blocked_rules_idx(vec![1])
            .build();
        let matches = build(&rules, enabled)
            .scan_with_options(&mut result, options)
            .unwrap();
        (matches, result)
    };
    let filtered = scan(true);
    assert_eq!(filtered, scan(false));
    let (matches, output) = filtered;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_value.as_deref(), Some("id2"));
    assert_eq!(
        output,
        json!({"message":"id1 [R] token", "ignore":"id1", "other":"id2 token"})
    );
}

#[test]
fn keyword_and_rule_keep_their_own_case_settings() {
    let keyword =
        RootRuleConfig::new_dyn(RegexRuleConfig::new("value").with_included_keywords(["ς"]));
    let case_sensitive = RootRuleConfig::new_dyn(RegexRuleConfig::new("ς"));
    for rules in [
        [keyword.clone(), case_sensitive.clone()],
        [case_sensitive, keyword],
    ] {
        for enabled in [false, true] {
            let matches = build(&rules, enabled)
                .scan(&mut "Σ value".to_owned())
                .unwrap();
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].match_value.as_deref(), Some("value"));
        }
    }
}

#[test]
fn custom_rule_can_replace_its_compiled_regex_and_decline_the_prefilter() {
    struct AdaptedRule(RegexRuleConfig);

    impl RuleConfig for AdaptedRule {
        fn convert_to_compiled_rule(
            &self,
            index: usize,
            labels: Labels,
        ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
            let mut compiled = self.0.convert_to_compiled_rule(index, labels)?;
            compiled.as_regex_rule_mut().unwrap().regex =
                crate::get_memoized_regex("x", regex_automata::meta::Regex::new).unwrap();
            Ok(compiled)
        }

        fn as_regex_rule(&self) -> Option<&RegexRuleConfig> {
            Some(&self.0)
        }
    }

    let rules = [
        RootRuleConfig::new_dyn(AdaptedRule(RegexRuleConfig::new("longer"))),
        redact("other"),
    ];
    let matches = build(&rules, true).scan(&mut "x".to_owned()).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_value.as_deref(), Some("x"));
}

#[test]
fn opted_in_rule_only_visits_candidate_fields_when_prefilter_is_enabled() {
    #[derive(Clone)]
    struct RecordingRule(mpsc::Sender<String>);

    impl RuleConfig for RecordingRule {
        fn convert_to_compiled_rule(
            &self,
            _: usize,
            _: Labels,
        ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
            Ok(Box::new(self.clone()))
        }

        fn pattern_for_prefilter(&self) -> Option<&str> {
            Some("ab[0-9]{2}")
        }
    }

    impl CompiledRule for RecordingRule {
        fn get_string_matches(
            &self,
            content: &str,
            _: &Path,
            _: &mut StringMatchesCtx,
        ) -> RuleResult {
            self.0.send(content.to_owned()).unwrap();
            Ok(RuleStatus::Done)
        }
    }

    let (sender, visits) = mpsc::channel();
    let rules = [RootRuleConfig::new_dyn(RecordingRule(sender))];
    let fields = ["ab", "xxxx", "ab12"];
    let mut event = json!(fields);
    Scanner::builder(&rules)
        .build()
        .unwrap()
        .scan(&mut event)
        .unwrap();
    assert_eq!(visits.try_iter().collect::<Vec<_>>(), fields);

    build(&rules, true).scan(&mut event).unwrap();
    assert_eq!(visits.try_iter().collect::<Vec<_>>(), ["ab12"]);
}
