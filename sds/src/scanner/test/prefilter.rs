use crate::scanner::prefilter::{
    KeywordLiterals, RulePrefilterSpec, longest_runs, longest_runs_portable,
};
use crate::{
    MatchAction, Path, PathSegment, ProximityKeywordsConfig, RegexRuleConfig, RootRuleConfig,
    RuleConfig, Scanner, ScannerBuilder, Scope, SimpleEvent,
};
use std::collections::BTreeMap;
use std::sync::Arc;

fn spec(pattern: &str) -> RulePrefilterSpec {
    RulePrefilterSpec::from_regex_rule(pattern, None).unwrap()
}

fn literals(pattern: &str) -> Option<Vec<String>> {
    spec(pattern).regex.literals.clone().map(|lits| {
        let mut lits: Vec<_> = lits
            .into_iter()
            .map(|lit| String::from_utf8_lossy(&lit).to_string())
            .collect();
        lits.sort();
        lits
    })
}

fn keywords(keywords: &[&str]) -> Option<KeywordLiterals> {
    RulePrefilterSpec::from_regex_rule(
        "abc",
        Some(&ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: keywords.iter().map(|s| s.to_string()).collect(),
            excluded_keywords: vec![],
        }),
    )
    .unwrap()
    .keywords
}

#[test]
fn minimum_length_comes_from_the_whole_pattern() {
    assert_eq!(spec("abc[a-z]{10}").regex.min_len, 13);
    // A multi-byte class counts its shortest encoding.
    assert_eq!(spec("\\d{4}").regex.min_len, 4);
    // Assertions have no width.
    assert_eq!(spec("\\bab\\b").regex.min_len, 2);
}

#[test]
fn literals_are_required_substrings() {
    assert_eq!(literals("aio_[A-Za-z0-9]{28}").unwrap(), vec!["aio_"]);
    // A literal inside a capture group and after an optional prefix.
    assert_eq!(
        literals("(?:^|[\\s=])(?<sds_match>ghp_[a-z]{10})(?:$|\\s)").unwrap(),
        vec!["ghp_"]
    );
    // An alternation needs every branch to have a literal.
    assert_eq!(literals("(?:foo|bar)[0-9]+").unwrap(), vec!["bar", "foo"]);
    assert_eq!(literals("(?:foo|[a-z]+)[0-9]+"), None);
    // An optional literal is not required.
    assert_eq!(literals("(?:foo)?[0-9]+"), None);
    // A repetition with a minimum of one still requires the literal.
    assert_eq!(literals("(?:foo){1,3}[0-9]+").unwrap(), vec!["foo"]);
    // A literal and a small class give a cross product, which keeps the condition selective.
    assert_eq!(literals("\\b3[47]\\d{13}\\b").unwrap(), vec!["34", "37"]);
    // Nothing is known about a pattern of only large classes.
    assert_eq!(literals("[a-z0-9]{32}"), None);
}

#[test]
fn case_insensitive_literals_keep_non_ascii_case_variants() {
    // Unicode case folding maps the Kelvin sign to k, so the variant must be present.
    let lits = literals("(?i)kk").unwrap();
    assert!(lits.contains(&"kk".to_string()));
    assert!(lits.contains(&"\u{212A}k".to_string()));
    assert!(lits.contains(&"\u{212A}\u{212A}".to_string()));
}

#[test]
fn keyword_literals_use_a_run_between_link_characters() {
    let lits = keywords(&["api key", "password"]).unwrap();
    assert_eq!(
        lits.content_keywords,
        vec![b"key".to_vec(), b"password".to_vec()]
    );
    assert_eq!(
        lits.path_keywords,
        vec![b"key".to_vec(), b"password".to_vec()]
    );

    // The path pattern splits camel case, and the content pattern does not.
    let lits = keywords(&["apiKey"]).unwrap();
    assert_eq!(lits.content_keywords, vec![b"apikey".to_vec()]);
    assert_eq!(lits.path_keywords, vec![b"key".to_vec()]);

    // A non-ASCII keyword needs non-ASCII text, so it adds no literal.
    let lits = keywords(&["\u{09CE}host", "token"]).unwrap();
    assert_eq!(lits.content_keywords, vec![b"token".to_vec()]);

    // A keyword without a usable literal makes the keyword condition unknown.
    assert_eq!(keywords(&["\u{212A}ey"]), None);
    assert_eq!(keywords(&["ok", "-"]), None);
}

#[test]
fn only_two_non_ascii_characters_fold_to_ascii() {
    use regex_syntax_08::hir::{ClassUnicode, ClassUnicodeRange};
    // This holds for the Unicode tables that the regex uses.
    let mut non_ascii = ClassUnicode::new([ClassUnicodeRange::new('\u{80}', '\u{10FFFF}')]);
    non_ascii.try_case_fold_simple().unwrap();
    let mut ascii_from_folding = ClassUnicode::new([ClassUnicodeRange::new('\0', '\u{7F}')]);
    ascii_from_folding.intersect(&non_ascii);
    let letters: Vec<_> = ascii_from_folding
        .iter()
        .flat_map(|range| range.start()..=range.end())
        .collect();
    assert_eq!(letters, vec!['K', 'S', 'k', 's']);
}

#[test]
fn simd_and_portable_runs_agree() {
    let mut rng = Rng(0xD6E8FEB86659FD93);
    let alphabet = b"0123456789abcdefxyzABC-_+/=.* \n\xC3\xA9";
    for _ in 0..2_000 {
        let len = rng.below(600) as usize;
        let content: Vec<u8> = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize])
            .collect();
        assert_eq!(longest_runs(&content), longest_runs_portable(&content));
    }
    // A run above the cap stays at the cap.
    assert_eq!(longest_runs(&[b'1'; 1000])[0], 255);
    assert_eq!(longest_runs_portable(&[b'1'; 1000])[0], 255);
}

// Patterns and keywords that exercise each code path of a regex rule.
fn rule_configs() -> Vec<RegexRuleConfig> {
    let keyword = |pattern: &str, keywords: &[&str]| {
        RegexRuleConfig::new(pattern).with_proximity_keywords(ProximityKeywordsConfig {
            look_ahead_character_count: 20,
            included_keywords: keywords.iter().map(|s| s.to_string()).collect(),
            excluded_keywords: vec![],
        })
    };
    vec![
        RegexRuleConfig::new("aio_[A-Za-z0-9]{4}"),
        RegexRuleConfig::new("(?i)token[0-9]{2}"),
        RegexRuleConfig::new("(?i)kk[0-9]"),
        RegexRuleConfig::new("(?i)ss[0-9]"),
        RegexRuleConfig::new("\\b3[47]\\d{3}\\b"),
        RegexRuleConfig::new("(?:foo|bar)[0-9]+"),
        RegexRuleConfig::new("[0-9a-f]{8}"),
        RegexRuleConfig::new("(?:^|\\s)(?<sds_match>sec_[a-z]{3})(?:$|\\s)")
            .with_pattern_capture_group("sds_match"),
        keyword("[a-z0-9]{6}", &["api key", "password"]),
        keyword("[A-Z]{5}", &["apiKey", "token"]),
        keyword("aio_[a-z]{2}", &["secret", "id"]),
        keyword("[0-9]{4}", &["-host", "host-", "k"]),
        keyword("[a-z]{7}", &["\u{09CE}host", "kelvin"]),
        keyword("(?i)ghp_[a-z]{3}", &["github", "git hub"]),
        RegexRuleConfig::new("[0-9]{3}-[0-9]{2}").with_excluded_keywords(["test", "example"]),
        keyword("[0-9]{5}", &["card"]).with_excluded_keywords(["fake"]),
    ]
}

const FRAGMENTS: &[&str] = &[
    "aio_Ab12",
    "aio_ab",
    "token12",
    "TOKEN34",
    "\u{212A}k1",
    "k\u{212A}2",
    "KK3",
    "\u{17F}S4",
    "ss5",
    "sS6",
    "34123",
    "37999",
    "foo1",
    "bar22",
    "deadbeef",
    "sec_abc",
    "api key",
    "api_key",
    "API-KEY",
    "apikey",
    "password",
    "PASSWORD",
    "apiKey",
    "APIKEY",
    "secret",
    "SECRET",
    "id",
    "valid",
    "-host",
    "host-",
    "local-host",
    "hostlocal",
    "k",
    "\u{212A}",
    "kelvin",
    "\u{212A}elvin",
    "\u{09CE}host",
    "github",
    "git hub",
    "git.hub",
    "ghp_abc",
    "GHP_XYZ",
    "123-45",
    "test",
    "example",
    "card",
    "fake",
    "12345",
    "abcdef",
    "ABCDE",
    "caf\u{e9}",
    "\u{65E5}\u{672C}\u{8A9E}",
    " ",
    "\n",
    "=",
    ":",
    "-",
    "_",
    ".",
    "/",
    "",
];

const PATH_FIELDS: &[&str] = &[
    "message",
    "api_key",
    "apiKey",
    "API-KEY",
    "api.key",
    "password",
    "secret",
    "user_id",
    "id",
    "my-host",
    "hostName",
    "token",
    "Tok\u{212A}en",
    "\u{212A}elvin",
    "kelvin",
    "card_number",
    "github",
    "gitHub",
    "x",
    "meta",
    "ſecret",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() % items.len() as u64) as usize]
    }

    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }
}

fn random_string(rng: &mut Rng) -> String {
    let mut out = String::new();
    for _ in 0..rng.below(6) {
        out.push_str(rng.pick(FRAGMENTS));
        if rng.below(3) == 0 {
            out.push(' ');
        }
    }
    out
}

fn random_event(rng: &mut Rng) -> SimpleEvent {
    let mut map = BTreeMap::new();
    for _ in 0..1 + rng.below(4) {
        let key = rng.pick(PATH_FIELDS).to_string();
        let value = match rng.below(4) {
            0 => {
                let mut inner = BTreeMap::new();
                inner.insert(
                    rng.pick(PATH_FIELDS).to_string(),
                    SimpleEvent::String(random_string(rng)),
                );
                SimpleEvent::Map(inner)
            }
            1 => SimpleEvent::List(vec![
                SimpleEvent::String(random_string(rng)),
                SimpleEvent::String(random_string(rng)),
            ]),
            _ => SimpleEvent::String(random_string(rng)),
        };
        map.insert(key, value);
    }
    SimpleEvent::Map(map)
}

fn build(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>], prefilter: bool) -> Scanner {
    ScannerBuilder::new(rules)
        .with_return_matches(true)
        .with_prefilter(prefilter)
        .build()
        .unwrap()
}

/// Scans with and without the prefilter, and requires the same matches and the same event.
fn assert_same_scan(with: &Scanner, without: &Scanner, event: &SimpleEvent) {
    let mut a = event.clone();
    let mut b = event.clone();
    let ma = with.scan(&mut a).unwrap();
    let mb = without.scan(&mut b).unwrap();
    assert_eq!(ma, mb, "matches differ for {event:?}");
    assert_eq!(a, b, "output differs for {event:?}");
}

fn differential(rules: Vec<RootRuleConfig<Arc<dyn RuleConfig>>>, seed: u64, rounds: usize) {
    let with = build(&rules, true);
    let without = build(&rules, false);
    let mut rng = Rng(seed);
    for _ in 0..rounds {
        assert_same_scan(&with, &without, &random_event(&mut rng));
    }
}

#[test]
fn prefilter_keeps_matches() {
    let rules = rule_configs()
        .into_iter()
        .map(|config| RootRuleConfig::new(Arc::new(config) as Arc<dyn RuleConfig>))
        .collect();
    differential(rules, 0x9E3779B97F4A7C15, 20_000);
}

#[test]
fn prefilter_keeps_redactions() {
    let rules = rule_configs()
        .into_iter()
        .map(|config| {
            RootRuleConfig::new(Arc::new(config) as Arc<dyn RuleConfig>).match_action(
                MatchAction::Redact {
                    replacement: "[R]".to_string(),
                },
            )
        })
        .collect();
    differential(rules, 0xC2B2AE3D27D4EB4F, 5_000);
}

#[test]
fn prefilter_keeps_multipass_exclusions() {
    // Matches from excluded paths must still be found, because they remove equal matches elsewhere.
    let excluded = Path::from(vec![PathSegment::Field("meta".into())]);
    let rules = rule_configs()
        .into_iter()
        .map(|config| {
            RootRuleConfig::new(Arc::new(config) as Arc<dyn RuleConfig>)
                .scope(Scope::exclude(vec![excluded.clone()]))
        })
        .collect();
    differential(rules, 0x165667B19E3779F9, 5_000);
}

#[test]
fn prefilter_keeps_matches_with_included_scopes() {
    // A rule with an include scope is only visited below the path, so the scanner has to use the
    // rule tree and not the survivors alone.
    let included = Path::from(vec![PathSegment::Field("message".into())]);
    let rules = rule_configs()
        .into_iter()
        .enumerate()
        .map(|(i, config)| {
            let rule = RootRuleConfig::new(Arc::new(config) as Arc<dyn RuleConfig>);
            if i % 2 == 0 {
                rule.scope(Scope::include(vec![included.clone()]))
            } else {
                rule
            }
        })
        .collect();
    differential(rules, 0x85EBCA77C2B2AE63, 5_000);
}

#[test]
fn prefilter_keeps_matches_when_a_string_has_no_rule_in_scope() {
    // All rules have an include scope, so the other fields have no rule in scope and the scanner
    // returns before the passes.
    let included = Path::from(vec![PathSegment::Field("message".into())]);
    let rules = rule_configs()
        .into_iter()
        .map(|config| {
            RootRuleConfig::new(Arc::new(config) as Arc<dyn RuleConfig>)
                .scope(Scope::include(vec![included.clone()]))
        })
        .collect();
    differential(rules, 0x165667B19E3779F9, 5_000);
}

#[test]
fn prefilter_keeps_matches_with_few_rules() {
    // Few rules do not get a literal pass, but the minimum length still applies.
    for config in rule_configs() {
        let rules = vec![RootRuleConfig::new(Arc::new(config) as Arc<dyn RuleConfig>)];
        differential(rules, 0x27D4EB2F165667C5, 300);
    }
}

#[test]
fn long_strings_keep_matches_when_the_passes_are_skipped() {
    // Four rules with required literals skip the passes on a long string.
    let rules: Vec<_> = [
        "aaa_[0-9]{4}",
        "bbb_[0-9]{4}",
        "ccc_[0-9]{4}",
        "ddd_[0-9]{4}",
    ]
    .iter()
    .map(|pattern| {
        RootRuleConfig::new(Arc::new(RegexRuleConfig::new(pattern)) as Arc<dyn RuleConfig>)
    })
    .collect();
    let with = build(&rules, true);
    let without = build(&rules, false);
    for len in [10usize, 300, 400, 5_000, 80_000] {
        let content = format!("{} ccc_1234 {} ddd_12", "x".repeat(len), "y".repeat(len));
        let event = SimpleEvent::Map(BTreeMap::from([(
            "message".to_string(),
            SimpleEvent::String(content),
        )]));
        assert_same_scan(&with, &without, &event);
        assert_eq!(with.scan(&mut event.clone()).unwrap().len(), 1);
    }
}

#[test]
fn a_path_keyword_keeps_a_rule_without_a_content_keyword() {
    let rules = vec![
        RootRuleConfig::new(
            Arc::new(RegexRuleConfig::new("[0-9]{4}").with_proximity_keywords(
                ProximityKeywordsConfig {
                    look_ahead_character_count: 30,
                    included_keywords: vec![
                        "secret".to_string(),
                        "token".to_string(),
                        "apiKey".to_string(),
                        "card".to_string(),
                    ],
                    excluded_keywords: vec![],
                },
            )) as Arc<dyn RuleConfig>,
        );
        4
    ];
    let scanner = build(&rules, true);
    let mut event = SimpleEvent::Map(BTreeMap::from([(
        "api_key".to_string(),
        SimpleEvent::String("1234".to_string()),
    )]));
    let matches = scanner.scan(&mut event).unwrap();
    assert!(!matches.is_empty());
    let mut unrelated = SimpleEvent::Map(BTreeMap::from([(
        "other".to_string(),
        SimpleEvent::String("1234".to_string()),
    )]));
    assert!(scanner.scan(&mut unrelated).unwrap().is_empty());
}
