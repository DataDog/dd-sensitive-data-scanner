use criterion::Criterion;
use dd_sds::{
    ContentVisitor, ExclusionCheck, Path, PathSegment, ProximityKeywordsConfig, RegexRuleConfig,
    RuleIndexVisitor, Scope, ScopedRuleSet,
};
use dd_sds::{LuhnChecksum, Validator};
use dd_sds::{Scanner, SimpleEvent};
use std::collections::BTreeMap;

pub fn scoped_ruleset(c: &mut Criterion) {
    let mut paths = vec![];

    for i in 0..100 {
        paths.push(Path::from(vec![PathSegment::Field(
            format!("key-{}", i).into(),
        )]));
    }
    let scope = Scope::include(paths.clone());
    let exclude_scope = Scope::Exclude(paths);

    let mut event_map = BTreeMap::new();

    for i in 0..100 {
        event_map.insert(
            format!("key-{}", i),
            SimpleEvent::String(format!("value-{}", i)),
        );
    }
    let mut event = SimpleEvent::Map(event_map);

    let mut scopes = vec![];

    for _ in 0..100 {
        scopes.push(scope.clone());
    }
    for _ in 0..100 {
        scopes.push(exclude_scope.clone());
    }

    let fast_rule_set = ScopedRuleSet::new(&scopes).with_implicit_index_wildcards(true);

    c.bench_function("scoped_rule_set", |b| {
        b.iter(|| {
            let mut num_visited = 0;
            struct Counter<'a> {
                num_visited: &'a mut i32,
            }

            impl<'a> ContentVisitor<'a> for Counter<'a> {
                fn visit_content(
                    &mut self,
                    _path: &Path<'a>,
                    _content: &str,
                    mut rules: RuleIndexVisitor,
                    _check: ExclusionCheck,
                ) -> bool {
                    rules.visit_rule_indices(|_rule_index| {
                        *self.num_visited += 1;
                    });
                    false
                }

            }

            fast_rule_set.visit_string_rule_combinations(
                &mut event,
                Counter {
                    num_visited: &mut num_visited,
                },
            );

            assert_eq!(num_visited, 20_000);
        })
    });
}

pub fn luhn_checksum(c: &mut Criterion) {
    let credit_cards = vec![
        // source https://www.paypalobjects.com/en_AU/vhelp/paypalmanager_help/credit_card_numbers.htm
        // American Express
        "378282246310005",
        "371449635398431",
        // American Express Corporate
        "378734493671000",
        // Australian BankCard
        "5610591081018250",
        // Diners Club
        "30569309025904",
        "38520000023237",
        // Discover
        "6011111111111117",
        // "6011 0009 9013 9424",
        // JCB
        "3530111333300000",
        // "35660020 20360505",
        // MasterCard
        "5555555555554444",
        // "5105 1051 0510 5100",
        // Visa
        "4111111111111111",
        "4012888888881881",
        "4222222222222",
        // Dankort (PBS)
        "5019717010103742",
        // Switch/Solo (Paymentech)
        "6331101999990016",
    ];
    c.bench_function("luhn-checksum", |b| {
        b.iter(|| {
            for credit_card in credit_cards.clone().into_iter() {
                LuhnChecksum.is_valid_match(credit_card);
                // luhn::valid(credit_card);
            }
        })
    });
}

pub fn included_keywords(c: &mut Criterion) {
    let scanner = Scanner::builder(&[RegexRuleConfig::new("[a-zA-z0-9]{4,25}")
        .proximity_keywords(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![
                "secret".to_string(),
                "password".to_string(),
                "token".to_string(),
                "key".to_string(),
                "code".to_string(),
                "credential".to_string(),
                "passphrase".to_string(),
                "ssn".to_string(),
                "confidential".to_string(),
                "private".to_string(),
            ],
            excluded_keywords: vec![],
        })
        .build()])
    .build()
    .unwrap();

    let mut message = "a".repeat(1_000_000);

    c.bench_function("included_keywords_worst_case_scenario", |b| {
        b.iter(|| {
            let matches = scanner.scan(&mut message, vec![]);
            assert_eq!(matches.len(), 0);
        })
    });
}

pub fn included_keywords_on_path(c: &mut Criterion) {
    let mut event_map = BTreeMap::new();

    for i in 0..100 {
        let mut nested_event = BTreeMap::new();
        for j in 0..100 {
            let is_secret = j % 6 == 0;
            let key = if is_secret { "secret" } else { "another-key" };
            nested_event.insert(key.to_string(), SimpleEvent::String(format!("value-{}", i)));
        }

        event_map.insert(format!("key-{}", i), SimpleEvent::Map(nested_event));
    }

    for i in 0..100 {
        let mut nested_event = BTreeMap::new();
        for j in 0..1000 {
            let mut double_nested_event = BTreeMap::new();
            for k in 0..100 {
                double_nested_event.insert(
                    "yet-another-key".to_string(),
                    SimpleEvent::String(format!("value-{}", i)),
                );
            }
            nested_event.insert(
                "randomkey".to_string(),
                SimpleEvent::Map(double_nested_event),
            );
        }

        event_map.insert(format!("ssn-{}", i), SimpleEvent::Map(nested_event));
    }

    let mut event = SimpleEvent::Map(event_map);

    let scanner = Scanner::builder(&[RegexRuleConfig::new("value")
        .proximity_keywords(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["secret".to_string(), "ssn".to_string()],
            excluded_keywords: vec![],
        })
        .build()])
    .with_keywords_should_match_event_paths(false)
    .build()
    .unwrap();

    c.bench_function("included_keywords_on_path_off", |b| {
        b.iter(|| {
            let matches = scanner.scan(&mut event, vec![]);
            assert_eq!(matches.len(), 0);
        });
    });

    let scanner = Scanner::builder(&[RegexRuleConfig::new("value")
        .proximity_keywords(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["secret".to_string(), "ssn".to_string()],
            excluded_keywords: vec![],
        })
        .build()])
    .with_keywords_should_match_event_paths(true)
    .build()
    .unwrap();

    c.bench_function("included_keywords_on_path_on", |b| {
        b.iter(|| {
            let matches = scanner.scan(&mut event, vec![]);
            assert!(!matches.is_empty());
        })
    });
}

criterion::criterion_group!(
    benches,
    scoped_ruleset,
    luhn_checksum,
    included_keywords,
    included_keywords_on_path
);

criterion::criterion_main!(benches);
