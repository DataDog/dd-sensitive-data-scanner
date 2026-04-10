use criterion::Criterion;
use dd_sds::{
    ContentVisitor, ExclusionCheck, Path, PathSegment, ProximityKeywordsConfig, RegexRuleConfig,
    RootRuleConfig, RuleIndexVisitor, ScannerError, Scope, ScopedRuleSet,
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
                ) -> Result<bool, ScannerError> {
                    rules.visit_rule_indices(|_rule_index| {
                        *self.num_visited += 1;
                        Ok(())
                    })?;
                    Ok(false)
                }
            }

            fast_rule_set
                .visit_string_rule_combinations(
                    &mut event,
                    Counter {
                        num_visited: &mut num_visited,
                    },
                )
                .unwrap();

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
    let scanner = Scanner::builder(&[RootRuleConfig::new(
        RegexRuleConfig::new("[a-zA-z0-9]{4,25}")
            .with_proximity_keywords(ProximityKeywordsConfig {
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
            .build(),
    )])
    .build()
    .unwrap();

    let mut message = "a".repeat(1_000_000);

    c.bench_function("included_keywords_worst_case_scenario", |b| {
        b.iter(|| {
            let matches = scanner.scan(&mut message);
            assert_eq!(matches.unwrap().len(), 0);
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
        for _j in 0..1000 {
            let mut double_nested_event = BTreeMap::new();
            for _k in 0..100 {
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

    let scanner = Scanner::builder(&[RootRuleConfig::new(
        RegexRuleConfig::new("value")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["secret".to_string(), "ssn".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )])
    .build()
    .unwrap();

    c.bench_function("included_keywords_on_path_on", |b| {
        b.iter(|| {
            let matches = scanner.scan(&mut event);
            assert!(!matches.unwrap().is_empty());
        })
    });
}

pub fn multipass_excluded_scan(c: &mut Criterion) {
    // Realistic event: deeply nested structure with many paths, simulating
    // a structured log with metadata, user data, and request/response bodies.
    let mut root = BTreeMap::new();

    // Top-level flat fields (50)
    for i in 0..50 {
        root.insert(
            format!("attr-{}", i),
            SimpleEvent::String(format!("token-abc-{}", i)),
        );
    }

    // Nested "user" object with 20 fields
    let mut user = BTreeMap::new();
    for i in 0..20 {
        user.insert(
            format!("field-{}", i),
            SimpleEvent::String("secret-key-99".to_string()),
        );
    }
    root.insert("user".to_string(), SimpleEvent::Map(user));

    // Nested "request" -> "headers" with 30 fields
    let mut headers = BTreeMap::new();
    for i in 0..30 {
        headers.insert(
            format!("x-header-{}", i),
            SimpleEvent::String("bearer-tok-123".to_string()),
        );
    }
    let mut request = BTreeMap::new();
    request.insert("headers".to_string(), SimpleEvent::Map(headers));
    // "request" -> "body" with 40 fields
    let mut body = BTreeMap::new();
    for i in 0..40 {
        body.insert(
            format!("param-{}", i),
            SimpleEvent::String(format!("val-xyz-{}", i % 5)),
        );
    }
    request.insert("body".to_string(), SimpleEvent::Map(body));
    root.insert("request".to_string(), SimpleEvent::Map(request));

    // Nested "response" -> "body" with 30 fields
    let mut resp_body = BTreeMap::new();
    for i in 0..30 {
        resp_body.insert(
            format!("field-{}", i),
            SimpleEvent::String("secret-key-99".to_string()),
        );
    }
    let mut response = BTreeMap::new();
    response.insert("body".to_string(), SimpleEvent::Map(resp_body));
    root.insert("response".to_string(), SimpleEvent::Map(response));

    // Array of 20 items
    let items: Vec<SimpleEvent> = (0..20)
        .map(|i| {
            let mut m = BTreeMap::new();
            m.insert(
                "id".to_string(),
                SimpleEvent::String(format!("item-id-{}", i)),
            );
            m.insert(
                "value".to_string(),
                SimpleEvent::String("secret-key-99".to_string()),
            );
            SimpleEvent::Map(m)
        })
        .collect();
    root.insert("items".to_string(), SimpleEvent::List(items));

    // Excluded scope fields that share content with scanned fields
    let mut excluded = BTreeMap::new();
    for i in 0..10 {
        excluded.insert(
            format!("internal-{}", i),
            SimpleEvent::String("secret-key-99".to_string()),
        );
    }
    root.insert("_metadata".to_string(), SimpleEvent::Map(excluded));

    let mut event = SimpleEvent::Map(root);

    // Exclude _metadata.* paths
    let excluded_paths: Vec<Path> = (0..10)
        .map(|i| {
            Path::from(vec![
                PathSegment::Field("_metadata".into()),
                PathSegment::Field(format!("internal-{}", i).into()),
            ])
        })
        .collect();

    let rule = RootRuleConfig::new(RegexRuleConfig::new("[a-z]+-[a-z]+-\\d+").build())
        .scope(Scope::exclude(excluded_paths))
        .match_action(dd_sds::MatchAction::None);

    let scanner = Scanner::builder(&[rule]).build().unwrap();

    c.bench_function("multipass_excluded_scan", |b| {
        b.iter(|| {
            let _result = scanner.scan(&mut event).unwrap();
        })
    });
}

criterion::criterion_group!(
    benches,
    scoped_ruleset,
    luhn_checksum,
    included_keywords,
    included_keywords_on_path,
    multipass_excluded_scan
);

criterion::criterion_main!(benches);
