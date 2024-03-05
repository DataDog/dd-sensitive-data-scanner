use criterion::{criterion_group, criterion_main};

mod scope_benchmark {
    use criterion::Criterion;
    use sds::{Path, PathSegment, Scope, ScopedRuleSet, SimpleEvent};
    use std::collections::BTreeMap;

    pub fn criterion_benchmark(c: &mut Criterion) {
        let mut paths = vec![];

        for i in 0..100 {
            paths.push(Path::from(vec![PathSegment::Field(
                format!("key-{}", i).into(),
            )]));
        }
        let scope = Scope::Include(paths.clone());
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

        let fast_rule_set = ScopedRuleSet::new(&scopes);

        c.bench_function("scoped_rule_set", |b| {
            b.iter(|| {
                let mut num_visited = 0;
                fast_rule_set.visit_string_rule_combinations(
                    &mut event,
                    |_path, _string, rule_visitor| {
                        rule_visitor.visit_rule_indices(|_rule_index| {
                            num_visited += 1;
                        });

                        false
                    },
                );
                assert_eq!(num_visited, 10_000);
            })
        });
    }
}

mod luhn_checksum_benchmark {
    use criterion::{black_box, BenchmarkId, Criterion};
    use sds::{LuhnChecksum, Validator};

    pub fn criterion_benchmark(c: &mut Criterion) {
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
}
criterion_group!(
    benches,
    scope_benchmark::criterion_benchmark,
    luhn_checksum_benchmark::criterion_benchmark
);
criterion_main!(benches);
