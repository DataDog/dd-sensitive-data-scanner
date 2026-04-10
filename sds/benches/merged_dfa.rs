use criterion::{Criterion, criterion_group, criterion_main};
use dd_sds::{MatchAction, RegexRuleConfig, RootRuleConfig, Scanner};
use std::fs::File;
use std::io::Read;

fn sample_regexes() -> Vec<String> {
    vec![
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string(),
        r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
        r"\b[A-CEGHJ-NPR-TW-Z]{2}\d{6}[A-D]?\b".to_string(),
        r"\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\d{10}".to_string(),
        r"(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/\d{4}".to_string(),
        r"\b(?:\d{4}[ -]?){3}\d{4}\b".to_string(),
        r"\b([0-9]{9}|[A-Z]{2}[0-9]{7})\b".to_string(),
        r"\b\d{8,17}\b".to_string(),
        r"\b[A-Z]{1,2}\d{6,8}\b".to_string(),
        r"\b[A-Z]{3}\d{8}\b".to_string(),
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b".to_string(),
        r"\b\d{9}\b".to_string(),
        r"(0[1-9]|1[0-2])\/\d{2}".to_string(),
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b".to_string(),
        r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b".to_string(),
        r"https?://[^\s/$.?#].[^\s]*".to_string(),
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b".to_string(),
        r"\b[A-HJ-NPR-Z0-9]{17}\b".to_string(),
        r"\b\d{2}-\d{7}\b".to_string(),
        r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b".to_string(),
        r"\b\d{6}\b".to_string(),
        r"\b[A-Z]{3}-\d{6}\b".to_string(),
        r"\b(sensitive note|confidential)\b".to_string(),
        r"[A-Za-z0-9_-]{28}".to_string(),
        r"\b[A-Za-z0-9]{32}\b".to_string(),
        r"\b[a-fA-F0-9]{64}\b".to_string(),
        r"(ftp|sftp):\/\/[^\s:@]+:[^\s@]+@([^\s\/:]+)(:[0-9]+)?\/?".to_string(),
        r"\b(?:\d{4}[- ]?){3}\d{4}\b".to_string(),
        r"\b(sensitive|confidential|private|restricted)\b".to_string(),
    ]
}

fn build_rules(regexes: &[String]) -> Vec<RootRuleConfig<std::sync::Arc<dyn dd_sds::RuleConfig>>> {
    regexes
        .iter()
        .map(|regex| RootRuleConfig::new(RegexRuleConfig::new(regex).build()))
        .collect()
}

fn sample_inputs() -> Vec<String> {
    let mut file = File::open("data/sample_logs.txt").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    data.lines().map(|x| x.to_string()).collect()
}

fn bench_scanner_construction(c: &mut Criterion) {
    let regexes = sample_regexes();
    let rules = build_rules(&regexes);

    let mut group = c.benchmark_group("merged_dfa_construction");

    group.bench_function("with_merged_dfa", |b| {
        b.iter(|| {
            Scanner::builder(&rules)
                .with_merged_dfa(true)
                .build()
                .unwrap()
        });
    });

    group.bench_function("without_merged_dfa", |b| {
        b.iter(|| {
            Scanner::builder(&rules)
                .with_merged_dfa(false)
                .build()
                .unwrap()
        });
    });

    group.finish();
}

fn bench_scan_no_matches(c: &mut Criterion) {
    let regexes = sample_regexes();
    let rules = build_rules(&regexes);

    let scanner_with = std::sync::Arc::new(
        Scanner::builder(&rules)
            .with_merged_dfa(true)
            .build()
            .unwrap(),
    );
    let scanner_without = std::sync::Arc::new(
        Scanner::builder(&rules)
            .with_merged_dfa(false)
            .build()
            .unwrap(),
    );

    // Content that shouldn't match any of the 29 patterns
    let content = "The quick brown fox jumps over the lazy dog. \
                   Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
                   Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

    let mut group = c.benchmark_group("merged_dfa_scan_no_matches");

    group.bench_function("with_merged_dfa", |b| {
        b.iter(|| {
            let mut input = content.to_string();
            let matches = scanner_with.scan(&mut input).unwrap();
            assert_eq!(matches.len(), 0);
        });
    });

    group.bench_function("without_merged_dfa", |b| {
        b.iter(|| {
            let mut input = content.to_string();
            let matches = scanner_without.scan(&mut input).unwrap();
            assert_eq!(matches.len(), 0);
        });
    });

    group.finish();
}

fn bench_scan_few_matches(c: &mut Criterion) {
    let regexes = sample_regexes();
    let rules = build_rules(&regexes);

    let scanner_with = std::sync::Arc::new(
        Scanner::builder(&rules)
            .with_merged_dfa(true)
            .build()
            .unwrap(),
    );
    let scanner_without = std::sync::Arc::new(
        Scanner::builder(&rules)
            .with_merged_dfa(false)
            .build()
            .unwrap(),
    );

    // Content that matches only a few patterns (email, IP)
    let content = "Contact user@example.com for server 192.168.1.100 details.";

    let mut group = c.benchmark_group("merged_dfa_scan_few_matches");

    group.bench_function("with_merged_dfa", |b| {
        b.iter(|| {
            let mut input = content.to_string();
            scanner_with.scan(&mut input).unwrap()
        });
    });

    group.bench_function("without_merged_dfa", |b| {
        b.iter(|| {
            let mut input = content.to_string();
            scanner_without.scan(&mut input).unwrap()
        });
    });

    group.finish();
}

fn bench_scan_realistic(c: &mut Criterion) {
    let regexes = sample_regexes();
    let rules: Vec<_> = regexes
        .iter()
        .map(|regex| {
            RootRuleConfig::new(RegexRuleConfig::new(regex)).match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
        })
        .collect();
    let dyn_rules: Vec<_> = rules.into_iter().map(|r| r.into_dyn()).collect();

    let scanner_with = std::sync::Arc::new(
        Scanner::builder(&dyn_rules)
            .with_merged_dfa(true)
            .build()
            .unwrap(),
    );
    let scanner_without = std::sync::Arc::new(
        Scanner::builder(&dyn_rules)
            .with_merged_dfa(false)
            .build()
            .unwrap(),
    );

    let sample_inputs = sample_inputs();

    let mut group = c.benchmark_group("merged_dfa_scan_realistic");

    group.bench_function("with_merged_dfa", |b| {
        b.iter(|| {
            let mut matches = 0;
            for input in &sample_inputs {
                let mut input = input.clone();
                let results = scanner_with.scan(&mut input).unwrap();
                matches += results.len();
            }
            matches
        });
    });

    group.bench_function("without_merged_dfa", |b| {
        b.iter(|| {
            let mut matches = 0;
            for input in &sample_inputs {
                let mut input = input.clone();
                let results = scanner_without.scan(&mut input).unwrap();
                matches += results.len();
            }
            matches
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_scanner_construction,
    bench_scan_no_matches,
    bench_scan_few_matches,
    bench_scan_realistic,
);
criterion_main!(benches);
