use crate::match_action::MatchAction;
use crate::scanner::regex_rule::config::{ProximityKeywordsConfig, RegexRuleConfig};
use crate::scanner::scope::Scope;
use crate::scanner::{RootRuleConfig, ScannerBuilder};
use crate::{simple_event::SimpleEvent, Path, PathSegment};
use metrics::{Key, Label};
use metrics_util::debugging::DebugValue;
use metrics_util::debugging::DebuggingRecorder;
use metrics_util::CompositeKey;
use metrics_util::MetricKind::Counter;
use std::collections::BTreeMap;

#[test]
fn should_submit_scanning_metrics() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let content_1 = "bcdef";
    let content_2 = "no match";

    metrics::with_local_recorder(&recorder, || {
        let rule_0 = RootRuleConfig::new(RegexRuleConfig::new(content_1).build())
            .match_action(MatchAction::None);

        let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();
        let mut content = SimpleEvent::Map(BTreeMap::from([
            (
                "key1".to_string(),
                SimpleEvent::String(content_1.to_string()),
            ),
            (
                "key2".to_string(),
                SimpleEvent::String(content_2.to_string()),
            ),
        ]));

        scanner.scan(&mut content);
    });

    let snapshot = snapshotter.snapshot().into_hashmap();

    let metric_name = "scanned_events";
    let metric_value = snapshot
        .get(&CompositeKey::new(Counter, Key::from_name(metric_name)))
        .expect("metric not found");
    assert_eq!(metric_value, &(None, None, DebugValue::Counter(1)));

    let metric_name = "scanning.match_count";
    let metric_value = snapshot
        .get(&CompositeKey::new(Counter, Key::from_name(metric_name)))
        .expect("metric not found");
    assert_eq!(metric_value, &(None, None, DebugValue::Counter(1)));

    let metric_name = "scanning.duration";
    let metric_value = snapshot
        .get(&CompositeKey::new(Counter, Key::from_name(metric_name)))
        .expect("metric not found");
    match metric_value.2 {
        DebugValue::Counter(val) => assert!(val > 0),
        _ => assert!(false),
    }
}

#[test]
fn should_submit_excluded_match_metric() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, || {
        let rule_0 = RootRuleConfig::new(RegexRuleConfig::new("bcdef").build())
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                "test".into(),
            )])]))
            .match_action(MatchAction::None);

        let scanner = ScannerBuilder::new(&[rule_0]).build().unwrap();
        let mut content = SimpleEvent::Map(BTreeMap::from([
            // z-match is considered as a false positive here
            (
                "z-match".to_string(),
                SimpleEvent::String("bcdef".to_string()),
            ),
            ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
        ]));

        scanner.scan(&mut content);
    });

    let snapshot = snapshotter.snapshot().into_hashmap();

    let metric_name = "false_positive.multipass.excluded_match";
    let metric_value = snapshot
        .get(&CompositeKey::new(Counter, Key::from_name(metric_name)))
        .expect("metric not found");

    assert_eq!(metric_value, &(None, None, DebugValue::Counter(1)));
}

#[test]
fn should_submit_excluded_keywords_metric() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, || {
        let redact_test_rule = RootRuleConfig::new(
            RegexRuleConfig::new("world")
                .proximity_keywords(ProximityKeywordsConfig {
                    look_ahead_character_count: 30,
                    included_keywords: vec![],
                    excluded_keywords: vec!["hello".to_string()],
                })
                .build(),
        )
        .match_action(MatchAction::Redact {
            replacement: "[REDACTED]".to_string(),
        });

        let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();
        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "test".to_string(),
            SimpleEvent::String("hello world".to_string()),
        )]));
        scanner.scan(&mut content);
    });

    let snapshot = snapshotter.snapshot().into_hashmap();

    let metric_name = "false_positive.proximity_keywords";

    let labels = vec![Label::new("type", "excluded_keywords")];

    let metric_value = snapshot
        .get(&CompositeKey::new(
            Counter,
            Key::from_parts(metric_name, labels),
        ))
        .expect("metric not found");

    assert_eq!(metric_value, &(None, None, DebugValue::Counter(1)));
}

#[test]
fn test_regex_match_and_included_keyword_same_index() {
    let email_rule = RootRuleConfig::new(
        RegexRuleConfig::new(".+")
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["email".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[email_rule])
        .with_return_matches(true)
        .build()
        .unwrap();
    let mut content = SimpleEvent::Map(BTreeMap::from([(
        "message".to_string(),
        SimpleEvent::String("email=firstname.lastname@acme.com&page2".to_string()),
    )]));
    let matches = scanner.scan(&mut content);
    assert_eq!(matches.len(), 1);

    assert_eq!(
        matches[0].match_value,
        Some("=firstname.lastname@acme.com&page2".to_string())
    );
}
