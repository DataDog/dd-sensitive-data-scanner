/// Regression test: scanning with match validation enabled must not panic when called
/// concurrently from multiple threads.
use crate::scanner::{RootRuleConfig, ScanOptionBuilder, ScannerBuilder};
use crate::{MatchAction, RegexRuleConfig};

#[test]
fn test_parallel_scan_with_validate_does_not_panic() {
    let scanner = std::sync::Arc::new(
        ScannerBuilder::new(
            &[RootRuleConfig::new(RegexRuleConfig::new("secret").build())
                .match_action(MatchAction::None)],
        )
        .with_return_matches(true)
        .build()
        .unwrap(),
    );

    // Reproduce the static-analyzer pattern: many events scanned concurrently from separate
    // threads, each calling scan_with_options(validate=true).
    let inputs: Vec<String> = (0..64)
        .map(|i| format!("event {i} contains secret"))
        .collect();

    std::thread::scope(|s| {
        for input in &inputs {
            let scanner = scanner.clone();
            let mut event = input.clone();
            s.spawn(move || {
                let result = scanner.scan_with_options(
                    &mut event,
                    ScanOptionBuilder::new()
                        .with_validate_matching(true)
                        .build(),
                );
                assert!(
                    result.is_ok(),
                    "scan_with_options returned an error: {result:?}"
                );
            });
        }
    });
}
