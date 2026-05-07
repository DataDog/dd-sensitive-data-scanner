/// Regression test for the LocalPool/RAYON_THREAD_POOL re-entrancy panic.
///
/// Before the fix, calling scan_with_options(validate=true) from multiple threads simultaneously
/// would panic with:
///   "cannot execute `LocalPool` executor from within another executor: EnterError"
///
/// The panic occurred because validate_matches() (which uses RAYON_THREAD_POOL) was called inside
/// block_on(), whose LocalPool context conflicts with rayon scheduler re-entrancy on the same thread.
///
/// The fix moves validate_matches() and the supporting-rule filter into finalize_matches(), called
/// after block_on() returns, fully outside any futures executor context.
use crate::scanner::{RootRuleConfig, ScanOptionBuilder, ScannerBuilder};
use crate::{MatchAction, RegexRuleConfig};

#[test]
fn test_parallel_scan_with_validate_does_not_panic() {
    let scanner = std::sync::Arc::new(
        ScannerBuilder::new(&[RootRuleConfig::new(RegexRuleConfig::new("secret").build())
            .match_action(MatchAction::None)])
        .with_return_matches(true)
        .build()
        .unwrap(),
    );

    // Reproduce the static-analyzer pattern: many events scanned concurrently from separate
    // threads, each calling scan_with_options(validate=true).
    let inputs: Vec<String> = (0..64).map(|i| format!("event {i} contains secret")).collect();

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
                assert!(result.is_ok(), "scan_with_options returned an error: {result:?}");
            });
        }
    });
}
