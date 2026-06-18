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

/// Regression test for the stack overflow fixed in `Scanner::validate_matches`.
///
/// When a validated scan runs on a Rayon worker (e.g. the caller scans via `into_par_iter`),
/// `validate_matches` blocks the worker on `install`, and Rayon keeps it busy by stealing the
/// next scan job and running it on the same stack — recursing until the stack overflows.
///
/// Forcing an actual overflow needs thousands of frames (flaky in a unit test), so we assert
/// the invariant instead: a validated scan on a Rayon worker must never re-enter another scan
/// on the same thread. The validator delay keeps the worker blocked long enough to steal a
/// sibling job if the fix regresses.
#[test]
fn test_rayon_parallel_scan_with_validate_does_not_reenter_on_same_thread() {
    use crate::match_validation::config::HttpStatusCodeRange;
    use crate::{CustomHttpConfig, MatchValidationType};
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use rayon::prelude::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let server = MockServer::start();
    // Delay the response so the calling worker stays blocked long enough to steal a sibling job
    // if the recursion regresses.
    let _mock = server.mock(|when, then| {
        when.method(GET).path("/");
        then.status(200).delay(Duration::from_millis(25));
    });

    let http_config = CustomHttpConfig::default()
        .with_endpoint(server.url("/").to_string())
        .with_request_headers(BTreeMap::from([(
            "authorization".to_string(),
            "Bearer $MATCH".to_string(),
        )]))
        .with_valid_http_status_code(vec![HttpStatusCodeRange {
            start: 200,
            end: 300,
        }]);

    let scanner = std::sync::Arc::new(
        ScannerBuilder::new(&[RootRuleConfig::new(
            RegexRuleConfig::new("\\bsecret_match\\b").build(),
        )
        .match_action(MatchAction::None)
        .third_party_active_checker(MatchValidationType::CustomHttp(http_config))])
        .with_return_matches(true)
        .build()
        .unwrap(),
    );

    thread_local! {
        // Set while this thread is inside a scan below; a stolen scan re-enters with it set.
        static IN_SCAN: Cell<bool> = const { Cell::new(false) };
    }
    static REENTRANCIES: AtomicUsize = AtomicUsize::new(0);

    let inputs: Vec<String> = (0..128)
        .map(|i| format!("event {i} has a secret_match in it"))
        .collect();

    // par_iter runs each scan on a Rayon worker — the context that triggered the recursion.
    let oks = inputs
        .par_iter()
        .map(|input| {
            let already_scanning = IN_SCAN.with(|f| f.replace(true));
            if already_scanning {
                REENTRANCIES.fetch_add(1, Ordering::Relaxed);
            }

            let mut event = input.clone();
            let ok = scanner
                .scan_with_options(
                    &mut event,
                    ScanOptionBuilder::new()
                        .with_validate_matching(true)
                        .build(),
                )
                .is_ok();

            IN_SCAN.with(|f| f.set(already_scanning));
            ok
        })
        .filter(|ok| *ok)
        .count();

    assert_eq!(oks, inputs.len(), "every validated scan should complete");
    assert_eq!(
        REENTRANCIES.load(Ordering::Relaxed),
        0,
        "a validated scan re-entered another scan on the same Rayon worker — the \
         validate_matches work-stealing recursion has regressed"
    );
}
