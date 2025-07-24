use crate::scanner::RuleResult;
use crate::{
    CompiledRule, CreateScannerError, Labels, MatchAction, Path, RootRuleConfig, RuleConfig,
    ScannerBuilder, ScannerError, StringMatch, StringMatchesCtx,
};
use futures::executor::block_on;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::block_in_place;

pub struct AsyncRuleConfig {
    wait: Duration,
}

pub struct AsyncCompiledRule {
    wait: Duration,
}

impl CompiledRule for AsyncCompiledRule {
    fn get_string_matches(
        &self,
        _content: &str,
        _path: &Path,
        ctx: &mut StringMatchesCtx,
    ) -> RuleResult {
        let wait = self.wait;
        ctx.process_async(move |ctx| {
            Box::pin(async move {
                tokio::time::sleep(wait).await;
                ctx.emit_match(StringMatch { start: 10, end: 16 });
                Ok(())
            })
        })
    }
}

impl RuleConfig for AsyncRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        _content: usize,
        _: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        Ok(Box::new(AsyncCompiledRule { wait: self.wait }))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_async_rule() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(Arc::new(AsyncRuleConfig {
        wait: Duration::from_millis(1),
    }) as Arc<dyn RuleConfig>)
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .build()
    .unwrap();

    // synchronous scan
    block_in_place(|| {
        let mut input = "this is a secret with random data".to_owned();
        let matched_rules = scanner.scan(&mut input).unwrap();
        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "this is a [REDACTED] with random data");
    });

    // async scan
    let mut input = "this is a secret with random data".to_owned();
    let matched_rules = scanner.scan_async(&mut input).await.unwrap();
    assert_eq!(matched_rules.len(), 1);
    assert_eq!(input, "this is a [REDACTED] with random data");
}

#[tokio::test(flavor = "multi_thread")]
async fn async_scan_timeout() {
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(Arc::new(AsyncRuleConfig {
        wait: Duration::from_secs(99999),
    }) as Arc<dyn RuleConfig>)
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .with_async_scan_timeout(Duration::from_millis(1))
    .build()
    .unwrap();

    let mut input = "this is a secret with random data".to_owned();
    let result = scanner.scan_async(&mut input).await;
    assert_eq!(result.is_err(), true);
    assert_eq!(result.unwrap_err(), ScannerError::Transient);
}

#[test]
fn async_scan_outside_of_tokio() {
    // Make sure scanning works without requiring users to explicitly enter a Tokio runtime.
    // This is done automatically for tests with `#[tokio::test]` so this one excludes it.

    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(Arc::new(AsyncRuleConfig {
        wait: Duration::from_millis(1),
    }) as Arc<dyn RuleConfig>)
    .match_action(MatchAction::Redact {
        replacement: "[REDACTED]".to_string(),
    })])
    .build()
    .unwrap();

    let fut = async move {
        let mut input = "this is a secret with random data".to_owned();
        let matched_rules = scanner.scan_async(&mut input).await.unwrap();
        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "this is a [REDACTED] with random data");
    };

    // moving the future to a separate thread before executing it to make sure it is `Send`
    std::thread::spawn(move || {
        block_on(fut);
    })
    .join()
    .unwrap();
}
