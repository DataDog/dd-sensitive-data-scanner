use crate::{
    CompiledRule, CreateScannerError, Event, EventVisitor, Labels, MatchAction, Path,
    RootRuleConfig, RuleConfig, RuleResult, ScannerBuilder, ScannerError, SharedData, StringMatch,
    StringMatchesCtx, Utf8Encoding,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use tokio::sync::oneshot;

struct LifecycleRule {
    finished: Arc<AtomicUsize>,
    released: mpsc::Sender<bool>,
}

#[derive(Default)]
struct CollectedStrings {
    has_seed: bool,
    waiters: Vec<oneshot::Sender<bool>>,
}

impl RuleConfig for LifecycleRule {
    fn convert_to_compiled_rule(
        &self,
        _: usize,
        _: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        Ok(Box::new(Self {
            finished: self.finished.clone(),
            released: self.released.clone(),
        }))
    }
}

impl CompiledRule for LifecycleRule {
    fn get_string_matches(
        &self,
        content: &str,
        _: &Path,
        ctx: &mut StringMatchesCtx<'_>,
    ) -> RuleResult {
        let state = ctx.per_event_data.get_mut_or_default::<CollectedStrings>();
        state.has_seed |= content == "seed";
        let (sender, receiver) = oneshot::channel();
        state.waiters.push(sender);
        let len = content.len();
        let released = self.released.clone();
        ctx.process_async(move |ctx| {
            Box::pin(async move {
                let result = receiver.await;
                released.send(result.is_ok()).unwrap();
                if result.unwrap_or(false) {
                    ctx.emit_match(StringMatch {
                        start: 0,
                        end: len,
                        keyword: None,
                    });
                }
                Ok(())
            })
        })
    }

    fn finish_per_event_data(&self, data: &mut SharedData) {
        self.finished.fetch_add(1, Ordering::SeqCst);
        if let Some(state) = data.get_mut::<CollectedStrings>() {
            for sender in state.waiters.drain(..) {
                let _ = sender.send(state.has_seed);
            }
        }
    }
}

struct FailedEvent;

impl Event for FailedEvent {
    type Encoding = Utf8Encoding;

    fn visit_event<'a>(
        &'a mut self,
        visitor: &mut impl EventVisitor<'a>,
    ) -> Result<(), ScannerError> {
        visitor.visit_string("foo")?;
        Err(ScannerError::Transient("failed traversal".into()))
    }

    fn visit_string_mut(&mut self, _: &Path, _: impl FnOnce(&mut String) -> bool) {
        panic!("a failed event must not be mutated");
    }
}

#[test]
fn finish_publishes_all_strings_before_sync_and_async_jobs_complete() {
    let (sender, receiver) = mpsc::channel();
    let finished = Arc::new(AtomicUsize::new(0));
    let rule = RootRuleConfig::new_dyn(LifecycleRule {
        finished: finished.clone(),
        released: sender,
    })
    .match_action(MatchAction::Redact {
        replacement: "masked".into(),
    });
    let scanner = ScannerBuilder::new(&[rule]).build().unwrap();
    for asynchronous in [false, true] {
        let mut event = crate::SimpleEvent::List(vec![
            crate::SimpleEvent::String("foo".into()),
            crate::SimpleEvent::String("seed".into()),
        ]);
        let matches = if asynchronous {
            futures::executor::block_on(scanner.scan_async(&mut event)).unwrap()
        } else {
            scanner.scan(&mut event).unwrap()
        };
        assert_eq!(matches.len(), 2);
        assert_eq!(
            event,
            crate::SimpleEvent::List(vec![crate::SimpleEvent::String("masked".into()); 2])
        );
        assert!(receiver.recv().unwrap());
        assert!(receiver.recv().unwrap());
    }
    assert_eq!(finished.load(Ordering::SeqCst), 2);
    let mut event = "foo".to_owned();
    assert!(scanner.scan(&mut event).unwrap().is_empty());
    assert_eq!(event, "foo");
}

#[test]
fn failed_traversal_cancels_waiters_without_finishing() {
    let (sender, receiver) = mpsc::channel();
    let finished = Arc::new(AtomicUsize::new(0));
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new(Arc::new(LifecycleRule {
        finished: finished.clone(),
        released: sender,
    }))])
    .build()
    .unwrap();
    assert!(scanner.scan(&mut FailedEvent).is_err());
    assert!(
        !receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    );
    assert_eq!(finished.load(Ordering::SeqCst), 0);
}

#[test]
fn blocked_rules_do_not_receive_finish_callbacks() {
    let (sender, _receiver) = mpsc::channel();
    let finished = Arc::new(AtomicUsize::new(0));
    let scanner = ScannerBuilder::new(&[RootRuleConfig::new_dyn(LifecycleRule {
        finished: finished.clone(),
        released: sender,
    })])
    .build()
    .unwrap();
    let options = crate::ScanOptionBuilder::new()
        .with_blocked_rules_idx(vec![0])
        .build();
    assert!(
        scanner
            .scan_with_options(&mut "seed".to_owned(), options)
            .unwrap()
            .is_empty()
    );
    assert_eq!(finished.load(Ordering::SeqCst), 0);
}
