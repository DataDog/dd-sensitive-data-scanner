use crate::encoding::Encoding;
use crate::event::Event;
use std::future::Future;

use crate::match_validation::{
    config::InternalMatchValidationType, config::MatchValidationType, match_status::MatchStatus,
    match_validator::MatchValidator,
};

use error::MatchValidatorCreationError;

use self::metrics::ScannerMetrics;
use crate::match_validation::match_validator::RAYON_THREAD_POOL;
use crate::observability::labels::Labels;
use crate::rule_match::{InternalRuleMatch, RuleMatch};
use crate::scanner::config::RuleConfig;
use crate::scanner::internal_rule_match_set::InternalRuleMatchSet;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::regex_rule::{RegexCaches, access_regex_caches};
use crate::scanner::scope::Scope;
pub use crate::scanner::shared_data::SharedData;
use crate::scanner::suppression::{CompiledSuppressions, SuppressionValidationError, Suppressions};
use crate::scoped_ruleset::{ContentVisitor, ExclusionCheck, ScopedRuleSet};
pub use crate::secondary_validation::Validator;
use crate::stats::GLOBAL_STATS;
use crate::tokio::TOKIO_RUNTIME;
use crate::{
    CreateScannerError, EncodeIndices, MatchAction, Path, RegexValidationError, ScannerError,
};
use ahash::{AHashMap, AHashSet};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub mod config;
pub mod error;
pub mod metrics;
pub mod regex_rule;
pub mod scope;
pub mod shared_data;
pub mod shared_pool;
pub mod suppression;

mod internal_rule_match_set;
#[cfg(test)]
mod test;

#[derive(Copy, Clone)]
pub struct StringMatch {
    pub start: usize,
    pub end: usize,
}

pub trait MatchEmitter<T = ()> {
    fn emit(&mut self, string_match: StringMatch) -> T;
}

// This implements MatchEmitter for mutable closures (so you can use a closure instead of a custom
// struct that implements MatchEmitter)
impl<F, T> MatchEmitter<T> for F
where
    F: FnMut(StringMatch) -> T,
{
    fn emit(&mut self, string_match: StringMatch) -> T {
        // This just calls the closure (itself)
        (self)(string_match)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RootRuleConfig<T> {
    pub match_action: MatchAction,
    #[serde(default)]
    pub scope: Scope,
    #[deprecated(note = "Use `third_party_active_checker` instead")]
    match_validation_type: Option<MatchValidationType>,
    third_party_active_checker: Option<MatchValidationType>,
    suppressions: Option<Suppressions>,
    #[serde(flatten)]
    pub inner: T,
}

impl<T> RootRuleConfig<T>
where
    T: RuleConfig + 'static,
{
    pub fn new_dyn(inner: T) -> RootRuleConfig<Arc<dyn RuleConfig>> {
        RootRuleConfig::new(Arc::new(inner) as Arc<dyn RuleConfig>)
    }

    pub fn into_dyn(self) -> RootRuleConfig<Arc<dyn RuleConfig>> {
        self.map_inner(|x| Arc::new(x) as Arc<dyn RuleConfig>)
    }
}

impl<T> RootRuleConfig<T> {
    pub fn new(inner: T) -> Self {
        #[allow(deprecated)]
        Self {
            match_action: MatchAction::None,
            scope: Scope::all(),
            match_validation_type: None,
            third_party_active_checker: None,
            suppressions: None,
            inner,
        }
    }

    pub fn map_inner<U>(self, func: impl FnOnce(T) -> U) -> RootRuleConfig<U> {
        #[allow(deprecated)]
        RootRuleConfig {
            match_action: self.match_action,
            scope: self.scope,
            match_validation_type: self.match_validation_type,
            third_party_active_checker: self.third_party_active_checker,
            suppressions: self.suppressions,
            inner: func(self.inner),
        }
    }

    pub fn match_action(mut self, action: MatchAction) -> Self {
        self.match_action = action;
        self
    }

    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    pub fn third_party_active_checker(
        mut self,
        match_validation_type: MatchValidationType,
    ) -> Self {
        self.third_party_active_checker = Some(match_validation_type);
        self
    }

    pub fn suppressions(mut self, suppressions: Suppressions) -> Self {
        self.suppressions = Some(suppressions);
        self
    }

    fn get_third_party_active_checker(&self) -> Option<&MatchValidationType> {
        #[allow(deprecated)]
        self.third_party_active_checker
            .as_ref()
            .or(self.match_validation_type.as_ref())
    }
}

impl<T> Deref for RootRuleConfig<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
pub struct RootCompiledRule {
    pub inner: Box<dyn CompiledRule>,
    pub scope: Scope,
    pub match_action: MatchAction,
    pub match_validation_type: Option<MatchValidationType>,
    pub suppressions: Option<CompiledSuppressions>,
}

impl RootCompiledRule {
    pub fn internal_match_validation_type(&self) -> Option<InternalMatchValidationType> {
        self.match_validation_type
            .as_ref()
            .map(|x| x.get_internal_match_validation_type())
    }
}

impl Deref for RootCompiledRule {
    type Target = dyn CompiledRule;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

pub struct StringMatchesCtx<'a> {
    rule_index: usize,
    pub regex_caches: &'a mut RegexCaches,
    pub exclusion_check: &'a ExclusionCheck<'a>,
    pub excluded_matches: &'a mut AHashSet<String>,
    pub match_emitter: &'a mut dyn MatchEmitter,
    pub wildcard_indices: Option<&'a Vec<(usize, usize)>>,

    // Shared Data
    pub per_string_data: &'a mut SharedData,
    pub per_scanner_data: &'a SharedData,
    pub per_event_data: &'a mut SharedData,
}

impl StringMatchesCtx<'_> {
    /// If a `get_string_matches` implementation needs to do any async processing (e.g. I/O),
    /// this function can be used to return an "async job" to find matches. The return value
    /// of `process_async` should be returned from the `get_string_matches` function. The future
    /// passed into this function will be spawned and executed immediately without blocking
    /// other `get_string_matches` calls. This means all the async jobs will run concurrently.
    ///
    /// The `ctx` available to async jobs is more restrictive than the normal `ctx` available in
    /// `get_string_matches`. The only thing you can do is return matches. If other data is needed,
    /// it should be accessed before `process_async` is called.
    pub fn process_async(
        &self,
        func: impl for<'a> FnOnce(
            &'a mut AsyncStringMatchesCtx,
        )
            -> Pin<Box<dyn Future<Output = Result<(), ScannerError>> + Send + 'a>>
        + Send
        + 'static,
    ) -> RuleResult {
        let rule_index = self.rule_index;

        // The future is spawned onto the tokio runtime immediately so it starts running
        // in the background
        let fut = TOKIO_RUNTIME.spawn(async move {
            let mut ctx = AsyncStringMatchesCtx {
                rule_matches: vec![],
            };
            (func)(&mut ctx).await?;

            Ok(AsyncRuleInfo {
                rule_index,
                rule_matches: ctx.rule_matches,
            })
        });

        Ok(RuleStatus::Pending(fut))
    }
}

pub struct AsyncStringMatchesCtx {
    rule_matches: Vec<StringMatch>,
}

impl AsyncStringMatchesCtx {
    pub fn emit_match(&mut self, string_match: StringMatch) {
        self.rule_matches.push(string_match);
    }
}

#[must_use]
pub enum RuleStatus {
    Done,
    Pending(PendingRuleResult),
}

// pub type PendingRuleResult = BoxFuture<'static, Result<AsyncRuleInfo, ScannerError>>;
pub type PendingRuleResult = JoinHandle<Result<AsyncRuleInfo, ScannerError>>;

pub struct PendingRuleJob {
    fut: PendingRuleResult,
    path: Path<'static>,
}

pub struct AsyncRuleInfo {
    rule_index: usize,
    rule_matches: Vec<StringMatch>,
}

/// A rule result that cannot be async
pub type RuleResult = Result<RuleStatus, ScannerError>;

// This is the public trait that is used to define the behavior of a compiled rule.
pub trait CompiledRule: Send + Sync {
    fn init_per_scanner_data(&self, _per_scanner_data: &mut SharedData) {
        // by default, no per-scanner data is initialized
    }

    fn init_per_string_data(&self, _labels: &Labels, _per_string_data: &mut SharedData) {
        // by default, no per-string data is initialized
    }

    fn init_per_event_data(&self, _per_event_data: &mut SharedData) {
        // by default, no per-event data is initialized
    }

    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        ctx: &mut StringMatchesCtx<'_>,
    ) -> RuleResult;

    // Whether a match from this rule should be excluded (marked as a false-positive)
    // if the content of this match was found in a match from an excluded scope
    fn should_exclude_multipass_v0(&self) -> bool {
        // default is to NOT use Multi-pass V0
        false
    }

    fn on_excluded_match_multipass_v0(&self) {
        // default is to do nothing
    }
}

impl<T> RuleConfig for Box<T>
where
    T: RuleConfig + ?Sized,
{
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        labels: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        self.as_ref().convert_to_compiled_rule(rule_index, labels)
    }
}

#[derive(Debug, PartialEq, Clone)]
struct ScannerFeatures {
    pub add_implicit_index_wildcards: bool,
    pub multipass_v0_enabled: bool,
    pub return_matches: bool,
    // This is a temporary flag to disable failed rules (instead of fail the entire scanner)
    // for regex rules that match an empty string
    pub skip_rules_with_regex_matching_empty_string: bool,
}

impl Default for ScannerFeatures {
    fn default() -> Self {
        Self {
            add_implicit_index_wildcards: false,
            multipass_v0_enabled: true,
            return_matches: false,
            skip_rules_with_regex_matching_empty_string: false,
        }
    }
}

pub struct ScanOptions {
    // The blocked_rules_idx parameter is a list of rule indices that should be skipped for this scan.
    // this list shall be small (<10), so a linear search is acceptable otherwise performance will be impacted.
    pub blocked_rules_idx: Vec<usize>,
    // The wildcarded_indices parameter is a map containing a list of tuples of (start, end) indices that should be treated as wildcards (for the message key only) per path.
    pub wildcarded_indices: AHashMap<Path<'static>, Vec<(usize, usize)>>,
    // Whether to validate matches using third-party validators (e.g., checksum validation for credit cards).
    // When enabled, the scanner automatically collects match content needed for validation.
    pub validate_matches: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            blocked_rules_idx: vec![],
            wildcarded_indices: AHashMap::new(),
            validate_matches: false,
        }
    }
}

pub struct ScanOptionBuilder {
    blocked_rules_idx: Vec<usize>,
    wildcarded_indices: AHashMap<Path<'static>, Vec<(usize, usize)>>,
    validate_matches: bool,
}

impl ScanOptionBuilder {
    pub fn new() -> Self {
        Self {
            blocked_rules_idx: vec![],
            wildcarded_indices: AHashMap::new(),
            validate_matches: false,
        }
    }

    pub fn with_blocked_rules_idx(mut self, blocked_rules_idx: Vec<usize>) -> Self {
        self.blocked_rules_idx = blocked_rules_idx;
        self
    }

    pub fn with_wildcarded_indices(
        mut self,
        wildcarded_indices: AHashMap<Path<'static>, Vec<(usize, usize)>>,
    ) -> Self {
        self.wildcarded_indices = wildcarded_indices;
        self
    }

    pub fn with_validate_matching(mut self, validate_matches: bool) -> Self {
        self.validate_matches = validate_matches;
        self
    }

    pub fn build(self) -> ScanOptions {
        ScanOptions {
            blocked_rules_idx: self.blocked_rules_idx,
            wildcarded_indices: self.wildcarded_indices,
            validate_matches: self.validate_matches,
        }
    }
}

pub struct Scanner {
    rules: Vec<RootCompiledRule>,
    scoped_ruleset: ScopedRuleSet,
    scanner_features: ScannerFeatures,
    metrics: ScannerMetrics,
    labels: Labels,
    match_validators_per_type: AHashMap<InternalMatchValidationType, Box<dyn MatchValidator>>,
    per_scanner_data: SharedData,
    async_scan_timeout: Duration,
}

impl Scanner {
    pub fn builder(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>]) -> ScannerBuilder<'_> {
        ScannerBuilder::new(rules)
    }

    // This function scans the given event with the rules configured in the scanner.
    // The event parameter is a mutable reference to the event that should be scanned (implemented the Event trait).
    // The return value is a list of RuleMatch objects, which contain information about the matches that were found.
    // This version uses default scan options (no validation, no blocked rules, no wildcarded indices).
    pub fn scan<E: Event>(&self, event: &mut E) -> Result<Vec<RuleMatch>, ScannerError> {
        self.scan_with_options(event, ScanOptions::default())
    }

    // This function scans the given event with the rules configured in the scanner.
    // The event parameter is a mutable reference to the event that should be scanned (implemented the Event trait).
    // The options parameter allows customizing the scan behavior (validation, blocked rules, etc.).
    // The return value is a list of RuleMatch objects, which contain information about the matches that were found.
    pub fn scan_with_options<E: Event>(
        &self,
        event: &mut E,
        options: ScanOptions,
    ) -> Result<Vec<RuleMatch>, ScannerError> {
        block_on(self.internal_scan_with_metrics(event, options))
    }

    // This function scans the given event with the rules configured in the scanner.
    // The event parameter is a mutable reference to the event that should be scanned (implemented the Event trait).
    // The return value is a list of RuleMatch objects, which contain information about the matches that were found.
    pub async fn scan_async<E: Event>(
        &self,
        event: &mut E,
    ) -> Result<Vec<RuleMatch>, ScannerError> {
        self.scan_async_with_options(event, ScanOptions::default())
            .await
    }

    pub async fn scan_async_with_options<E: Event>(
        &self,
        event: &mut E,
        options: ScanOptions,
    ) -> Result<Vec<RuleMatch>, ScannerError> {
        let fut = self.internal_scan_with_metrics(event, options);

        // The sleep from the timeout requires being in a tokio context
        // The guard needs to be dropped before await since the guard is !Send
        let timeout = {
            let _tokio_guard = TOKIO_RUNTIME.enter();
            timeout(self.async_scan_timeout, fut)
        };

        timeout.await.unwrap_or(Err(ScannerError::Transient(
            "Async scan timeout".to_string(),
        )))
    }

    fn record_metrics(&self, output_rule_matches: &[RuleMatch], start: Instant) {
        // Record detection time
        self.metrics
            .duration_ns
            .increment(start.elapsed().as_nanos() as u64);
        // Add number of scanned events
        self.metrics.num_scanned_events.increment(1);
        // Add number of matches
        self.metrics
            .match_count
            .increment(output_rule_matches.len() as u64);
    }

    async fn internal_scan_with_metrics<E: Event>(
        &self,
        event: &mut E,
        options: ScanOptions,
    ) -> Result<Vec<RuleMatch>, ScannerError> {
        let start = Instant::now();
        let result = self.internal_scan(event, options).await;
        match &result {
            Ok(rule_matches) => {
                self.record_metrics(rule_matches, start);
            }
            Err(_) => {
                self.record_metrics(&[], start);
            }
        }
        result
    }

    async fn internal_scan<E: Event>(
        &self,
        event: &mut E,
        options: ScanOptions,
    ) -> Result<Vec<RuleMatch>, ScannerError> {
        // If validation is requested, we need to collect match content even if the scanner
        // wasn't originally configured to return matches
        let need_match_content = self.scanner_features.return_matches || options.validate_matches;
        // All matches, after some (but not all) false-positives have been removed.
        let mut rule_matches = InternalRuleMatchSet::new();
        let mut excluded_matches = AHashSet::new();
        let mut async_jobs = vec![];

        access_regex_caches(|regex_caches| {
            self.scoped_ruleset.visit_string_rule_combinations(
                event,
                ScannerContentVisitor {
                    scanner: self,
                    regex_caches,
                    rule_matches: &mut rule_matches,
                    blocked_rules: &options.blocked_rules_idx,
                    excluded_matches: &mut excluded_matches,
                    per_event_data: SharedData::new(),
                    wildcarded_indexes: &options.wildcarded_indices,
                    async_jobs: &mut async_jobs,
                },
            )
        })?;

        // The async jobs were already spawned on the tokio runtime, so the
        // results just need to be collected
        for job in async_jobs {
            let rule_info = job.fut.await.unwrap()?;
            rule_matches.push_async_matches(
                &job.path,
                rule_info
                    .rule_matches
                    .into_iter()
                    .map(|x| InternalRuleMatch::new(rule_info.rule_index, x)),
            );
        }

        let mut output_rule_matches = vec![];

        for (path, mut rule_matches) in rule_matches.into_iter() {
            // All rule matches in each inner list are for a single path, so they can be processed independently.
            event.visit_string_mut(&path, |content| {
                // calculate_indices requires that matches are sorted by start index
                rule_matches.sort_unstable_by_key(|rule_match| rule_match.utf8_start);

                <<E as Event>::Encoding>::calculate_indices(
                    content,
                    rule_matches.iter_mut().map(
                        |rule_match: &mut InternalRuleMatch<E::Encoding>| EncodeIndices {
                            utf8_start: rule_match.utf8_start,
                            utf8_end: rule_match.utf8_end,
                            custom_start: &mut rule_match.custom_start,
                            custom_end: &mut rule_match.custom_end,
                        },
                    ),
                );

                if self.scanner_features.multipass_v0_enabled {
                    // Now that the `excluded_matches` set is fully populated, filter out any matches
                    // that are the same as excluded matches (also known as "Multi-pass V0")
                    rule_matches.retain(|rule_match| {
                        if self.rules[rule_match.rule_index]
                            .inner
                            .should_exclude_multipass_v0()
                        {
                            let is_false_positive = excluded_matches
                                .contains(&content[rule_match.utf8_start..rule_match.utf8_end]);
                            if is_false_positive && self.scanner_features.multipass_v0_enabled {
                                self.rules[rule_match.rule_index].on_excluded_match_multipass_v0();
                            }
                            !is_false_positive
                        } else {
                            true
                        }
                    });
                }

                self.suppress_matches::<E::Encoding>(&mut rule_matches, content);

                self.sort_and_remove_overlapping_rules::<E::Encoding>(&mut rule_matches);

                let will_mutate = rule_matches
                    .iter()
                    .any(|rule_match| self.rules[rule_match.rule_index].match_action.is_mutating());

                self.apply_match_actions(
                    content,
                    &path,
                    &mut rule_matches,
                    &mut output_rule_matches,
                    need_match_content,
                );

                will_mutate
            });
        }

        if options.validate_matches {
            self.validate_matches(&mut output_rule_matches);
        }

        Ok(output_rule_matches)
    }

    pub fn suppress_matches<E: Encoding>(
        &self,
        rule_matches: &mut Vec<InternalRuleMatch<E>>,
        content: &str,
    ) {
        rule_matches.retain(|rule_match| {
            if let Some(suppressions) = &self.rules[rule_match.rule_index].suppressions {
                let mut match_should_be_suppressed;
                access_regex_caches(|regex_caches| {
                    match_should_be_suppressed = suppressions.should_match_be_suppressed(
                        &content[rule_match.utf8_start..rule_match.utf8_end],
                    );
                });

                if match_should_be_suppressed {
                    self.metrics.suppressed_match_count.increment(1);
                }
                !match_should_be_suppressed
            } else {
                true
            }
        });
    }

    pub fn validate_matches(&self, rule_matches: &mut Vec<RuleMatch>) {
        // Create MatchValidatorRuleMatch per match_validator_type to pass it to each match_validator
        let mut match_validator_rule_match_per_type = AHashMap::new();

        let mut validated_rule_matches = vec![];

        for mut rule_match in rule_matches.drain(..) {
            let rule = &self.rules[rule_match.rule_index];
            if let Some(match_validation_type) = rule.internal_match_validation_type() {
                match_validator_rule_match_per_type
                    .entry(match_validation_type)
                    .or_insert_with(Vec::new)
                    .push(rule_match)
            } else {
                // There is no match validator for this rule, so mark it as not available.
                rule_match.match_status.merge(MatchStatus::NotAvailable);
                validated_rule_matches.push(rule_match);
            }
        }

        RAYON_THREAD_POOL.install(|| {
            use rayon::prelude::*;

            match_validator_rule_match_per_type.par_iter_mut().for_each(
                |(match_validation_type, matches_per_type)| {
                    let match_validator = self.match_validators_per_type.get(match_validation_type);
                    if let Some(match_validator) = match_validator {
                        match_validator
                            .as_ref()
                            .validate(matches_per_type, &self.rules)
                    }
                },
            );
        });

        // Refill the rule_matches with the validated matches
        for (_, mut matches) in match_validator_rule_match_per_type {
            validated_rule_matches.append(&mut matches);
        }

        // Sort rule_matches by start index
        validated_rule_matches.sort_by_key(|rule_match| rule_match.start_index);
        *rule_matches = validated_rule_matches;
    }

    /// Apply mutations from actions, and shift indices to match the mutated values.
    /// This assumes the matches are all from the content given, and are sorted by start index.
    fn apply_match_actions<E: Encoding>(
        &self,
        content: &mut String,
        path: &Path<'static>,
        rule_matches: &mut [InternalRuleMatch<E>],
        output_rule_matches: &mut Vec<RuleMatch>,
        need_match_content: bool,
    ) {
        let mut utf8_byte_delta: isize = 0;
        let mut custom_index_delta: <E>::IndexShift = <E>::zero_shift();

        for rule_match in rule_matches {
            output_rule_matches.push(self.apply_match_actions_for_string::<E>(
                content,
                path.clone(),
                rule_match,
                &mut utf8_byte_delta,
                &mut custom_index_delta,
                need_match_content,
            ));
        }
    }

    /// This will be called once for each match of a single string. The rules must be passed in in order of the start index. Mutating rules must not overlap.
    fn apply_match_actions_for_string<E: Encoding>(
        &self,
        content: &mut String,
        path: Path<'static>,
        rule_match: &InternalRuleMatch<E>,
        // The current difference in length between the original and mutated string
        utf8_byte_delta: &mut isize,

        // The difference between the custom index on the original string and the mutated string
        custom_index_delta: &mut <E>::IndexShift,
        need_match_content: bool,
    ) -> RuleMatch {
        let rule = &self.rules[rule_match.rule_index];

        let custom_start =
            (<E>::get_index(&rule_match.custom_start, rule_match.utf8_start) as isize
                + <E>::get_shift(custom_index_delta, *utf8_byte_delta)) as usize;

        let mut matched_content_copy = None;

        if need_match_content {
            // This copies part of the is_mutating block but is seperate since can't mix compilation condition and code condition
            let mutated_utf8_match_start =
                (rule_match.utf8_start as isize + *utf8_byte_delta) as usize;
            let mutated_utf8_match_end = (rule_match.utf8_end as isize + *utf8_byte_delta) as usize;

            // Matches for mutating rules must have valid indices
            debug_assert!(content.is_char_boundary(mutated_utf8_match_start));
            debug_assert!(content.is_char_boundary(mutated_utf8_match_end));

            let matched_content = &content[mutated_utf8_match_start..mutated_utf8_match_end];
            matched_content_copy = Some(matched_content.to_string());
        }

        if rule.match_action.is_mutating() {
            let mutated_utf8_match_start =
                (rule_match.utf8_start as isize + *utf8_byte_delta) as usize;
            let mutated_utf8_match_end = (rule_match.utf8_end as isize + *utf8_byte_delta) as usize;

            // Matches for mutating rules must have valid indices
            debug_assert!(content.is_char_boundary(mutated_utf8_match_start));
            debug_assert!(content.is_char_boundary(mutated_utf8_match_end));

            let matched_content = &content[mutated_utf8_match_start..mutated_utf8_match_end];
            if let Some(replacement) = rule.match_action.get_replacement(matched_content) {
                let before_replacement = &matched_content[replacement.start..replacement.end];

                // update indices to match the new mutated content
                <E>::adjust_shift(
                    custom_index_delta,
                    before_replacement,
                    &replacement.replacement,
                );
                *utf8_byte_delta +=
                    replacement.replacement.len() as isize - before_replacement.len() as isize;

                let replacement_start = mutated_utf8_match_start + replacement.start;
                let replacement_end = mutated_utf8_match_start + replacement.end;
                content.replace_range(replacement_start..replacement_end, &replacement.replacement);
            }
        }

        let shift_offset = <E>::get_shift(custom_index_delta, *utf8_byte_delta);
        let custom_end = (<E>::get_index(&rule_match.custom_end, rule_match.utf8_end) as isize
            + shift_offset) as usize;

        let rule = &self.rules[rule_match.rule_index];

        let match_status: MatchStatus = if rule.match_validation_type.is_some() {
            MatchStatus::NotChecked
        } else {
            MatchStatus::NotAvailable
        };

        RuleMatch {
            rule_index: rule_match.rule_index,
            path,
            replacement_type: rule.match_action.replacement_type(),
            start_index: custom_start,
            end_index_exclusive: custom_end,
            shift_offset,
            match_value: matched_content_copy,
            match_status,
        }
    }

    fn sort_and_remove_overlapping_rules<E: Encoding>(
        &self,
        rule_matches: &mut Vec<InternalRuleMatch<E>>,
    ) {
        // Some of the scanner code relies on the behavior here, such as the sort order and removal of overlapping mutating rules.
        // Be very careful if this function is modified.

        rule_matches.sort_unstable_by(|a, b| {
            // Mutating rules are a higher priority (earlier in the list)
            let ord = self.rules[a.rule_index]
                .match_action
                .is_mutating()
                .cmp(&self.rules[b.rule_index].match_action.is_mutating())
                .reverse();

            // Earlier start offset
            let ord = ord.then(a.utf8_start.cmp(&b.utf8_start));

            // Longer matches
            let ord = ord.then(a.len().cmp(&b.len()).reverse());

            // Matches from earlier rules
            let ord = ord.then(a.rule_index.cmp(&b.rule_index));

            // swap the order of everything so matches can be efficiently popped off the back as they are processed
            ord.reverse()
        });

        let mut retained_rules: Vec<InternalRuleMatch<E>> = vec![];

        'rule_matches: while let Some(rule_match) = rule_matches.pop() {
            if self.rules[rule_match.rule_index].match_action.is_mutating() {
                // Mutating rules are kept only if they don't overlap with a previous rule.
                if let Some(last) = retained_rules.last()
                    && last.utf8_end > rule_match.utf8_start
                {
                    continue;
                }
            } else {
                // Only retain if it doesn't overlap with any other rule. Since mutating matches are sorted before non-mutated matches
                // this needs to check all retained matches (instead of just the last one)
                for retained_rule in &retained_rules {
                    if retained_rule.utf8_start < rule_match.utf8_end
                        && retained_rule.utf8_end > rule_match.utf8_start
                    {
                        continue 'rule_matches;
                    }
                }
            };
            retained_rules.push(rule_match);
        }

        // ensure rules are sorted by start index (other parts of the library required this to function correctly)
        retained_rules.sort_unstable_by_key(|rule_match| rule_match.utf8_start);

        *rule_matches = retained_rules;
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        let stats = &*GLOBAL_STATS;
        stats.scanner_deletions.increment(1);
        stats.decrement_total_scanners();
    }
}

#[derive(Default)]
pub struct ScannerBuilder<'a> {
    rules: &'a [RootRuleConfig<Arc<dyn RuleConfig>>],
    labels: Labels,
    scanner_features: ScannerFeatures,
    async_scan_timeout: Duration,
}

impl ScannerBuilder<'_> {
    pub fn new(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>]) -> ScannerBuilder<'_> {
        ScannerBuilder {
            rules,
            labels: Labels::empty(),
            scanner_features: ScannerFeatures::default(),
            async_scan_timeout: Duration::from_secs(60 * 5),
        }
    }

    pub fn labels(mut self, labels: Labels) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_async_scan_timeout(mut self, duration: Duration) -> Self {
        self.async_scan_timeout = duration;
        self
    }

    pub fn with_implicit_wildcard_indexes_for_scopes(mut self, value: bool) -> Self {
        self.scanner_features.add_implicit_index_wildcards = value;
        self
    }

    pub fn with_return_matches(mut self, value: bool) -> Self {
        self.scanner_features.return_matches = value;
        self
    }

    /// Enables/Disables the Multipass V0 feature. This defaults to TRUE.
    /// Multipass V0 saves matches from excluded scopes, and marks any identical
    /// matches in included scopes as a false positive.
    pub fn with_multipass_v0(mut self, value: bool) -> Self {
        self.scanner_features.multipass_v0_enabled = value;
        self
    }

    pub fn with_skip_rules_with_regex_matching_empty_string(mut self, value: bool) -> Self {
        self.scanner_features
            .skip_rules_with_regex_matching_empty_string = value;
        self
    }

    pub fn build(self) -> Result<Scanner, CreateScannerError> {
        let mut match_validators_per_type = AHashMap::new();

        for rule in self.rules.iter() {
            if let Some(match_validation_type) = &rule.get_third_party_active_checker()
                && match_validation_type.can_create_match_validator()
            {
                let internal_type = match_validation_type.get_internal_match_validation_type();
                let match_validator = match_validation_type.into_match_validator();
                if let Ok(match_validator) = match_validator {
                    if !match_validators_per_type.contains_key(&internal_type) {
                        match_validators_per_type.insert(internal_type, match_validator);
                    }
                } else {
                    return Err(CreateScannerError::InvalidMatchValidator(
                        MatchValidatorCreationError::InternalError,
                    ));
                }
            }
        }

        let compiled_rules = self
            .rules
            .iter()
            .enumerate()
            .filter_map(|(rule_index, config)| {
                let inner = match config.convert_to_compiled_rule(rule_index, self.labels.clone()) {
                    Ok(inner) => Ok(inner),
                    Err(err) => {
                        if self
                            .scanner_features
                            .skip_rules_with_regex_matching_empty_string
                            && err
                            == CreateScannerError::InvalidRegex(
                            RegexValidationError::MatchesEmptyString,
                        )
                        {
                            // this is a temporary feature to skip rules that should be considered invalid.
                            #[allow(clippy::print_stdout)]
                            {
                                println!("skipping rule that matches empty string: rule_index={}, labels={:?}", rule_index, self.labels.clone());
                            }
                            return None;
                        } else {
                            Err(err)
                        }
                    }
                };
                Some((config, inner))
            })
            .map(|(config, inner)| {
                config.match_action.validate()?;
                let compiled_suppressions = match &config.suppressions {
                    Some(s) => Some(s.clone().try_into()?),
                    None => None,
                };
                Ok(RootCompiledRule {
                    inner: inner?,
                    scope: config.scope.clone(),
                    match_action: config.match_action.clone(),
                    match_validation_type: config.get_third_party_active_checker().cloned(),
                    suppressions: compiled_suppressions,
                })
            })
            .collect::<Result<Vec<RootCompiledRule>, CreateScannerError>>()?;

        let mut per_scanner_data = SharedData::new();

        compiled_rules.iter().for_each(|rule| {
            rule.init_per_scanner_data(&mut per_scanner_data);
        });

        let scoped_ruleset = ScopedRuleSet::new(
            &compiled_rules
                .iter()
                .map(|rule| rule.scope.clone())
                .collect::<Vec<_>>(),
        )
        .with_implicit_index_wildcards(self.scanner_features.add_implicit_index_wildcards);

        {
            let stats = &*GLOBAL_STATS;
            stats.scanner_creations.increment(1);
            stats.increment_total_scanners();
        }

        Ok(Scanner {
            rules: compiled_rules,
            scoped_ruleset,
            scanner_features: self.scanner_features,
            metrics: ScannerMetrics::new(&self.labels),
            match_validators_per_type,
            labels: self.labels,
            per_scanner_data,
            async_scan_timeout: self.async_scan_timeout,
        })
    }
}

struct ScannerContentVisitor<'a, E: Encoding> {
    scanner: &'a Scanner,
    regex_caches: &'a mut RegexCaches,
    rule_matches: &'a mut InternalRuleMatchSet<E>,
    // Rules that shall be skipped for this scan
    // This list shall be small (<10), so a linear search is acceptable
    blocked_rules: &'a Vec<usize>,
    excluded_matches: &'a mut AHashSet<String>,
    per_event_data: SharedData,
    wildcarded_indexes: &'a AHashMap<Path<'static>, Vec<(usize, usize)>>,
    async_jobs: &'a mut Vec<PendingRuleJob>,
}

impl<'a, E: Encoding> ContentVisitor<'a> for ScannerContentVisitor<'a, E> {
    fn visit_content<'b>(
        &'b mut self,
        path: &Path<'a>,
        content: &str,
        mut rule_visitor: crate::scoped_ruleset::RuleIndexVisitor,
        exclusion_check: ExclusionCheck<'b>,
    ) -> Result<bool, ScannerError> {
        // matches for a single path
        let mut path_rules_matches = vec![];

        // Create a map of per rule type data that can be shared between rules of the same type
        let mut per_string_data = SharedData::new();
        let wildcard_indices_per_path = self.wildcarded_indexes.get(path);

        rule_visitor.visit_rule_indices(|rule_index| {
            if self.blocked_rules.contains(&rule_index) {
                return Ok(());
            }
            let rule = &self.scanner.rules[rule_index];
            {
                // creating the emitter is basically free, it will get mostly optimized away
                let mut emitter = |rule_match: StringMatch| {
                    // This should never happen, but to ensure no empty match is ever generated
                    // (which may cause an infinite loop), this will panic instead.
                    assert_ne!(rule_match.start, rule_match.end, "empty match detected");
                    path_rules_matches.push(InternalRuleMatch::new(rule_index, rule_match));
                };

                rule.init_per_string_data(&self.scanner.labels, &mut per_string_data);

                // TODO: move this somewhere higher?
                rule.init_per_event_data(&mut self.per_event_data);

                let mut ctx = StringMatchesCtx {
                    rule_index,
                    regex_caches: self.regex_caches,
                    exclusion_check: &exclusion_check,
                    excluded_matches: self.excluded_matches,
                    match_emitter: &mut emitter,
                    wildcard_indices: wildcard_indices_per_path,
                    per_string_data: &mut per_string_data,
                    per_scanner_data: &self.scanner.per_scanner_data,
                    per_event_data: &mut self.per_event_data,
                };

                let async_status = rule.get_string_matches(content, path, &mut ctx)?;

                match async_status {
                    RuleStatus::Done => {
                        // nothing to do
                    }
                    RuleStatus::Pending(fut) => {
                        self.async_jobs.push(PendingRuleJob {
                            fut,
                            path: path.into_static(),
                        });
                    }
                }
            }
            Ok(())
        })?;

        // If there are any matches, the string will need to be accessed to check for false positives from
        // excluded matches, any to potentially mutate the string.
        // If there are any async jobs, this is also true since it's not known yet whether there
        // will be a match
        let needs_to_access_content = !path_rules_matches.is_empty() || !self.async_jobs.is_empty();

        self.rule_matches
            .push_sync_matches(path, path_rules_matches);

        Ok(needs_to_access_content)
    }
}

// Calculates the next starting position for a regex match if a the previous match is a false positive
fn get_next_regex_start(content: &str, regex_match: (usize, usize)) -> Option<usize> {
    // The next valid UTF8 char after the start of the regex match is used
    if let Some((i, _)) = content[regex_match.0..].char_indices().nth(1) {
        Some(regex_match.0 + i)
    } else {
        // There are no more chars left in the string to scan
        None
    }
}

fn is_false_positive_match(
    regex_match_range: (usize, usize),
    rule: &RegexCompiledRule,
    content: &str,
    check_excluded_keywords: bool,
) -> bool {
    if check_excluded_keywords
        && let Some(excluded_keywords) = &rule.excluded_keywords
        && excluded_keywords.is_false_positive_match(content, regex_match_range.0)
    {
        return true;
    }

    if let Some(validator) = rule.validator.as_ref()
        && !validator.is_valid_match(&content[regex_match_range.0..regex_match_range.1])
    {
        return true;
    }
    false
}
