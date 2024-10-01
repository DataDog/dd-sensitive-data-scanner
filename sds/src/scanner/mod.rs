use crate::encoding::Encoding;
use crate::event::Event;

use crate::match_validation::{
    config::InternalMatchValidationType, config::MatchValidationType, match_status::MatchStatus,
    match_validator::MatchValidator, validator_utils::new_match_validator_from_type,
};

use error::MatchValidationError;

use crate::observability::labels::Labels;
use crate::rule_match::{InternalRuleMatch, RuleMatch};
use crate::scoped_ruleset::{ContentVisitor, ExclusionCheck, ScopedRuleSet};
pub use crate::secondary_validation::Validator;
use crate::{CreateScannerError, EncodeIndices, MatchAction, Path};
use regex_automata::meta::{Cache, Regex as MetaRegex};
use std::any::{Any, TypeId};
use std::sync::Arc;

use self::cache_pool::{CachePool, CachePoolBuilder, CachePoolGuard};
use self::metrics::ScannerMetrics;
use crate::scanner::config::RuleConfig;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::scope::Scope;
use crate::stats::GLOBAL_STATS;
use ahash::{AHashMap, AHashSet};
use regex_automata::Match;
use crate::scanner::regex_rule::{take_regex_caches, RegexCaches};

pub mod cache_pool;
pub mod config;
pub mod error;
pub mod metrics;
pub mod regex_rule;
pub mod scope;

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

// CompiledRuleDyn is a private trait that is used to hide the complexity of downcasting the group data
// into the correct type.
// This is used to allow the group data to be stored in a map only if the group of rule has a groupData associated with it (unlike regex rules)
pub trait CompiledRuleDyn: Send + Sync {
    fn get_match_action(&self) -> &MatchAction;
    fn get_scope(&self) -> &Scope;

    #[allow(clippy::too_many_arguments)]
    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        regex_caches: &mut RegexCaches,
        group_data: &mut AHashMap<TypeId, Box<dyn Any>>,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        should_keywords_match_event_paths: bool,
    );

    // Whether a match from this rule should be excluded (marked as a false-positive)
    // if the content of this match was found in a match from an excluded scope
    fn should_exclude_multipass_v0(&self) -> bool {
        // default is to NOT use Multi-pass V0
        false
    }

    fn on_excluded_match_multipass_v0(&self) {
        // default is to do nothing
    }

    fn get_match_validation_type(&self) -> Option<&MatchValidationType>;

    fn get_internal_match_validation_type(&self) -> Option<&InternalMatchValidationType>;
}

// This is the "hidden" implementation of CompiledRuleDyn for any type that implements CompiledRule
// get_string_matches will downcast the group data to the correct type and call the actual implementation
// done in the CompiledRule trait
impl<T: CompiledRule> CompiledRuleDyn for T {
    fn get_match_action(&self) -> &MatchAction {
        self.get_match_action()
    }

    fn get_scope(&self) -> &Scope {
        self.get_scope()
    }

    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        regex_caches: &mut RegexCaches,
        group_data: &mut AHashMap<TypeId, Box<dyn Any>>,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        should_keywords_match_event_paths: bool,
    ) {
        let group_data_any = group_data
            .entry(TypeId::of::<T::GroupData>())
            .or_insert_with(|| Box::new(T::GroupData::default()));
        let group_data: &mut T::GroupData = group_data_any.downcast_mut().unwrap();
        self.get_string_matches(
            content,
            path,
            regex_caches,
            group_data,
            exclusion_check,
            excluded_matches,
            match_emitter,
            should_keywords_match_event_paths,
        )
    }

    fn should_exclude_multipass_v0(&self) -> bool {
        T::should_exclude_multipass_v0(self)
    }

    fn on_excluded_match_multipass_v0(&self) {
        T::on_excluded_match_multipass_v0(self)
    }

    fn get_match_validation_type(&self) -> Option<&MatchValidationType> {
        T::get_match_validation_type(self)
    }

    fn get_internal_match_validation_type(&self) -> Option<&InternalMatchValidationType> {
        T::get_internal_match_validation_type(self)
    }
}

// This is the public trait that is used to define the behavior of a compiled rule.
pub trait CompiledRule: Send + Sync {
    /// Data that is instantiated once per string being scanned, and shared with all rules that
    /// have the same `GroupData` type. `Default` will be used to initialize this data.
    type GroupData: Default + 'static;

    fn get_match_action(&self) -> &MatchAction;
    fn get_scope(&self) -> &Scope;

    #[allow(clippy::too_many_arguments)]
    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        regex_caches: &mut RegexCaches,
        // caches: &mut CachePoolGuard<'_>,
        group_data: &mut Self::GroupData,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        should_keywords_match_event_paths: bool,
    );

    // Whether a match from this rule should be excluded (marked as a false-positive)
    // if the content of this match was found in a match from an excluded scope
    fn should_exclude_multipass_v0(&self) -> bool {
        // default is to NOT use Multi-pass V0
        false
    }

    fn on_excluded_match_multipass_v0(&self) {
        // default is to do nothing
    }

    fn get_match_validation_type(&self) -> Option<&MatchValidationType>;

    // This is the match validation type key used in the match_validators_per_type map
    fn get_internal_match_validation_type(&self) -> Option<&InternalMatchValidationType>;
}

impl<T> RuleConfig for Box<T>
where
    T: RuleConfig + ?Sized,
{
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        labels: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError> {
        self.as_ref()
            .convert_to_compiled_rule(rule_index, labels, cache_pool_builder)
    }

    fn get_match_validation_type(&self) -> Option<&MatchValidationType> {
        self.as_ref().get_match_validation_type()
    }
}

#[derive(Debug, PartialEq, Clone)]
struct ScannerFeatures {
    pub should_keywords_match_event_paths: bool,
    pub add_implicit_index_wildcards: bool,
    pub multipass_v0_enabled: bool,
    pub return_matches: bool,
}

impl Default for ScannerFeatures {
    fn default() -> Self {
        Self {
            should_keywords_match_event_paths: false,
            add_implicit_index_wildcards: false,
            multipass_v0_enabled: true,

            return_matches: false,
        }
    }
}

pub struct Scanner {
    rules: Vec<Box<dyn CompiledRuleDyn>>,
    scoped_ruleset: ScopedRuleSet,
    cache_pool: CachePool,
    scanner_features: ScannerFeatures,
    metrics: ScannerMetrics,

    match_validators_per_type: AHashMap<InternalMatchValidationType, Box<dyn MatchValidator>>,
}

impl Scanner {
    pub fn builder(rules: &[Arc<dyn RuleConfig>]) -> ScannerBuilder {
        ScannerBuilder::new(rules)
    }

    // This function scans the given event with the rules configured in the scanner.
    // The event parameter is a mutable reference to the event that should be scanned (implemented the Event trait).
    // The blocked_rules_idx parameter is a list of rule indices that should be skipped for this scan.
    // this list shall be small (<10), so a linear search is acceptable otherwise performance will be impacted.
    // The return value is a list of RuleMatch objects, which contain information about the matches that were found.
    pub fn scan<E: Event>(&self, event: &mut E, blocked_rules_idx: Vec<usize>) -> Vec<RuleMatch> {
        // This is a set of caches (1 for each rule) that can be used for scanning. This is obtained once per scan to reduce
        // lock contention. (Normally it has to be obtained for each regex scan individually)
        // let caches: regex_automata::util::pool::PoolGuard<
        //     '_,
        //     Vec<regex_automata::meta::Cache>,
        //     Box<dyn Fn() -> Vec<regex_automata::meta::Cache> + Send + Sync>,
        // > = self.cache_pool.get();

        let mut regex_caches = take_regex_caches();

        // All matches, after some (but not all) false-positives have been removed.
        // This is a vec of vecs, where each inner vec is a set of matches for a single path.
        let mut rule_matches_list = vec![];

        let mut excluded_matches = AHashSet::new();

        // Measure detection time
        let start = std::time::Instant::now();
        self.scoped_ruleset.visit_string_rule_combinations(
            event,
            ScannerContentVisitor {
                scanner: self,
                regex_caches: &mut regex_caches,
                rule_matches: &mut rule_matches_list,
                blocked_rules: &blocked_rules_idx,
                excluded_matches: &mut excluded_matches,
            },
        );
        let mut output_rule_matches = vec![];

        for (path, rule_matches) in &mut rule_matches_list {
            // All rule matches in each inner list are for a single path, so they can be processed independently.
            event.visit_string_mut(path, |content| {
                if self.scanner_features.multipass_v0_enabled {
                    // Now that the `excluded_matches` set is fully populated, filter out any matches
                    // that are the same as excluded matches (also known as "Multi-pass V0")
                    rule_matches.retain(|rule_match| {
                        if self.rules[rule_match.rule_index].should_exclude_multipass_v0() {
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

                self.sort_and_remove_overlapping_rules::<E::Encoding>(rule_matches);

                let will_mutate = rule_matches.iter().any(|rule_match| {
                    self.rules[rule_match.rule_index]
                        .get_match_action()
                        .is_mutating()
                });

                self.apply_match_actions(content, path, rule_matches, &mut output_rule_matches);

                will_mutate
            });
        }
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

        output_rule_matches
    }

    pub async fn validate_matches(
        &self,
        rule_matches: &mut Vec<RuleMatch>,
    ) -> Result<(), MatchValidationError> {
        if !self.scanner_features.return_matches {
            return Err(MatchValidationError::NoMatchValidationType);
        }
        // Create MatchValidatorRuleMatch per match_validator_type to pass it to each match_validator
        let mut match_validator_rule_match_per_type = AHashMap::new();
        for rule_match in rule_matches.drain(..) {
            let rule = &self.rules[rule_match.rule_index];
            if let Some(match_validation_type) = rule.get_internal_match_validation_type() {
                if !match_validator_rule_match_per_type.contains_key(match_validation_type) {
                    match_validator_rule_match_per_type.insert(match_validation_type, Vec::new());
                }
                match_validator_rule_match_per_type
                    .get_mut(match_validation_type)
                    .unwrap()
                    .push(rule_match);
            }
        }

        // Call the validate per match_validator_type with their matches and the RuleMatch list and collect the results
        let futures = match_validator_rule_match_per_type.iter_mut().filter_map(
            |(match_validation_type, matches_per_type)| {
                let match_validator = self.match_validators_per_type.get(match_validation_type);
                match_validator.map(|match_validator| {
                    match_validator
                        .as_ref()
                        .validate(matches_per_type, &self.rules)
                })
            },
        );

        // Wait for all result to complete
        let _ = futures::future::join_all(futures).await;
        // Refill the rule_matches with the validated matches
        for (_, mut matches) in match_validator_rule_match_per_type {
            rule_matches.append(&mut matches);
        }

        // Sort rule_matches by start index
        rule_matches.sort_by_key(|rule_match| rule_match.start_index);
        Ok(())
    }

    /// Apply mutations from actions, and shift indices to match the mutated values.
    /// This assumes the matches are all from the content given, and are sorted by start index.
    fn apply_match_actions<E: Encoding>(
        &self,
        content: &mut String,
        path: &Path<'static>,
        rule_matches: &mut [InternalRuleMatch<E>],
        output_rule_matches: &mut Vec<RuleMatch>,
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
    ) -> RuleMatch {
        let rule = &self.rules[rule_match.rule_index];

        let custom_start =
            (<E>::get_index(&rule_match.custom_start, rule_match.utf8_start) as isize
                + <E>::get_shift(custom_index_delta, *utf8_byte_delta)) as usize;

        let mut matched_content_copy = None;

        if self.scanner_features.return_matches {
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

        if rule.get_match_action().is_mutating() {
            let mutated_utf8_match_start =
                (rule_match.utf8_start as isize + *utf8_byte_delta) as usize;
            let mutated_utf8_match_end = (rule_match.utf8_end as isize + *utf8_byte_delta) as usize;

            // Matches for mutating rules must have valid indices
            debug_assert!(content.is_char_boundary(mutated_utf8_match_start));
            debug_assert!(content.is_char_boundary(mutated_utf8_match_end));

            let matched_content = &content[mutated_utf8_match_start..mutated_utf8_match_end];
            if let Some(replacement) = rule.get_match_action().get_replacement(matched_content) {
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

        let match_status: MatchStatus = if rule.get_match_validation_type().is_some() {
            MatchStatus::NotChecked
        } else {
            MatchStatus::NotAvailable
        };

        RuleMatch {
            rule_index: rule_match.rule_index,
            path,
            replacement_type: rule.get_match_action().replacement_type(),
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
                .get_match_action()
                .is_mutating()
                .cmp(&self.rules[b.rule_index].get_match_action().is_mutating())
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
            if self.rules[rule_match.rule_index]
                .get_match_action()
                .is_mutating()
            {
                // Mutating rules are kept only if they don't overlap with a previous rule.
                if let Some(last) = retained_rules.last() {
                    if last.utf8_end > rule_match.utf8_start {
                        continue;
                    }
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
    rules: &'a [Arc<dyn RuleConfig>],
    labels: Labels,
    scanner_features: ScannerFeatures,
}

impl ScannerBuilder<'_> {
    pub fn new(rules: &[Arc<dyn RuleConfig>]) -> ScannerBuilder {
        ScannerBuilder {
            rules,
            labels: Labels::empty(),
            scanner_features: ScannerFeatures::default(),
        }
    }

    pub fn labels(mut self, labels: Labels) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_keywords_should_match_event_paths(mut self, value: bool) -> Self {
        self.scanner_features.should_keywords_match_event_paths = value;
        self
    }

    pub fn with_implicit_wildcard_indexes_for_scopes(mut self, value: bool) -> Self {
        self.scanner_features.add_implicit_index_wildcards = value;
        self
    }

    /// Enables/Disables the Multipass V0 feature. This defaults to TRUE.
    /// Multipass V0 saves matches from excluded scopes, and marks any identical
    /// matches in included scopes as a false positive.
    pub fn with_multipass_v0(mut self, value: bool) -> Self {
        self.scanner_features.multipass_v0_enabled = value;
        self
    }

    pub fn build(self) -> Result<Scanner, CreateScannerError> {
        let mut scanner_features = self.scanner_features.clone();
        let mut cache_pool_builder = CachePoolBuilder::new();
        let mut match_validators_per_type = AHashMap::new();

        for rule in self.rules.iter() {
            if let Some(match_validation_type) = rule.get_match_validation_type() {
                if match_validation_type.can_create_match_validator() {
                    let internal_type = match_validation_type.get_internal_match_validation_type();
                    if !match_validators_per_type.contains_key(&internal_type) {
                        match_validators_per_type.insert(
                            internal_type,
                            new_match_validator_from_type(match_validation_type),
                        );
                        // Let's add return_matches to the scanner features
                        scanner_features.return_matches = true;
                    }
                }
            }
        }

        let compiled_rules = self
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, config)| {
                config.convert_to_compiled_rule(
                    rule_index,
                    self.labels.clone(),
                    &mut cache_pool_builder,
                )
            })
            .collect::<Result<Vec<Box<dyn CompiledRuleDyn>>, CreateScannerError>>()?;

        let scoped_ruleset = ScopedRuleSet::new(
            &compiled_rules
                .iter()
                .map(|rule| rule.get_scope().clone())
                .collect::<Vec<_>>(),
        )
        .with_implicit_index_wildcards(self.scanner_features.add_implicit_index_wildcards);

        let cache_pool = cache_pool_builder.build();

        {
            let stats = &*GLOBAL_STATS;

            let caches = cache_pool.get();
            let total_cache_size: usize = caches
                .iter()
                .map(|x| x.memory_usage() + std::mem::size_of::<Cache>())
                .sum();

            stats.scanner_creations.increment(1);
            stats.increment_total_scanners();
            stats
                .regex_cache_per_scanner
                .record(total_cache_size as f64);
            stats
                .number_of_rules_per_scanner
                .record(self.rules.len() as f64);
        }

        Ok(Scanner {
            rules: compiled_rules,
            scoped_ruleset,
            cache_pool,
            scanner_features,
            metrics: ScannerMetrics::new(&self.labels),
            match_validators_per_type,
        })
    }
}

struct ScannerContentVisitor<'a, E: Encoding> {
    scanner: &'a Scanner,
    regex_caches: &'a mut RegexCaches,
    rule_matches: &'a mut Vec<(crate::Path<'static>, Vec<InternalRuleMatch<E>>)>,
    // Rules that shall be skipped for this scan
    // This list shall be small (<10), so a linear search is acceptable
    blocked_rules: &'a Vec<usize>,
    excluded_matches: &'a mut AHashSet<String>,
}

impl<'a, E: Encoding> ContentVisitor<'a> for ScannerContentVisitor<'a, E> {
    fn visit_content<'b>(
        &'b mut self,
        path: &Path<'a>,
        content: &str,
        mut rule_visitor: crate::scoped_ruleset::RuleIndexVisitor,
        exclusion_check: ExclusionCheck<'b>,
    ) -> bool {
        // matches for a single path
        let mut path_rules_matches = vec![];

        // Create a map of per rule type data that can be shared between rules of the same type
        let mut group_data: AHashMap<TypeId, Box<dyn Any>> = AHashMap::new();

        rule_visitor.visit_rule_indices(|rule_index| {
            if self.blocked_rules.contains(&rule_index) {
                return;
            }
            let rule = &self.scanner.rules[rule_index];
            {
                // creating the emitter is basically free, it will get mostly optimized away
                let mut emitter = |rule_match: StringMatch| {
                    path_rules_matches.push(InternalRuleMatch {
                        rule_index,
                        utf8_start: rule_match.start,
                        utf8_end: rule_match.end,
                        custom_start: E::zero_index(),
                        custom_end: E::zero_index(),
                    });
                };

                rule.get_string_matches(
                    content,
                    path,
                    &mut self.regex_caches,
                    &mut group_data,
                    &exclusion_check,
                    self.excluded_matches,
                    &mut emitter,
                    self.scanner
                        .scanner_features
                        .should_keywords_match_event_paths,
                );
            }
        });

        // calculate_indices requires that matches are sorted by start index
        path_rules_matches.sort_unstable_by_key(|rule_match| rule_match.utf8_start);

        E::calculate_indices(
            content,
            path_rules_matches
                .iter_mut()
                .map(|rule_match: &mut InternalRuleMatch<E>| EncodeIndices {
                    utf8_start: rule_match.utf8_start,
                    utf8_end: rule_match.utf8_end,
                    custom_start: &mut rule_match.custom_start,
                    custom_end: &mut rule_match.custom_end,
                }),
        );

        // If there are any matches, the string will need to be accessed to check for false positives from
        // excluded matches, any to potentially mutate the string.
        let has_match = !path_rules_matches.is_empty();

        if has_match {
            self.rule_matches
                .push((path.into_static(), path_rules_matches));
        }

        has_match
    }
}

// Calculates the next starting position for a regex match if a the previous match is a false positive
fn get_next_regex_start(content: &str, regex_match: &Match) -> Option<usize> {
    // The next valid UTF8 char after the start of the regex match is used
    if let Some((i, _)) = content[regex_match.start()..].char_indices().nth(1) {
        Some(regex_match.start() + i)
    } else {
        // There are no more chars left in the string to scan
        None
    }
}

fn is_false_positive_match(
    regex_match: &Match,
    rule: &RegexCompiledRule,
    content: &str,
    check_excluded_keywords: bool,
) -> bool {
    if check_excluded_keywords {
        if let Some(excluded_keywords) = &rule.excluded_keywords {
            if excluded_keywords.is_false_positive_match(content, regex_match.start()) {
                return true;
            }
        }
    }

    if let Some(validator) = rule.validator.as_ref() {
        if !validator.is_valid_match(&content[regex_match.range()]) {
            return true;
        };
    }
    false
}

#[cfg(test)]
mod test {
    use super::cache_pool::{CachePoolBuilder, CachePoolGuard};
    use super::CompiledRuleDyn;
    use super::*;
    use super::{MatchEmitter, ScannerBuilder, StringMatch};
    use crate::match_action::{MatchAction, MatchActionValidationError};

    use crate::match_validation::config::{AwsConfig, AwsType, MatchValidationType};

    use crate::match_validation::http_validator::HttpValidatorConfigBuilder;
    use crate::match_validation::validator_utils::generate_aws_headers_and_body;
    use crate::observability::labels::Labels;
    use crate::scanner::regex_rule::config::{
        ProximityKeywordsConfig, RegexRuleConfig, SecondaryValidator, SecondaryValidator::*,
    };
    use crate::scanner::scope::Scope;
    use crate::scanner::{get_next_regex_start, CreateScannerError, Scanner};
    use crate::scoped_ruleset::ExclusionCheck;
    use crate::validation::RegexValidationError;
    use std::{fmt, time::Duration};

    use crate::{simple_event::SimpleEvent, PartialRedactDirection, Path, PathSegment, RuleMatch};
    use crate::{Encoding, Utf8Encoding};
    use ahash::AHashSet;
    use httpmock::{Method::GET, Method::POST, MockServer};

    use regex_automata::Match;
    use std::collections::BTreeMap;

    use super::CompiledRule;
    use super::RuleConfig;

    pub struct DumbRuleConfig {}

    pub struct DumbCompiledRule {
        pub match_action: MatchAction,
        pub scope: Scope,
    }

    impl CompiledRule for DumbCompiledRule {
        type GroupData = ();

        fn get_match_action(&self) -> &MatchAction {
            &self.match_action
        }
        fn get_scope(&self) -> &Scope {
            &self.scope
        }
        fn get_string_matches(
            &self,
            _content: &str,
            _path: &Path,
            _regex_caches: &mut RegexCaches,
            // _caches: &mut CachePoolGuard<'_>,
            _group_data: &mut Self::GroupData,
            _exclusion_check: &ExclusionCheck<'_>,
            _excluded_matches: &mut AHashSet<String>,
            match_emitter: &mut dyn MatchEmitter,
            _should_keywords_match_event_paths: bool,
        ) {
            match_emitter.emit(StringMatch { start: 10, end: 16 });
        }

        fn get_match_validation_type(&self) -> Option<&MatchValidationType> {
            None
        }

        fn get_internal_match_validation_type(&self) -> Option<&InternalMatchValidationType> {
            None
        }
    }

    impl RuleConfig for DumbRuleConfig {
        fn convert_to_compiled_rule(
            &self,
            _content: usize,
            _: Labels,
            _: &mut CachePoolBuilder,
        ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError> {
            Ok(Box::new(DumbCompiledRule {
                match_action: MatchAction::Redact {
                    replacement: "[REDACTED]".to_string(),
                },
                scope: Scope::default(),
            }))
        }

        fn get_match_validation_type(&self) -> Option<&MatchValidationType> {
            None
        }
    }

    #[test]
    fn dumb_custom_rule() {
        let scanner = ScannerBuilder::new(&[Arc::new(DumbRuleConfig {})])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut input = "this is a secret with random data".to_owned();

        let matched_rules = scanner.scan(&mut input, vec![]);

        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "this is a [REDACTED] with random data");
    }

    #[test]
    fn test_mixed_rules() {
        let scanner = ScannerBuilder::new(&[
            Arc::new(DumbRuleConfig {}),
            RegexRuleConfig::new("secret")
                .match_action(MatchAction::Redact {
                    replacement: "[SECRET]".to_string(),
                })
                .build(),
        ])
        .with_keywords_should_match_event_paths(true)
        .build()
        .unwrap();

        let mut input = "this is a dumbss with random data and a secret".to_owned();

        let matched_rules = scanner.scan(&mut input, vec![]);

        assert_eq!(matched_rules.len(), 2);
        assert_eq!(
            input,
            "this is a [REDACTED] with random data and a [SECRET]"
        );
    }

    #[test]
    fn simple_redaction() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("secret")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build()])
        .with_keywords_should_match_event_paths(true)
        .build()
        .unwrap();

        let mut input = "text with secret".to_owned();

        let matched_rules = scanner.scan(&mut input, vec![]);

        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "text with [REDACTED]");
    }

    #[test]
    fn simple_redaction_with_additional_labels() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("secret")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build()])
        .labels(Labels::new(&[("key".to_string(), "value".to_string())]))
        .with_keywords_should_match_event_paths(true)
        .build()
        .unwrap();

        let mut input = "text with secret".to_owned();

        let matched_rules = scanner.scan(&mut input, vec![]);

        assert_eq!(matched_rules.len(), 1);
        assert_eq!(input, "text with [REDACTED]");
    }

    #[test]
    fn should_fail_on_compilation_error() {
        let scanner_result = ScannerBuilder::new(&[RegexRuleConfig::new("\\u").build()])
            .with_keywords_should_match_event_paths(true)
            .build();
        assert!(scanner_result.is_err());
        assert_eq!(
            scanner_result.err().unwrap(),
            CreateScannerError::InvalidRegex(RegexValidationError::InvalidSyntax)
        )
    }

    #[test]
    fn should_validate_zero_char_count_partial_redact() {
        let scanner_result = ScannerBuilder::new(&[RegexRuleConfig::new("secret")
            .match_action(MatchAction::PartialRedact {
                direction: PartialRedactDirection::LastCharacters,
                character_count: 0,
            })
            .build()])
        .with_keywords_should_match_event_paths(true)
        .build();

        assert!(scanner_result.is_err());
        assert_eq!(
            scanner_result.err().unwrap(),
            CreateScannerError::InvalidMatchAction(
                MatchActionValidationError::PartialRedactionNumCharsZero
            )
        )
    }

    #[test]
    fn multiple_replacements() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("\\d")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build()])
        .with_keywords_should_match_event_paths(true)
        .build()
        .unwrap();

        let mut content = "testing 1 2 3".to_string();

        let matches = scanner.scan(&mut content, vec![]);

        assert_eq!(content, "testing [REDACTED] [REDACTED] [REDACTED]");
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn match_rule_index() {
        let scanner = ScannerBuilder::new(&[
            RegexRuleConfig::new("a").build(),
            RegexRuleConfig::new("b").build(),
        ])
        .with_keywords_should_match_event_paths(true)
        .build()
        .unwrap();

        let mut content = "a b".to_string();

        let matches = scanner.scan(&mut content, vec![]);

        assert_eq!(content, "a b");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].rule_index, 0);
        assert_eq!(
            (
                matches[0].start_index,
                matches[0].end_index_exclusive,
                matches[0].shift_offset
            ),
            (0, 1, 0)
        );
        assert_eq!(matches[1].rule_index, 1);
        assert_eq!(
            (
                matches[1].start_index,
                matches[1].end_index_exclusive,
                matches[1].shift_offset
            ),
            (2, 3, 0)
        );
    }

    #[test]
    fn test_indices() {
        let test_builder = RegexRuleConfig::new("test");
        let detect_test_rule = test_builder.build();
        let redact_test_rule = test_builder
            .match_action(MatchAction::Redact {
                replacement: "[test]".to_string(),
            })
            .build();
        let redact_test_rule_2 = RegexRuleConfig::new("ab")
            .match_action(MatchAction::Redact {
                replacement: "[ab]".to_string(),
            })
            .build();

        let test_cases = vec![
            (vec![detect_test_rule.clone()], "test1", vec![(0, 4, 0)]),
            (vec![redact_test_rule.clone()], "test2", vec![(0, 6, 2)]),
            (vec![redact_test_rule.clone()], "xtestx", vec![(1, 7, 2)]),
            (
                vec![redact_test_rule.clone()],
                "xtestxtestx",
                vec![(1, 7, 2), (8, 14, 4)],
            ),
            (
                vec![redact_test_rule_2.clone()],
                "xtestxabx",
                vec![(6, 10, 2)],
            ),
            (
                vec![redact_test_rule_2.clone(), redact_test_rule.clone()],
                "xtestxabx",
                vec![(1, 7, 2), (8, 12, 4)],
            ),
            (
                vec![detect_test_rule.clone(), redact_test_rule_2.clone()],
                "ab-test",
                vec![(0, 4, 2), (5, 9, 2)],
            ),
        ];

        for (rule_config, input, expected_indices) in test_cases {
            let scanner = ScannerBuilder::new(rule_config.leak())
                .with_keywords_should_match_event_paths(true)
                .build()
                .unwrap();
            let mut input = input.to_string();
            let matches = scanner.scan(&mut input, vec![]);

            assert_eq!(matches.len(), expected_indices.len());
            for (rule_match, expected_range) in matches.iter().zip(expected_indices) {
                assert_eq!(
                    (
                        rule_match.start_index,
                        rule_match.end_index_exclusive,
                        rule_match.shift_offset
                    ),
                    expected_range
                );
            }
        }
    }

    #[test]
    fn test_included_keywords_match_content() {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[redact_test_rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "hello [REDACTED]");
        assert_eq!(matches.len(), 1);

        let mut content = "he**o world".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "he**o world");
        assert_eq!(matches.len(), 0);

        let mut content = "world hello world".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "world hello [REDACTED]");
        assert_eq!(matches.len(), 1);
    }

    fn build_test_scanner(should_keywords_match_event_paths: bool) -> Scanner {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["awsAccess".to_string(), "access/key".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        return Scanner::builder(&[redact_test_rule])
            .with_keywords_should_match_event_paths(should_keywords_match_event_paths)
            .build()
            .unwrap();
    }

    #[test]
    fn test_included_keywords_match_path_feature_disabled() {
        let scanner = build_test_scanner(false);

        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "aws".to_string(),
            SimpleEvent::Map(BTreeMap::from([(
                "access".to_string(),
                SimpleEvent::String("hello world".to_string()),
            )])),
        )]));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_included_keywords_match_path() {
        let scanner = build_test_scanner(true);

        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "aws".to_string(),
            SimpleEvent::Map(BTreeMap::from([(
                "access".to_string(),
                SimpleEvent::String("hello world".to_string()),
            )])),
        )]));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_included_keywords_match_path_case_insensitive() {
        let scanner = build_test_scanner(true);

        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "access".to_string(),
            SimpleEvent::Map(BTreeMap::from([(
                "KEY".to_string(),
                SimpleEvent::String("hello world".to_string()),
            )])),
        )]));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_included_keywords_path_not_matching() {
        let scanner = build_test_scanner(true);

        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "aws".to_string(),
            SimpleEvent::List(vec![
                SimpleEvent::Map(BTreeMap::from([(
                    "key".to_string(),
                    SimpleEvent::String("hello world".to_string()),
                )])),
                SimpleEvent::Map(BTreeMap::from([(
                    "access".to_string(),
                    SimpleEvent::String("hello".to_string()),
                )])),
            ]),
        )]));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_included_keywords_path_with_uncaught_separator_symbol() {
        let scanner = build_test_scanner(true);

        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "aws%access".to_string(),
            SimpleEvent::String("hello".to_string()),
        )]));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_included_keywords_path_deep() {
        let scanner = build_test_scanner(true);

        let mut content = SimpleEvent::Map(BTreeMap::from([(
            "aws".to_string(),
            SimpleEvent::List(vec![
                SimpleEvent::Map(BTreeMap::from([(
                    "key".to_string(),
                    SimpleEvent::String("hello world".to_string()),
                )])),
                SimpleEvent::Map(BTreeMap::from([
                    (
                        "access".to_string(),
                        SimpleEvent::Map(BTreeMap::from([(
                            "random_key".to_string(),
                            SimpleEvent::String("hello world".to_string()),
                        )])),
                    ),
                    (
                        "another_key".to_string(),
                        SimpleEvent::String("hello world".to_string()),
                    ),
                ])),
            ]),
        )]));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_blocked_rules() {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[redact_test_rule]).build().unwrap();
        let mut content = "hello world".to_string();

        // Scan with no blocked rules
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "hello [REDACTED]");
        assert_eq!(matches.len(), 1);

        // Scan with blocked rules
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content, vec![0]);
        assert_eq!(content, "hello world");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_excluded_keywords() {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec![],
                excluded_keywords: vec!["hello".to_string()],
            })
            .build();

        let scanner = ScannerBuilder::new(&[redact_test_rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "hello world");
        assert_eq!(matches.len(), 0);

        let mut content = "he**o world".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "he**o [REDACTED]");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_luhn_checksum() {
        let rule = RegexRuleConfig::new("(\\d{16})|((\\d{4} ){3}\\d{4})").match_action(
            MatchAction::Redact {
                replacement: "[credit card]".to_string(),
            },
        );

        let rule_with_checksum = rule.validator(SecondaryValidator::LuhnChecksum).build();

        let scanner = ScannerBuilder::new(&[rule.build()])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "4556997807150071  4111 1111 1111 1111".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 2);
        assert_eq!(content, "[credit card]  [credit card]");

        let scanner = ScannerBuilder::new(&[rule_with_checksum])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "4556997807150071  4111 1111 1111 1111".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "4556997807150071  [credit card]");
    }

    #[test]
    fn test_chinese_id_checksum() {
        let rule = RegexRuleConfig::new("\\d+").match_action(MatchAction::Redact {
            replacement: "[IDCARD]".to_string(),
        });

        let rule_with_checksum = rule.validator(ChineseIdChecksum).build();

        let scanner = ScannerBuilder::new(&[rule.build()])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "513231200012121657 513231200012121651".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 2);
        assert_eq!(content, "[IDCARD] [IDCARD]");

        let scanner = ScannerBuilder::new(&[rule_with_checksum])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "513231200012121657 513231200012121651".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "[IDCARD] 513231200012121651");
    }

    #[test]
    fn test_iban_checksum() {
        let rule_with_checksum = RegexRuleConfig::new("DE[0-9]+")
            .match_action(MatchAction::Redact {
                replacement: "[IBAN]".to_string(),
            })
            .validator(IbanChecker)
            .build();

        // Valid content with checksum
        let mut content = "number=DE44500105175407324931".to_string();
        let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
            .build()
            .unwrap();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "number=[IBAN]");

        // Invalid content with checksum
        let mut content = "number=DE34500105175407324931".to_string();
        let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
            .build()
            .unwrap();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 0);
        assert_eq!(content, "number=DE34500105175407324931");
    }

    #[test]
    fn test_github_token_checksum() {
        let rule = RegexRuleConfig::new("[^ ]+").match_action(MatchAction::Redact {
            replacement: "[GITHUB]".to_string(),
        });

        let rule_with_checksum = rule.validator(GithubTokenChecksum).build();

        let scanner = ScannerBuilder::new(&[rule.build()])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content =
            "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
                .to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 2);
        assert_eq!(content, "[GITHUB] [GITHUB]");

        let scanner = ScannerBuilder::new(&[rule_with_checksum])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content =
            "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 ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5"
                .to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "[GITHUB] ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V5");
    }

    #[test]
    fn test_nhs_checksum() {
        let rule_with_checksum = RegexRuleConfig::new(".+")
            .match_action(MatchAction::Redact {
                replacement: "[NHS]".to_string(),
            })
            .validator(NhsCheckDigit)
            .build();

        let mut content = "1234567881".to_string();
        // Test matching NHS number with checksum
        let scanner = ScannerBuilder::new(&[rule_with_checksum.clone()])
            .build()
            .unwrap();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "[NHS]");
    }

    #[test]
    fn test_overlapping_mutations() {
        // This reproduces a bug where overlapping mutations weren't filtered out, resulting in invalid
        // UTF-8 indices being calculated which resulted in a panic if they were used.

        let rule = RegexRuleConfig::new("hello")
            .match_action(MatchAction::Redact {
                replacement: "*".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule.clone(), rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(content, "* world");

        // The rule was cloned, so if this is only 1, the 2nd was filtered out
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_multiple_partial_redactions() {
        let rule = RegexRuleConfig::new("...")
            .match_action(MatchAction::PartialRedact {
                direction: PartialRedactDirection::FirstCharacters,
                character_count: 1,
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule.clone(), rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "hello world".to_string();
        let matches = scanner.scan(&mut content, vec![]);

        assert_eq!(matches.len(), 3);
        assert_eq!(content, "*el*o *orld");

        assert_eq!(
            matches[0],
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: crate::ReplacementType::PartialStart,
                start_index: 0,
                end_index_exclusive: 3,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );

        assert_eq!(
            matches[1],
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: crate::ReplacementType::PartialStart,
                start_index: 3,
                end_index_exclusive: 6,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );

        assert_eq!(
            matches[2],
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: crate::ReplacementType::PartialStart,
                start_index: 6,
                end_index_exclusive: 9,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );
    }

    #[test]
    fn assert_scanner_is_sync_send() {
        // This ensures that the scanner is safe to use from multiple threads.
        fn assert_send<T: Send + Sync>() {}

        assert_send::<Scanner>();
    }

    #[test]
    fn matches_should_take_precedence_over_non_mutating_overlapping_matches() {
        let rule_0 = RegexRuleConfig::new("...")
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RegexRuleConfig::new("...")
            .match_action(MatchAction::Redact {
                replacement: "***".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_0, rule_1])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "hello world".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        matches.sort();

        assert_eq!(matches.len(), 3);
        assert_eq!(content, "*********ld");

        assert_eq!(
            matches[0],
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: crate::ReplacementType::Placeholder,
                start_index: 0,
                end_index_exclusive: 3,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );

        assert_eq!(
            matches[1],
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: crate::ReplacementType::Placeholder,
                start_index: 3,
                end_index_exclusive: 6,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );

        assert_eq!(
            matches[2],
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: crate::ReplacementType::Placeholder,
                start_index: 6,
                end_index_exclusive: 9,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );
    }

    #[test]
    fn test_overlapping_mutation_higher_priority() {
        // A mutating match is a higher priority even if it starts after a non-mutating match

        let rule_0 = RegexRuleConfig::new("abc")
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RegexRuleConfig::new("bcd")
            .match_action(MatchAction::Redact {
                replacement: "***".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_0, rule_1])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "abcdef".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        matches.sort();

        assert_eq!(matches.len(), 1);
        assert_eq!(content, "a***ef");

        assert_eq!(
            matches[0],
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: crate::ReplacementType::Placeholder,
                start_index: 1,
                end_index_exclusive: 4,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );
    }

    #[test]
    fn test_overlapping_start_offset() {
        // The match that starts first is used (if the mutation is the same)

        let rule_0 = RegexRuleConfig::new("abc")
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RegexRuleConfig::new("bcd")
            .match_action(MatchAction::None)
            .build();

        let scanner = ScannerBuilder::new(&[rule_0, rule_1])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "abcdef".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        matches.sort();

        assert_eq!(matches.len(), 1);
        assert_eq!(content, "abcdef");

        assert_eq!(
            matches[0],
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: crate::ReplacementType::None,
                start_index: 0,
                end_index_exclusive: 3,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );
    }

    #[test]
    fn test_overlapping_length() {
        // If 2 matches have the same mutation and same start, the longer one is taken

        let rule_0 = RegexRuleConfig::new("abc")
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RegexRuleConfig::new("abcd")
            .match_action(MatchAction::None)
            .build();

        let scanner = ScannerBuilder::new(&[rule_0, rule_1])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "abcdef".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        matches.sort();

        assert_eq!(matches.len(), 1);
        assert_eq!(content, "abcdef");

        assert_eq!(
            matches[0],
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: crate::ReplacementType::None,
                start_index: 0,
                end_index_exclusive: 4,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );
    }

    #[test]
    fn test_overlapping_rule_order() {
        // If 2 matches have the same mutation, same start, and the same length, the one with the lower rule index is used

        let rule_0 = RegexRuleConfig::new("abc")
            .match_action(MatchAction::None)
            .build();

        let rule_1 = RegexRuleConfig::new("abc")
            .match_action(MatchAction::None)
            .build();

        let scanner = ScannerBuilder::new(&[rule_0, rule_1])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();
        let mut content = "abcdef".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        matches.sort();

        assert_eq!(matches.len(), 1);
        assert_eq!(content, "abcdef");

        assert_eq!(
            matches[0],
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: crate::ReplacementType::None,
                start_index: 0,
                end_index_exclusive: 3,
                shift_offset: 0,

                match_value: None,

                match_status: MatchStatus::NotAvailable,
            }
        );
    }

    #[test]
    fn should_skip_match_when_present_in_excluded_matches() {
        // If 2 matches have the same mutation and same start, the longer one is taken

        let rule_0 = RegexRuleConfig::new("b.*")
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                "test".into(),
            )])]))
            .match_action(MatchAction::Redact {
                replacement: "[scrub]".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content = SimpleEvent::Map(BTreeMap::from([
            (
                "a-match".to_string(),
                SimpleEvent::String("bcdef".to_string()),
            ),
            (
                "z-match".to_string(),
                SimpleEvent::String("bcdef".to_string()),
            ),
            ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
        ]));

        let matches = scanner.scan(&mut content, vec![]);

        // "test" is excluded because it matches the excluded scope.
        // Both "a-match" and "z-match" are excluded due to having the
        // same match value as "test" (multi-pass V0)
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn should_be_able_to_disable_multipass_v0() {
        let rule_0 = RegexRuleConfig::new("b.*")
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                "test".into(),
            )])]))
            .match_action(MatchAction::Redact {
                replacement: "[scrub]".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .with_multipass_v0(false)
            .build()
            .unwrap();

        let mut content = SimpleEvent::Map(BTreeMap::from([
            (
                "a-match".to_string(),
                SimpleEvent::String("bcdef".to_string()),
            ),
            (
                "z-match".to_string(),
                SimpleEvent::String("bcdef".to_string()),
            ),
            ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
        ]));

        let matches = scanner.scan(&mut content, vec![]);

        // "test" is excluded because it matches the excluded scope.
        // Both "a-match" and "z-match" are kept since multipass V0 is disabled
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn should_not_exclude_false_positive_matches() {
        // If a match in an excluded scope is a false-positive due to keyword proximity matching,
        // it is not saved in the excluded matches.

        let rule_0 = RegexRuleConfig::new("b.*")
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["secret".to_string()],
                excluded_keywords: vec![],
            })
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                "test".into(),
            )])]))
            .match_action(MatchAction::Redact {
                replacement: "[scrub]".to_string(),
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content = SimpleEvent::Map(BTreeMap::from([
            (
                "message".to_string(),
                SimpleEvent::String("secret abcdef".to_string()),
            ),
            ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
        ]));

        let matches = scanner.scan(&mut content, vec![]);

        // The match from the "test" field (which is excluded) is the same as the match from "message", so it is
        // treated as a false positive.
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_calculate_indices_is_called_with_sorted_start_index() {
        // A custom "Event" implementation is used here to use a different encoding that asserts the indices are in order
        struct OrderAssertEvent(SimpleEvent);

        impl crate::Event for OrderAssertEvent {
            type Encoding = AssertOrderEncoding;

            fn visit_event<'a>(&'a mut self, visitor: &mut impl crate::EventVisitor<'a>) {
                self.0.visit_event(visitor)
            }

            fn visit_string_mut(&mut self, path: &Path, visit: impl FnMut(&mut String) -> bool) {
                self.0.visit_string_mut(path, visit)
            }
        }

        struct AssertOrderEncoding;

        impl Encoding for AssertOrderEncoding {
            type Index = <Utf8Encoding as Encoding>::Index;
            type IndexShift = <Utf8Encoding as Encoding>::IndexShift;

            fn zero_index() -> Self::Index {
                <Utf8Encoding as Encoding>::zero_index()
            }

            fn zero_shift() -> Self::IndexShift {
                <Utf8Encoding as Encoding>::zero_shift()
            }

            fn get_index(value: &Self::Index, utf8_index: usize) -> usize {
                <Utf8Encoding as Encoding>::get_index(value, utf8_index)
            }

            fn calculate_indices<'a>(
                _content: &str,
                match_visitor: impl Iterator<Item = crate::EncodeIndices<'a, Self>>,
            ) {
                let mut prev_start = 0;
                for indices in match_visitor {
                    assert!(
                        indices.utf8_start >= prev_start,
                        "Indices are not in order."
                    );
                    prev_start = indices.utf8_start;
                }
            }

            fn adjust_shift(shift: &mut Self::IndexShift, before: &str, after: &str) {
                <Utf8Encoding as Encoding>::adjust_shift(shift, before, after)
            }

            fn get_shift(value: &Self::IndexShift, utf8_shift: isize) -> isize {
                <Utf8Encoding as Encoding>::get_shift(value, utf8_shift)
            }
        }

        // `rule_0` has a match after `rule_1` (out of order)
        let rule_0 = RegexRuleConfig::new("efg").build();
        let rule_1 = RegexRuleConfig::new("abc").build();

        let scanner = ScannerBuilder::new(&[rule_0, rule_1])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content = OrderAssertEvent(SimpleEvent::Map(BTreeMap::from([(
            "message".to_string(),
            SimpleEvent::String("abc-efg".to_string()),
        )])));

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_hash_with_leading_zero() {
        let rule_0 = RegexRuleConfig::new(".+")
            .match_action(MatchAction::Hash)
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content =
            SimpleEvent::String("rand string that has a leading zero after hashing: y".to_string());

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);

        // normally 09d99e4b6ad0d289, but the leading 0 is removed
        assert_eq!(content, SimpleEvent::String("9d99e4b6ad0d289".to_string()));
    }

    #[test]
    fn test_hash_with_leading_zero_utf16() {
        #[allow(deprecated)]
        let rule_0 = RegexRuleConfig::new(".+")
            .match_action(MatchAction::Utf16Hash)
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content = "rand string that has a leading zero after hashing: S".to_string();

        let matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);

        // normally 08c3ad1a22e2edb1, but the leading 0 is removed
        assert_eq!(content, "8c3ad1a22e2edb1");
    }

    #[test]
    fn test_internal_overlapping_matches() {
        // A simple "credit-card rule is modified a bit to allow a multi-char character in the match
        let rule_0 = RegexRuleConfig::new("([\\d€]+){1}(,\\d+){3}")
            .match_action(MatchAction::Redact {
                replacement: "[credit card]".to_string(),
            })
            .validator(LuhnChecksum)
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        // The first 4 numbers match as a credit-card, but fail the luhn checksum.
        // The last 4 numbers (which overlap with the first match) pass the checksum.
        let mut content = "[5€184,5185,5252,5052,5005]".to_string();

        let matches = scanner.scan(&mut content, vec![]);
        // This is mostly asserting that the scanner doesn't panic when encountering multibyte characters
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_next_regex_start_after_false_positive() {
        let content = "          testtest";
        let regex_match = Match::must(0, 10..14);
        assert_eq!(get_next_regex_start(content, &regex_match), Some(11));
    }

    #[test]
    fn test_excluded_keyword_with_excluded_chars_in_content() {
        let rule_0 = RegexRuleConfig::new("value")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec![],
                excluded_keywords: vec!["test".to_string()],
            })
            .build();

        let scanner = ScannerBuilder::new(&[rule_0])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        // "test" should NOT be detected as an excluded keyword because "-" is ignored, so the word
        // boundary shouldn't match here
        let mut content = "x-test=value".to_string();

        let matches = scanner.scan(&mut content, vec![]);
        // This should match because "test" is not found, so it's not a false-positive
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_included_keyword_not_match_further_than_look_ahead_character_count() {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[redact_test_rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content = "hello [this block is exactly 37 chars long] world".to_string();
        let matches = scanner.scan(&mut content, vec![]);

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_included_keyword_multiple_matches_in_one_prefix() {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[redact_test_rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content = "hello world world".to_string();
        let matches = scanner.scan(&mut content, vec![]);

        // Both "world" matches fit within the 30 char prefix.
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_included_keyword_multiple_prefix_matches() {
        let redact_test_rule = RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["hello".to_string()],
                excluded_keywords: vec![],
            })
            .build();

        let scanner = ScannerBuilder::new(&[redact_test_rule])
            .with_keywords_should_match_event_paths(true)
            .build()
            .unwrap();

        let mut content =
            "hello world [this takes up enough space to separate the prefixes] world hello world"
                .to_string();
        let matches = scanner.scan(&mut content, vec![]);

        // Both "worlds" after a "hello" should match
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_included_keywords_on_start_boundary_with_space_including_word_boundary() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("ab")
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["id".to_string()],
                excluded_keywords: vec![],
            })
            .build()])
        .build()
        .unwrap();

        let mut content = "users id   ab".to_string();
        let matches = scanner.scan(&mut content, vec![]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start_index, 11);
        assert_eq!(matches[0].end_index_exclusive, 13);
    }

    #[test]
    fn test_included_keywords_on_end_boundary() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("abc")
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["id".to_string()],
                excluded_keywords: vec![],
            })
            .build()])
        .build()
        .unwrap();

        let mut content = "users idabc".to_string();
        let matches = scanner.scan(&mut content, vec![]);

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn should_not_look_ahead_too_far() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("x")
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 10,
                included_keywords: vec!["host".to_string()],
                excluded_keywords: vec![],
            })
            .build()])
        .build()
        .unwrap();

        let mut content = "host           x".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 0);

        let mut content = "host      x".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 1);

        let mut content = "host       x".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 0);

        let mut content = " host      x".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 1);
    }

    #[test]
    fn test_included_and_excluded_keyword() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("world")
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 11,
                included_keywords: vec!["hey".to_string()],
                excluded_keywords: vec!["hello".to_string()],
            })
            .build()])
        .build()
        .unwrap();

        // only the included keyword is present
        let mut content = "hey world".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 1);

        // only the excluded keyword is present
        let mut content = "hello world".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 0);

        // no keyword is present
        let mut content = "world".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 0);

        // included and excluded keywords are present
        let mut content = "hey, hello world".to_string();
        assert_eq!(scanner.scan(&mut content, vec![]).len(), 1);
    }

    #[test]
    fn test_should_return_match_with_match_validation() {
        use crate::match_validation::config::HttpValidatorConfig;

        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(HttpValidatorConfig::new(
                "http://localhost:8080",
            )))
            .build()])
        .build()
        .unwrap();

        let mut content = "hey world".to_string();
        let rule_match = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_match.len(), 1);
        assert_eq!(content, "hey [REDACTED]");
        assert_eq!(rule_match[0].match_value, Some("world".to_string()));
    }

    #[tokio::test]
    async fn test_should_error_if_no_match_validation() {
        let scanner = ScannerBuilder::new(&[RegexRuleConfig::new("world")
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .build()])
        .build()
        .unwrap();

        let mut content = "hey world".to_string();
        let mut rule_match = scanner.scan(&mut content, vec![]);
        assert_eq!(rule_match.len(), 1);
        assert_eq!(content, "hey [REDACTED]");
        assert_eq!(rule_match[0].match_value, None);
        // Let's call validate and check that it panics
        let err = scanner.validate_matches(&mut rule_match).await;
        assert!(err.is_err());
    }

    #[test]
    fn test_should_allocate_match_validator_depending_on_match_type() {
        use crate::match_validation::config::{AwsConfig, HttpValidatorConfig};

        let rule_aws_id = RegexRuleConfig::new("aws-id")
            .match_action(MatchAction::Redact {
                replacement: "[AWS ID]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsId))
            .build();
        let rule_aws_secret = RegexRuleConfig::new("aws-secret")
            .match_action(MatchAction::Redact {
                replacement: "[AWS SECRET]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsSecret(
                AwsConfig::default(),
            )))
            .build();

        let rule_custom_http_1_domain_1 = RegexRuleConfig::new("custom-http1")
            .match_action(MatchAction::Redact {
                replacement: "[CUSTOM HTTP1]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(HttpValidatorConfig::new(
                "http://localhost:8080",
            )))
            .build();

        let rule_custom_http_2_domain_1 = RegexRuleConfig::new("custom-http2")
            .match_action(MatchAction::Redact {
                replacement: "[CUSTOM HTTP2]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(HttpValidatorConfig::new(
                "http://localhost:8080",
            )))
            .build();

        let rule_custom_http_domain_2 = RegexRuleConfig::new("custom-http3")
            .match_action(MatchAction::Redact {
                replacement: "[CUSTOM HTTP2]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(HttpValidatorConfig::new(
                "http://localhost:8081",
            )))
            .build();

        let scanner = ScannerBuilder::new(&[
            rule_aws_id,
            rule_aws_secret,
            rule_custom_http_1_domain_1,
            rule_custom_http_2_domain_1,
            rule_custom_http_domain_2,
        ])
        .build()
        .unwrap();

        // Let's check the number of entries in the match validator map
        let match_validator_map = &scanner.match_validators_per_type;
        assert_eq!(match_validator_map.len(), 3);
        // Custom assertion to check if the validators are the same
        let aws_validator = match_validator_map
            .get(&InternalMatchValidationType::Aws)
            .unwrap();
        let http_2_validator = match_validator_map
            .get(&InternalMatchValidationType::CustomHttp(
                "http://localhost:8080".to_string(),
            ))
            .unwrap();
        let http_1_validator = match_validator_map
            .get(&InternalMatchValidationType::CustomHttp(
                "http://localhost:8081".to_string(),
            ))
            .unwrap();
        assert!(!std::ptr::eq(
            http_1_validator.as_ref(),
            http_2_validator.as_ref()
        ));
        assert!(!std::ptr::eq(
            aws_validator.as_ref(),
            http_2_validator.as_ref()
        ));
        assert!(!std::ptr::eq(
            aws_validator.as_ref(),
            http_1_validator.as_ref()
        ));
    }

    #[tokio::test]
    async fn test_aws_id_only_shall_not_validate() {
        let rule_aws_id = RegexRuleConfig::new("aws_id")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_ID]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsId))
            .build();

        let scanner = ScannerBuilder::new(&[rule_aws_id]).build().unwrap();
        let mut content = "this is an aws_id".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "this is an [AWS_ID]");
        assert!(scanner.validate_matches(&mut matches).await.is_err());
        assert_eq!(matches[0].match_status, MatchStatus::NotChecked);
    }

    #[tokio::test]
    async fn test_mock_same_http_validator_several_matches() {
        let server = MockServer::start();

        // Create a mock on the server.
        let mock_service_valid = server.mock(|when, then| {
            when.method(GET)
                .path("/")
                .header("authorization", "Bearer valid_match");
            then.status(200);
        });
        let mock_service_invalid = server.mock(|when, then| {
            when.method(GET)
                .path("/")
                .header("authorization", "Bearer invalid_match");
            then.status(404).header("content-type", "text/html");
        });
        let mock_service_error = server.mock(|when, then| {
            when.method(GET)
                .path("/")
                .header("authorization", "Bearer error_match");
            then.status(500).header("content-type", "text/html");
        });

        let rule_valid_match = RegexRuleConfig::new("\\bvalid_match\\b")
            .match_action(MatchAction::Redact {
                replacement: "[VALID]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorConfigBuilder::new(server.url("/").to_string()).build(),
            ))
            .build();

        let rule_invalid_match = RegexRuleConfig::new("\\binvalid_match\\b")
            .match_action(MatchAction::Redact {
                replacement: "[INVALID]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorConfigBuilder::new(server.url("/").to_string()).build(),
            ))
            .build();

        let rule_error_match = RegexRuleConfig::new("\\berror_match\\b")
            .match_action(MatchAction::Redact {
                replacement: "[ERROR]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorConfigBuilder::new(server.url("/").to_string()).build(),
            ))
            .build();
        let scanner =
            ScannerBuilder::new(&[rule_valid_match, rule_invalid_match, rule_error_match])
                .build()
                .unwrap();

        let mut content =
            "this is a content with a valid_match an invalid_match and an error_match".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 3);
        assert_eq!(
            content,
            "this is a content with a [VALID] an [INVALID] and an [ERROR]"
        );
        assert!(scanner.validate_matches(&mut matches).await.is_ok());
        mock_service_valid.assert();
        mock_service_invalid.assert();
        mock_service_error.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
        assert_eq!(matches[1].match_status, MatchStatus::Invalid);
        assert_eq!(
            matches[2].match_status,
            MatchStatus::Error("Unexpected HTTP status code 500".to_string())
        );
    }

    #[tokio::test]
    async fn test_mock_http_timeout() {
        let server = MockServer::start();
        let _ = server.mock(|when, then| {
            when.method(GET)
                .path("/")
                .header("authorization", "Bearer valid_match");
            then.status(200);
        });
        let rule_valid_match = RegexRuleConfig::new("\\bvalid_match\\b")
            .match_action(MatchAction::Redact {
                replacement: "[VALID]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorConfigBuilder::new(server.url("/").to_string())
                    .set_timeout(Duration::from_micros(0))
                    .build(),
            ))
            .build();

        let scanner = ScannerBuilder::new(&[rule_valid_match]).build().unwrap();

        let mut content = "this is a content with a valid_match".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 1);
        assert_eq!(content, "this is a content with a [VALID]");
        assert!(scanner.validate_matches(&mut matches).await.is_ok());
        // This will be in the form "Error making HTTP request: "
        match &matches[0].match_status {
            MatchStatus::Error(val) => {
                assert!(val.starts_with("Error making HTTP request:"));
            }
            _ => assert!(false),
        }
    }
    #[tokio::test]
    async fn test_mock_multiple_match_validators() {
        let server = MockServer::start();

        // Create a mock on the server.
        let mock_http_service_valid = server.mock(|when, then| {
            when.method(GET).path("/http-service");
            then.status(200);
        });
        let mock_aws_service_valid = server.mock(|when, then| {
            when.method(POST).path("/aws-service");
            then.status(200);
        });

        let rule_valid_match = RegexRuleConfig::new("\\bvalid_match\\b")
            .match_action(MatchAction::Redact {
                replacement: "[VALID]".to_string(),
            })
            .match_validation_type(MatchValidationType::CustomHttp(
                HttpValidatorConfigBuilder::new(server.url("/http-service").to_string()).build(),
            ))
            .build();

        let rule_aws_id = RegexRuleConfig::new("\\baws_id\\b")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_ID]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsId))
            .build();

        let rule_aws_secret = RegexRuleConfig::new("\\baws_secret\\b")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_SECRET]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsSecret(AwsConfig {
                aws_sts_endpoint: server.url("/aws-service").to_string(),
                forced_datetime_utc: None,
                timeout: Duration::from_secs(1),
            })))
            .build();

        let scanner = ScannerBuilder::new(&[rule_valid_match, rule_aws_id, rule_aws_secret])
            .build()
            .unwrap();

        let mut content =
            "this is a content with a valid_match an aws_id and an aws_secret".to_string();
        let mut matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 3);
        assert_eq!(
            content,
            "this is a content with a [VALID] an [AWS_ID] and an [AWS_SECRET]"
        );
        assert!(scanner.validate_matches(&mut matches).await.is_ok());
        mock_http_service_valid.assert();
        mock_aws_service_valid.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
        assert_eq!(matches[1].match_status, MatchStatus::Valid);
        assert_eq!(matches[2].match_status, MatchStatus::Valid);
    }
    #[tokio::test]
    async fn test_mock_aws_validator() {
        let server = MockServer::start();
        let server_url = server.url("/").to_string();

        // Compute signature for valid match
        let datetime = chrono::Utc::now();

        let aws_id_valid = "AKIAYYB64AB3GAW3WH79";
        let aws_id_invalid = "AKIAYYB64AB3GAW3WH70";
        let aws_id_error = "AKIAYYB64AB3GAW3WH71";
        let aws_secret_1 = "uYd/WrqSWR6m7rkYsjqGnD3QsmO7hQjDFXPQHMVy";
        let aws_secret_2 = "uYd/WrqSWR6m7rkYsjqGnD3QsmO7hQjDFXPZHMVy";

        let (_, headers_valid) = generate_aws_headers_and_body(
            &datetime,
            server_url.as_str(),
            &aws_id_valid,
            &aws_secret_1,
        );
        let valid_authorization = headers_valid.get("authorization").unwrap();
        let (_, headers_invalid) = generate_aws_headers_and_body(
            &datetime,
            server_url.as_str(),
            &aws_id_invalid,
            &aws_secret_1,
        );
        let invalid_authorization_1 = headers_invalid.get("authorization").unwrap();
        let (_, headers_invalid) = generate_aws_headers_and_body(
            &datetime,
            server_url.as_str(),
            &aws_id_valid,
            &aws_secret_2,
        );
        let invalid_authorization_2 = headers_invalid.get("authorization").unwrap();
        let (_, headers_error) = generate_aws_headers_and_body(
            &datetime,
            server_url.as_str(),
            &aws_id_error,
            &aws_secret_1,
        );
        let error_authorization_1 = headers_error.get("authorization").unwrap();
        let (_, headers_error) = generate_aws_headers_and_body(
            &datetime,
            server_url.as_str(),
            &aws_id_error,
            &aws_secret_2,
        );
        let error_authorization_2 = headers_error.get("authorization").unwrap();
        // Create a mock on the server.
        let mock_service_valid = server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .header("authorization", valid_authorization.to_str().unwrap());
            then.status(200);
        });
        let mock_service_invalid_1 = server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .header("authorization", invalid_authorization_1.to_str().unwrap());
            then.status(403);
        });
        let mock_service_invalid_2 = server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .header("authorization", invalid_authorization_2.to_str().unwrap());
            then.status(403);
        });
        let mock_service_error_1 = server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .header("authorization", error_authorization_1.to_str().unwrap());
            then.status(500);
        });
        let mock_service_error_2 = server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .header("authorization", error_authorization_2.to_str().unwrap());
            then.status(500);
        });
        let rule_aws_id = RegexRuleConfig::new("AKIA[0-9A-Z]{16}")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_ID]".to_string(),
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsId))
            .build();

        let rule_aws_secret = RegexRuleConfig::new("[A-Za-z0-9/+]{40}")
            .match_action(MatchAction::Redact {
                replacement: "[AWS_SECRET]".to_string(),
            })
            .proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["aws_secret".to_string()],
                excluded_keywords: vec![],
            })
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsSecret(AwsConfig {
                aws_sts_endpoint: server_url.clone(),
                forced_datetime_utc: Some(datetime),
                timeout: Duration::from_secs(5),
            })))
            .build();

        let scanner = ScannerBuilder::new(&[rule_aws_id, rule_aws_secret])
            .build()
            .unwrap();

        let mut content = fmt::format(format_args!(
                                "content with a valid aws_id {}, an invalid aws_id {}, an error aws_id {} and an aws_secret {} and an other aws_secret {}", aws_id_valid, aws_id_invalid, aws_id_error, aws_secret_1, aws_secret_2));
        let mut matches = scanner.scan(&mut content, vec![]);
        assert_eq!(matches.len(), 5);
        assert_eq!(
            content,
            "content with a valid aws_id [AWS_ID], an invalid aws_id [AWS_ID], an error aws_id [AWS_ID] and an aws_secret [AWS_SECRET] and an other aws_secret [AWS_SECRET]"
        );
        assert!(scanner.validate_matches(&mut matches).await.is_ok());
        mock_service_valid.assert();
        mock_service_invalid_1.assert();
        mock_service_invalid_2.assert();
        mock_service_error_1.assert();
        mock_service_error_2.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
        assert_eq!(matches[1].match_status, MatchStatus::Invalid);
        assert_eq!(
            matches[2].match_status,
            MatchStatus::Error("Unexpected HTTP status code 500".to_string())
        );
        assert_eq!(matches[3].match_status, MatchStatus::Valid);
        // ID1 + SECRET2 should be in error so it should contain error and not invalid
        assert_eq!(
            matches[4].match_status,
            MatchStatus::Error("Unexpected HTTP status code 500".to_string())
        );
    }

    mod metrics_test {
        use crate::match_action::MatchAction;
        use crate::scanner::regex_rule::config::{ProximityKeywordsConfig, RegexRuleConfig};
        use crate::scanner::scope::Scope;
        use crate::scanner::ScannerBuilder;
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
                let rule_0 = RegexRuleConfig::new(content_1)
                    .match_action(MatchAction::None)
                    .build();

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

                scanner.scan(&mut content, vec![]);
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
                let rule_0 = RegexRuleConfig::new("bcdef")
                    .scope(Scope::exclude(vec![Path::from(vec![PathSegment::Field(
                        "test".into(),
                    )])]))
                    .match_action(MatchAction::None)
                    .build();

                let scanner = ScannerBuilder::new(&[rule_0])
                    .with_keywords_should_match_event_paths(true)
                    .build()
                    .unwrap();
                let mut content = SimpleEvent::Map(BTreeMap::from([
                    // z-match is considered as a false positive here
                    (
                        "z-match".to_string(),
                        SimpleEvent::String("bcdef".to_string()),
                    ),
                    ("test".to_string(), SimpleEvent::String("bcdef".to_string())),
                ]));

                scanner.scan(&mut content, vec![]);
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
                let redact_test_rule = RegexRuleConfig::new("world")
                    .match_action(MatchAction::Redact {
                        replacement: "[REDACTED]".to_string(),
                    })
                    .proximity_keywords(ProximityKeywordsConfig {
                        look_ahead_character_count: 30,
                        included_keywords: vec![],
                        excluded_keywords: vec!["hello".to_string()],
                    })
                    .build();

                let scanner = ScannerBuilder::new(&[redact_test_rule])
                    .with_keywords_should_match_event_paths(true)
                    .build()
                    .unwrap();
                let mut content = SimpleEvent::Map(BTreeMap::from([(
                    "test".to_string(),
                    SimpleEvent::String("hello world".to_string()),
                )]));
                scanner.scan(&mut content, vec![]);
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
    }
}
