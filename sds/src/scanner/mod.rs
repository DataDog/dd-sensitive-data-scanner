use crate::encoding::Encoding;
use crate::event::Event;

use crate::match_validation::{
    config::InternalMatchValidationType, config::MatchValidationType, match_status::MatchStatus,
    match_validator::MatchValidator,
};
use rayon::prelude::*;

use error::{MatchValidationError, MatchValidatorCreationError};

use crate::observability::labels::Labels;
use crate::rule_match::{InternalRuleMatch, RuleMatch};
use crate::scoped_ruleset::{ContentVisitor, ExclusionCheck, ScopedRuleSet};
pub use crate::secondary_validation::Validator;
use crate::{CreateScannerError, EncodeIndices, MatchAction, Path};
use std::any::{Any, TypeId};
use std::ops::Deref;
use std::sync::Arc;

use self::metrics::ScannerMetrics;
use crate::proximity_keywords::CompiledIncludedProximityKeywords;
use crate::scanner::config::RuleConfig;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::regex_rule::{access_regex_caches, RegexCaches};
use crate::scanner::scope::Scope;
use crate::stats::GLOBAL_STATS;
use ahash::{AHashMap, AHashSet};
use regex_automata::Match;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub mod config;
pub mod error;
pub mod metrics;
pub mod regex_rule;
pub mod scope;
pub mod shared_pool;

#[cfg(test)]
mod test;

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
    pub match_validation_type: Option<MatchValidationType>,
    pub inner: T,
}

impl<T> RootRuleConfig<T> {
    pub fn new(inner: T) -> Self {
        Self {
            match_action: MatchAction::None,
            scope: Scope::all(),
            match_validation_type: None,
            inner,
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

    pub fn match_validation_type(mut self, match_validation_type: MatchValidationType) -> Self {
        self.match_validation_type = Some(match_validation_type);
        self
    }
}

impl<T> Deref for RootRuleConfig<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
pub struct RootCompiledRule {
    pub inner: Box<dyn CompiledRuleDyn>,
    pub scope: Scope,
    pub match_action: MatchAction,
    pub match_validation_type: Option<MatchValidationType>,
}

impl RootCompiledRule {
    pub fn internal_match_validation_type(&self) -> Option<InternalMatchValidationType> {
        self.match_validation_type
            .as_ref()
            .map(|x| x.get_internal_match_validation_type())
    }
}

impl Deref for RootCompiledRule {
    type Target = dyn CompiledRuleDyn;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

// CompiledRuleDyn is a private trait that is used to hide the complexity of downcasting the group data
// into the correct type.
// This is used to allow the group data to be stored in a map only if the group of rule has a groupData associated with it (unlike regex rules)
pub trait CompiledRuleDyn: Send + Sync {
    fn create_group_data(&self, labels: &Labels) -> Option<Box<dyn Any>>;
    fn create_group_config(&self) -> Option<Box<dyn Any>>;
    fn create_rule_scan_cache(&self) -> Option<Box<dyn Any>>;

    // TODO: remove this?
    fn get_included_keywords(&self) -> Option<&CompiledIncludedProximityKeywords> {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        regex_caches: &mut RegexCaches,
        group_data: &mut AHashMap<TypeId, Box<dyn Any>>,
        group_config: &AHashMap<TypeId, Box<dyn Any + Send + Sync>>,
        rule_scan_cache: &mut AHashMap<TypeId, Box<dyn Any>>,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        scanner_labels: &Labels,
        wildcard_indices: Option<&Vec<(usize, usize)>>,
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

    // fn get_match_validation_type(&self) -> Option<&MatchValidationType>;

    // fn get_internal_match_validation_type(&self) -> Option<&InternalMatchValidationType>;

    fn process_scanner_config(
        &self,
        group_config: &mut AHashMap<TypeId, Box<dyn Any + Send + Sync>>,
    );
}

// This is the "hidden" implementation of CompiledRuleDyn for any type that implements CompiledRule
// get_string_matches will downcast the group data to the correct type and call the actual implementation
// done in the CompiledRule trait
impl<T: CompiledRule> CompiledRuleDyn for T {
    fn create_group_data(&self, labels: &Labels) -> Option<Box<dyn Any>> {
        let group_data = self.create_group_data(labels);
        if TypeId::of::<<T as CompiledRule>::GroupData>() == TypeId::of::<()>() {
            None
        } else {
            Some(Box::new(group_data))
        }
    }

    fn create_group_config(&self) -> Option<Box<dyn Any>> {
        let group_config = self.create_group_config();
        if TypeId::of::<<T as CompiledRule>::GroupConfig>() == TypeId::of::<()>() {
            None
        } else {
            Some(Box::new(group_config))
        }
    }

    fn create_rule_scan_cache(&self) -> Option<Box<dyn Any>> {
        let rule_scan_cache = self.create_rule_scan_cache();
        if TypeId::of::<<T as CompiledRule>::RuleScanCache>() == TypeId::of::<()>() {
            None
        } else {
            Some(Box::new(rule_scan_cache))
        }
    }

    fn get_included_keywords(&self) -> Option<&CompiledIncludedProximityKeywords> {
        self.get_included_keywords()
    }

    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        regex_caches: &mut RegexCaches,
        group_data: &mut AHashMap<TypeId, Box<dyn Any>>,
        group_config: &AHashMap<TypeId, Box<dyn Any + Send + Sync>>,
        rule_scan_cache: &mut AHashMap<TypeId, Box<dyn Any>>,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        scanner_labels: &Labels,
        wildcard_indices: Option<&Vec<(usize, usize)>>,
    ) {
        let group_data_any = group_data
            .entry(TypeId::of::<T::GroupData>())
            .or_insert_with(|| Box::new(self.create_group_data(scanner_labels)));
        let group_data: &mut T::GroupData = group_data_any.downcast_mut().unwrap();

        let group_config_any = group_config.get(&TypeId::of::<T::GroupConfig>()).unwrap();
        let group_config: &T::GroupConfig = group_config_any.downcast_ref().unwrap();

        let rule_scan_cache_any = rule_scan_cache
            .entry(TypeId::of::<T::RuleScanCache>())
            .or_insert_with(|| Box::new(self.create_rule_scan_cache()));
        let rule_scan_cache: &mut T::RuleScanCache = rule_scan_cache_any.downcast_mut().unwrap();

        self.get_string_matches(
            content,
            path,
            regex_caches,
            group_data,
            group_config,
            rule_scan_cache,
            exclusion_check,
            excluded_matches,
            match_emitter,
            wildcard_indices,
        )
    }

    fn should_exclude_multipass_v0(&self) -> bool {
        T::should_exclude_multipass_v0(self)
    }

    fn on_excluded_match_multipass_v0(&self) {
        T::on_excluded_match_multipass_v0(self)
    }

    // method used to provide each rule the list of rules enabled for a scanner
    // this is used to allow rules that have group data to enabled/disable some features in this group
    fn process_scanner_config(
        &self,
        group_config: &mut AHashMap<TypeId, Box<dyn Any + Send + Sync>>,
    ) {
        let group_config_any = group_config
            .entry(TypeId::of::<T::GroupConfig>())
            .or_insert_with(|| Box::new(self.create_group_config()));
        let group_config: &mut T::GroupConfig = group_config_any.downcast_mut().unwrap();
        T::process_scanner_config(self, group_config);
    }
}

// This is the public trait that is used to define the behavior of a compiled rule.
pub trait CompiledRule: Send + Sync {
    /// Data that is instantiated once per string being scanned, and shared with all rules that
    /// have the same `GroupData` type. `Default` will be used to initialize this data.
    type GroupData: 'static;
    /// Data that is instantiated once per scanner, and shared with all rules that
    /// have the same `GroupData` type. `Default` will be used to initialize this data
    type GroupConfig: 'static + Send + Sync;

    // Each rule can have a cache that is shared during the whole scan of an even
    type RuleScanCache: 'static;

    /// Create a new instance of GroupData with the given scanner.
    fn create_group_data(&self, labels: &Labels) -> Self::GroupData;

    /// Create a new instance of GroupData with the given scanner.
    fn create_group_config(&self) -> Self::GroupConfig;

    /// Create a new instance of RuleScanCache
    fn create_rule_scan_cache(&self) -> Self::RuleScanCache;

    fn get_included_keywords(&self) -> Option<&CompiledIncludedProximityKeywords> {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        regex_caches: &mut RegexCaches,
        group_data: &mut Self::GroupData,
        group_config: &Self::GroupConfig,
        rule_scan_cache: &mut Self::RuleScanCache,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        wildcard_indices: Option<&Vec<(usize, usize)>>,
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

    // method used to provide each rule the list of rules enabled for a scanner
    // this is used to allow rules that have group data to enabled/disable some features in this group
    fn process_scanner_config(&self, group_config: &mut Self::GroupConfig);
}

impl<T> RuleConfig for Box<T>
where
    T: RuleConfig + ?Sized,
{
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        labels: Labels,
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError> {
        self.as_ref().convert_to_compiled_rule(rule_index, labels)
    }
}

#[derive(Debug, PartialEq, Clone)]
struct ScannerFeatures {
    pub add_implicit_index_wildcards: bool,
    pub multipass_v0_enabled: bool,
    pub return_matches: bool,
}

impl Default for ScannerFeatures {
    fn default() -> Self {
        Self {
            add_implicit_index_wildcards: false,
            multipass_v0_enabled: true,
            return_matches: false,
        }
    }
}

pub struct ScanOptions {
    // The blocked_rules_idx parameter is a list of rule indices that should be skipped for this scan.
    // this list shall be small (<10), so a linear search is acceptable otherwise performance will be impacted.
    pub blocked_rules_idx: Vec<usize>,
    // The wildcarded_indices parameter is a map containing a list of tuples of (start, end) indices that should be treated as wildcards (for the message key only) per path.
    pub wildcarded_indices: AHashMap<Path<'static>, Vec<(usize, usize)>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            blocked_rules_idx: vec![],
            wildcarded_indices: AHashMap::new(),
        }
    }
}

pub struct ScanOptionBuilder {
    blocked_rules_idx: Vec<usize>,
    wildcarded_indices: AHashMap<Path<'static>, Vec<(usize, usize)>>,
}

impl ScanOptionBuilder {
    pub fn new() -> Self {
        Self {
            blocked_rules_idx: vec![],
            wildcarded_indices: AHashMap::new(),
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

    pub fn build(self) -> ScanOptions {
        ScanOptions {
            blocked_rules_idx: self.blocked_rules_idx,
            wildcarded_indices: self.wildcarded_indices,
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
    group_configs: AHashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Scanner {
    pub fn builder(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>]) -> ScannerBuilder {
        ScannerBuilder::new(rules)
    }

    pub fn scan_with_options<E: Event>(
        &self,
        event: &mut E,
        options: ScanOptions,
    ) -> Vec<RuleMatch> {
        // All matches, after some (but not all) false-positives have been removed.
        // This is a vec of vecs, where each inner vec is a set of matches for a single path.
        let mut rule_matches_list = vec![];

        let mut excluded_matches = AHashSet::new();

        // Measure detection time
        let start = std::time::Instant::now();
        access_regex_caches(|regex_caches| {
            self.scoped_ruleset.visit_string_rule_combinations(
                event,
                ScannerContentVisitor {
                    scanner: self,
                    regex_caches,
                    rule_matches: &mut rule_matches_list,
                    blocked_rules: &options.blocked_rules_idx,
                    excluded_matches: &mut excluded_matches,
                    rule_scan_caches: AHashMap::new(),
                    wildcarded_indexes: &options.wildcarded_indices,
                },
            );
        });

        let mut output_rule_matches = vec![];

        for (path, rule_matches) in &mut rule_matches_list {
            // All rule matches in each inner list are for a single path, so they can be processed independently.
            event.visit_string_mut(path, |content| {
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

                self.sort_and_remove_overlapping_rules::<E::Encoding>(rule_matches);

                let will_mutate = rule_matches
                    .iter()
                    .any(|rule_match| self.rules[rule_match.rule_index].match_action.is_mutating());

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

    // This function scans the given event with the rules configured in the scanner.
    // The event parameter is a mutable reference to the event that should be scanned (implemented the Event trait).
    // The return value is a list of RuleMatch objects, which contain information about the matches that were found.
    pub fn scan<E: Event>(&self, event: &mut E) -> Vec<RuleMatch> {
        self.scan_with_options(event, ScanOptions::default())
    }

    pub fn validate_matches(
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
            if let Some(match_validation_type) = rule.internal_match_validation_type() {
                match_validator_rule_match_per_type
                    .entry(match_validation_type)
                    .or_insert_with(|| vec![])
                    .push(rule_match)
            }
        }

        // Call the validate per match_validator_type with their matches and the RuleMatch list and collect the results
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
    rules: &'a [RootRuleConfig<Arc<dyn RuleConfig>>],
    labels: Labels,
    scanner_features: ScannerFeatures,
}

impl ScannerBuilder<'_> {
    pub fn new(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>]) -> ScannerBuilder {
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

    pub fn build(self) -> Result<Scanner, CreateScannerError> {
        let mut scanner_features = self.scanner_features.clone();
        let mut match_validators_per_type = AHashMap::new();

        for rule in self.rules.iter() {
            if let Some(match_validation_type) = &rule.match_validation_type {
                if match_validation_type.can_create_match_validator() {
                    let internal_type = match_validation_type.get_internal_match_validation_type();
                    let match_validator = match_validation_type.into_match_validator();
                    if let Ok(match_validator) = match_validator {
                        if !match_validators_per_type.contains_key(&internal_type) {
                            match_validators_per_type.insert(internal_type, match_validator);
                            // Let's add return_matches to the scanner features
                            scanner_features.return_matches = true;
                        }
                    } else {
                        return Err(CreateScannerError::InvalidMatchValidator(
                            MatchValidatorCreationError::InternalError,
                        ));
                    }
                }
            }
        }

        let compiled_rules = self
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, config)| {
                let inner = config.convert_to_compiled_rule(rule_index, self.labels.clone())?;
                config.match_action.validate()?;
                Ok(RootCompiledRule {
                    inner,
                    scope: config.scope.clone(),
                    match_action: config.match_action.clone(),
                    match_validation_type: config.match_validation_type.clone(),
                })
            })
            .collect::<Result<Vec<RootCompiledRule>, CreateScannerError>>()?;

        let mut group_configs: AHashMap<TypeId, Box<dyn Any + Send + Sync>> = AHashMap::new();
        compiled_rules.iter().for_each(|rule| {
            rule.process_scanner_config(&mut group_configs);
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
            scanner_features,
            metrics: ScannerMetrics::new(&self.labels),
            match_validators_per_type,
            labels: self.labels,
            group_configs,
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
    rule_scan_caches: AHashMap<TypeId, Box<dyn Any>>,
    wildcarded_indexes: &'a AHashMap<Path<'static>, Vec<(usize, usize)>>,
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
        let wildcard_indices_per_path = self.wildcarded_indexes.get(path);

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
                    self.regex_caches,
                    &mut group_data,
                    &self.scanner.group_configs,
                    &mut self.rule_scan_caches,
                    &exclusion_check,
                    self.excluded_matches,
                    &mut emitter,
                    &self.scanner.labels,
                    wildcard_indices_per_path,
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
