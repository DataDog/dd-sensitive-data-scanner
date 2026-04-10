use crate::normalization::rust_regex_adapter::convert_to_rust_regex;
use crate::scanner::RootCompiledRule;
use crate::scanner::config::RuleConfig;
use crate::scanner::shared_pool::{AutoStacksSizeGuard, SharedPool};
use regex_automata::meta::{self, Cache, Regex as MetaRegex};
use regex_automata::{Input, MatchKind, PatternID, PatternSet};
use std::sync::Arc;

/// Default NFA size limit for the merged DFA (10x the individual rule limit of 1,000,000)
pub const DEFAULT_MERGED_NFA_SIZE_LIMIT: usize = 10_000_000;

pub struct MergedDfaCache {
    cache: Cache,
    patset: PatternSet,
}

pub struct MergedDfa {
    regex: MetaRegex,
    rule_to_pattern: Vec<Option<usize>>,
    cache_pool: SharedPool<Box<MergedDfaCache>>,
}

impl MergedDfa {
    pub fn new(
        compiled_rules: &[RootCompiledRule],
        rule_configs: &[crate::scanner::RootRuleConfig<Arc<dyn RuleConfig>>],
        nfa_size_limit: usize,
    ) -> Option<Self> {
        let mut mergeable: Vec<(usize, String)> = Vec::new();

        for (i, (compiled, config)) in compiled_rules.iter().zip(rule_configs.iter()).enumerate() {
            let regex_config = match config.inner.as_regex_rule() {
                Some(rc) => rc,
                None => continue,
            };

            let compiled_regex = match compiled.as_regex_rule() {
                Some(cr) => cr,
                None => continue,
            };

            if compiled_regex.included_keywords.is_some() {
                continue;
            }
            if compiled_regex.pattern_capture_groups.is_some() {
                continue;
            }

            match convert_to_rust_regex(&regex_config.pattern) {
                Ok(normalized) => mergeable.push((i, normalized)),
                Err(_) => continue,
            }
        }

        if mergeable.is_empty() {
            return None;
        }

        let mut pattern_to_rule = Vec::with_capacity(mergeable.len());
        let mut patterns = Vec::with_capacity(mergeable.len());
        for (rule_idx, pattern) in &mergeable {
            pattern_to_rule.push(*rule_idx);
            patterns.push(pattern.clone());
        }

        // MatchKind::All is required so that which_overlapping_matches reports
        // every pattern that matches anywhere in the haystack, not just the
        // leftmost-first winner.
        let regex = meta::Builder::new()
            .configure(
                meta::Config::new()
                    .match_kind(MatchKind::All)
                    .nfa_size_limit(Some(nfa_size_limit))
                    .hybrid_cache_capacity(2 * (1 << 20)),
            )
            .syntax(
                regex_automata::util::syntax::Config::default()
                    .dot_matches_new_line(false)
                    .unicode(true),
            )
            .build_many(&patterns)
            .ok()?;

        let mut rule_to_pattern = vec![None; compiled_rules.len()];
        for (pattern_idx, &rule_idx) in pattern_to_rule.iter().enumerate() {
            rule_to_pattern[rule_idx] = Some(pattern_idx);
        }

        let regex_clone = regex.clone();
        let pattern_len = regex.pattern_len();
        let cache_pool = SharedPool::new(
            Box::new(move || {
                Box::new(MergedDfaCache {
                    cache: regex_clone.create_cache(),
                    patset: PatternSet::new(pattern_len),
                })
            }),
            num_cpus::get(),
        );

        Some(Self {
            regex,
            rule_to_pattern,
            cache_pool,
        })
    }

    /// Returns the pattern index for a given rule index, or None if the rule is not merged.
    pub fn rule_to_pattern(&self, rule_index: usize) -> Option<usize> {
        self.rule_to_pattern.get(rule_index).copied().flatten()
    }

    /// Runs the merged regex against content and returns a pool guard containing the PatternSet.
    /// The caller should use `pattern_matched` to check individual patterns.
    pub fn get_matching_rules(
        &self,
        content: &str,
    ) -> Box<dyn AutoStacksSizeGuard<Box<MergedDfaCache>> + '_> {
        let mut guard = self.cache_pool.get();
        {
            let cache = guard.get_ref();
            cache.patset.clear();
            let input = Input::new(content);
            self.regex
                .which_overlapping_matches_with(&mut cache.cache, &input, &mut cache.patset);
        }
        guard
    }

    /// Check if a specific pattern (by index) matched in the given cache.
    pub fn pattern_matched(cache: &MergedDfaCache, pattern_id: usize) -> bool {
        cache.patset.contains(PatternID::new_unchecked(pattern_id))
    }
}
