use super::Validator;
use crate::proximity_keywords::{
    contains_keyword_in_path, get_prefix_start, is_index_within_prefix,
    CompiledExcludedProximityKeywords, CompiledIncludedProximityKeywords,
};
use crate::scanner::metrics::Metrics;
use crate::scanner::{get_next_regex_start, is_false_positive_match};
use crate::{
    CachePoolGuard, CompiledRuleTrait, ExclusionCheck, MatchAction, MatchEmitter, Path, Scope,
    StringMatch,
};
use ahash::AHashSet;
use regex_automata::meta::Cache;
use regex_automata::meta::Regex as MetaRegex;
use regex_automata::Input;
use std::sync::Arc;

/// This is the internal representation of a rule after it has been validated / compiled.
pub struct RegexCompiledRule {
    pub rule_index: usize,
    pub regex: MetaRegex,
    pub match_action: MatchAction,
    pub scope: Scope,
    pub included_keywords: Option<CompiledIncludedProximityKeywords>,
    pub excluded_keywords: Option<CompiledExcludedProximityKeywords>,
    pub validator: Option<Arc<dyn Validator>>,
    pub rule_cache_index: usize,
    pub metrics: Metrics,
}

impl CompiledRuleTrait for RegexCompiledRule {
    fn get_match_action(&self) -> &MatchAction {
        &self.match_action
    }
    fn get_scope(&self) -> &Scope {
        &self.scope
    }
    fn get_string_matches(
        &self,
        content: &str,
        path: &Path,
        caches: &mut CachePoolGuard<'_>,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        should_keywords_match_event_paths: bool,
    ) {
        match self.included_keywords {
            Some(ref included_keywords) => {
                self.get_string_matches_with_included_keywords(
                    content,
                    path,
                    caches,
                    exclusion_check,
                    excluded_matches,
                    match_emitter,
                    should_keywords_match_event_paths,
                    included_keywords,
                );
            }
            None => {
                let true_positive_search = self.true_positive_matches(
                    content,
                    0,
                    &mut caches[self.rule_cache_index],
                    true,
                    exclusion_check,
                    excluded_matches,
                );
                for string_match in true_positive_search {
                    match_emitter.emit(string_match);
                }
            }
        }
    }
}

impl RegexCompiledRule {
    fn get_string_matches_with_included_keywords(
        &self,
        content: &str,
        path: &Path,
        caches: &mut CachePoolGuard<'_>,
        exclusion_check: &ExclusionCheck<'_>,
        excluded_matches: &mut AHashSet<String>,
        match_emitter: &mut dyn MatchEmitter,
        should_keywords_match_event_paths: bool,
        included_keywords: &CompiledIncludedProximityKeywords,
    ) {
        let cache = &mut caches[self.rule_cache_index];

        if should_keywords_match_event_paths {
            let sanitized_path = path.sanitize();
            if contains_keyword_in_path(&sanitized_path, &included_keywords.keywords_pattern) {
                // since the path contains a match, we can skip future included keyword checks
                let true_positive_search = self.true_positive_matches(
                    content,
                    0,
                    &mut caches[self.rule_cache_index],
                    false,
                    exclusion_check,
                    excluded_matches,
                );
                for string_match in true_positive_search {
                    match_emitter.emit(string_match);
                }
                return;
            }
        }

        let mut included_keyword_matches = included_keywords.keyword_matches(content);

        'included_keyword_search: while let Some(included_keyword_match_start) =
            included_keyword_matches.next()
        {
            let true_positive_search = self.true_positive_matches(
                content,
                included_keyword_match_start,
                cache,
                false,
                exclusion_check,
                excluded_matches,
            );

            for true_positive_match in true_positive_search {
                if is_index_within_prefix(
                    content,
                    included_keyword_match_start,
                    true_positive_match.start,
                    included_keywords.look_ahead_character_count,
                ) {
                    // The match start might be further than the current start, so some chars
                    // can be skipped before the next included keyword scanning. The start
                    // is used instead of the end since the included keyword can overlap with
                    // a previous match (maybe this can be removed in the future?)
                    included_keyword_matches.skip_to(true_positive_match.start);
                    match_emitter.emit(true_positive_match);

                    // Continue search since another true positive could potentially be found within the same prefix
                } else {
                    // This match is ignored since it is not within the prefix, but
                    // the start of the match may be far ahead of the current start, so
                    // use it to reduce future scanning
                    let new_start = get_prefix_start(
                        true_positive_match.start,
                        included_keywords.look_ahead_character_count,
                        content,
                    )
                    .start;
                    included_keyword_matches.skip_to(new_start);
                    // Switch back to included keyword search, since we are past the prefix
                    continue 'included_keyword_search;
                }
            }
            // no more "true positive" matches were found in the entire string, so there's no need
            // to continue scanning for included keywords.
            break;
        }
    }

    fn true_positive_matches<'a>(
        &'a self,
        content: &'a str,
        start: usize,
        cache: &'a mut Cache,
        check_excluded_keywords: bool,
        exclusion_check: &'a ExclusionCheck<'a>,
        excluded_matches: &'a mut AHashSet<String>,
    ) -> TruePositiveSearch<'a> {
        TruePositiveSearch {
            rule: self,
            content,
            start,
            cache,
            check_excluded_keywords,
            exclusion_check,
            excluded_matches,
        }
    }
}

pub struct TruePositiveSearch<'a> {
    rule: &'a RegexCompiledRule,
    content: &'a str,
    start: usize,
    cache: &'a mut Cache,
    check_excluded_keywords: bool,
    exclusion_check: &'a ExclusionCheck<'a>,
    excluded_matches: &'a mut AHashSet<String>,
}

impl<'a> Iterator for TruePositiveSearch<'a> {
    type Item = StringMatch;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let input = Input::new(self.content).range(self.start..);

            if let Some(regex_match) = self.rule.regex.search_with(self.cache, &input) {
                // this is only checking extra validators (e.g. checksums)
                let is_false_positive_match = is_false_positive_match(
                    &regex_match,
                    self.rule,
                    self.content,
                    self.check_excluded_keywords,
                );

                if is_false_positive_match {
                    if let Some(next) = get_next_regex_start(self.content, &regex_match) {
                        self.start = next;
                    } else {
                        // There are no more chars to scan
                        return None;
                    }
                } else {
                    // The next match will start at the end of this match. This is fine because
                    // patterns that can match empty matches are rejected.
                    self.start = regex_match.end();

                    if self.exclusion_check.is_excluded(self.rule.rule_index) {
                        // Matches from excluded paths are saved and used to treat additional equal matches as false positives
                        self.excluded_matches
                            .insert(self.content[regex_match.range()].to_string());
                    } else {
                        // If the matched content is in `excluded_matches` it should not count as a match.
                        // This is temporary to maintain backwards compatibility, but this should eventually happen
                        // after all scanning is done so `excluded_matches` is fully populated.
                        if !self
                            .excluded_matches
                            .contains(&self.content[regex_match.range()])
                        {
                            return Some(StringMatch {
                                start: regex_match.start(),
                                end: regex_match.end(),
                            });
                        } else {
                            self.rule
                                .metrics
                                .false_positive_excluded_attributes
                                .increment(1)
                        }
                    }
                }
            } else {
                return None;
            }
        }
    }
}
