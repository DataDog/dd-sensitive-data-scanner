//! A match must contain every adjacent byte pair in a required literal.

use crate::normalization::rust_regex_adapter::convert_to_rust_regex;
use crate::{RootRuleConfig, RuleConfig};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use regex_syntax_08::hir::{Hir, HirKind};
use std::sync::Arc;

pub(super) struct ScanPrefilter {
    rules: Vec<RuleConditions>,
}

#[derive(Clone, Copy, Default)]
struct RuleConditions {
    min_len: usize,
    pairs: u64,
}

// Scanners often share patterns. Reuse the analysis when a consumer rebuilds its scanners.
static CONDITIONS: Lazy<Cache<String, RuleConditions>> = Lazy::new(|| Cache::new(1_000));

pub(super) fn clear_cache() {
    if let Some(cache) = Lazy::get(&CONDITIONS) {
        cache.invalidate_all();
        cache.run_pending_tasks();
    }
}

impl ScanPrefilter {
    pub(super) fn new(rules: &[RootRuleConfig<Arc<dyn RuleConfig>>]) -> Option<Self> {
        let rules: Vec<_> = rules
            .iter()
            .map(|rule| {
                rule.inner
                    .pattern_for_prefilter()
                    .map(|pattern| {
                        CONDITIONS.get_with_by_ref(pattern, || {
                            RuleConditions::from_pattern(pattern).unwrap_or_default()
                        })
                    })
                    .unwrap_or_default()
            })
            .collect();
        rules
            .iter()
            .any(|rule| rule.min_len > 0 || rule.pairs != 0)
            .then_some(Self { rules })
    }

    pub(super) fn can_skip(
        &self,
        index: usize,
        content: &str,
        field_pairs: &mut Option<u64>,
    ) -> bool {
        let rule = &self.rules[index];
        if content.len() < rule.min_len {
            return true;
        }
        // Longer fields cost more to read and tend to fill the mask.
        if rule.pairs == 0 || content.len() > 256 {
            return false;
        }
        let pairs = field_pairs.get_or_insert_with(|| pair_mask(content.as_bytes()));
        rule.pairs & !*pairs != 0
    }
}

impl RuleConditions {
    fn from_pattern(pattern: &str) -> Option<Self> {
        let regex = convert_to_rust_regex(pattern).ok()?;
        let hir =
            regex_automata::util::syntax::parse_with(&regex, &crate::validation::rule_syntax())
                .ok()?;
        Some(Self {
            min_len: hir.properties().minimum_len()?,
            pairs: required_pairs(&hir),
        })
    }
}

fn required_pairs(hir: &Hir) -> u64 {
    match hir.kind() {
        HirKind::Literal(lit) => pair_mask(&lit.0),
        HirKind::Capture(capture) => required_pairs(&capture.sub),
        HirKind::Repetition(rep) if rep.min > 0 => required_pairs(&rep.sub),
        HirKind::Concat(subs) => subs
            .iter()
            .map(required_pairs)
            .fold(0, |bits, sub| bits | sub),
        HirKind::Alternation(subs) => subs
            .iter()
            .map(required_pairs)
            .reduce(|bits, sub| bits & sub)
            .unwrap_or(0),
        _ => 0,
    }
}

fn pair_mask(bytes: &[u8]) -> u64 {
    let mut bits = 0;
    for pair in bytes.windows(2) {
        // Hash collisions keep extra rules eligible. Only an absent bit excludes a match.
        let hash = pair[0].wrapping_mul(13).wrapping_add(pair[1]);
        bits |= 1u64 << (hash & 63);
    }
    bits
}
