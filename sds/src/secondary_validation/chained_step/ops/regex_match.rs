//! `RegexMatch`: full match of `param` against an SDS regex, optionally capturing named groups.
//!
//! Inputs: `param` (bytes), `pattern` (SDS regex syntax), `mode` (`match`, the default, or
//! `not_match`). Outputs map new variables to named groups: `{"body": "$body"}`.
//!
//! The pattern is validated and built at compile time through `validate_and_create_regex`, so SDS
//! complexity limits apply, the syntax is converted, and patterns that can match the empty string
//! are rejected (`invalid_value`). It is compiled as `(?:pattern)\z` and searched with
//! `Anchored::Yes`, so a match exists iff some way of matching covers the whole value; this is a
//! true full match even for alternations such as `a|ab`, which a plain anchored leftmost-first
//! search would stop short on. Only named groups can be output; an output naming a group the
//! pattern lacks is `malformed`, and `not_match` cannot have outputs (`malformed`).
//!
//! Runtime failures (see [`Failure::class`]):
//! - `match` and the value does not fully match: **negative**;
//! - `not_match` and the value fully matches: **negative**;
//! - a captured group did not participate in the match: **error** (its output has no value);
//! - the thread-local regex cache could not be acquired: **error**.

use super::Operand;
use crate::scanner::regex_rule::{SharedRegex, get_memoized_regex};
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{
    Frame, FrameFailure, RegexCacheEntry, SlotType, Value,
};
use crate::validation::validate_and_create_regex;
use regex_automata::{Anchored, Input, PatternID};
use smallvec::SmallVec;

pub(crate) const INPUT_KEYS: SinceTable<()> =
    &[("param", (), 1), ("pattern", (), 1), ("mode", (), 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Match,
    NotMatch,
}

const MODES: SinceTable<Mode> = &[("match", Mode::Match, 1), ("not_match", Mode::NotMatch, 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    NoMatch,
    UnexpectedMatch,
    GroupDidNotParticipate,
    CacheUnavailable,
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::NoMatch => FailureClass::Negative,
            Failure::UnexpectedMatch => FailureClass::Negative,
            Failure::GroupDidNotParticipate => FailureClass::Error,
            Failure::CacheUnavailable => FailureClass::Error,
            Failure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for Failure {
    fn from(failure: FrameFailure) -> Self {
        Failure::Frame(failure)
    }
}

pub(crate) struct RegexMatch {
    param: Operand,
    regex: SharedRegex,
    mode: Mode,
    /// (capture group index, output slot)
    captures: SmallVec<[(usize, usize); 2]>,
}

impl std::fmt::Debug for RegexMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegexMatch")
            .field("param", &self.param)
            .field("mode", &self.mode)
            .field("captures", &self.captures)
            .finish_non_exhaustive()
    }
}

impl RegexMatch {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_bytes_operand("param", builder)?;
        let pattern = inputs.required_literal("pattern")?;
        let mode = inputs
            .choice("mode", MODES, builder)?
            .unwrap_or(Mode::Match);
        // Validating the bare pattern first guarantees that wrapping it cannot change how it
        // parses (an unbalanced `)` would otherwise escape the wrapper group).
        if let Err(error) = validate_and_create_regex(pattern) {
            return fail(
                FallbackReason::InvalidValue,
                format!("invalid `pattern`: {error}"),
            );
        }
        let full_match_pattern = format!("(?:{pattern})\\z");
        let regex = match get_memoized_regex(&full_match_pattern, validate_and_create_regex) {
            Ok(regex) => regex,
            Err(error) => {
                return fail(
                    FallbackReason::InvalidValue,
                    format!("invalid `pattern`: {error}"),
                );
            }
        };
        builder.register_regex()?;
        let group_info = regex.group_info();
        if mode == Mode::NotMatch && !outputs.entries().is_empty() {
            return fail(
                FallbackReason::Malformed,
                "`not_match` produces no captures, so it cannot declare outputs",
            );
        }
        let mut captures = SmallVec::new();
        for &(name, group) in outputs.entries() {
            let Some(group_index) = group_info.to_index(PatternID::ZERO, group) else {
                return fail(
                    FallbackReason::Malformed,
                    format!("output `{name}`: the pattern has no capture group named `{group}`"),
                );
            };
            captures.push((group_index, builder.define(name, SlotType::Bytes)?));
        }
        Ok(Self {
            param,
            regex,
            mode,
            captures,
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let span = self.param.load_span(frame)?;
        let (haystack, regex_caches) = frame.bytes_and_regex_caches(span)?;
        let entry = regex_caches
            .entry(self.regex.cache_key)
            .ok_or(Failure::CacheUnavailable)?
            .or_insert_with(|| RegexCacheEntry {
                cache: self.regex.create_cache(),
                captures: self.regex.create_captures(),
            });
        let input = Input::new(haystack).anchored(Anchored::Yes);
        let haystack_len = haystack.len();

        if self.captures.is_empty() {
            let is_full_match = self
                .regex
                .search_half_with(&mut entry.cache, &input)
                .is_some_and(|half_match| half_match.offset() == haystack_len);
            return match (self.mode, is_full_match) {
                (Mode::Match, true) | (Mode::NotMatch, false) => Ok(()),
                (Mode::Match, false) => Err(Failure::NoMatch),
                (Mode::NotMatch, true) => Err(Failure::UnexpectedMatch),
            };
        }

        self.regex
            .search_captures_with(&mut entry.cache, &input, &mut entry.captures);
        let is_full_match = entry
            .captures
            .get_match()
            .is_some_and(|found| found.end() == haystack_len);
        if !is_full_match {
            return Err(Failure::NoMatch);
        }
        let mut group_spans: SmallVec<[(usize, regex_automata::Span); 2]> = SmallVec::new();
        for &(group_index, slot) in &self.captures {
            let group_span = entry
                .captures
                .get_group(group_index)
                .ok_or(Failure::GroupDidNotParticipate)?;
            group_spans.push((slot, group_span));
        }
        for (slot, group_span) in group_spans {
            let captured = span
                .narrow(group_span.start, group_span.end)
                .ok_or(Failure::Frame(FrameFailure::DanglingReference))?;
            frame.set(slot, Value::Bytes(captured))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{
        assert_fallback, chain, evaluates_to, step,
    };
    use serde_json::json;

    fn regex_check(pattern: &str, mode: &str) -> serde_json::Value {
        chain(vec![step(
            "RegexMatch",
            json!({"param": "$GLOBAL_MATCH", "pattern": pattern, "mode": mode}),
            json!({}),
        )])
    }

    fn capture_then_compare(pattern: &str, group: &str, expected: &str) -> serde_json::Value {
        chain(vec![
            step(
                "RegexMatch",
                json!({"param": "$GLOBAL_MATCH", "pattern": pattern}),
                json!({"captured": format!("${group}")}),
            ),
            step(
                "Compare",
                json!({"a": "$captured", "b": expected, "config": "="}),
                json!({}),
            ),
        ])
    }

    #[test]
    fn mode_outcomes() {
        for (pattern, mode, input, outcome) in [
            ("tkn_[a-z0-9]+", "match", "tkn_abc1", ChainOutcome::Valid),
            ("tkn_[a-z]+", "match", "tkn_abc1", ChainOutcome::Invalid),
            ("tkn_[a-z]+", "match", "xtkn_abc", ChainOutcome::Invalid),
            ("foo", "not_match", "bar", ChainOutcome::Valid),
            ("foo", "not_match", "foo", ChainOutcome::Invalid),
        ] {
            evaluates_to(&regex_check(pattern, mode), input, outcome);
        }
    }

    #[test]
    fn alternation_full_match_is_not_cut_short_by_leftmost_first() {
        evaluates_to(&regex_check("a|ab", "match"), "ab", ChainOutcome::Valid);
    }

    #[test]
    fn named_group_is_captured() {
        evaluates_to(
            &capture_then_compare("tkn_(?<body>[a-z]+)_[0-9]+", "body", "abc"),
            "tkn_abc_42",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn non_participating_group_is_error() {
        evaluates_to(
            &capture_then_compare("(?<letters>[a-z]+)|[0-9]+", "letters", "abc"),
            "123",
            ChainOutcome::Error,
        );
    }

    #[test]
    fn matches_non_utf8_bytes_from_scratch() {
        // Decoding "/w==" yields 0xFF, which is not UTF-8; the regex must still run on it.
        let config = chain(vec![
            step(
                "Decode",
                json!({"param": "$GLOBAL_MATCH", "scheme": "base64"}),
                json!({"raw": "$OUTPUT"}),
            ),
            step(
                "RegexMatch",
                json!({"param": "$raw", "pattern": "foo"}),
                json!({}),
            ),
        ]);
        evaluates_to(&config, "/w==", ChainOutcome::Invalid);
    }

    #[test]
    fn invalid_configs_fall_back() {
        let five_regexes = chain(
            (0..5)
                .map(|index| {
                    step(
                        "RegexMatch",
                        json!({"param": "$GLOBAL_MATCH", "pattern": format!("x{index}")}),
                        json!({}),
                    )
                })
                .collect(),
        );
        let not_match_with_output = chain(vec![step(
            "RegexMatch",
            json!({"param": "$GLOBAL_MATCH", "pattern": "(?<body>foo)", "mode": "not_match"}),
            json!({"body": "$body"}),
        )]);
        for (config, reason) in [
            (
                regex_check("(unclosed", "match"),
                FallbackReason::InvalidValue,
            ),
            (regex_check("a*", "match"), FallbackReason::InvalidValue),
            // Must not escape the `(?:pattern)\z` wrapper.
            (regex_check("a)|(b", "match"), FallbackReason::InvalidValue),
            (five_regexes, FallbackReason::LimitExceeded),
            (
                capture_then_compare("tkn_(?<body>[a-z]+)", "missing", "abc"),
                FallbackReason::Malformed,
            ),
            (not_match_with_output, FallbackReason::Malformed),
        ] {
            assert_fallback(&config, reason);
        }
    }

    #[test]
    fn same_pattern_in_two_chains_uses_independent_captures() {
        let first = capture_then_compare("(?<body>[a-z]+)_[0-9]+", "body", "abc");
        let second = capture_then_compare("(?<body>[a-z]+)_[0-9]+", "body", "xyz");
        evaluates_to(&first, "abc_1", ChainOutcome::Valid);
        evaluates_to(&second, "xyz_2", ChainOutcome::Valid);
        evaluates_to(&first, "xyz_2", ChainOutcome::Invalid);
    }
}
