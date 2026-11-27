//! `Split`: the part of `param` before or after one occurrence of `separator`.
//!
//! Inputs: `param` (bytes), `separator` (non-empty literal), `occurrence` (integer index),
//! `part` (`before` | `after`). The separator itself is excluded from the result, which is a
//! narrower span of `param`.
//!
//! Occurrences are found left to right without overlapping, like Python's `str.split`, and
//! `occurrence` indexes them with Python semantics: `0` is the first, `-1` the last, `-2` the one
//! before it.
//!
//! Runtime failures (see [`Failure::class`]):
//! - no occurrence at that index (including no separator at all): **negative**. The value lacks
//!   the token's structure, exactly like a hand-written validator returning `false` when a token
//!   has no `_`.

use super::Operand;
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, OutputSlots, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{
    Frame, FrameFailure, SlotType, Span, Value,
};

pub(crate) const INPUT_KEYS: SinceTable<()> = &[
    ("param", (), 1),
    ("separator", (), 1),
    ("occurrence", (), 1),
    ("part", (), 1),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Before,
    After,
}

const PARTS: SinceTable<Part> = &[("before", Part::Before, 1), ("after", Part::After, 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    OccurrenceNotFound,
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::OccurrenceNotFound => FailureClass::Negative,
            Failure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for Failure {
    fn from(failure: FrameFailure) -> Self {
        Failure::Frame(failure)
    }
}

#[derive(Debug)]
pub(crate) struct Split {
    param: Operand,
    separator: Span,
    occurrence: i64,
    part: Part,
    outputs: OutputSlots,
}

impl Split {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_bytes_operand("param", builder)?;
        let separator = inputs.required_literal("separator")?;
        if separator.is_empty() {
            return fail(
                FallbackReason::InvalidValue,
                "`separator` must not be empty",
            );
        }
        let separator = builder.add_literal(separator.as_bytes())?;
        let occurrence = inputs.required_integer("occurrence")?;
        let part = inputs.required_choice("part", PARTS, builder)?;
        let outputs = outputs.single(SlotType::Bytes, builder)?;
        Ok(Self {
            param,
            separator,
            occurrence,
            part,
            outputs,
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let span = self.param.load_span(frame)?;
        let haystack = frame.bytes(span)?;
        let separator = frame.bytes(self.separator)?;
        let index = if self.occurrence < 0 {
            let count = occurrences(haystack, separator).count();
            i64::try_from(count)
                .ok()
                .and_then(|count| count.checked_add(self.occurrence))
                .and_then(|index| usize::try_from(index).ok())
        } else {
            usize::try_from(self.occurrence).ok()
        }
        .ok_or(Failure::OccurrenceNotFound)?;
        let position = occurrences(haystack, separator)
            .nth(index)
            .ok_or(Failure::OccurrenceNotFound)?;
        let (start, end) = match self.part {
            Part::Before => (0, position),
            Part::After => (position + separator.len(), span.len()),
        };
        let part = span
            .narrow(start, end)
            .ok_or(Failure::Frame(FrameFailure::DanglingReference))?;
        frame.store_all(&self.outputs, Value::Bytes(part))?;
        Ok(())
    }
}

/// Start positions of the non-overlapping occurrences of a non-empty `separator`, left to right.
fn occurrences<'a>(haystack: &'a [u8], separator: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut next_start = 0;
    std::iter::from_fn(move || {
        let offset = haystack
            .get(next_start..)?
            .windows(separator.len())
            .position(|window| window == separator)?;
        let position = next_start + offset;
        next_start = position + separator.len();
        Some(position)
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{
        assert_fallback, chain, evaluates_to, step,
    };
    use serde_json::json;

    fn split_then_compare(
        separator: &str,
        occurrence: i64,
        part: &str,
        expected: &str,
    ) -> serde_json::Value {
        chain(vec![
            step(
                "Split",
                json!({"param": "$GLOBAL_MATCH", "separator": separator, "occurrence": occurrence, "part": part}),
                json!({"piece": "$OUTPUT"}),
            ),
            step(
                "Compare",
                json!({"a": "$piece", "b": expected, "config": "="}),
                json!({}),
            ),
        ])
    }

    #[test]
    fn splits_around_selected_occurrence() {
        for (separator, occurrence, part, input, expected) in [
            ("_", 0, "before", "a_b_c", "a"),
            ("_", 0, "after", "a_b_c", "b_c"),
            ("_", 1, "before", "a_b_c", "a_b"),
            ("_", -1, "after", "a_b_c", "c"),
            ("_", -2, "after", "a_b_c", "b_c"),
            ("_", -1, "after", "abc_", ""),
            // Non-overlapping, like Python: "aaaa".split("aa") has two separators, not three.
            ("aa", -1, "before", "aaaa", "aa"),
        ] {
            evaluates_to(
                &split_then_compare(separator, occurrence, part, expected),
                input,
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn index_without_an_occurrence_is_negative() {
        for (occurrence, input) in [(0, "abc"), (2, "a_b_c"), (-3, "a_b_c"), (i64::MIN, "a_b")] {
            evaluates_to(
                &split_then_compare("_", occurrence, "after", "x"),
                input,
                ChainOutcome::Invalid,
            );
        }
    }

    #[test]
    fn non_integer_occurrence_is_invalid_value() {
        let config = chain(vec![step(
            "Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": "last", "part": "after"}),
            json!({"piece": "$OUTPUT"}),
        )]);
        assert_fallback(&config, FallbackReason::InvalidValue);
    }

    #[test]
    fn empty_separator_is_invalid_value() {
        assert_fallback(
            &split_then_compare("", 0, "after", "x"),
            FallbackReason::InvalidValue,
        );
    }
}
