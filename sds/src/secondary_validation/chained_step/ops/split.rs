//! `Split`: the parts of `param` before and after one occurrence of `separator`.
//!
//! Inputs: `param` (bytes), `separator` (non-empty literal), `occurrence` (integer index).
//! `output` names a variable for either or both parts, e.g.
//! `{"before": "head", "after": "tail"}`, so one step yields both sides. At least one part is
//! required and any other key is `malformed`. The separator itself is excluded; both parts are
//! narrower spans of `param`.
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
    ChainBuilder, CompileResult, FallbackReason, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{
    Frame, FrameFailure, SlotType, Span, Value,
};
use smallvec::SmallVec;

pub(crate) const INPUT_KEYS: SinceTable<()> = &[
    ("param", (), 1),
    ("separator", (), 1),
    ("occurrence", (), 1),
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
    outputs: SmallVec<[(Part, usize); 2]>,
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
        let outputs = outputs.parts("Split", PARTS, SlotType::Bytes, builder)?;
        if outputs.is_empty() {
            return fail(
                FallbackReason::Malformed,
                "`output` of op `Split` needs `before`, `after` or both",
            );
        }
        Ok(Self {
            param,
            separator,
            occurrence,
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
        let after_separator = position + separator.len();
        for &(part, slot) in &self.outputs {
            let (start, end) = match part {
                Part::Before => (0, position),
                Part::After => (after_separator, span.len()),
            };
            let narrowed = span
                .narrow(start, end)
                .ok_or(Failure::Frame(FrameFailure::DanglingReference))?;
            frame.set(slot, Value::Bytes(narrowed))?;
        }
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
        assert_fallback, chain, check, evaluates_to, step,
    };
    use serde_json::{Value as JsonValue, json};

    fn split_step(separator: &str, occurrence: i64, output: JsonValue) -> JsonValue {
        step(
            "Split",
            json!({"param": "$GLOBAL_MATCH", "separator": separator, "occurrence": occurrence}),
            output,
        )
    }

    /// Joins both parts with `|` so one comparison checks the two outputs of a single step.
    fn split_then_compare(separator: &str, occurrence: i64, expected: &str) -> JsonValue {
        chain(vec![
            split_step(
                separator,
                occurrence,
                json!({"before": "head", "after": "tail"}),
            ),
            step(
                "Format",
                json!({"template": "{head}|{tail}"}),
                json!("parts"),
            ),
            check(
                "Compare",
                json!({"a": "$parts", "b": expected, "operator": "="}),
            ),
        ])
    }

    #[test]
    fn splits_around_selected_occurrence() {
        for (separator, occurrence, input, expected) in [
            ("_", 0, "a_b_c", "a|b_c"),
            ("_", 1, "a_b_c", "a_b|c"),
            ("_", -1, "a_b_c", "a_b|c"),
            ("_", -2, "a_b_c", "a|b_c"),
            ("_", -1, "abc_", "abc|"),
            // Non-overlapping, like Python: "aaaa".split("aa") has two separators, not three.
            ("aa", -1, "aaaa", "aa|"),
        ] {
            evaluates_to(
                &split_then_compare(separator, occurrence, expected),
                input,
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn a_single_output_is_enough() {
        let config = chain(vec![
            split_step("_", -1, json!({"after": "tail"})),
            check("Compare", json!({"a": "$tail", "b": "c", "operator": "="})),
        ]);
        evaluates_to(&config, "a_b_c", ChainOutcome::Valid);
    }

    #[test]
    fn index_without_an_occurrence_is_negative() {
        for (occurrence, input) in [(0, "abc"), (2, "a_b_c"), (-3, "a_b_c"), (i64::MIN, "a_b")] {
            evaluates_to(
                &split_then_compare("_", occurrence, "x"),
                input,
                ChainOutcome::Invalid,
            );
        }
    }

    #[test]
    fn invalid_configs_fall_back() {
        let with_occurrence = |occurrence: JsonValue| {
            chain(vec![step(
                "Split",
                json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": occurrence}),
                json!({"after": "tail"}),
            )])
        };
        for (config, reason) in [
            (with_occurrence(json!("last")), FallbackReason::InvalidValue),
            (
                chain(vec![split_step("", 0, json!({"after": "tail"}))]),
                FallbackReason::InvalidValue,
            ),
            (
                chain(vec![split_step("_", 0, json!({}))]),
                FallbackReason::Malformed,
            ),
        ] {
            assert_fallback(&config, reason);
        }
    }
}
