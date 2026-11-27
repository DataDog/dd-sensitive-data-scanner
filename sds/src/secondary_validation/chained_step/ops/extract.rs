//! `Extract`: byte slice `[start:end]` of `param`.
//!
//! Inputs: `param` (bytes), `config` (`"[a:b]"`; either bound may be omitted; negative bounds
//! count from the end). The result is a narrower span, so it never copies.
//!
//! Compile-time: a missing or unparsable `config`, a step (`[a:b:c]`) or a single index (`[a]`)
//! is `invalid_value`.
//!
//! Runtime failures (see [`Failure::class`]):
//! - a bound outside `0..=len` after resolving negatives: **error** (no clamping, the token does
//!   not have the shape the chain expects, so it cannot be evaluated);
//! - start after end: **error**, for the same reason.

use super::Operand;
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, OutputSlots, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{Frame, FrameFailure, SlotType, Value};

pub(crate) const INPUT_KEYS: SinceTable<()> = &[("param", (), 1), ("config", (), 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    BoundOutOfRange,
    StartAfterEnd,
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::BoundOutOfRange => FailureClass::Error,
            Failure::StartAfterEnd => FailureClass::Error,
            Failure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for Failure {
    fn from(failure: FrameFailure) -> Self {
        Failure::Frame(failure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SliceBounds {
    pub start: Option<i64>,
    pub end: Option<i64>,
}

#[derive(Debug)]
pub(crate) struct Extract {
    param: Operand,
    bounds: SliceBounds,
    outputs: OutputSlots,
}

impl Extract {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_bytes_operand("param", builder)?;
        let bounds = parse_slice(inputs.required_literal("config")?)?;
        let outputs = outputs.single(SlotType::Bytes, builder)?;
        Ok(Self {
            param,
            bounds,
            outputs,
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let span = self.param.load_span(frame)?;
        let (start, end) = resolve_bounds(self.bounds, span.len())?;
        let narrowed = span
            .narrow(start, end)
            .ok_or(Failure::Frame(FrameFailure::DanglingReference))?;
        frame.store_all(&self.outputs, Value::Bytes(narrowed))?;
        Ok(())
    }
}

pub(crate) fn parse_slice(config: &str) -> CompileResult<SliceBounds> {
    let invalid = || {
        fail(
            FallbackReason::InvalidValue,
            format!("`config` must be a slice like `[a:b]`, got `{config}`"),
        )
    };
    let Some(inner) = config
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return invalid();
    };
    let mut parts = inner.split(':');
    let (Some(start), Some(end), None) = (parts.next(), parts.next(), parts.next()) else {
        return invalid();
    };
    let parse_bound = |bound: &str| -> Result<Option<i64>, ()> {
        if bound.is_empty() {
            Ok(None)
        } else {
            bound.parse::<i64>().map(Some).map_err(|_| ())
        }
    };
    match (parse_bound(start), parse_bound(end)) {
        (Ok(start), Ok(end)) => Ok(SliceBounds { start, end }),
        _ => invalid(),
    }
}

/// Resolves Python-style bounds against `len` with checked arithmetic, without clamping.
pub(crate) fn resolve_bounds(bounds: SliceBounds, len: usize) -> Result<(usize, usize), Failure> {
    let len_i64 = i64::try_from(len).map_err(|_| Failure::BoundOutOfRange)?;
    let resolve = |bound: Option<i64>, default: i64| -> Result<usize, Failure> {
        let absolute = match bound {
            None => default,
            Some(bound) if bound < 0 => {
                len_i64.checked_add(bound).ok_or(Failure::BoundOutOfRange)?
            }
            Some(bound) => bound,
        };
        if absolute < 0 || absolute > len_i64 {
            return Err(Failure::BoundOutOfRange);
        }
        usize::try_from(absolute).map_err(|_| Failure::BoundOutOfRange)
    };
    let start = resolve(bounds.start, 0)?;
    let end = resolve(bounds.end, len_i64)?;
    if start > end {
        return Err(Failure::StartAfterEnd);
    }
    Ok((start, end))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{
        assert_fallback, chain, evaluates_to, step,
    };
    use serde_json::json;

    fn extract_then_compare(slice: &str, expected: &str) -> serde_json::Value {
        chain(vec![
            step(
                "Extract",
                json!({"param": "$GLOBAL_MATCH", "config": slice}),
                json!({"part": "$OUTPUT"}),
            ),
            step(
                "Compare",
                json!({"a": "$part", "b": expected, "config": "="}),
                json!({}),
            ),
        ])
    }

    fn bounds(start: Option<i64>, end: Option<i64>) -> SliceBounds {
        SliceBounds { start, end }
    }

    #[test]
    fn slices_resolve_bounds() {
        for (slice, input, expected) in [
            ("[1:3]", "abcdef", "bc"),
            ("[-3:-1]", "abcdef", "de"),
            ("[:]", "abc", "abc"),
            ("[:-2]", "abc", "a"),
            ("[-2:]", "abc", "bc"),
            ("[2:2]", "abc", ""),
        ] {
            evaluates_to(
                &extract_then_compare(slice, expected),
                input,
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn slices_operate_on_bytes_not_chars() {
        // "é" is two bytes; [1:] starts inside it, which must not panic or require UTF-8.
        evaluates_to(
            &extract_then_compare("[1:]", "bc"),
            "\u{e9}bc",
            ChainOutcome::Invalid,
        );
        evaluates_to(
            &extract_then_compare("[2:]", "bc"),
            "\u{e9}bc",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn out_of_range_bounds_are_errors() {
        for slice in ["[0:10]", "[-4:]", "[2:1]"] {
            evaluates_to(
                &extract_then_compare(slice, "abc"),
                "abc",
                ChainOutcome::Error,
            );
        }
    }

    #[test]
    fn i64_extreme_bounds_are_errors_without_overflow() {
        assert_eq!(
            resolve_bounds(bounds(Some(i64::MIN), None), 3),
            Err(Failure::BoundOutOfRange)
        );
        assert_eq!(
            resolve_bounds(bounds(None, Some(i64::MAX)), 3),
            Err(Failure::BoundOutOfRange)
        );
        evaluates_to(
            &extract_then_compare("[-9223372036854775808:]", "abc"),
            "abc",
            ChainOutcome::Error,
        );
    }

    #[test]
    fn malformed_slices_are_invalid_value() {
        for slice in ["[1:2:3]", "[1]", "1:2", "[a:b]", "[99999999999999999999:]"] {
            assert_fallback(
                &extract_then_compare(slice, "x"),
                FallbackReason::InvalidValue,
            );
        }
    }

    #[test]
    fn extract_of_literal_param_slices_the_literal() {
        let config = chain(vec![
            step(
                "Extract",
                json!({"param": "literal", "config": "[0:3]"}),
                json!({"part": "$OUTPUT"}),
            ),
            step(
                "Compare",
                json!({"a": "$part", "b": "$GLOBAL_MATCH", "config": "="}),
                json!({}),
            ),
        ]);
        evaluates_to(&config, "lit", ChainOutcome::Valid);
    }
}
