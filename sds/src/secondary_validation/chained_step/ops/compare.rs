//! `Compare`: compares two values of the same kind.
//!
//! Inputs: `a`, `b` (variables or literals; literals are bytes), `config` (`=`, `!=`, or `=i` for
//! ASCII case-insensitive equality). Both sides must be bytes or both ints (`malformed`
//! otherwise). Int comparison compares values only and ignores `bits`, so a 32-bit CRC can be
//! compared with a 64-bit decoded checksum. `=i` applies to bytes only (`malformed` on ints).
//!
//! Runtime failures (see [`Failure::class`]):
//! - the comparison is false: **negative**.

use super::Operand;
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{Frame, FrameFailure, SlotType, Value};

pub(crate) const INPUT_KEYS: SinceTable<()> = &[("a", (), 1), ("b", (), 1), ("config", (), 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Equal,
    NotEqual,
    EqualIgnoreAsciiCase,
}

const COMPARISONS: SinceTable<Comparison> = &[
    ("=", Comparison::Equal, 1),
    ("!=", Comparison::NotEqual, 1),
    ("=i", Comparison::EqualIgnoreAsciiCase, 1),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    ComparisonFalse,
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::ComparisonFalse => FailureClass::Negative,
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
pub(crate) struct Compare {
    a: Operand,
    b: Operand,
    comparison: Comparison,
}

fn is_int(ty: SlotType) -> bool {
    matches!(ty, SlotType::Int { .. })
}

impl Compare {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let a = inputs.required_operand("a", builder)?;
        let b = inputs.required_operand("b", builder)?;
        let comparison = inputs.required_choice("config", COMPARISONS, builder)?;
        if is_int(a.ty) != is_int(b.ty) {
            return fail(
                FallbackReason::Malformed,
                "`a` and `b` must both be bytes or both be ints",
            );
        }
        if is_int(a.ty) && comparison == Comparison::EqualIgnoreAsciiCase {
            return fail(FallbackReason::Malformed, "`=i` only applies to bytes");
        }
        outputs.none("Compare")?;
        Ok(Self { a, b, comparison })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let is_true = match (self.a.load(frame)?, self.b.load(frame)?) {
            (Value::Int(a), Value::Int(b)) => match self.comparison {
                Comparison::Equal => a == b,
                Comparison::NotEqual => a != b,
                Comparison::EqualIgnoreAsciiCase => {
                    return Err(Failure::Frame(FrameFailure::DanglingReference));
                }
            },
            (a @ Value::Bytes(_), b @ Value::Bytes(_)) => {
                let (a, b) = (frame.bytes_of(a)?, frame.bytes_of(b)?);
                match self.comparison {
                    Comparison::Equal => a == b,
                    Comparison::NotEqual => a != b,
                    Comparison::EqualIgnoreAsciiCase => a.eq_ignore_ascii_case(b),
                }
            }
            _ => return Err(Failure::Frame(FrameFailure::DanglingReference)),
        };
        if is_true {
            Ok(())
        } else {
            Err(Failure::ComparisonFalse)
        }
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

    fn compare_with_literal(config: &str, literal: &str) -> serde_json::Value {
        chain(vec![step(
            "Compare",
            json!({"a": "$GLOBAL_MATCH", "b": literal, "config": config}),
            json!({}),
        )])
    }

    /// Compares CRC32(GLOBAL_MATCH) (32 bits) with a base62-decoded int (64 bits).
    fn compare_crc_with_decoded(config: &str, encoded: &str) -> serde_json::Value {
        chain(vec![
            step(
                "Checksum",
                json!({"param": "$GLOBAL_MATCH", "alg": "crc32"}),
                json!({"crc": "$OUTPUT"}),
            ),
            step(
                "Decode",
                json!({"param": encoded, "scheme": "base62", "as": "int"}),
                json!({"decoded": "$OUTPUT"}),
            ),
            step(
                "Compare",
                json!({"a": "$crc", "b": "$decoded", "config": config}),
                json!({}),
            ),
        ])
    }

    #[test]
    fn bytes_comparison_outcomes() {
        for (comparison, literal, input, outcome) in [
            ("=", "foo", "foo", ChainOutcome::Valid),
            ("=", "foo", "fOo", ChainOutcome::Invalid),
            ("!=", "foo", "bar", ChainOutcome::Valid),
            ("!=", "foo", "foo", ChainOutcome::Invalid),
            ("=i", "fOo", "FoO", ChainOutcome::Valid),
            ("=i", "foo", "fob", ChainOutcome::Invalid),
        ] {
            evaluates_to(&compare_with_literal(comparison, literal), input, outcome);
        }
    }

    #[test]
    fn int_comparison_ignores_bits() {
        let encoded = base62::encode(crc32fast::hash(b"foo"));
        evaluates_to(
            &compare_crc_with_decoded("=", &encoded),
            "foo",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn int_decoded_above_32_bits_does_not_equal_truncated_crc() {
        // A 6-digit base62 value can exceed 32 bits; it must not be truncated before comparing.
        let crc = u64::from(crc32fast::hash(b"foo"));
        let encoded = base62::encode(crc + (1u64 << 32));
        evaluates_to(
            &compare_crc_with_decoded("=", &encoded),
            "foo",
            ChainOutcome::Invalid,
        );
    }

    #[test]
    fn type_mismatches_are_malformed() {
        let int_against_literal = chain(vec![
            step(
                "Checksum",
                json!({"param": "$GLOBAL_MATCH", "alg": "crc32"}),
                json!({"crc": "$OUTPUT"}),
            ),
            step(
                "Compare",
                json!({"a": "$crc", "b": "123", "config": "="}),
                json!({}),
            ),
        ]);
        for config in [int_against_literal, compare_crc_with_decoded("=i", "abc")] {
            assert_fallback(&config, FallbackReason::Malformed);
        }
    }

    #[test]
    fn dollar_dollar_literal_compares_with_leading_dollar() {
        evaluates_to(
            &compare_with_literal("=", "$$foo"),
            "$foo",
            ChainOutcome::Valid,
        );
    }
}
