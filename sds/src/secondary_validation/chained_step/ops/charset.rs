//! `Charset`: checks the bytes of `param` against a set of allowed ASCII characters.
//!
//! Inputs: `param` (bytes), `allowed` (a character-class body such as `A-Za-z0-9_=-`), `mode`
//! (`all`, the default: every byte must be allowed; `any_outside`: at least one byte must be
//! outside the set, which is how `NonHexChecker` is expressed).
//!
//! `allowed` is compiled to a 256-bit bitmap, so the check never touches a regex engine. Syntax:
//! single characters, ranges `a-z`, a `-` at the start or end is literal, and `\` escapes the next
//! character. Non-ASCII characters, reversed ranges, a trailing `\` and an empty set are
//! `invalid_value`. Non-ASCII bytes in `param` are never in the set.
//!
//! Runtime failures (see [`Failure::class`]):
//! - `all` and a byte is outside the set: **negative**;
//! - `any_outside` and every byte is inside the set (including an empty value): **negative**.

use super::Operand;
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{Frame, FrameFailure};

pub(crate) const INPUT_KEYS: SinceTable<()> =
    &[("param", (), 1), ("allowed", (), 1), ("mode", (), 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    All,
    AnyOutside,
}

const MODES: SinceTable<Mode> = &[("all", Mode::All, 1), ("any_outside", Mode::AnyOutside, 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    ByteOutsideSet,
    NoByteOutsideSet,
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::ByteOutsideSet => FailureClass::Negative,
            Failure::NoByteOutsideSet => FailureClass::Negative,
            Failure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for Failure {
    fn from(failure: FrameFailure) -> Self {
        Failure::Frame(failure)
    }
}

/// Only ASCII can be allowed, so 128 bits suffice; bytes >= 128 are always outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct AsciiSet(u128);

impl AsciiSet {
    fn insert(&mut self, byte: u8) {
        self.0 |= 1u128 << byte;
    }

    fn contains(&self, byte: u8) -> bool {
        byte < 128 && self.0 & (1u128 << byte) != 0
    }
}

#[derive(Debug)]
pub(crate) struct Charset {
    param: Operand,
    allowed: AsciiSet,
    mode: Mode,
}

impl Charset {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_bytes_operand("param", builder)?;
        let allowed = parse_allowed(inputs.required_literal("allowed")?)?;
        let mode = inputs.choice("mode", MODES, builder)?.unwrap_or(Mode::All);
        outputs.none("Charset")?;
        Ok(Self {
            param,
            allowed,
            mode,
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let bytes = frame.bytes(self.param.load_span(frame)?)?;
        match self.mode {
            Mode::All => {
                if bytes.iter().all(|&byte| self.allowed.contains(byte)) {
                    Ok(())
                } else {
                    Err(Failure::ByteOutsideSet)
                }
            }
            Mode::AnyOutside => {
                if bytes.iter().any(|&byte| !self.allowed.contains(byte)) {
                    Ok(())
                } else {
                    Err(Failure::NoByteOutsideSet)
                }
            }
        }
    }
}

pub(crate) fn parse_allowed(allowed: &str) -> CompileResult<AsciiSet> {
    if !allowed.is_ascii() {
        return fail(
            FallbackReason::InvalidValue,
            "`allowed` may only contain ASCII characters",
        );
    }
    let mut chars: Vec<u8> = Vec::with_capacity(allowed.len());
    // `true` marks a `-` that separates a range, as opposed to an escaped or edge `-`.
    let mut is_range_dash: Vec<bool> = Vec::with_capacity(allowed.len());
    let mut bytes = allowed.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            let Some(escaped) = bytes.next() else {
                return fail(
                    FallbackReason::InvalidValue,
                    "`allowed` ends with a lone `\\`",
                );
            };
            chars.push(escaped);
            is_range_dash.push(false);
        } else {
            chars.push(byte);
            is_range_dash.push(byte == b'-');
        }
    }
    if chars.is_empty() {
        return fail(FallbackReason::InvalidValue, "`allowed` must not be empty");
    }
    let mut set = AsciiSet::default();
    let mut index = 0;
    while let Some(&low) = chars.get(index) {
        let next_is_range_dash = is_range_dash.get(index + 1).copied().unwrap_or(false);
        match (next_is_range_dash, chars.get(index + 2)) {
            (true, Some(&high)) => {
                if low > high {
                    return fail(
                        FallbackReason::InvalidValue,
                        format!(
                            "`allowed` has a reversed range `{}-{}`",
                            low as char, high as char
                        ),
                    );
                }
                for byte in low..=high {
                    set.insert(byte);
                }
                index += 3;
            }
            _ => {
                set.insert(low);
                index += 1;
            }
        }
    }
    Ok(set)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{
        assert_fallback, chain, evaluates_to, step,
    };
    use serde_json::json;

    fn charset(allowed: &str, mode: &str) -> serde_json::Value {
        chain(vec![step(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": allowed, "mode": mode}),
            json!({}),
        )])
    }

    fn set_of(allowed: &str) -> AsciiSet {
        match parse_allowed(allowed) {
            Ok(set) => set,
            Err(failure) => panic!("{failure:?}"),
        }
    }

    #[test]
    fn mode_outcomes() {
        let default_mode = chain(vec![step(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": "a-z"}),
            json!({}),
        )]);
        for (config, input, outcome) in [
            (default_mode.clone(), "abc", ChainOutcome::Valid),
            (default_mode, "abC", ChainOutcome::Invalid),
            (charset("a-z", "all"), "ab\u{f1}", ChainOutcome::Invalid),
            (
                charset("0-9a-f", "any_outside"),
                "abcz",
                ChainOutcome::Valid,
            ),
            (
                charset("0-9a-f", "any_outside"),
                "abc123",
                ChainOutcome::Invalid,
            ),
        ] {
            evaluates_to(&config, input, outcome);
        }
    }

    #[test]
    fn dashes_are_literal_at_edges_or_escaped() {
        assert!(set_of("-a").contains(b'-'));
        assert!(set_of("a-").contains(b'-'));
        assert!(!set_of("a-c").contains(b'-'));
        let escaped = set_of("a\\-c");
        assert!(escaped.contains(b'-'));
        assert!(!escaped.contains(b'b'));
    }

    #[test]
    fn invalid_allowed_is_invalid_value() {
        for allowed in ["a-z\u{e9}", "z-a", "", "a\\"] {
            assert_fallback(&charset(allowed, "all"), FallbackReason::InvalidValue);
        }
    }

    #[test]
    fn declaring_an_output_on_a_check_is_malformed() {
        assert_fallback(
            &chain(vec![step(
                "Charset",
                json!({"param": "$GLOBAL_MATCH", "allowed": "a"}),
                json!({"x": "$OUTPUT"}),
            )]),
            FallbackReason::Malformed,
        );
    }
}
