//! `Format`: builds bytes from a template with `{var}` placeholders.
//!
//! Inputs: `template`. Placeholders name variables without the `$` (`{body}`, `{GLOBAL_MATCH}`);
//! `{{` and `}}` are literal braces. Bytes are copied verbatim and an int renders as decimal. The
//! template is parsed at compile time: an unclosed `{`, a lone `}` or an invalid placeholder name
//! is `invalid_value`, an undefined variable is `malformed`, and more than 16 placeholders is
//! `limit_exceeded`.
//!
//! Runtime failures (see [`Failure::class`]):
//! - the result exceeds the per-value or per-call scratch budget: **error**.

use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, OutputSlots, StepInputs, StepOutputs, fail,
    is_valid_variable_name,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{
    Frame, FrameFailure, SlotType, Span, Value,
};

use super::Operand;

pub(crate) const INPUT_KEYS: SinceTable<()> = &[("template", (), 1)];

pub(crate) const MAX_PLACEHOLDERS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for Failure {
    fn from(failure: FrameFailure) -> Self {
        Failure::Frame(failure)
    }
}

#[derive(Debug, Clone, Copy)]
enum Piece {
    Literal(Span),
    Variable(Operand),
}

#[derive(Debug)]
pub(crate) struct Format {
    pieces: Vec<Piece>,
    outputs: OutputSlots,
}

impl Format {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let template = inputs.required_literal("template")?;
        let pieces = parse_template(template, builder)?;
        let outputs = outputs.single(SlotType::Bytes, builder)?;
        Ok(Self { pieces, outputs })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let start = frame.begin_scratch_value();
        for piece in &self.pieces {
            match piece {
                Piece::Literal(span) => frame.append_span(start, *span)?,
                Piece::Variable(operand) => match operand.load(frame)? {
                    Value::Bytes(span) => frame.append_span(start, span)?,
                    Value::Int(value) => {
                        let mut digits = [0u8; 20];
                        let rendered = render_decimal(value, &mut digits);
                        frame.append_bytes(start, rendered)?;
                    }
                },
            }
        }
        let span = frame.end_scratch_value(start)?;
        frame.store_all(&self.outputs, Value::Bytes(span))?;
        Ok(())
    }
}

fn render_decimal(mut value: u64, buffer: &mut [u8; 20]) -> &[u8] {
    let mut start = buffer.len();
    loop {
        start -= 1;
        if let Some(digit) = buffer.get_mut(start) {
            // `value % 10` is below 10, so the cast cannot truncate.
            *digit = b'0' + (value % 10) as u8;
        }
        value /= 10;
        if value == 0 || start == 0 {
            break;
        }
    }
    buffer.get(start..).unwrap_or_default()
}

fn parse_template(template: &str, builder: &mut ChainBuilder) -> CompileResult<Vec<Piece>> {
    let mut pieces = Vec::new();
    let mut literal: Vec<u8> = Vec::new();
    let mut placeholder_count = 0;
    let mut rest = template;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("{{") {
            literal.push(b'{');
            rest = after;
        } else if let Some(after) = rest.strip_prefix("}}") {
            literal.push(b'}');
            rest = after;
        } else if let Some(after) = rest.strip_prefix('{') {
            let Some((name, after_placeholder)) = after.split_once('}') else {
                return fail(
                    FallbackReason::InvalidValue,
                    "`template` has an unclosed `{`",
                );
            };
            if !is_valid_variable_name(name) {
                return fail(
                    FallbackReason::InvalidValue,
                    format!("`template` has an invalid placeholder `{{{name}}}`"),
                );
            }
            placeholder_count += 1;
            if placeholder_count > MAX_PLACEHOLDERS {
                return fail(
                    FallbackReason::LimitExceeded,
                    format!("`template` may have at most {MAX_PLACEHOLDERS} placeholders"),
                );
            }
            if !literal.is_empty() {
                pieces.push(Piece::Literal(builder.add_literal(&literal)?));
                literal.clear();
            }
            pieces.push(Piece::Variable(builder.variable(name)?));
            rest = after_placeholder;
        } else if rest.starts_with('}') {
            return fail(
                FallbackReason::InvalidValue,
                "`template` has a lone `}` (use `}}`)",
            );
        } else {
            let next_brace = rest.find(['{', '}']).unwrap_or(rest.len());
            let (text, after) = rest.split_at_checked(next_brace).unwrap_or((rest, ""));
            literal.extend_from_slice(text.as_bytes());
            rest = after;
        }
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(builder.add_literal(&literal)?));
    }
    Ok(pieces)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{
        assert_fallback, chain, evaluates_to, step,
    };
    use serde_json::json;

    fn format_then_compare(template: &str, expected: &str) -> serde_json::Value {
        chain(vec![
            step(
                "Split",
                json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": 0, "part": "after"}),
                json!({"body": "$OUTPUT"}),
            ),
            step(
                "Format",
                json!({"template": template}),
                json!({"formatted": "$OUTPUT"}),
            ),
            step(
                "Compare",
                json!({"a": "$formatted", "b": expected, "config": "="}),
                json!({}),
            ),
        ])
    }

    #[test]
    fn substitutes_placeholders_and_literals() {
        evaluates_to(
            &format_then_compare("<{body}|{GLOBAL_MATCH}>", "<abc|tkn_abc>"),
            "tkn_abc",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn double_braces_are_literal() {
        evaluates_to(
            &format_then_compare("{{{body}}}", "{abc}"),
            "tkn_abc",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn renders_zero_and_u64_max() {
        let mut buffer = [0u8; 20];
        assert_eq!(render_decimal(0, &mut buffer), b"0");
        assert_eq!(
            render_decimal(u64::MAX, &mut buffer),
            u64::MAX.to_string().as_bytes()
        );
    }

    #[test]
    fn doubling_past_value_budget_is_error() {
        // Each Format doubles the value; 4 KiB is exceeded after a few steps.
        let mut steps = vec![step(
            "Format",
            json!({"template": "{GLOBAL_MATCH}{GLOBAL_MATCH}"}),
            json!({"v0": "$OUTPUT"}),
        )];
        for index in 1..8 {
            steps.push(step(
                "Format",
                json!({"template": format!("{{v{}}}{{v{}}}", index - 1, index - 1)}),
                json!({format!("v{index}"): "$OUTPUT"}),
            ));
        }
        evaluates_to(&chain(steps), &"x".repeat(64), ChainOutcome::Error);
    }

    #[test]
    fn many_values_past_call_budget_is_error() {
        // 5 values of 4 KiB each stay under the per-value limit but exceed 16 KiB per call.
        let steps = (0..5)
            .map(|index| {
                step(
                    "Format",
                    json!({"template": "{GLOBAL_MATCH}"}),
                    json!({format!("copy{index}"): "$OUTPUT"}),
                )
            })
            .collect();
        evaluates_to(&chain(steps), &"x".repeat(4096), ChainOutcome::Error);
    }

    #[test]
    fn invalid_templates_fall_back() {
        let too_many_placeholders = "{body}".repeat(17);
        for (template, reason) in [
            ("{body", FallbackReason::InvalidValue),
            ("a}b", FallbackReason::InvalidValue),
            ("{}", FallbackReason::InvalidValue),
            ("{nope}", FallbackReason::Malformed),
            (
                too_many_placeholders.as_str(),
                FallbackReason::LimitExceeded,
            ),
        ] {
            assert_fallback(&format_then_compare(template, "x"), reason);
        }
    }
}
