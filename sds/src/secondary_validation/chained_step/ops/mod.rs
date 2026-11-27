//! The op catalogue. Each op module owns its input-key `since` table, its compile function and a
//! `Failure` enum whose `class()` is the single, auditable place where its runtime failures are
//! classified as negative checks or errors.

mod charset;
mod checksum;
mod codec;
mod compare;
mod extract;
mod format;
mod regex_match;
mod split;

use super::FailureClass;
use super::compile::{ChainBuilder, CompileResult, StepInputs, StepOutputs};
use super::since::{OpKind, SinceTable};
use super::value::{Frame, FrameFailure, SlotType, Value};

/// A data input resolved at compile time: either a slot or a constant (literal) value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Operand {
    source: OperandSource,
    pub ty: SlotType,
}

#[derive(Debug, Clone, Copy)]
enum OperandSource {
    Slot(usize),
    Constant(Value),
}

impl Operand {
    pub fn slot(slot: usize, ty: SlotType) -> Self {
        Self {
            source: OperandSource::Slot(slot),
            ty,
        }
    }

    pub fn constant(value: Value) -> Self {
        let ty = match value {
            Value::Bytes(_) => SlotType::Bytes,
            Value::Int(_) => SlotType::Int { bits: 64 },
        };
        Self {
            source: OperandSource::Constant(value),
            ty,
        }
    }

    pub fn load(&self, frame: &Frame<'_>) -> Result<Value, FrameFailure> {
        match self.source {
            OperandSource::Slot(slot) => frame.get(slot),
            OperandSource::Constant(value) => Ok(value),
        }
    }

    pub fn load_span(&self, frame: &Frame<'_>) -> Result<super::value::Span, FrameFailure> {
        match self.load(frame)? {
            Value::Bytes(span) => Ok(span),
            Value::Int(_) => Err(FrameFailure::DanglingReference),
        }
    }

    pub fn load_int(&self, frame: &Frame<'_>) -> Result<u64, FrameFailure> {
        match self.load(frame)? {
            Value::Int(value) => Ok(value),
            Value::Bytes(_) => Err(FrameFailure::DanglingReference),
        }
    }
}

#[derive(Debug)]
pub(crate) enum CompiledOp {
    Extract(extract::Extract),
    Split(split::Split),
    Charset(charset::Charset),
    RegexMatch(regex_match::RegexMatch),
    Format(format::Format),
    Checksum(checksum::Checksum),
    Encode(codec::Encode),
    Decode(codec::Decode),
    Compare(compare::Compare),
}

impl CompiledOp {
    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), FailureClass> {
        match self {
            CompiledOp::Extract(op) => op.run(frame).map_err(extract::Failure::class),
            CompiledOp::Split(op) => op.run(frame).map_err(split::Failure::class),
            CompiledOp::Charset(op) => op.run(frame).map_err(charset::Failure::class),
            CompiledOp::RegexMatch(op) => op.run(frame).map_err(regex_match::Failure::class),
            CompiledOp::Format(op) => op.run(frame).map_err(format::Failure::class),
            CompiledOp::Checksum(op) => op.run(frame).map_err(checksum::Failure::class),
            CompiledOp::Encode(op) => op.run(frame).map_err(codec::EncodeFailure::class),
            CompiledOp::Decode(op) => op.run(frame).map_err(|failure| op.classify(failure)),
            CompiledOp::Compare(op) => op.run(frame).map_err(compare::Failure::class),
        }
    }
}

pub(crate) fn input_keys(kind: OpKind) -> SinceTable<()> {
    match kind {
        OpKind::Extract => extract::INPUT_KEYS,
        OpKind::Split => split::INPUT_KEYS,
        OpKind::Charset => charset::INPUT_KEYS,
        OpKind::RegexMatch => regex_match::INPUT_KEYS,
        OpKind::Format => format::INPUT_KEYS,
        OpKind::Checksum => checksum::INPUT_KEYS,
        OpKind::Encode => codec::ENCODE_INPUT_KEYS,
        OpKind::Decode => codec::DECODE_INPUT_KEYS,
        OpKind::Compare => compare::INPUT_KEYS,
    }
}

pub(crate) fn compile_op(
    kind: OpKind,
    inputs: &StepInputs<'_>,
    outputs: StepOutputs<'_>,
    builder: &mut ChainBuilder,
) -> CompileResult<CompiledOp> {
    Ok(match kind {
        OpKind::Extract => {
            CompiledOp::Extract(extract::Extract::compile(inputs, outputs, builder)?)
        }
        OpKind::Split => CompiledOp::Split(split::Split::compile(inputs, outputs, builder)?),
        OpKind::Charset => {
            CompiledOp::Charset(charset::Charset::compile(inputs, outputs, builder)?)
        }
        OpKind::RegexMatch => {
            CompiledOp::RegexMatch(regex_match::RegexMatch::compile(inputs, outputs, builder)?)
        }
        OpKind::Format => CompiledOp::Format(format::Format::compile(inputs, outputs, builder)?),
        OpKind::Checksum => {
            CompiledOp::Checksum(checksum::Checksum::compile(inputs, outputs, builder)?)
        }
        OpKind::Encode => CompiledOp::Encode(codec::Encode::compile(inputs, outputs, builder)?),
        OpKind::Decode => CompiledOp::Decode(codec::Decode::compile(inputs, outputs, builder)?),
        OpKind::Compare => {
            CompiledOp::Compare(compare::Compare::compile(inputs, outputs, builder)?)
        }
    })
}
