//! `Checksum`: computes a checksum over the bytes of `param`.
//!
//! Inputs: `param` (bytes), `alg` (`crc32`: CRC-32/ISO-HDLC, the IEEE polynomial used by
//! `crc32fast`). The output is an int with `bits = 32`.
//!
//! Runtime failures (see [`Failure::class`]): none besides value-model failures, which are
//! **errors**.

use super::Operand;
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, StepInputs, StepOutputs,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{Frame, FrameFailure, SlotType, Value};

pub(crate) const INPUT_KEYS: SinceTable<()> = &[("param", (), 1), ("alg", (), 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Algorithm {
    Crc32,
}

pub(super) const ALGORITHMS: SinceTable<Algorithm> = &[("crc32", Algorithm::Crc32, 1)];

impl Algorithm {
    pub(super) fn bits(self) -> u8 {
        match self {
            Algorithm::Crc32 => 32,
        }
    }

    pub(super) fn compute(self, bytes: &[u8]) -> u64 {
        match self {
            Algorithm::Crc32 => u64::from(crc32fast::hash(bytes)),
        }
    }
}

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

#[derive(Debug)]
pub(crate) struct Checksum {
    param: Operand,
    algorithm: Algorithm,
    output: Option<usize>,
}

impl Checksum {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_bytes_operand("param", builder)?;
        let algorithm = inputs.required_choice("alg", ALGORITHMS, builder)?;
        let output = outputs.single(
            "Checksum",
            SlotType::Int {
                bits: algorithm.bits(),
            },
            builder,
        )?;
        Ok(Self {
            param,
            algorithm,
            output,
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let bytes = frame.bytes(self.param.load_span(frame)?)?;
        let checksum = self.algorithm.compute(bytes);
        frame.store(self.output, Value::Int(checksum))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{chain, check, evaluates_to, step};
    use serde_json::json;

    #[test]
    fn crc32_is_the_ieee_variant() {
        // CRC-32/ISO-HDLC check value for "123456789"; other CRC-32 variants differ.
        let config = chain(vec![
            step(
                "Checksum",
                json!({"param": "123456789", "alg": "crc32"}),
                json!("crc"),
            ),
            step(
                "Encode",
                json!({"param": "$crc", "scheme": "hex", "case": "upper"}),
                json!("crc_hex"),
            ),
            check(
                "Compare",
                json!({"a": "$crc_hex", "b": "$GLOBAL_MATCH", "operator": "="}),
            ),
        ]);
        evaluates_to(&config, "CBF43926", ChainOutcome::Valid);
    }
}
