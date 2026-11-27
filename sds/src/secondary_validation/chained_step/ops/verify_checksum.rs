//! `VerifyChecksum`: checks that `embedded` encodes the checksum of `payload`.
//!
//! Inputs: `payload` (bytes), `embedded` (bytes), `alg` (as in `Checksum`: `crc32`), `scheme`
//! (`hex`, `base62`, `base64`, `base64url`, `base64_nopad`, `base64url_nopad`), `endian` (`big`,
//! the default, or `little`; hex and base64 schemes only, `invalid_value` on base62). It has no
//! result, so declaring an `output` is `malformed`.
//!
//! `embedded` is decoded and compared with the checksum by value, instead of re-encoding the
//! checksum and comparing text. That is why there is no `case`, `width` or comparison operator:
//! - hex and base64: `embedded` must decode to exactly `bits / 8` bytes (4 for crc32), read in
//!   `endian` order. Hex accepts either case.
//! - base62: the numeric value is compared, so leading zero digits are not required. The rule's
//!   regex pins the checksum length, which is what keeps a short encoding from matching.
//!
//! Runtime failures (see [`Failure::class`]):
//! - `embedded` does not decode under `scheme`: **negative**;
//! - `embedded` decodes to the wrong number of bytes: **negative**;
//! - the decoded value differs from the checksum: **negative**.

use super::Operand;
use super::checksum::{ALGORITHMS, Algorithm};
use super::codec::{
    ENDIANS, Endian, MAX_BASE64_INT_CHARS, SCHEMES, Scheme, bytes_to_int, decode_base64, decode_hex,
};
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{Frame, FrameFailure};

pub(crate) const INPUT_KEYS: SinceTable<()> = &[
    ("payload", (), 1),
    ("embedded", (), 1),
    ("alg", (), 1),
    ("scheme", (), 1),
    ("endian", (), 1),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Undecodable,
    WrongLength,
    Mismatch,
    Frame(FrameFailure),
}

impl Failure {
    pub fn class(self) -> FailureClass {
        match self {
            Failure::Undecodable => FailureClass::Negative,
            Failure::WrongLength => FailureClass::Negative,
            Failure::Mismatch => FailureClass::Negative,
            Failure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for Failure {
    fn from(failure: FrameFailure) -> Self {
        Failure::Frame(failure)
    }
}

impl From<super::codec::DecodeFailure> for Failure {
    fn from(failure: super::codec::DecodeFailure) -> Self {
        match failure {
            super::codec::DecodeFailure::Frame(failure) => Failure::Frame(failure),
            _ => Failure::Undecodable,
        }
    }
}

#[derive(Debug)]
pub(crate) struct VerifyChecksum {
    payload: Operand,
    embedded: Operand,
    algorithm: Algorithm,
    scheme: Scheme,
    endian: Endian,
}

impl VerifyChecksum {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let payload = inputs.required_bytes_operand("payload", builder)?;
        let embedded = inputs.required_bytes_operand("embedded", builder)?;
        let algorithm = inputs.required_choice("alg", ALGORITHMS, builder)?;
        let scheme = inputs.required_choice("scheme", SCHEMES, builder)?;
        let endian = inputs.choice("endian", ENDIANS, builder)?;
        if endian.is_some() && scheme == Scheme::Base62 {
            return fail(
                FallbackReason::InvalidValue,
                "`endian` does not apply to `base62`, which encodes the numeric value",
            );
        }
        outputs.none("VerifyChecksum")?;
        Ok(Self {
            payload,
            embedded,
            algorithm,
            scheme,
            endian: endian.unwrap_or(Endian::Big),
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), Failure> {
        let checksum = self
            .algorithm
            .compute(frame.bytes(self.payload.load_span(frame)?)?);
        let embedded = frame.bytes(self.embedded.load_span(frame)?)?;
        let byte_len = usize::from(self.algorithm.bits() / 8);
        let mut buffer = [0u8; 9];
        let embedded_value = match self.scheme {
            Scheme::Base62 => base62::decode(embedded).map_err(|_| Failure::Undecodable)?,
            Scheme::Hex => {
                if embedded.len() != byte_len * 2 {
                    return Err(Failure::WrongLength);
                }
                let written = decode_hex(embedded, &mut buffer)?;
                u128::from(bytes_to_int(decoded(&buffer, written)?, self.endian))
            }
            Scheme::Base64(variant) => {
                // Bounds the decode to the stack buffer; anything longer has too many bytes.
                if embedded.len() > MAX_BASE64_INT_CHARS {
                    return Err(Failure::WrongLength);
                }
                let written = decode_base64(variant, embedded, &mut buffer)?;
                if written != byte_len {
                    return Err(Failure::WrongLength);
                }
                u128::from(bytes_to_int(decoded(&buffer, written)?, self.endian))
            }
        };
        if embedded_value == u128::from(checksum) {
            Ok(())
        } else {
            Err(Failure::Mismatch)
        }
    }
}

fn decoded(buffer: &[u8], written: usize) -> Result<&[u8], Failure> {
    buffer
        .get(..written)
        .ok_or(Failure::Frame(FrameFailure::DanglingReference))
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::compile::FallbackReason;
    use crate::secondary_validation::chained_step::test::{assert_fallback, chain, evaluates_to};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use serde_json::{Value as JsonValue, json};

    const PAYLOAD: &str = "foo";

    fn crc() -> u32 {
        crc32fast::hash(PAYLOAD.as_bytes())
    }

    /// Verifies the CRC32 of `foo` against the whole match.
    fn verify(extra_inputs: JsonValue) -> JsonValue {
        let mut inputs = json!({"payload": PAYLOAD, "embedded": "$GLOBAL_MATCH", "alg": "crc32"});
        if let (Some(inputs), Some(extra)) = (inputs.as_object_mut(), extra_inputs.as_object()) {
            inputs.extend(extra.clone());
        }
        chain(vec![json!({"op": "VerifyChecksum", "input": inputs})])
    }

    #[test]
    fn hex_accepts_either_case() {
        for embedded in [format!("{:08x}", crc()), format!("{:08X}", crc())] {
            evaluates_to(
                &verify(json!({"scheme": "hex"})),
                &embedded,
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn base62_compares_the_numeric_value() {
        evaluates_to(
            &verify(json!({"scheme": "base62"})),
            &base62::encode(crc()),
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn base64_nopad_decodes_the_checksum_bytes() {
        evaluates_to(
            &verify(json!({"scheme": "base64_nopad"})),
            &STANDARD_NO_PAD.encode(crc().to_be_bytes()),
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn endian_selects_the_byte_order() {
        let little_endian_hex = format!("{:08x}", crc().swap_bytes());
        for (endian, outcome) in [
            ("little", ChainOutcome::Valid),
            ("big", ChainOutcome::Invalid),
        ] {
            evaluates_to(
                &verify(json!({"scheme": "hex", "endian": endian})),
                &little_endian_hex,
                outcome,
            );
        }
    }

    #[test]
    fn mismatch_is_negative() {
        evaluates_to(
            &verify(json!({"scheme": "hex"})),
            &format!("{:08x}", crc() ^ 1),
            ChainOutcome::Invalid,
        );
    }

    #[test]
    fn undecodable_or_wrong_length_embedded_is_negative() {
        let crc_hex = format!("{:08x}", crc());
        for (scheme, embedded) in [
            ("hex", "zzzzzzzz".to_string()),
            ("hex", format!("{crc_hex}00")),
            ("hex", crc_hex[1..].to_string()),
            ("base62", "not-base62".to_string()),
            ("base62", "z".repeat(30)),
            ("base64_nopad", STANDARD_NO_PAD.encode([0u8; 5])),
            ("base64_nopad", "A".repeat(40)),
        ] {
            evaluates_to(
                &verify(json!({"scheme": scheme})),
                &embedded,
                ChainOutcome::Invalid,
            );
        }
    }

    #[test]
    fn invalid_configs_fall_back() {
        let with_output = chain(vec![json!({
            "op": "VerifyChecksum",
            "input": {"payload": PAYLOAD, "embedded": "$GLOBAL_MATCH", "alg": "crc32", "scheme": "hex"},
            "output": "ok"
        })]);
        for (config, reason) in [
            (
                verify(json!({"scheme": "base62", "endian": "little"})),
                FallbackReason::InvalidValue,
            ),
            (with_output, FallbackReason::Malformed),
            (verify(json!({})), FallbackReason::Malformed),
        ] {
            assert_fallback(&config, reason);
        }
    }
}
