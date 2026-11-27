//! `Encode` and `Decode`: text encodings of bytes and ints.
//!
//! Schemes: `hex`, `base62` (alphabet `0-9A-Za-z`, as used by GitHub tokens), `base64`,
//! `base64url`, `base64_nopad`, `base64url_nopad`. Padded base64 schemes require canonical
//! padding when decoding; `_nopad` schemes reject it.
//!
//! # Encode
//!
//! Inputs: `param` (bytes or int), `scheme`, `case` (`lower`, the default, or `upper`; hex only),
//! `width` (int param, hex or base62 only), `endian` (`big`, the default, or `little`; int param,
//! hex or base64 only).
//! - Bytes are encoded as-is (base62 has no byte form: `malformed`).
//! - For hex and base64, an int is first serialized to `bits / 8` bytes in `endian` order, so a
//!   CRC32 always yields 8 hex digits (or 6 base64-nopad characters).
//! - For base62, the numeric value is encoded.
//! - `width` zero-pads on the left. It defaults to the minimum digit count that fits any value
//!   of the int's `bits` (8 hex / 6 base62 digits for 32 bits). It must be at least that count
//!   (`invalid_value`), so every value fits, and at most 64 (`limit_exceeded`).
//!
//! Runtime failures (see [`EncodeFailure::class`]):
//! - scratch budget exceeded: **error**.
//!
//! # Decode
//!
//! Inputs: `param` (bytes), `scheme`, `as` (`bytes`, the default, or `int`), `endian` (`as: int`
//! with hex or base64 only; default `big`), `on_failure` (`pass` or `fail`, optional). base62
//! only decodes `as: int`. `as: int` produces an int with `bits = 64`. Hex accepts mixed case.
//!
//! `on_failure` lets the rule decide what any decoding failure below means, ending the chain:
//! `pass` keeps the match, `fail` drops it. Every decoding failure is already negative, so `fail`
//! only states the default explicitly. Scratch budget failures are not decoding failures and stay
//! **errors** whatever `on_failure` says.
//!
//! Runtime failures (see [`DecodeFailure::class`]). Text that does not decode, or decodes to
//! something the chain cannot use, means the token is not genuine:
//! - a character outside the alphabet: **negative**;
//! - odd-length hex (hex is decoded byte-wise, also for `as: int`): **negative**;
//! - base64 with invalid length, padding or trailing bits: **negative**;
//! - empty input with `as: int`: **negative** (there is no number);
//! - `as: int` overflow: **negative**, since no checksum this engine computes is wider than 64
//!   bits. The length is checked before the content: hex longer than 16 digits, base64 longer
//!   than 12 characters or decoding to more than 8 bytes, and base62 values above `u64::MAX`;
//! - scratch budget exceeded: **error**.

use super::Operand;
use crate::secondary_validation::chained_step::FailureClass;
use crate::secondary_validation::chained_step::compile::{
    ChainBuilder, CompileResult, FallbackReason, StepInputs, StepOutputs, fail,
};
use crate::secondary_validation::chained_step::since::SinceTable;
use crate::secondary_validation::chained_step::value::{Frame, FrameFailure, SlotType, Value};
use base64::Engine;
use base64::engine::Config;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

pub(crate) const ENCODE_INPUT_KEYS: SinceTable<()> = &[
    ("param", (), 1),
    ("scheme", (), 1),
    ("case", (), 1),
    ("width", (), 1),
    ("endian", (), 1),
];

pub(crate) const DECODE_INPUT_KEYS: SinceTable<()> = &[
    ("param", (), 1),
    ("scheme", (), 1),
    ("as", (), 1),
    ("endian", (), 1),
    ("on_failure", (), 1),
];

pub(crate) const MAX_WIDTH: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scheme {
    Hex,
    Base62,
    Base64(Base64Variant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Base64Variant {
    Standard,
    UrlSafe,
    StandardNoPad,
    UrlSafeNoPad,
}

impl Base64Variant {
    fn engine(self) -> &'static GeneralPurpose {
        match self {
            Base64Variant::Standard => &STANDARD,
            Base64Variant::UrlSafe => &URL_SAFE,
            Base64Variant::StandardNoPad => &STANDARD_NO_PAD,
            Base64Variant::UrlSafeNoPad => &URL_SAFE_NO_PAD,
        }
    }
}

pub(super) const SCHEMES: SinceTable<Scheme> = &[
    ("hex", Scheme::Hex, 1),
    ("base62", Scheme::Base62, 1),
    ("base64", Scheme::Base64(Base64Variant::Standard), 1),
    ("base64url", Scheme::Base64(Base64Variant::UrlSafe), 1),
    (
        "base64_nopad",
        Scheme::Base64(Base64Variant::StandardNoPad),
        1,
    ),
    (
        "base64url_nopad",
        Scheme::Base64(Base64Variant::UrlSafeNoPad),
        1,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Lower,
    Upper,
}

const CASES: SinceTable<Case> = &[("lower", Case::Lower, 1), ("upper", Case::Upper, 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Endian {
    Big,
    Little,
}

pub(super) const ENDIANS: SinceTable<Endian> =
    &[("big", Endian::Big, 1), ("little", Endian::Little, 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeAs {
    Bytes,
    Int,
}

const DECODE_AS: SinceTable<DecodeAs> = &[("bytes", DecodeAs::Bytes, 1), ("int", DecodeAs::Int, 1)];

const DECODED_INT_BITS: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnFailure {
    Pass,
    Fail,
}

const ON_FAILURE: SinceTable<OnFailure> =
    &[("pass", OnFailure::Pass, 1), ("fail", OnFailure::Fail, 1)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeFailure {
    Frame(FrameFailure),
}

impl EncodeFailure {
    pub fn class(self) -> FailureClass {
        match self {
            EncodeFailure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for EncodeFailure {
    fn from(failure: FrameFailure) -> Self {
        EncodeFailure::Frame(failure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeFailure {
    InvalidCharacter,
    OddLength,
    InvalidBase64,
    EmptyInput,
    Overflow,
    Frame(FrameFailure),
}

impl DecodeFailure {
    pub fn class(self) -> FailureClass {
        match self {
            DecodeFailure::InvalidCharacter => FailureClass::Negative,
            DecodeFailure::OddLength => FailureClass::Negative,
            DecodeFailure::InvalidBase64 => FailureClass::Negative,
            DecodeFailure::EmptyInput => FailureClass::Negative,
            DecodeFailure::Overflow => FailureClass::Negative,
            DecodeFailure::Frame(_) => FailureClass::Error,
        }
    }
}

impl From<FrameFailure> for DecodeFailure {
    fn from(failure: FrameFailure) -> Self {
        DecodeFailure::Frame(failure)
    }
}

#[derive(Debug, Clone, Copy)]
enum EncodeForm {
    HexBytes {
        case: Case,
    },
    HexInt {
        case: Case,
        byte_len: usize,
        endian: Endian,
        width: usize,
    },
    Base62Int {
        width: usize,
    },
    Base64Bytes {
        variant: Base64Variant,
    },
    Base64Int {
        variant: Base64Variant,
        byte_len: usize,
        endian: Endian,
    },
}

#[derive(Debug)]
pub(crate) struct Encode {
    param: Operand,
    form: EncodeForm,
    output: Option<usize>,
}

impl Encode {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_operand("param", builder)?;
        let scheme = inputs.required_choice("scheme", SCHEMES, builder)?;
        let case = inputs.choice("case", CASES, builder)?;
        let width = inputs.unsigned("width")?;
        let endian = inputs.choice("endian", ENDIANS, builder)?;

        if case.is_some() && scheme != Scheme::Hex {
            return fail(FallbackReason::InvalidValue, "`case` only applies to `hex`");
        }
        if let Some(width) = width {
            if param.ty == SlotType::Bytes {
                return fail(FallbackReason::Malformed, "`width` requires an int `param`");
            }
            if !matches!(scheme, Scheme::Hex | Scheme::Base62) {
                return fail(
                    FallbackReason::InvalidValue,
                    "`width` only applies to `hex` and `base62`",
                );
            }
            if width > MAX_WIDTH {
                return fail(
                    FallbackReason::LimitExceeded,
                    format!("`width` must be at most {MAX_WIDTH}"),
                );
            }
        }
        if endian.is_some() {
            if param.ty == SlotType::Bytes {
                return fail(
                    FallbackReason::Malformed,
                    "`endian` requires an int `param`",
                );
            }
            if scheme == Scheme::Base62 {
                return fail(
                    FallbackReason::InvalidValue,
                    "`endian` does not apply to `base62`, which encodes the numeric value",
                );
            }
        }
        // `width` is at most 64 here, so the conversion cannot fail.
        let width = width.and_then(|width| usize::try_from(width).ok());
        let case = case.unwrap_or(Case::Lower);
        let endian = endian.unwrap_or(Endian::Big);

        let form = match (scheme, param.ty) {
            (Scheme::Hex, SlotType::Bytes) => EncodeForm::HexBytes { case },
            (Scheme::Hex, SlotType::Int { bits }) => {
                let byte_len = usize::from(bits / 8);
                let natural_width = byte_len * 2;
                let width = width.unwrap_or(natural_width);
                if width < natural_width {
                    return fail(
                        FallbackReason::InvalidValue,
                        format!("`width` must be at least {natural_width} for a {bits}-bit int"),
                    );
                }
                EncodeForm::HexInt {
                    case,
                    byte_len,
                    endian,
                    width,
                }
            }
            (Scheme::Base62, SlotType::Bytes) => {
                return fail(
                    FallbackReason::Malformed,
                    "`base62` encodes ints only, but `param` is bytes",
                );
            }
            (Scheme::Base62, SlotType::Int { bits }) => {
                let natural_width = max_base62_digits(bits);
                let width = width.unwrap_or(natural_width);
                if width < natural_width {
                    return fail(
                        FallbackReason::InvalidValue,
                        format!("`width` must be at least {natural_width} for a {bits}-bit int"),
                    );
                }
                EncodeForm::Base62Int { width }
            }
            (Scheme::Base64(variant), SlotType::Bytes) => EncodeForm::Base64Bytes { variant },
            (Scheme::Base64(variant), SlotType::Int { bits }) => EncodeForm::Base64Int {
                variant,
                byte_len: usize::from(bits / 8),
                endian,
            },
        };
        let output = outputs.single("Encode", SlotType::Bytes, builder)?;
        Ok(Self {
            param,
            form,
            output,
        })
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), EncodeFailure> {
        let span = match self.form {
            EncodeForm::HexBytes { case } => {
                let source = self.param.load_span(frame)?;
                let encoded_len = source
                    .len()
                    .checked_mul(2)
                    .ok_or(FrameFailure::ValueTooLarge)?;
                frame.write_scratch(Some(source), encoded_len, |bytes, out| {
                    write_hex(bytes, case, out)
                })?
            }
            EncodeForm::HexInt {
                case,
                byte_len,
                endian,
                width,
            } => {
                let mut buffer = [0u8; 8];
                let bytes =
                    int_to_bytes(self.param.load_int(frame)?, byte_len, endian, &mut buffer)?;
                frame.write_scratch(None, width, |_, out| {
                    let padding = width.saturating_sub(bytes.len() * 2);
                    let (pad, digits) = out
                        .split_at_mut_checked(padding)
                        .ok_or(FrameFailure::DanglingReference)?;
                    pad.fill(b'0');
                    write_hex(bytes, case, digits)?;
                    Ok::<usize, EncodeFailure>(width)
                })?
            }
            EncodeForm::Base62Int { width } => {
                let mut digits = [0u8; 22];
                let digit_count = base62::encode_bytes(self.param.load_int(frame)?, &mut digits)
                    .map_err(|_| FrameFailure::DanglingReference)?;
                let digits = digits
                    .get(..digit_count)
                    .ok_or(FrameFailure::DanglingReference)?;
                // Compile time guarantees `width` fits any value of the slot's `bits`.
                let padding = width
                    .checked_sub(digit_count)
                    .ok_or(FrameFailure::DanglingReference)?;
                frame.write_scratch(None, width, |_, out| {
                    let (pad, tail) = out
                        .split_at_mut_checked(padding)
                        .ok_or(FrameFailure::DanglingReference)?;
                    pad.fill(b'0');
                    tail.copy_from_slice(digits);
                    Ok::<usize, EncodeFailure>(width)
                })?
            }
            EncodeForm::Base64Bytes { variant } => {
                let source = self.param.load_span(frame)?;
                write_base64(frame, variant, Some(source), source.len(), None)?
            }
            EncodeForm::Base64Int {
                variant,
                byte_len,
                endian,
            } => {
                let mut buffer = [0u8; 8];
                let bytes =
                    int_to_bytes(self.param.load_int(frame)?, byte_len, endian, &mut buffer)?;
                write_base64(frame, variant, None, bytes.len(), Some(bytes))?
            }
        };
        frame.store(self.output, Value::Bytes(span))?;
        Ok(())
    }
}

/// Base64-encodes either a frame span (`source`) or a small stack buffer (`direct`).
fn write_base64(
    frame: &mut Frame<'_>,
    variant: Base64Variant,
    source: Option<crate::secondary_validation::chained_step::value::Span>,
    input_len: usize,
    direct: Option<&[u8]>,
) -> Result<crate::secondary_validation::chained_step::value::Span, EncodeFailure> {
    let engine = variant.engine();
    let encoded_len = base64::encoded_len(input_len, engine.config().encode_padding())
        .ok_or(FrameFailure::ValueTooLarge)?;
    frame.write_scratch(source, encoded_len, |bytes, out| {
        let input = direct.unwrap_or(bytes);
        engine
            .encode_slice(input, out)
            .map_err(|_| EncodeFailure::Frame(FrameFailure::DanglingReference))
    })
}

fn write_hex(bytes: &[u8], case: Case, out: &mut [u8]) -> Result<usize, EncodeFailure> {
    let alphabet: &[u8; 16] = match case {
        Case::Lower => b"0123456789abcdef",
        Case::Upper => b"0123456789ABCDEF",
    };
    if out.len() < bytes.len() * 2 {
        return Err(FrameFailure::DanglingReference.into());
    }
    let (pairs, _) = out.as_chunks_mut::<2>();
    for (byte, pair) in bytes.iter().zip(pairs.iter_mut()) {
        let high = alphabet
            .get(usize::from(byte >> 4))
            .copied()
            .unwrap_or(b'0');
        let low = alphabet
            .get(usize::from(byte & 0xF))
            .copied()
            .unwrap_or(b'0');
        *pair = [high, low];
    }
    Ok(bytes.len() * 2)
}

fn int_to_bytes(
    value: u64,
    byte_len: usize,
    endian: Endian,
    buffer: &mut [u8; 8],
) -> Result<&[u8], FrameFailure> {
    let range = match endian {
        Endian::Big => {
            *buffer = value.to_be_bytes();
            8usize
                .checked_sub(byte_len)
                .ok_or(FrameFailure::DanglingReference)?..8
        }
        Endian::Little => {
            *buffer = value.to_le_bytes();
            0..byte_len
        }
    };
    buffer.get(range).ok_or(FrameFailure::DanglingReference)
}

/// The number of base62 digits needed for the largest `bits`-bit value.
pub(super) fn max_base62_digits(bits: u8) -> usize {
    let mut remaining = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut digits = 1;
    while remaining >= 62 {
        remaining /= 62;
        digits += 1;
    }
    digits
}

#[derive(Debug, Clone, Copy)]
enum DecodeForm {
    HexBytes,
    HexInt {
        endian: Endian,
    },
    Base62Int,
    Base64Bytes {
        variant: Base64Variant,
    },
    Base64Int {
        variant: Base64Variant,
        endian: Endian,
    },
}

#[derive(Debug)]
pub(crate) struct Decode {
    param: Operand,
    form: DecodeForm,
    on_failure: Option<OnFailure>,
    output: Option<usize>,
}

/// 16 hex digits = 8 bytes = the largest int.
const MAX_HEX_INT_DIGITS: usize = 16;
/// 12 base64 characters decode to at most 9 bytes; anything longer certainly overflows.
pub(super) const MAX_BASE64_INT_CHARS: usize = 12;

impl Decode {
    pub fn compile(
        inputs: &StepInputs<'_>,
        outputs: StepOutputs<'_>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        let param = inputs.required_bytes_operand("param", builder)?;
        let scheme = inputs.required_choice("scheme", SCHEMES, builder)?;
        let decode_as = inputs.choice("as", DECODE_AS, builder)?;
        let endian = inputs.choice("endian", ENDIANS, builder)?;
        let on_failure = inputs.choice("on_failure", ON_FAILURE, builder)?;

        let decode_as = match (scheme, decode_as) {
            (Scheme::Base62, Some(DecodeAs::Bytes)) => {
                return fail(
                    FallbackReason::InvalidValue,
                    "`base62` decodes `as: int` only",
                );
            }
            (Scheme::Base62, None) => DecodeAs::Int,
            (_, decode_as) => decode_as.unwrap_or(DecodeAs::Bytes),
        };
        if endian.is_some() && (decode_as != DecodeAs::Int || scheme == Scheme::Base62) {
            return fail(
                FallbackReason::InvalidValue,
                "`endian` only applies to `as: int` with `hex` or base64 schemes",
            );
        }
        let endian = endian.unwrap_or(Endian::Big);
        let form = match (scheme, decode_as) {
            (Scheme::Hex, DecodeAs::Bytes) => DecodeForm::HexBytes,
            (Scheme::Hex, DecodeAs::Int) => DecodeForm::HexInt { endian },
            (Scheme::Base62, _) => DecodeForm::Base62Int,
            (Scheme::Base64(variant), DecodeAs::Bytes) => DecodeForm::Base64Bytes { variant },
            (Scheme::Base64(variant), DecodeAs::Int) => DecodeForm::Base64Int { variant, endian },
        };
        let output_type = match decode_as {
            DecodeAs::Bytes => SlotType::Bytes,
            DecodeAs::Int => SlotType::Int {
                bits: DECODED_INT_BITS,
            },
        };
        let output = outputs.single("Decode", output_type, builder)?;
        Ok(Self {
            param,
            form,
            on_failure,
            output,
        })
    }

    /// `on_failure` overrides how a decoding failure is classified. Failures of the engine itself
    /// (`Frame`, e.g. the scratch budget) are not decoding failures and keep their class.
    pub fn classify(&self, failure: DecodeFailure) -> FailureClass {
        match (self.on_failure, failure) {
            (_, DecodeFailure::Frame(_)) | (None, _) => failure.class(),
            (Some(OnFailure::Pass), _) => FailureClass::Pass,
            (Some(OnFailure::Fail), _) => FailureClass::Negative,
        }
    }

    pub fn run(&self, frame: &mut Frame<'_>) -> Result<(), DecodeFailure> {
        let source = self.param.load_span(frame)?;
        let value = match self.form {
            DecodeForm::HexBytes => {
                if source.len() % 2 != 0 {
                    return Err(DecodeFailure::OddLength);
                }
                let span = frame.write_scratch(Some(source), source.len() / 2, decode_hex)?;
                Value::Bytes(span)
            }
            DecodeForm::HexInt { endian } => {
                let text = frame.bytes(source)?;
                if text.len() > MAX_HEX_INT_DIGITS {
                    return Err(DecodeFailure::Overflow);
                }
                if text.is_empty() {
                    return Err(DecodeFailure::EmptyInput);
                }
                if text.len() % 2 != 0 {
                    return Err(DecodeFailure::OddLength);
                }
                let mut buffer = [0u8; 8];
                let written = decode_hex(text, &mut buffer)?;
                let bytes = buffer
                    .get(..written)
                    .ok_or(DecodeFailure::Frame(FrameFailure::DanglingReference))?;
                Value::Int(bytes_to_int(bytes, endian))
            }
            DecodeForm::Base62Int => {
                let text = frame.bytes(source)?;
                let decoded = base62::decode(text).map_err(|error| match error {
                    base62::DecodeError::EmptyInput => DecodeFailure::EmptyInput,
                    base62::DecodeError::InvalidBase62Byte(_, _) => DecodeFailure::InvalidCharacter,
                    base62::DecodeError::ArithmeticOverflow => DecodeFailure::Overflow,
                })?;
                Value::Int(u64::try_from(decoded).map_err(|_| DecodeFailure::Overflow)?)
            }
            DecodeForm::Base64Bytes { variant } => {
                let estimate = base64::decoded_len_estimate(source.len());
                let span = frame.write_scratch(Some(source), estimate, |text, out| {
                    decode_base64(variant, text, out)
                })?;
                Value::Bytes(span)
            }
            DecodeForm::Base64Int { variant, endian } => {
                let text = frame.bytes(source)?;
                if text.len() > MAX_BASE64_INT_CHARS {
                    return Err(DecodeFailure::Overflow);
                }
                let mut buffer = [0u8; 9];
                let written = decode_base64(variant, text, &mut buffer)?;
                if written == 0 {
                    return Err(DecodeFailure::EmptyInput);
                }
                if written > 8 {
                    return Err(DecodeFailure::Overflow);
                }
                let bytes = buffer
                    .get(..written)
                    .ok_or(DecodeFailure::Frame(FrameFailure::DanglingReference))?;
                Value::Int(bytes_to_int(bytes, endian))
            }
        };
        frame.store(self.output, value)?;
        Ok(())
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Callers check that `text` has even length.
pub(super) fn decode_hex(text: &[u8], out: &mut [u8]) -> Result<usize, DecodeFailure> {
    let decoded_len = text.len() / 2;
    if out.len() < decoded_len {
        return Err(FrameFailure::DanglingReference.into());
    }
    let (pairs, remainder) = text.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(DecodeFailure::OddLength);
    }
    for (&[high, low], byte) in pairs.iter().zip(out.iter_mut()) {
        let (Some(high), Some(low)) = (hex_digit(high), hex_digit(low)) else {
            return Err(DecodeFailure::InvalidCharacter);
        };
        *byte = high << 4 | low;
    }
    Ok(decoded_len)
}

pub(super) fn decode_base64(
    variant: Base64Variant,
    text: &[u8],
    out: &mut [u8],
) -> Result<usize, DecodeFailure> {
    variant
        .engine()
        .decode_slice(text, out)
        .map_err(|error| match error {
            base64::DecodeSliceError::DecodeError(_) => DecodeFailure::InvalidBase64,
            base64::DecodeSliceError::OutputSliceTooSmall => {
                DecodeFailure::Frame(FrameFailure::DanglingReference)
            }
        })
}

pub(super) fn bytes_to_int(bytes: &[u8], endian: Endian) -> u64 {
    let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
    match endian {
        Endian::Big => bytes.iter().fold(0, fold),
        Endian::Little => bytes.iter().rev().fold(0, fold),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secondary_validation::chained_step::ChainOutcome;
    use crate::secondary_validation::chained_step::test::{
        assert_fallback, chain, check, evaluates_to, step,
    };
    use serde_json::{Value as JsonValue, json};

    /// `GLOBAL_MATCH` is `<text>|<expected>`; the chain encodes `<text>` and compares.
    fn encode_bytes_chain(encode_inputs: JsonValue) -> JsonValue {
        let mut inputs = encode_inputs;
        if let Some(map) = inputs.as_object_mut() {
            map.insert("param".into(), json!("$text"));
        }
        chain(vec![
            split_pipe(),
            step("Encode", inputs, json!("encoded")),
            check(
                "Compare",
                json!({"a": "$encoded", "b": "$expected", "operator": "="}),
            ),
        ])
    }

    /// `GLOBAL_MATCH` is `<crc input>|<expected>`; encodes the CRC32 of `<crc input>`.
    fn encode_crc_chain(encode_inputs: JsonValue) -> JsonValue {
        let mut inputs = encode_inputs;
        if let Some(map) = inputs.as_object_mut() {
            map.insert("param".into(), json!("$crc"));
        }
        chain(vec![
            split_pipe(),
            step(
                "Checksum",
                json!({"param": "$text", "alg": "crc32"}),
                json!("crc"),
            ),
            step("Encode", inputs, json!("encoded")),
            check(
                "Compare",
                json!({"a": "$encoded", "b": "$expected", "operator": "="}),
            ),
        ])
    }

    /// `GLOBAL_MATCH` is `<encoded>|<expected decimal or text>`.
    fn decode_chain(decode_inputs: JsonValue) -> JsonValue {
        let mut inputs = decode_inputs;
        let as_int = inputs.get("as") == Some(&json!("int"))
            || inputs.get("scheme") == Some(&json!("base62"));
        if let Some(map) = inputs.as_object_mut() {
            map.insert("param".into(), json!("$text"));
        }
        let mut steps = vec![split_pipe(), step("Decode", inputs, json!("decoded"))];
        if as_int {
            steps.push(step(
                "Format",
                json!({"template": "{decoded}"}),
                json!("rendered"),
            ));
            steps.push(check(
                "Compare",
                json!({"a": "$rendered", "b": "$expected", "operator": "="}),
            ));
        } else {
            steps.push(check(
                "Compare",
                json!({"a": "$decoded", "b": "$expected", "operator": "="}),
            ));
        }
        chain(steps)
    }

    fn split_pipe() -> JsonValue {
        step(
            "Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "|", "occurrence": 0}),
            json!({"before": "text", "after": "expected"}),
        )
    }

    fn crc_of(text: &str) -> u32 {
        crc32fast::hash(text.as_bytes())
    }

    // ---- Encode ----

    #[test]
    fn encode_bytes_hex_case() {
        for (inputs, input) in [
            (json!({"scheme": "hex"}), "\u{1}\u{7f}z|017f7a"),
            (json!({"scheme": "hex", "case": "upper"}), "z|7A"),
        ] {
            evaluates_to(&encode_bytes_chain(inputs), input, ChainOutcome::Valid);
        }
    }

    #[test]
    fn encode_int_hex_endian() {
        let input = "abcdef1234567890";
        let crc = crc_of(input);
        for (inputs, expected) in [
            (json!({"scheme": "hex"}), crc),
            (
                json!({"scheme": "hex", "endian": "little"}),
                crc.swap_bytes(),
            ),
        ] {
            evaluates_to(
                &encode_crc_chain(inputs),
                &format!("{input}|{expected:08x}"),
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn encode_int_default_width_fits_any_32_bit_value() {
        // CRC32("") is 0, so the whole output is padding.
        for (scheme, expected) in [("hex", "00000000"), ("base62", "000000")] {
            evaluates_to(
                &encode_crc_chain(json!({"scheme": scheme})),
                &format!("|{expected}"),
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn encode_width_pads_left_with_zero_digits() {
        for (scheme, width, expected) in [("hex", 10, "0000000000"), ("base62", 8, "00000000")] {
            evaluates_to(
                &encode_crc_chain(json!({"scheme": scheme, "width": width})),
                &format!("|{expected}"),
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn encode_bytes_base64_padded_and_unpadded() {
        for (scheme, input) in [("base64", "ab|YWI="), ("base64_nopad", "ab|YWI")] {
            evaluates_to(
                &encode_bytes_chain(json!({"scheme": scheme})),
                input,
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn base64url_uses_url_alphabet() {
        // 0xFB 0xFF encodes to "+/8=" in the standard alphabet.
        let config = chain(vec![
            step(
                "Decode",
                json!({"param": "-_8=", "scheme": "base64url"}),
                json!("raw"),
            ),
            step(
                "Encode",
                json!({"param": "$raw", "scheme": "base64"}),
                json!("standard"),
            ),
            step(
                "Encode",
                json!({"param": "$raw", "scheme": "base64url_nopad"}),
                json!("url"),
            ),
            step(
                "Format",
                json!({"template": "{standard} {url}"}),
                json!("both"),
            ),
            check(
                "Compare",
                json!({"a": "$both", "b": "$GLOBAL_MATCH", "operator": "="}),
            ),
        ]);
        evaluates_to(&config, "+/8= -_8", ChainOutcome::Valid);
    }

    #[test]
    fn encode_invalid_input_combinations_fall_back() {
        for (config, reason) in [
            (
                encode_bytes_chain(json!({"scheme": "base64", "case": "upper"})),
                FallbackReason::InvalidValue,
            ),
            (
                encode_bytes_chain(json!({"scheme": "hex", "width": 8})),
                FallbackReason::Malformed,
            ),
            (
                encode_crc_chain(json!({"scheme": "base64", "width": 8})),
                FallbackReason::InvalidValue,
            ),
            (
                encode_crc_chain(json!({"scheme": "base62", "width": 5})),
                FallbackReason::InvalidValue,
            ),
            (
                encode_crc_chain(json!({"scheme": "base62", "width": 65})),
                FallbackReason::LimitExceeded,
            ),
            (
                encode_crc_chain(json!({"scheme": "base62", "width": "6"})),
                FallbackReason::InvalidValue,
            ),
            (
                encode_crc_chain(json!({"scheme": "hex", "width": 7})),
                FallbackReason::InvalidValue,
            ),
            (
                encode_bytes_chain(json!({"scheme": "hex", "endian": "little"})),
                FallbackReason::Malformed,
            ),
            (
                encode_crc_chain(json!({"scheme": "base62", "endian": "little"})),
                FallbackReason::InvalidValue,
            ),
            (
                encode_bytes_chain(json!({"scheme": "base62"})),
                FallbackReason::Malformed,
            ),
        ] {
            assert_fallback(&config, reason);
        }
    }

    #[test]
    fn encode_hex_of_large_value_past_budget_is_error() {
        evaluates_to(
            &encode_bytes_chain(json!({"scheme": "hex"})),
            &format!("{}|x", "a".repeat(2049)),
            ChainOutcome::Error,
        );
    }

    #[test]
    fn max_base62_digits_matches_bit_widths() {
        // 64 bits takes the branch that avoids overflowing `1 << bits`.
        assert_eq!(max_base62_digits(32), 6);
        assert_eq!(max_base62_digits(64), 11);
    }

    // ---- Decode ----

    #[test]
    fn decode_hex_bytes_accepts_mixed_case() {
        evaluates_to(
            &decode_chain(json!({"scheme": "hex"})),
            "7a7A|zz",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn decode_hex_odd_length_is_negative() {
        evaluates_to(
            &decode_chain(json!({"scheme": "hex"})),
            "7a7|z",
            ChainOutcome::Invalid,
        );
    }

    #[test]
    fn decode_hex_invalid_character_is_negative() {
        evaluates_to(
            &decode_chain(json!({"scheme": "hex"})),
            "7g|z",
            ChainOutcome::Invalid,
        );
    }

    #[test]
    fn decode_base62_invalid_character_is_negative() {
        evaluates_to(
            &decode_chain(json!({"scheme": "base62"})),
            "L-Z|0",
            ChainOutcome::Invalid,
        );
    }

    #[test]
    fn decode_int_endian() {
        // "0102" and "AQI" both decode to the bytes 0x01 0x02.
        for (inputs, input) in [
            (json!({"scheme": "hex", "as": "int"}), "0102|258"),
            (
                json!({"scheme": "hex", "as": "int", "endian": "little"}),
                "0102|513",
            ),
            (json!({"scheme": "base64_nopad", "as": "int"}), "AQI|258"),
            (
                json!({"scheme": "base64_nopad", "as": "int", "endian": "little"}),
                "AQI|513",
            ),
        ] {
            evaluates_to(&decode_chain(inputs), input, ChainOutcome::Valid);
        }
    }

    #[test]
    fn decode_base62_defaults_to_int() {
        evaluates_to(
            &decode_chain(json!({"scheme": "base62"})),
            "LZ|1337",
            ChainOutcome::Valid,
        );
    }

    #[test]
    fn decode_int_of_empty_input_is_negative() {
        for inputs in [
            json!({"scheme": "hex", "as": "int"}),
            json!({"scheme": "base62"}),
            json!({"scheme": "base64", "as": "int"}),
        ] {
            evaluates_to(&decode_chain(inputs), "|0", ChainOutcome::Invalid);
        }
    }

    #[test]
    fn decode_int_of_u64_max_is_valid() {
        for (inputs, encoded) in [
            (
                json!({"scheme": "hex", "as": "int"}),
                "ffffffffffffffff".to_string(),
            ),
            (json!({"scheme": "base62"}), base62::encode(u64::MAX)),
        ] {
            evaluates_to(
                &decode_chain(inputs),
                &format!("{encoded}|{}", u64::MAX),
                ChainOutcome::Valid,
            );
        }
    }

    #[test]
    fn decode_int_overflow_is_negative() {
        for (inputs, encoded) in [
            (
                json!({"scheme": "hex", "as": "int"}),
                "000000000000000001".to_string(),
            ),
            (
                json!({"scheme": "base62"}),
                base62::encode(u128::from(u64::MAX) + 1),
            ),
            // Above u128: the base62 decoder itself overflows.
            (json!({"scheme": "base62"}), "z".repeat(30)),
            // 9 bytes, within the 12-character pre-check.
            (
                json!({"scheme": "base64", "as": "int"}),
                "AAAAAAAAAAAA".to_string(),
            ),
            (
                json!({"scheme": "base64", "as": "int"}),
                "AAAAAAAAAAAAAAAA".to_string(),
            ),
        ] {
            evaluates_to(
                &decode_chain(inputs),
                &format!("{encoded}|0"),
                ChainOutcome::Invalid,
            );
        }
    }

    #[test]
    fn decode_base64_padding_follows_scheme() {
        for (scheme, encoded, outcome) in [
            ("base64", "YWI=", ChainOutcome::Valid),
            ("base64", "YWI", ChainOutcome::Invalid),
            ("base64_nopad", "YWI", ChainOutcome::Valid),
            ("base64_nopad", "YWI=", ChainOutcome::Invalid),
        ] {
            evaluates_to(
                &decode_chain(json!({"scheme": scheme})),
                &format!("{encoded}|ab"),
                outcome,
            );
        }
    }

    #[test]
    fn decode_invalid_input_combinations_fall_back() {
        let crc_then_decode = chain(vec![
            step(
                "Checksum",
                json!({"param": "$GLOBAL_MATCH", "alg": "crc32"}),
                json!("crc"),
            ),
            step(
                "Decode",
                json!({"param": "$crc", "scheme": "hex"}),
                json!("decoded"),
            ),
        ]);
        for (config, reason) in [
            (
                decode_chain(json!({"scheme": "base62", "as": "bytes"})),
                FallbackReason::InvalidValue,
            ),
            (
                decode_chain(json!({"scheme": "hex", "endian": "little"})),
                FallbackReason::InvalidValue,
            ),
            (
                decode_chain(json!({"scheme": "base62", "endian": "little"})),
                FallbackReason::InvalidValue,
            ),
            (crc_then_decode, FallbackReason::Malformed),
        ] {
            assert_fallback(&config, reason);
        }
    }

    #[test]
    fn hex_round_trip_over_all_ascii_bytes() {
        let config = chain(vec![
            step(
                "Encode",
                json!({"param": "$GLOBAL_MATCH", "scheme": "hex"}),
                json!("encoded"),
            ),
            step(
                "Decode",
                json!({"param": "$encoded", "scheme": "hex"}),
                json!("decoded"),
            ),
            check(
                "Compare",
                json!({"a": "$decoded", "b": "$GLOBAL_MATCH", "operator": "="}),
            ),
        ]);
        let all_ascii: String = (0u8..128).map(char::from).collect();
        evaluates_to(&config, &all_ascii, ChainOutcome::Valid);
    }

    #[test]
    fn on_failure_pass_keeps_the_match_on_a_decoding_failure() {
        let config = chain(vec![step(
            "Decode",
            json!({"param": "$GLOBAL_MATCH", "scheme": "hex", "on_failure": "pass"}),
            json!("decoded"),
        )]);
        evaluates_to(&config, "zz", ChainOutcome::Valid);
    }

    #[test]
    fn on_failure_does_not_override_budget_errors() {
        // 6000 base64 characters decode to more than the 4 KiB per-value budget.
        let config = chain(vec![step(
            "Decode",
            json!({"param": "$GLOBAL_MATCH", "scheme": "base64", "on_failure": "pass"}),
            json!("decoded"),
        )]);
        evaluates_to(&config, &"A".repeat(6000), ChainOutcome::Error);
    }
}
