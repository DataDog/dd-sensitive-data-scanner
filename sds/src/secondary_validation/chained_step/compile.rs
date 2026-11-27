//! Build-time half of the chain: version gate, config validation, variable resolution and type
//! inference. Every field is read out of a `serde_json::Value`, so no config shape can fail to
//! deserialize or panic; it can only be refused or fall back.

use super::ops::{self, Operand};
use super::since::{self, FeatureRequirement, SinceTable};
use super::value::{MAX_VALUE_LEN, SlotType, Source, Span, Value};
use super::{CHAINED_STEP_VALIDATOR_VERSION, CompiledChain};
use serde_json::{Map, Value as JsonValue};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt;

pub(crate) const MAX_STEPS: usize = 32;
/// Includes the predefined `$GLOBAL_MATCH` slot.
pub(crate) const MAX_SLOTS: usize = 32;
pub(crate) const MAX_REGEXES: usize = 4;
/// Bounds the literal pool so every literal offset fits a `u32` span with a wide margin.
const MAX_LITERAL_POOL_LEN: usize = 64 * 1024;

pub(crate) const GLOBAL_MATCH: &str = "GLOBAL_MATCH";
pub(crate) const OUTPUT: &str = "OUTPUT";
const RESERVED_NAMES: [&str; 2] = [GLOBAL_MATCH, OUTPUT];

/// Why a chain resolves to its `default_response` at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FallbackReason {
    UnknownOp,
    UnknownField,
    InvalidValue,
    LimitExceeded,
    /// Structurally wrong: missing required field, empty steps, read before write, reserved or
    /// duplicate variable name, type mismatch, unknown placeholder or output source.
    Malformed,
}

impl FallbackReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            FallbackReason::UnknownOp => "unknown_op",
            FallbackReason::UnknownField => "unknown_field",
            FallbackReason::InvalidValue => "invalid_value",
            FallbackReason::LimitExceeded => "limit_exceeded",
            FallbackReason::Malformed => "malformed",
        }
    }
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build-time result of [`compile_chain`]. Version refusals disable the rule; `Fallback` means the
/// validator becomes its constant `default_response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainCompileError {
    FutureVersion {
        declared: u64,
        supported: u32,
    },
    MissingVersion,
    InvalidVersion,
    Fallback {
        reason: FallbackReason,
        step_index: Option<usize>,
        step_name: Option<String>,
        detail: String,
    },
}

impl fmt::Display for ChainCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainCompileError::FutureVersion {
                declared,
                supported,
            } => write!(
                f,
                "future_version: chain version {declared} is newer than the supported version {supported}"
            ),
            ChainCompileError::MissingVersion => {
                f.write_str("missing_version: the chain config has no `version`")
            }
            ChainCompileError::InvalidVersion => {
                f.write_str("invalid_version: `version` must be a positive integer")
            }
            ChainCompileError::Fallback {
                reason,
                step_index,
                step_name,
                detail,
            } => {
                write_location(f, *step_index, step_name.as_deref())?;
                write!(f, "{reason}: {detail}")
            }
        }
    }
}

impl std::error::Error for ChainCompileError {}

/// Strict, authoring-time validation failure from [`validate_chain_strict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainValidationError {
    Compile(ChainCompileError),
    /// The chain uses a feature introduced after its declared `version`, so a runtime that only
    /// supports the declared version would not understand it.
    UnderDeclaredVersion {
        declared: u32,
        required: u32,
        feature: String,
        step_index: Option<usize>,
        step_name: Option<String>,
    },
}

impl fmt::Display for ChainValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainValidationError::Compile(error) => error.fmt(f),
            ChainValidationError::UnderDeclaredVersion {
                declared,
                required,
                feature,
                step_index,
                step_name,
            } => {
                write_location(f, *step_index, step_name.as_deref())?;
                write!(
                    f,
                    "under_declared_version: {feature} requires version {required}, but the chain declares version {declared}"
                )
            }
        }
    }
}

impl std::error::Error for ChainValidationError {}

fn write_location(
    f: &mut fmt::Formatter<'_>,
    step_index: Option<usize>,
    step_name: Option<&str>,
) -> fmt::Result {
    match (step_index, step_name) {
        (Some(index), Some(name)) => write!(f, "step {index} ({name:?}): "),
        (Some(index), None) => write!(f, "step {index}: "),
        (None, _) => f.write_str("config: "),
    }
}

/// A build-time failure before its step location is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompileFailure {
    pub reason: FallbackReason,
    pub detail: String,
}

pub(crate) type CompileResult<T> = Result<T, CompileFailure>;

pub(crate) fn fail<T>(reason: FallbackReason, detail: impl Into<String>) -> CompileResult<T> {
    Err(CompileFailure {
        reason,
        detail: detail.into(),
    })
}

/// Compiles the validator `config` object (`default_response` is not part of it).
pub fn compile_chain(config: &JsonValue) -> Result<CompiledChain, ChainCompileError> {
    let JsonValue::Object(config) = config else {
        return Err(ChainCompileError::Fallback {
            reason: FallbackReason::Malformed,
            step_index: None,
            step_name: None,
            detail: format!("config must be an object, got {}", json_kind(config)),
        });
    };
    // The version gate runs before anything else so a future chain is refused even when the rest
    // of it would not parse on this runtime.
    let declared_version = check_version(config)?;
    let mut builder = ChainBuilder::new();
    let steps = compile_steps(config, &mut builder).map_err(|failure| {
        let (step_index, step_name) = builder.current_step.clone();
        ChainCompileError::Fallback {
            reason: failure.reason,
            step_index,
            step_name,
            detail: failure.detail,
        }
    })?;
    Ok(CompiledChain {
        steps,
        slot_count: builder.slot_types.len(),
        literals: builder.literals,
        declared_version,
        required_version: builder.requirement,
    })
}

/// Rejects everything [`compile_chain`] would refuse or fall back on, plus chains whose declared
/// `version` is lower than a feature they use.
pub fn validate_chain_strict(config: &JsonValue) -> Result<(), ChainValidationError> {
    let chain = compile_chain(config).map_err(ChainValidationError::Compile)?;
    check_declared_version(chain.declared_version, chain.required_version.as_ref())
}

pub(crate) fn check_declared_version(
    declared: u32,
    requirement: Option<&FeatureRequirement>,
) -> Result<(), ChainValidationError> {
    match requirement {
        Some(requirement) if requirement.since > declared => {
            Err(ChainValidationError::UnderDeclaredVersion {
                declared,
                required: requirement.since,
                feature: requirement.feature.clone(),
                step_index: requirement.step_index,
                step_name: requirement.step_name.clone(),
            })
        }
        _ => Ok(()),
    }
}

fn check_version(config: &Map<String, JsonValue>) -> Result<u32, ChainCompileError> {
    let version = config
        .get("version")
        .ok_or(ChainCompileError::MissingVersion)?;
    let declared = version
        .as_u64()
        .filter(|&declared| declared > 0)
        .ok_or(ChainCompileError::InvalidVersion)?;
    match u32::try_from(declared) {
        Ok(declared) if declared <= CHAINED_STEP_VALIDATOR_VERSION => Ok(declared),
        _ => Err(ChainCompileError::FutureVersion {
            declared,
            supported: CHAINED_STEP_VALIDATOR_VERSION,
        }),
    }
}

fn compile_steps(
    config: &Map<String, JsonValue>,
    builder: &mut ChainBuilder,
) -> CompileResult<Vec<ops::CompiledOp>> {
    check_keys(config, since::CONFIG_KEYS, "config", builder)?;
    let steps = match config.get("steps") {
        None => return fail(FallbackReason::Malformed, "`steps` is required"),
        Some(JsonValue::Array(steps)) => steps,
        Some(other) => {
            return fail(
                FallbackReason::InvalidValue,
                format!("`steps` must be a list, got {}", json_kind(other)),
            );
        }
    };
    if steps.is_empty() {
        return fail(FallbackReason::Malformed, "`steps` must not be empty");
    }
    if steps.len() > MAX_STEPS {
        return fail(
            FallbackReason::LimitExceeded,
            format!("at most {MAX_STEPS} steps are allowed, got {}", steps.len()),
        );
    }
    let mut compiled = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        builder.current_step = (Some(index), None);
        compiled.push(compile_step(step, builder)?);
    }
    builder.current_step = (None, None);
    Ok(compiled)
}

fn compile_step(step: &JsonValue, builder: &mut ChainBuilder) -> CompileResult<ops::CompiledOp> {
    let JsonValue::Object(step) = step else {
        return fail(
            FallbackReason::InvalidValue,
            format!("a step must be an object, got {}", json_kind(step)),
        );
    };
    match step.get("name") {
        None => {}
        Some(JsonValue::String(name)) => builder.current_step.1 = Some(name.clone()),
        Some(other) => {
            return fail(
                FallbackReason::InvalidValue,
                format!("`name` must be a string, got {}", json_kind(other)),
            );
        }
    }
    check_keys(step, since::STEP_KEYS, "step", builder)?;
    if let Some(comment) = step.get("comment")
        && !comment.is_string()
    {
        return fail(
            FallbackReason::InvalidValue,
            format!("`comment` must be a string, got {}", json_kind(comment)),
        );
    }
    let op = match step.get("op") {
        None => return fail(FallbackReason::Malformed, "`op` is required"),
        Some(JsonValue::String(op)) => op,
        Some(other) => {
            return fail(
                FallbackReason::InvalidValue,
                format!("`op` must be a string, got {}", json_kind(other)),
            );
        }
    };
    let Some((kind, op_since)) = since::lookup(since::OPS, op) else {
        return fail(FallbackReason::UnknownOp, format!("unknown op `{op}`"));
    };
    builder.require(op_since, || format!("op `{op}`"));
    let inputs = match step.get("input") {
        Some(JsonValue::Object(inputs)) => Some(inputs),
        Some(other) => {
            return fail(
                FallbackReason::InvalidValue,
                format!("`input` must be an object, got {}", json_kind(other)),
            );
        }
        None => None,
    };
    let inputs = StepInputs::new(inputs, ops::input_keys(kind), op, builder)?;
    let outputs = StepOutputs::parse(step.get("output"))?;
    ops::compile_op(kind, &inputs, outputs, builder)
}

fn check_keys(
    object: &Map<String, JsonValue>,
    table: SinceTable<()>,
    context: &str,
    builder: &mut ChainBuilder,
) -> CompileResult<()> {
    for key in object.keys() {
        let Some(((), key_since)) = since::lookup(table, key) else {
            return fail(
                FallbackReason::UnknownField,
                format!("unknown {context} field `{key}`"),
            );
        };
        builder.require(key_since, || format!("{context} field `{key}`"));
    }
    Ok(())
}

pub(crate) fn json_kind(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "a boolean",
        JsonValue::Number(_) => "a number",
        JsonValue::String(_) => "a string",
        JsonValue::Array(_) => "a list",
        JsonValue::Object(_) => "an object",
    }
}

/// Build-time state shared across steps: variable scope, slot types and the literal pool.
pub(crate) struct ChainBuilder {
    variables: HashMap<String, usize>,
    slot_types: Vec<SlotType>,
    literals: Vec<u8>,
    regex_count: usize,
    requirement: Option<FeatureRequirement>,
    current_step: (Option<usize>, Option<String>),
}

impl ChainBuilder {
    fn new() -> Self {
        let mut variables = HashMap::new();
        variables.insert(GLOBAL_MATCH.to_string(), 0);
        Self {
            variables,
            slot_types: vec![SlotType::Bytes],
            literals: Vec::new(),
            regex_count: 0,
            requirement: None,
            current_step: (None, None),
        }
    }

    pub fn require(&mut self, feature_since: u32, feature: impl FnOnce() -> String) {
        let already_required = self
            .requirement
            .as_ref()
            .is_some_and(|requirement| requirement.since >= feature_since);
        if !already_required {
            self.requirement = Some(FeatureRequirement {
                since: feature_since,
                feature: feature(),
                step_index: self.current_step.0,
                step_name: self.current_step.1.clone(),
            });
        }
    }

    pub fn add_literal(&mut self, bytes: &[u8]) -> CompileResult<Span> {
        if bytes.len() > MAX_VALUE_LEN {
            return fail(
                FallbackReason::LimitExceeded,
                format!("a literal is limited to {MAX_VALUE_LEN} bytes"),
            );
        }
        let start = self.literals.len();
        let end = start + bytes.len();
        if end > MAX_LITERAL_POOL_LEN {
            return fail(
                FallbackReason::LimitExceeded,
                format!("the chain's literals are limited to {MAX_LITERAL_POOL_LEN} bytes"),
            );
        }
        let (Ok(start), Ok(end)) = (u32::try_from(start), u32::try_from(end)) else {
            return fail(FallbackReason::LimitExceeded, "literal pool too large");
        };
        self.literals.extend_from_slice(bytes);
        Ok(Span {
            source: Source::Literal,
            start,
            end,
        })
    }

    pub fn variable(&self, name: &str) -> CompileResult<Operand> {
        if name == OUTPUT {
            return fail(
                FallbackReason::Malformed,
                "`$OUTPUT` is an output source and cannot be read",
            );
        }
        let Some(&slot) = self.variables.get(name) else {
            return fail(
                FallbackReason::Malformed,
                format!("`${name}` is read before it is defined"),
            );
        };
        let Some(&ty) = self.slot_types.get(slot) else {
            return fail(FallbackReason::Malformed, format!("`${name}` has no slot"));
        };
        Ok(Operand::slot(slot, ty))
    }

    pub fn define(&mut self, name: &str, ty: SlotType) -> CompileResult<usize> {
        if RESERVED_NAMES.contains(&name) {
            return fail(
                FallbackReason::Malformed,
                format!("`{name}` is a reserved name and cannot be written"),
            );
        }
        if !is_valid_variable_name(name) {
            return fail(
                FallbackReason::InvalidValue,
                format!("`{name}` is not a valid variable name (expected [A-Za-z_][A-Za-z0-9_]*)"),
            );
        }
        if self.variables.contains_key(name) {
            return fail(
                FallbackReason::Malformed,
                format!("`{name}` is already defined"),
            );
        }
        if self.slot_types.len() >= MAX_SLOTS {
            return fail(
                FallbackReason::LimitExceeded,
                format!("at most {MAX_SLOTS} variables are allowed, including $GLOBAL_MATCH"),
            );
        }
        let slot = self.slot_types.len();
        self.slot_types.push(ty);
        self.variables.insert(name.to_string(), slot);
        Ok(slot)
    }

    pub fn register_regex(&mut self) -> CompileResult<()> {
        if self.regex_count >= MAX_REGEXES {
            return fail(
                FallbackReason::LimitExceeded,
                format!("at most {MAX_REGEXES} regexes are allowed per chain"),
            );
        }
        self.regex_count += 1;
        Ok(())
    }
}

pub(crate) fn is_valid_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// What a string means once the `$` convention is applied.
enum Reference<'a> {
    Literal(&'a str),
    Variable(&'a str),
}

/// `$name` is a variable reference, `$$...` is a literal starting with `$`, anything else is a
/// literal.
fn parse_reference(raw: &str) -> Reference<'_> {
    match raw.strip_prefix('$') {
        Some(rest) if rest.starts_with('$') => Reference::Literal(rest),
        Some(name) => Reference::Variable(name),
        None => Reference::Literal(raw),
    }
}

/// The `input` object of one step, with its keys already checked against the op's table.
pub(crate) struct StepInputs<'a> {
    map: Option<&'a Map<String, JsonValue>>,
}

impl<'a> StepInputs<'a> {
    fn new(
        map: Option<&'a Map<String, JsonValue>>,
        allowed: SinceTable<()>,
        op: &str,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Self> {
        if let Some(map) = map {
            for key in map.keys() {
                let Some(((), key_since)) = since::lookup(allowed, key) else {
                    return fail(
                        FallbackReason::UnknownField,
                        format!("unknown input `{key}` for op `{op}`"),
                    );
                };
                builder.require(key_since, || format!("input `{key}` of op `{op}`"));
            }
        }
        Ok(Self { map })
    }

    fn raw(&self, key: &str) -> Option<&'a JsonValue> {
        self.map.and_then(|map| map.get(key))
    }

    fn string(&self, key: &str) -> CompileResult<Option<&'a str>> {
        match self.raw(key) {
            None => Ok(None),
            Some(JsonValue::String(value)) => Ok(Some(value)),
            Some(other) => fail(
                FallbackReason::InvalidValue,
                format!("input `{key}` must be a string, got {}", json_kind(other)),
            ),
        }
    }

    /// A data input: a variable reference or a literal.
    pub fn operand(&self, key: &str, builder: &mut ChainBuilder) -> CompileResult<Option<Operand>> {
        let Some(raw) = self.string(key)? else {
            return Ok(None);
        };
        match parse_reference(raw) {
            Reference::Variable("") => fail(
                FallbackReason::InvalidValue,
                format!(
                    "input `{key}`: `$` must be followed by a variable name (use `$$` for a literal `$`)"
                ),
            ),
            Reference::Variable(name) => builder.variable(name).map(Some),
            Reference::Literal(literal) => {
                let span = builder.add_literal(literal.as_bytes())?;
                Ok(Some(Operand::constant(Value::Bytes(span))))
            }
        }
    }

    pub fn required_operand(
        &self,
        key: &str,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Operand> {
        self.operand(key, builder)?.map_or_else(|| missing(key), Ok)
    }

    /// A bytes data input; an `Int` variable here is a type mismatch.
    pub fn required_bytes_operand(
        &self,
        key: &str,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Operand> {
        let operand = self.required_operand(key, builder)?;
        if operand.ty != SlotType::Bytes {
            return fail(
                FallbackReason::Malformed,
                format!("input `{key}` must be bytes, got an int"),
            );
        }
        Ok(operand)
    }

    /// A configuration input: always a literal, so `$name` is rejected (`$$` still escapes).
    pub fn literal(&self, key: &str) -> CompileResult<Option<&'a str>> {
        let Some(raw) = self.string(key)? else {
            return Ok(None);
        };
        match parse_reference(raw) {
            Reference::Literal(literal) => Ok(Some(literal)),
            Reference::Variable(_) => fail(
                FallbackReason::InvalidValue,
                format!(
                    "input `{key}` does not accept variable references (use `$$` for a literal `$`)"
                ),
            ),
        }
    }

    pub fn required_literal(&self, key: &str) -> CompileResult<&'a str> {
        self.literal(key)?.map_or_else(|| missing(key), Ok)
    }

    /// A configuration input restricted to the names of `table`.
    pub fn choice<T: Copy>(
        &self,
        key: &str,
        table: SinceTable<T>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<Option<T>> {
        let Some(name) = self.literal(key)? else {
            return Ok(None);
        };
        let Some((value, value_since)) = since::lookup(table, name) else {
            let expected: Vec<&str> = table.iter().map(|(name, _, _)| *name).collect();
            return fail(
                FallbackReason::InvalidValue,
                format!(
                    "input `{key}`: unknown value `{name}` (expected one of {})",
                    expected.join(", ")
                ),
            );
        };
        builder.require(value_since, || format!("value `{name}` of input `{key}`"));
        Ok(Some(value))
    }

    pub fn required_choice<T: Copy>(
        &self,
        key: &str,
        table: SinceTable<T>,
        builder: &mut ChainBuilder,
    ) -> CompileResult<T> {
        self.choice(key, table, builder)?
            .map_or_else(|| missing(key), Ok)
    }

    pub fn unsigned(&self, key: &str) -> CompileResult<Option<u64>> {
        match self.raw(key) {
            None => Ok(None),
            Some(value) => match value.as_u64() {
                Some(number) => Ok(Some(number)),
                None => fail(
                    FallbackReason::InvalidValue,
                    format!(
                        "input `{key}` must be a non-negative integer, got {}",
                        json_kind(value)
                    ),
                ),
            },
        }
    }
}

fn missing<T>(key: &str) -> CompileResult<T> {
    fail(
        FallbackReason::Malformed,
        format!("input `{key}` is required"),
    )
}

/// The `output` object of one step: new variable name -> `$source`.
pub(crate) struct StepOutputs<'a> {
    entries: SmallVec<[(&'a str, &'a str); 4]>,
}

impl<'a> StepOutputs<'a> {
    fn parse(output: Option<&'a JsonValue>) -> CompileResult<Self> {
        let mut entries = SmallVec::new();
        let map = match output {
            None => return Ok(Self { entries }),
            Some(JsonValue::Object(map)) => map,
            Some(other) => {
                return fail(
                    FallbackReason::InvalidValue,
                    format!("`output` must be an object, got {}", json_kind(other)),
                );
            }
        };
        for (name, source) in map {
            let JsonValue::String(source) = source else {
                return fail(
                    FallbackReason::InvalidValue,
                    format!(
                        "output `{name}` must be a `$source` string, got {}",
                        json_kind(source)
                    ),
                );
            };
            let source = match parse_reference(source) {
                Reference::Variable(source) if !source.is_empty() => source,
                _ => {
                    return fail(
                        FallbackReason::InvalidValue,
                        format!("output `{name}` must reference a `$source`, got `{source}`"),
                    );
                }
            };
            entries.push((name.as_str(), source));
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[(&'a str, &'a str)] {
        &self.entries
    }

    /// For ops with no result (checks): any output is an error.
    pub fn none(self, op: &str) -> CompileResult<()> {
        match self.entries.first() {
            None => Ok(()),
            Some((name, _)) => fail(
                FallbackReason::Malformed,
                format!("op `{op}` produces no output, but `{name}` is declared"),
            ),
        }
    }

    /// For ops with a single result: every output must read `$OUTPUT`.
    pub fn single(self, ty: SlotType, builder: &mut ChainBuilder) -> CompileResult<OutputSlots> {
        let mut slots = OutputSlots::new();
        for (name, source) in self.entries {
            if source != OUTPUT {
                return fail(
                    FallbackReason::Malformed,
                    format!("output `{name}`: unknown source `${source}` (expected `$OUTPUT`)"),
                );
            }
            slots.push(builder.define(name, ty)?);
        }
        Ok(slots)
    }
}

pub(crate) type OutputSlots = SmallVec<[usize; 2]>;
