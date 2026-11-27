//! Shared helpers and chain-level tests (config shape, version gate, variables, budgets).

mod parity;
mod strict;
mod targets;

use super::compile::FallbackReason;
use super::{
    CHAINED_STEP_VALIDATOR_VERSION, ChainCompileError, ChainOutcome, CompiledChain, compile_chain,
};
use serde_json::{Value as JsonValue, json};

pub(crate) fn chain(steps: Vec<JsonValue>) -> JsonValue {
    json!({"version": CHAINED_STEP_VALIDATOR_VERSION, "steps": steps})
}

/// A step named after its op, so failure messages are predictable. `output` is a variable name
/// for single-result ops, or an object for Split.
pub(crate) fn step(op: &str, inputs: JsonValue, output: JsonValue) -> JsonValue {
    json!({"name": op.to_lowercase(), "op": op, "input": inputs, "output": output})
}

/// A step for an op with no result.
pub(crate) fn check(op: &str, inputs: JsonValue) -> JsonValue {
    json!({"name": op.to_lowercase(), "op": op, "input": inputs})
}

/// A RegexMatch step; `captures` maps new variables to group names.
pub(crate) fn regex_step(inputs: JsonValue, captures: JsonValue) -> JsonValue {
    json!({"name": "regexmatch", "op": "RegexMatch", "input": inputs, "captures": captures})
}

pub(crate) fn compiled(config: &JsonValue) -> CompiledChain {
    match compile_chain(config) {
        Ok(chain) => chain,
        Err(error) => panic!("chain should compile, got: {error}"),
    }
}

pub(crate) fn evaluates_to(config: &JsonValue, input: &str, expected: ChainOutcome) {
    assert_eq!(
        compiled(config).evaluate(input),
        expected,
        "input {input:?} with chain {config}"
    );
}

pub(crate) fn compile_error(config: &JsonValue) -> ChainCompileError {
    match compile_chain(config) {
        Ok(_) => panic!("chain should not compile: {config}"),
        Err(error) => error,
    }
}

pub(crate) fn assert_fallback(config: &JsonValue, expected: FallbackReason) {
    match compile_error(config) {
        ChainCompileError::Fallback { reason, .. } => {
            assert_eq!(reason, expected, "chain {config}")
        }
        other => panic!("expected fallback {expected:?}, got {other:?}"),
    }
}

fn charset_step() -> JsonValue {
    check(
        "Charset",
        json!({"param": "$GLOBAL_MATCH", "allowed": "a-z"}),
    )
}

fn with_field(mut value: JsonValue, key: &str, field: JsonValue) -> JsonValue {
    if let Some(map) = value.as_object_mut() {
        map.insert(key.to_string(), field);
    }
    value
}

fn without_field(mut value: JsonValue, key: &str) -> JsonValue {
    if let Some(map) = value.as_object_mut() {
        map.remove(key);
    }
    value
}

// ---- Version gate ----

#[test]
fn versions_up_to_supported_are_accepted() {
    for version in 1..=CHAINED_STEP_VALIDATOR_VERSION {
        evaluates_to(
            &json!({"version": version, "steps": [charset_step()]}),
            "abc",
            ChainOutcome::Valid,
        );
    }
}

#[test]
fn future_versions_are_refused() {
    // u64::MAX guards against truncating the declared version to u32 before comparing.
    for declared in [u64::from(CHAINED_STEP_VALIDATOR_VERSION) + 1, u64::MAX] {
        assert_eq!(
            compile_error(&json!({"version": declared, "steps": [charset_step()]})),
            ChainCompileError::FutureVersion {
                declared,
                supported: CHAINED_STEP_VALIDATOR_VERSION
            }
        );
    }
}

#[test]
fn future_version_is_refused_before_parsing_steps() {
    let declared = u64::from(CHAINED_STEP_VALIDATOR_VERSION) + 1;
    assert!(matches!(
        compile_error(&json!({"version": declared, "steps": "garbage", "future_key": 1})),
        ChainCompileError::FutureVersion { .. }
    ));
}

#[test]
fn missing_version_is_refused() {
    assert_eq!(
        compile_error(&json!({"steps": [charset_step()]})),
        ChainCompileError::MissingVersion
    );
}

#[test]
fn invalid_versions_are_refused() {
    for version in [json!(0), json!(-1), json!(1.5), json!("1")] {
        assert_eq!(
            compile_error(&json!({"version": version, "steps": [charset_step()]})),
            ChainCompileError::InvalidVersion,
            "version {version}"
        );
    }
}

// ---- Config shape ----

#[test]
fn wrongly_typed_fields_fall_back() {
    for (config, reason) in [
        (json!([charset_step()]), FallbackReason::Malformed),
        (
            json!({"version": 1, "steps": {"op": "Charset"}}),
            FallbackReason::InvalidValue,
        ),
        (chain(vec![json!("Charset")]), FallbackReason::InvalidValue),
        (
            chain(vec![with_field(charset_step(), "name", json!(1))]),
            FallbackReason::InvalidValue,
        ),
        (
            chain(vec![with_field(charset_step(), "comment", json!(["a"]))]),
            FallbackReason::InvalidValue,
        ),
        (
            chain(vec![with_field(charset_step(), "op", json!(1))]),
            FallbackReason::InvalidValue,
        ),
        (
            chain(vec![with_field(charset_step(), "input", json!("param"))]),
            FallbackReason::InvalidValue,
        ),
        (
            chain(vec![check("Charset", json!({"param": 1, "allowed": "a"}))]),
            FallbackReason::InvalidValue,
        ),
    ] {
        assert_fallback(&config, reason);
    }
}

/// Every way an `output` or `captures` field can have the wrong shape for its op.
#[test]
fn output_shape_errors_fall_back() {
    let extract = |output: JsonValue| {
        step(
            "Extract",
            json!({"param": "$GLOBAL_MATCH", "slice": "[0:1]"}),
            output,
        )
    };
    let split = |output: JsonValue| {
        step(
            "Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": 0}),
            output,
        )
    };
    let regex = |captures: JsonValue| {
        regex_step(
            json!({"param": "$GLOBAL_MATCH", "pattern": "(?<body>[a-z]+)"}),
            captures,
        )
    };
    for (step, reason) in [
        (extract(json!({"first": "x"})), FallbackReason::InvalidValue),
        (extract(json!(1)), FallbackReason::InvalidValue),
        (extract(json!("$first")), FallbackReason::InvalidValue),
        (
            with_field(extract(json!("first")), "captures", json!({"x": "body"})),
            FallbackReason::Malformed,
        ),
        (split(json!("tail")), FallbackReason::InvalidValue),
        (split(json!({"after": 1})), FallbackReason::InvalidValue),
        (split(json!({"middle": "x"})), FallbackReason::Malformed),
        (regex(json!(["body"])), FallbackReason::InvalidValue),
        (regex(json!({"body": 1})), FallbackReason::InvalidValue),
        (
            with_field(regex(json!({})), "output", json!("body")),
            FallbackReason::Malformed,
        ),
        (
            with_field(charset_step(), "output", json!("x")),
            FallbackReason::Malformed,
        ),
        (
            with_field(charset_step(), "captures", json!({})),
            FallbackReason::Malformed,
        ),
    ] {
        assert_fallback(&chain(vec![step]), reason);
    }
}

#[test]
fn missing_required_fields_are_malformed() {
    for config in [
        json!({"version": 1}),
        chain(vec![]),
        chain(vec![without_field(charset_step(), "op")]),
        chain(vec![json!({"op": "Charset"})]),
    ] {
        assert_fallback(&config, FallbackReason::Malformed);
    }
}

#[test]
fn unknown_fields_are_unknown_field() {
    for config in [
        with_field(chain(vec![charset_step()]), "extra", json!(1)),
        chain(vec![with_field(charset_step(), "params", json!({}))]),
        chain(vec![check(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": "a", "strict": true}),
        )]),
    ] {
        assert_fallback(&config, FallbackReason::UnknownField);
    }
}

#[test]
fn unknown_op_is_unknown_op() {
    assert_fallback(
        &chain(vec![check("JSONParse", json!({}))]),
        FallbackReason::UnknownOp,
    );
}

#[test]
fn unknown_choice_value_is_invalid_value() {
    assert_fallback(
        &chain(vec![check(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": "a", "mode": "some"}),
        )]),
        FallbackReason::InvalidValue,
    );
}

#[test]
fn step_limit_is_32() {
    evaluates_to(&chain(vec![charset_step(); 32]), "abc", ChainOutcome::Valid);
    assert_fallback(
        &chain(vec![charset_step(); 33]),
        FallbackReason::LimitExceeded,
    );
}

fn compare_with_literal_of_len(len: usize) -> JsonValue {
    check(
        "Compare",
        json!({"a": "$GLOBAL_MATCH", "b": "x".repeat(len), "operator": "!="}),
    )
}

#[test]
fn literal_limit_is_4_kib() {
    evaluates_to(
        &chain(vec![compare_with_literal_of_len(4096)]),
        "abc",
        ChainOutcome::Valid,
    );
    assert_fallback(
        &chain(vec![compare_with_literal_of_len(4097)]),
        FallbackReason::LimitExceeded,
    );
}

#[test]
fn literal_pool_limit_is_64_kib() {
    evaluates_to(
        &chain(vec![compare_with_literal_of_len(4096); 16]),
        "abc",
        ChainOutcome::Valid,
    );
    let mut over_the_pool = vec![compare_with_literal_of_len(4096); 16];
    over_the_pool.push(compare_with_literal_of_len(1));
    assert_fallback(&chain(over_the_pool), FallbackReason::LimitExceeded);
}

#[test]
fn unnamed_step_with_comment_is_accepted() {
    let config = chain(vec![json!({
        "comment": "letters only",
        "op": "Charset",
        "input": {"param": "$GLOBAL_MATCH", "allowed": "a-z"}
    })]);
    evaluates_to(&config, "abc", ChainOutcome::Valid);
}

#[test]
fn fallback_reports_step_index_and_name() {
    let config = chain(vec![charset_step(), check("Nope", json!({}))]);
    assert_eq!(
        compile_error(&config),
        ChainCompileError::Fallback {
            reason: FallbackReason::UnknownOp,
            step_index: Some(1),
            step_name: Some("nope".to_string()),
            detail: "unknown op `Nope`".to_string(),
        }
    );
}

// ---- Variables ----

fn extract_into(name: &str, param: &str) -> JsonValue {
    step(
        "Extract",
        json!({"param": param, "slice": "[0:1]"}),
        json!(name),
    )
}

#[test]
fn invalid_variable_flow_is_malformed() {
    for steps in [
        vec![
            extract_into("first", "$later"),
            extract_into("later", "$GLOBAL_MATCH"),
        ],
        vec![extract_into("same", "$same")],
        vec![extract_into("GLOBAL_MATCH", "$GLOBAL_MATCH")],
        vec![
            extract_into("x", "$GLOBAL_MATCH"),
            extract_into("x", "$GLOBAL_MATCH"),
        ],
    ] {
        assert_fallback(&chain(steps), FallbackReason::Malformed);
    }
}

#[test]
fn invalid_references_are_invalid_value() {
    for config in [
        chain(vec![extract_into("1x", "$GLOBAL_MATCH")]),
        chain(vec![extract_into("a-b", "$GLOBAL_MATCH")]),
        chain(vec![extract_into("x", "$")]),
        chain(vec![check(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": "$GLOBAL_MATCH"}),
        )]),
    ] {
        assert_fallback(&config, FallbackReason::InvalidValue);
    }
}

#[test]
fn dollar_dollar_in_config_input_is_a_literal_dollar() {
    let config = chain(vec![check(
        "Charset",
        json!({"param": "$GLOBAL_MATCH", "allowed": "$$a"}),
    )]);
    evaluates_to(&config, "$a$", ChainOutcome::Valid);
}

#[test]
fn slot_limit_counts_global_match() {
    let extracts = |count: usize| -> Vec<JsonValue> {
        (0..count)
            .map(|index| extract_into(&format!("v{index}"), "$GLOBAL_MATCH"))
            .collect()
    };
    let mut fills_every_slot = extracts(31);
    fills_every_slot.push(check(
        "Compare",
        json!({"a": "$v30", "b": "a", "operator": "="}),
    ));
    evaluates_to(&chain(fills_every_slot), "abc", ChainOutcome::Valid);
    assert_fallback(&chain(extracts(32)), FallbackReason::LimitExceeded);
}

// ---- Runtime ----

/// Doubling a match longer than 2 KiB exceeds the 4 KiB per-value budget.
fn double_the_match() -> JsonValue {
    step(
        "Format",
        json!({"template": "{GLOBAL_MATCH}{GLOBAL_MATCH}"}),
        json!("doubled"),
    )
}

#[test]
fn chain_stops_at_first_negative_check() {
    let config = chain(vec![
        check(
            "Compare",
            json!({"a": "$GLOBAL_MATCH", "b": "x", "operator": "="}),
        ),
        double_the_match(),
    ]);
    evaluates_to(&config, &"y".repeat(3000), ChainOutcome::Invalid);
}

#[test]
fn chain_stops_at_first_error() {
    let config = chain(vec![
        double_the_match(),
        check(
            "Compare",
            json!({"a": "$GLOBAL_MATCH", "b": "x", "operator": "="}),
        ),
    ]);
    evaluates_to(&config, &"y".repeat(3000), ChainOutcome::Error);
}

#[test]
fn scratch_is_reset_between_calls() {
    // Each call uses close to the per-call budget; without a reset the second call would fail.
    let steps = (0..3)
        .map(|index| {
            step(
                "Format",
                json!({"template": "{GLOBAL_MATCH}"}),
                json!(format!("copy{index}")),
            )
        })
        .collect();
    let chain = compiled(&chain(steps));
    let input = "x".repeat(4096);
    for _ in 0..4 {
        assert_eq!(chain.evaluate(&input), ChainOutcome::Valid);
    }
}

#[test]
fn clearing_caches_keeps_chains_working() {
    let chain = compiled(&chain(vec![check(
        "RegexMatch",
        json!({"param": "$GLOBAL_MATCH", "pattern": "tkn_[a-z0-9]+"}),
    )]));
    assert_eq!(chain.evaluate("tkn_abc"), ChainOutcome::Valid);
    super::clear_chain_caches();
    assert_eq!(chain.evaluate("tkn_abc"), ChainOutcome::Valid);
    assert_eq!(chain.evaluate("tkn_ABC"), ChainOutcome::Invalid);
}

#[test]
fn chains_evaluate_concurrently() {
    let chain = std::sync::Arc::new(compiled(&chain(vec![
        regex_step(
            json!({"param": "$GLOBAL_MATCH", "pattern": "tkn_(?<body>[a-z]+)"}),
            json!({"body": "body"}),
        ),
        step(
            "Encode",
            json!({"param": "$body", "scheme": "hex"}),
            json!("hex"),
        ),
        check(
            "Compare",
            json!({"a": "$hex", "b": "616263", "operator": "="}),
        ),
    ])));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let chain = chain.clone();
            std::thread::spawn(move || {
                (0..200).all(|_| {
                    chain.evaluate("tkn_abc") == ChainOutcome::Valid
                        && chain.evaluate("tkn_abd") == ChainOutcome::Invalid
                })
            })
        })
        .collect();
    for handle in handles {
        assert!(matches!(handle.join(), Ok(true)));
    }
}
