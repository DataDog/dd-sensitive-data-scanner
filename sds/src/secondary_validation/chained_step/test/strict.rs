//! `validate_chain_strict`: everything that would refuse or fall back is an error, with a message
//! naming the step and the reason.

use super::{chain, check, step};
use crate::secondary_validation::chained_step::compile::FallbackReason;
use crate::secondary_validation::chained_step::compile::check_declared_version;
use crate::secondary_validation::chained_step::since::FeatureRequirement;
use crate::secondary_validation::chained_step::{
    ChainCompileError, ChainValidationError, validate_chain_strict,
};
use serde_json::{Value as JsonValue, json};

fn strict_error(config: &JsonValue) -> ChainValidationError {
    match validate_chain_strict(config) {
        Ok(()) => panic!("strict validation should fail for {config}"),
        Err(error) => error,
    }
}

/// A valid first step, so failures are reported on step 1 with its name.
fn chain_failing_at_step_1(failing_step: JsonValue) -> JsonValue {
    chain(vec![
        check(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": "a-z"}),
        ),
        failing_step,
    ])
}

fn named(mut step: JsonValue, name: &str) -> JsonValue {
    if let Some(map) = step.as_object_mut() {
        map.insert("name".into(), json!(name));
    }
    step
}

fn assert_strict_reports(config: &JsonValue, reason: FallbackReason, step_name: &str) {
    let error = strict_error(config);
    match &error {
        ChainValidationError::Compile(ChainCompileError::Fallback {
            reason: actual,
            step_index,
            step_name: actual_name,
            ..
        }) => {
            assert_eq!(*actual, reason);
            assert_eq!(*step_index, Some(1));
            assert_eq!(actual_name.as_deref(), Some(step_name));
        }
        other => panic!("expected a fallback, got {other:?}"),
    }
    let message = error.to_string();
    assert!(message.contains(step_name), "{message}");
    assert!(message.contains(reason.as_str()), "{message}");
    assert!(message.contains("step 1"), "{message}");
}

#[test]
fn valid_chain_passes() {
    assert_eq!(
        validate_chain_strict(&chain(vec![check(
            "Charset",
            json!({"param": "$GLOBAL_MATCH", "allowed": "a-z"})
        )])),
        Ok(())
    );
}

#[test]
fn reports_each_fallback_reason_with_step_and_name() {
    for (failing_step, reason) in [
        (check("Teleport", json!({})), FallbackReason::UnknownOp),
        (
            check(
                "Charset",
                json!({"param": "$GLOBAL_MATCH", "allowed": "a", "x": 1}),
            ),
            FallbackReason::UnknownField,
        ),
        (
            check(
                "Charset",
                json!({"param": "$GLOBAL_MATCH", "allowed": "z-a"}),
            ),
            FallbackReason::InvalidValue,
        ),
        (
            step(
                "Format",
                json!({"template": "{GLOBAL_MATCH}".repeat(17)}),
                json!("x"),
            ),
            FallbackReason::LimitExceeded,
        ),
        (
            check("Charset", json!({"param": "$undefined", "allowed": "a"})),
            FallbackReason::Malformed,
        ),
    ] {
        assert_strict_reports(
            &chain_failing_at_step_1(named(failing_step, "failing")),
            reason,
            "failing",
        );
    }
}

#[test]
fn reports_config_level_fallback_without_step() {
    let error = strict_error(&chain(vec![]));
    assert!(matches!(
        error,
        ChainValidationError::Compile(ChainCompileError::Fallback {
            reason: FallbackReason::Malformed,
            step_index: None,
            ..
        })
    ));
    assert!(
        error.to_string().starts_with("config: malformed"),
        "{error}"
    );
}

#[test]
fn under_declared_version_is_rejected_with_feature_and_step() {
    // Every current feature is `since: 1`, the lowest valid version, so under-declaration can only
    // be exercised directly against the check.
    let requirement = FeatureRequirement {
        since: 2,
        feature: "op `JSONParse`".to_string(),
        step_index: Some(3),
        step_name: Some("parse".to_string()),
    };
    let error = match check_declared_version(1, Some(&requirement)) {
        Ok(()) => panic!("version 1 must not cover a since-2 feature"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        ChainValidationError::UnderDeclaredVersion {
            declared: 1,
            required: 2,
            feature: "op `JSONParse`".to_string(),
            step_index: Some(3),
            step_name: Some("parse".to_string()),
        }
    );
    let message = error.to_string();
    assert!(message.contains("step 3 (\"parse\")"), "{message}");
    assert!(message.contains("under_declared_version"), "{message}");
    assert!(message.contains("JSONParse"), "{message}");
}

#[test]
fn declared_version_covering_requirement_passes() {
    let requirement = FeatureRequirement {
        since: 1,
        feature: "op `Extract`".to_string(),
        step_index: Some(0),
        step_name: None,
    };
    assert_eq!(check_declared_version(1, Some(&requirement)), Ok(()));
    assert_eq!(check_declared_version(1, None), Ok(()));
}

#[test]
fn compiled_chain_records_its_required_version() {
    let chain = super::compiled(&chain(vec![check(
        "Charset",
        json!({"param": "$GLOBAL_MATCH", "allowed": "a"}),
    )]));
    assert_eq!(
        chain.required_version.map(|requirement| requirement.since),
        Some(1)
    );
}
