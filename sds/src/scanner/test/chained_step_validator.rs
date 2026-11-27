use super::validator_rules::{build_scanner, plain_rule, rule_with_validator, scan};
use serde_json::{Value, json};

fn chained_validator(default_response: &str, config: Value) -> Value {
    json!({"type": "ChainedStepValidator", "default_response": default_response, "config": config})
}

fn step(op: &str, inputs: Value, output: &str) -> Value {
    json!({"op": op, "input": inputs, "output": output})
}

fn check(op: &str, inputs: Value) -> Value {
    json!({"op": op, "input": inputs})
}

fn compare_global_match_to(expected: &str) -> Value {
    json!({"version": 1, "steps": [
        check("Compare", json!({"a": "$GLOBAL_MATCH", "b": expected, "operator": "="})),
    ]})
}

/// `tkn_<body><crc32(body) as 8 lowercase hex digits>`
fn crc32_hex_suffix_chain() -> Value {
    json!({"version": 1, "steps": [
        step("Extract", json!({"param": "$GLOBAL_MATCH", "slice": "[4:-8]"}), "body"),
        step("Extract", json!({"param": "$GLOBAL_MATCH", "slice": "[-8:]"}), "embedded"),
        check("VerifyChecksum", json!({
            "payload": "$body", "embedded": "$embedded", "alg": "crc32", "scheme": "hex"})),
    ]})
}

fn crc32_hex_token(body: &str) -> String {
    format!("tkn_{body}{:08x}", crc32fast::hash(body.as_bytes()))
}

#[test]
fn chained_rule_redacts_only_tokens_with_a_valid_checksum() {
    let scanner = build_scanner(vec![rule_with_validator(
        "tkn_[a-z0-9]+",
        chained_validator("pass", crc32_hex_suffix_chain()),
    )]);
    let valid = crc32_hex_token("abc123");
    let forged = format!("tkn_abc124{}", &valid[10..]);

    assert_eq!(
        scan(&scanner, &format!("{valid} {forged}")).0,
        format!("[REDACTED] {forged}")
    );
}

#[test]
fn chain_sees_the_sds_match_capture_as_global_match() {
    let mut rule = rule_with_validator(
        "key=(?<sds_match>tkn_[a-z]+)",
        chained_validator("fail", compare_global_match_to("tkn_abc")),
    );
    rule.inner = rule
        .inner
        .with_pattern_capture_groups(vec!["sds_match".to_string()]);
    let scanner = build_scanner(vec![rule]);

    assert_eq!(scan(&scanner, "key=tkn_abc").0, "key=[REDACTED]");
}

#[test]
fn future_chain_version_disables_only_that_rule() {
    let future_chain = json!({"version": 1_000_000, "steps": []});
    let scanner = build_scanner(vec![
        rule_with_validator("secret", chained_validator("pass", future_chain)),
        plain_rule("foo"),
    ]);

    assert_eq!(scan(&scanner, "secret foo").0, "secret [REDACTED]");
}

#[test]
fn chain_without_default_response_disables_only_that_rule() {
    let validator =
        json!({"type": "ChainedStepValidator", "config": compare_global_match_to("secret")});
    let scanner = build_scanner(vec![
        rule_with_validator("secret", validator),
        plain_rule("foo"),
    ]);

    assert_eq!(scan(&scanner, "secret foo").0, "secret [REDACTED]");
}

#[test]
fn unparseable_step_resolves_to_default_response() {
    let chain = json!({"version": 1, "steps": [check("FutureOp", json!({}))]});
    let scanner = build_scanner(vec![rule_with_validator(
        "secret",
        chained_validator("pass", chain),
    )]);

    assert_eq!(scan(&scanner, "a secret").0, "a [REDACTED]");
}

#[test]
fn runtime_error_resolves_to_default_response() {
    // Doubling a match longer than 2 KiB exceeds the 4 KiB per-value budget, so the long match
    // can't be evaluated while the short one fails the comparison: only the long one is kept, by
    // the `pass` default.
    let chain = json!({"version": 1, "steps": [
        step("Format", json!({"template": "{GLOBAL_MATCH}{GLOBAL_MATCH}"}), "doubled"),
        check("Compare", json!({"a": "$doubled", "b": "nothing", "operator": "="})),
    ]});
    let scanner = build_scanner(vec![rule_with_validator(
        "tkn_[a-z]+",
        chained_validator("pass", chain),
    )]);
    let long_match = format!("tkn_{}", "a".repeat(2100));

    assert_eq!(
        scan(&scanner, &format!("tkn_ab {long_match}")).0,
        "tkn_ab [REDACTED]"
    );
}
