//! Target-rule formats from the credential-rules survey, exercised with fake tokens that have the
//! same structure as the real ones. Each checksum is computed in the test with `crc32fast` and the
//! reference encoders (`base62`, `base64`, `format!`), independently of the chain under test.

use super::{check, compiled, step};
use crate::secondary_validation::chained_step::ChainOutcome;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde_json::{Value as JsonValue, json};

const FAKE_BODIES: [&str; 4] = [
    "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
    "0000000000000000000000000000000000000000",
    "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponm",
    "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
];

fn crc(bytes: &str) -> u32 {
    crc32fast::hash(bytes.as_bytes())
}

/// Replaces the byte at `index` with a different alphanumeric byte.
fn flip(token: &str, index: usize) -> String {
    token
        .char_indices()
        .map(|(position, c)| match (position == index, c) {
            (true, 'a') => 'b',
            (true, _) => 'a',
            (false, c) => c,
        })
        .collect()
}

fn verify(payload: &str, embedded: &str, scheme: &str, endian: Option<&str>) -> JsonValue {
    let mut inputs =
        json!({"payload": payload, "embedded": embedded, "alg": "crc32", "scheme": scheme});
    if let (Some(endian), Some(inputs)) = (endian, inputs.as_object_mut()) {
        inputs.insert("endian".into(), json!(endian));
    }
    check("VerifyChecksum", inputs)
}

/// Each genuine token is valid; corrupting the payload at `corrupt_at`, corrupting the last
/// checksum character, or matching a value without the token's structure is negative.
fn assert_target(
    chain: &JsonValue,
    make_token: impl Fn(&str) -> String,
    corrupt_at: usize,
    unstructured: &str,
) {
    let chain = compiled(chain);
    for body in FAKE_BODIES {
        let token = make_token(body);
        assert_eq!(chain.evaluate(&token), ChainOutcome::Valid, "{token}");
        let corrupted = flip(&token, corrupt_at);
        assert_eq!(
            chain.evaluate(&corrupted),
            ChainOutcome::Invalid,
            "{corrupted}"
        );
        let bad_checksum = flip(&token, token.len() - 1);
        assert_eq!(
            chain.evaluate(&bad_checksum),
            ChainOutcome::Invalid,
            "{bad_checksum}"
        );
    }
    assert_eq!(
        chain.evaluate(unstructured),
        ChainOutcome::Invalid,
        "{unstructured}"
    );
}

/// bitrise-style: `bitpat_<body>_<6 base62>`, with the CRC32 over `bitpat_<body>` (the final `_`
/// excluded).
fn bitrise_style_chain() -> JsonValue {
    json!({"version": 1, "steps": [
        step("Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": -1}),
            json!({"before": "payload", "after": "embedded"})),
        verify("$payload", "$embedded", "base62", None),
    ]})
}

fn bitrise_style_token(payload: &str, crc_input: &str) -> String {
    format!("{payload}_{:0>6}", base62::encode(crc(crc_input)))
}

#[test]
fn bitrise_style_token_is_verified() {
    assert_target(
        &bitrise_style_chain(),
        |body| {
            let payload = format!("bitpat_{body}");
            bitrise_style_token(&payload, &payload)
        },
        7,
        "nounderscore",
    );
}

#[test]
fn bitrise_style_crc_over_the_final_underscore_is_rejected() {
    let chain = compiled(&bitrise_style_chain());
    for body in FAKE_BODIES {
        let payload = format!("bitpat_{body}");
        let token = bitrise_style_token(&payload, &format!("{payload}_"));
        assert_eq!(chain.evaluate(&token), ChainOutcome::Invalid, "{token}");
    }
}

/// zuplo-style: `<prefix>_<hex body>_<hex CRC32 of the body>`, in either case.
fn zuplo_style_chain() -> JsonValue {
    json!({"version": 1, "steps": [
        step("Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": -1}),
            json!({"before": "head", "after": "embedded"})),
        step("Split",
            json!({"param": "$head", "separator": "_", "occurrence": 0}),
            json!({"after": "body"})),
        verify("$body", "$embedded", "hex", None),
    ]})
}

#[test]
fn zuplo_style_token() {
    assert_target(
        &zuplo_style_chain(),
        |body| format!("fkzp_{body}_{:08x}", crc(body)),
        7,
        "nounderscore",
    );
}

#[test]
fn zuplo_style_upper_case_checksum_is_accepted() {
    let chain = compiled(&zuplo_style_chain());
    for body in FAKE_BODIES {
        let token = format!("fkzp_{body}_{:08X}", crc(body));
        assert_eq!(chain.evaluate(&token), ChainOutcome::Valid, "{token}");
    }
}

/// grafana-style: CRC32 over prefix + body, appended as little-endian hex.
fn grafana_style_chain() -> JsonValue {
    json!({"version": 1, "steps": [
        step("Split",
            json!({"param": "$GLOBAL_MATCH", "separator": "_", "occurrence": -1}),
            json!({"before": "payload", "after": "embedded"})),
        verify("$payload", "$embedded", "hex", Some("little")),
    ]})
}

#[test]
fn grafana_style_token() {
    let make_token = |body: &str| {
        let payload = format!("fkgs_{body}");
        format!("{payload}_{:08x}", crc(&payload).swap_bytes())
    };
    assert_target(&grafana_style_chain(), make_token, 7, "nounderscore");
}

/// confluent-style: CRC32 over bytes [4:58], appended as base64 (no padding) of its little-endian
/// bytes.
fn confluent_style_chain() -> JsonValue {
    json!({"version": 1, "steps": [
        step("Extract", json!({"param": "$GLOBAL_MATCH", "slice": "[4:58]"}), json!("payload")),
        step("Extract", json!({"param": "$GLOBAL_MATCH", "slice": "[58:]"}), json!("embedded")),
        verify("$payload", "$embedded", "base64_nopad", Some("little")),
    ]})
}

fn make_confluent_style_token(body: &str) -> String {
    // 4-byte header + 54-byte payload + 6 base64 characters.
    let payload: String = body.chars().chain(body.chars().take(14)).collect();
    format!(
        "FKCF{payload}{}",
        STANDARD_NO_PAD.encode(crc(&payload).to_le_bytes())
    )
}

#[test]
fn confluent_style_token() {
    assert_target(
        &confluent_style_chain(),
        make_confluent_style_token,
        10,
        "FKCF",
    );
}
