use crate::match_validation::config_v2::TemplatedMatchString;
use crate::scanner::{CreateScannerError, RootRuleConfig, ScanOptionBuilder};
use crate::{
    CustomHttpConfigV2, HttpCallConfig, HttpMethod, HttpRequestConfig, HttpResponseConfig,
    MatchAction, MatchPairingConfig, MatchValidationType, PairedValidatorConfig, RegexRuleConfig,
    ResponseCondition, ResponseConditionType, ScannerBuilder, StatusCodeMatcher,
};
use httpmock::Method::GET;
use httpmock::MockServer;
use std::collections::BTreeMap;

/// Supporting rules must not appear in scan output during a plain scan.
#[test]
fn test_supporting_rule_match_excluded_from_scan_output() {
    let supporting_rule =
        RootRuleConfig::new(RegexRuleConfig::new("\\bsecret_prefix_\\w+\\b").build())
            .match_action(MatchAction::None)
            .is_supporting_rule(true);

    let main_rule = RootRuleConfig::new(RegexRuleConfig::new("\\bmain_\\w+\\b").build())
        .match_action(MatchAction::None);

    let scanner = ScannerBuilder::new(&[supporting_rule, main_rule])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "secret_prefix_abc and main_token".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    // Only the main rule match should appear
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_value, Some("main_token".to_string()));
}

/// Supporting rules must not appear in scan output even when validate_matches is used.
/// The supporting rule's match value must still be used to populate template variables
/// for the main rule's HTTP call.
#[test]
fn test_supporting_rule_excluded_from_output_but_used_for_match_pairing() {
    let server = MockServer::start();

    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/validate")
            .query_param("secret", "api_key_abc123")
            .query_param("subdomain", "acme_corp");
        then.status(200);
    });

    let supporting_rule = RootRuleConfig::new(RegexRuleConfig::new("\\b[a-z_]+_corp\\b").build())
        .match_action(MatchAction::None)
        .is_supporting_rule(true)
        .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
            provides: Some(vec![PairedValidatorConfig {
                kind: "vendor_xyz".to_string(),
                name: "client_subdomain".to_string(),
            }]),
            calls: vec![],
            match_pairing: None,
        }));

    let mut parameters = BTreeMap::new();
    parameters.insert("client_subdomain".to_string(), "$SUBDOMAIN".to_string());

    let main_rule = RootRuleConfig::new(RegexRuleConfig::new("\\bapi_key_[a-z0-9]+\\b").build())
        .match_action(MatchAction::None)
        .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
            match_pairing: Some(MatchPairingConfig {
                kind: "vendor_xyz".to_string(),
                parameters,
            }),
            provides: None,
            calls: vec![HttpCallConfig {
                request: HttpRequestConfig {
                    endpoint: TemplatedMatchString(format!(
                        "{}/validate?secret=$MATCH&subdomain=$SUBDOMAIN",
                        server.base_url()
                    )),
                    method: HttpMethod::Get,
                    hosts: vec![],
                    headers: BTreeMap::new(),
                    body: None,
                    timeout: std::time::Duration::from_secs(3),
                },
                response: HttpResponseConfig {
                    conditions: vec![ResponseCondition {
                        condition_type: ResponseConditionType::Valid,
                        status_code: Some(StatusCodeMatcher::Single(200)),
                        raw_body: None,
                        body: None,
                    }],
                },
            }],
        }));

    let scanner = ScannerBuilder::new(&[supporting_rule, main_rule])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "subdomain: acme_corp, key: api_key_abc123".to_string();
    let matches = scanner
        .scan_with_options(
            &mut content,
            ScanOptionBuilder::new()
                .with_validate_matching(true)
                .build(),
        )
        .unwrap();

    // The supporting rule match must not appear in output
    assert!(
        matches
            .iter()
            .all(|m| m.match_value.as_deref() != Some("acme_corp")),
        "supporting rule match should not appear in output"
    );

    // The main rule match must appear
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_value, Some("api_key_abc123".to_string()));

    // The HTTP mock was called, proving the template variable was resolved from the
    // supporting rule's match even though that match is not in the output
    mock.assert();
}

/// Non-supporting rules are unaffected and always appear in output.
#[test]
fn test_non_supporting_rule_always_in_output() {
    let rule = RootRuleConfig::new(RegexRuleConfig::new("\\btoken_\\w+\\b").build())
        .match_action(MatchAction::None);

    let scanner = ScannerBuilder::new(&[rule])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "token_abc123".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_value, Some("token_abc123".to_string()));
}

/// is_supporting_rule must default to false when deserializing from JSON (Go FFI path).
#[test]
fn test_is_supporting_rule_defaults_to_false_on_deserialization() {
    let json = r#"{"match_action":{"type":"None"},"pattern":"hello"}"#;
    let config: RootRuleConfig<RegexRuleConfig> = serde_json::from_str(json).unwrap();
    assert!(!config.is_supporting_rule);
}

/// is_supporting_rule is correctly round-tripped through JSON serialization.
#[test]
fn test_is_supporting_rule_serialization_round_trip() {
    let config = RootRuleConfig::new(RegexRuleConfig::new("hello")).is_supporting_rule(true);
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: RootRuleConfig<RegexRuleConfig> = serde_json::from_str(&json).unwrap();
    assert!(deserialized.is_supporting_rule);
}

/// When only supporting rules match (no main rules match), the output must be empty.
#[test]
fn test_only_supporting_rule_matches_produces_empty_output() {
    let supporting_rule =
        RootRuleConfig::new(RegexRuleConfig::new("\\bsupporting_\\w+\\b").build())
            .match_action(MatchAction::None)
            .is_supporting_rule(true);

    let scanner = ScannerBuilder::new(&[supporting_rule])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "supporting_value".to_string();
    let matches = scanner.scan(&mut content).unwrap();

    assert!(matches.is_empty());
}

/// Building a scanner with a supporting rule that has a non-None match action must fail.
#[test]
fn test_supporting_rule_with_match_action_is_rejected_at_build_time() {
    let supporting_rule = RootRuleConfig::new(RegexRuleConfig::new("\\bsecret_\\w+\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[REDACTED]".to_string(),
        })
        .is_supporting_rule(true);

    let result = ScannerBuilder::new(&[supporting_rule]).build();

    assert_eq!(
        result.err().unwrap(),
        CreateScannerError::SupportingRuleHasMatchAction
    );
}
