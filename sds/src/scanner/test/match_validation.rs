use crate::match_validation::config::HttpStatusCodeRange;
use crate::match_validation::config_v2::TemplatedMatchString;
use crate::match_validation::validator_utils::generate_aws_headers_and_body;
use crate::scanner::RootRuleConfig;
use crate::{
    AwsConfig, AwsType, CustomHttpConfig, CustomHttpConfigV2, HttpCallConfig, HttpErrorInfo,
    HttpMethod, HttpRequestConfig, HttpResponseConfig, InternalMatchValidationType, MatchAction,
    MatchPairingConfig, MatchStatus, MatchValidationType, PairedValidatorConfig,
    ProximityKeywordsConfig, RegexRuleConfig, ResponseCondition, ResponseConditionType, RuleMatch,
    Scanner, ScannerBuilder, StatusCodeMatcher, UnknownResponseTypeInfo, ValidationError,
};
use httpmock::Method::{GET, POST};
use httpmock::{MockServer, Regex};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

#[test]
fn test_should_return_match_with_match_validation() {
    let mut http_config = CustomHttpConfig::default();
    http_config.set_endpoint("http://localhost:8080".to_string());
    let scanner =
        ScannerBuilder::new(&[RootRuleConfig::new(RegexRuleConfig::new("world").build())
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })
            .third_party_active_checker(MatchValidationType::CustomHttp(http_config))])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "hey world".to_string();
    let rule_match = scanner.scan(&mut content).unwrap();
    assert_eq!(rule_match.len(), 1);
    assert_eq!(content, "hey [REDACTED]");
    assert_eq!(rule_match[0].match_value, Some("world".to_string()));
}

#[test]
fn test_should_error_if_no_match_validation() {
    let scanner =
        ScannerBuilder::new(&[RootRuleConfig::new(RegexRuleConfig::new("world").build())
            .match_action(MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            })])
        .build()
        .unwrap();

    let mut content = "hey world".to_string();
    let mut rule_match = scanner.scan(&mut content).unwrap();
    assert_eq!(rule_match.len(), 1);
    assert_eq!(content, "hey [REDACTED]");
    assert_eq!(rule_match[0].match_value, None);
    scanner.validate_matches(&mut rule_match);
}

#[test]
fn test_should_allocate_match_validator_depending_on_match_type() {
    use crate::match_validation::config::AwsConfig;

    let rule_aws_id = RootRuleConfig::new(RegexRuleConfig::new("aws-id").build())
        .match_action(MatchAction::Redact {
            replacement: "[AWS ID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsId));
    let rule_aws_secret = RootRuleConfig::new(RegexRuleConfig::new("aws-secret").build())
        .match_action(MatchAction::Redact {
            replacement: "[AWS SECRET]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsSecret(
            AwsConfig::default(),
        )));

    let http_config = CustomHttpConfig::default()
        .with_endpoint("http://localhost:8080".to_string())
        .with_request_headers(BTreeMap::from([(
            "authorization".to_string(),
            "Bearer $MATCH".to_string(),
        )]));
    let rule_custom_http_1_domain_1 =
        RootRuleConfig::new(RegexRuleConfig::new("custom-http1").build())
            .match_action(MatchAction::Redact {
                replacement: "[CUSTOM HTTP1]".to_string(),
            })
            .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));

    let rule_custom_http_2_domain_1 =
        RootRuleConfig::new(RegexRuleConfig::new("custom-http2").build())
            .match_action(MatchAction::Redact {
                replacement: "[CUSTOM HTTP2]".to_string(),
            })
            .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));

    let rule_custom_http_3_domain_2 =
        RootRuleConfig::new(RegexRuleConfig::new("custom-http3").build())
            .match_action(MatchAction::Redact {
                replacement: "[CUSTOM HTTP3]".to_string(),
            })
            .third_party_active_checker(MatchValidationType::CustomHttp(
                CustomHttpConfig::default().with_endpoint("http://localhost:8081".to_string()),
            ));

    let scanner = ScannerBuilder::new(&[
        rule_aws_id,
        rule_aws_secret,
        rule_custom_http_1_domain_1,
        rule_custom_http_2_domain_1,
        rule_custom_http_3_domain_2,
    ])
    .build()
    .unwrap();

    // Let's check the number of entries in the match validator map
    let match_validator_map = &scanner.match_validators_per_type;
    assert_eq!(match_validator_map.len(), 3);
    // Custom assertion to check if the validators are the same
    let aws_validator = match_validator_map
        .get(&InternalMatchValidationType::Aws)
        .unwrap();
    let http_2_validator = match_validator_map
        .get(&InternalMatchValidationType::CustomHttp(vec![
            "http://localhost:8080".to_string(),
        ]))
        .unwrap();
    let http_1_validator = match_validator_map
        .get(&InternalMatchValidationType::CustomHttp(vec![
            "http://localhost:8081".to_string(),
        ]))
        .unwrap();
    assert!(!std::ptr::eq(
        http_1_validator.as_ref(),
        http_2_validator.as_ref()
    ));
    assert!(!std::ptr::eq(
        aws_validator.as_ref(),
        http_2_validator.as_ref()
    ));
    assert!(!std::ptr::eq(
        aws_validator.as_ref(),
        http_1_validator.as_ref()
    ));
}

#[test]
fn test_aws_id_only_shall_not_validate() {
    let rule_aws_id = RootRuleConfig::new(RegexRuleConfig::new("aws_id").build())
        .match_action(MatchAction::Redact {
            replacement: "[AWS_ID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsId));

    let scanner = ScannerBuilder::new(&[rule_aws_id]).build().unwrap();
    let mut content = "this is an aws_id".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "this is an [AWS_ID]");
    scanner.validate_matches(&mut matches);
    assert_eq!(matches[0].match_status, MatchStatus::NotChecked);
}

#[test]
fn test_mock_same_http_validator_several_matches() {
    let server = MockServer::start();

    // Create a mock on the server.
    let mock_service_valid = server.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer valid_match");
        then.status(200);
    });
    let mock_service_invalid = server.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer invalid_match");
        then.status(404).header("content-type", "text/html");
    });
    let mock_service_error = server.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer error_match");
        then.status(500).header("content-type", "text/html");
    });

    let http_config = CustomHttpConfig::default()
        .with_endpoint(server.url("/").to_string())
        .with_request_headers(BTreeMap::from([(
            "authorization".to_string(),
            "Bearer $MATCH".to_string(),
        )]))
        .with_valid_http_status_code(vec![HttpStatusCodeRange {
            start: 200,
            end: 300,
        }])
        .with_invalid_http_status_code(vec![HttpStatusCodeRange {
            start: 403,
            end: 500,
        }]);

    let rule_valid_match = RootRuleConfig::new(RegexRuleConfig::new("\\bvalid_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[VALID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));

    let rule_invalid_match =
        RootRuleConfig::new(RegexRuleConfig::new("\\binvalid_match\\b").build())
            .match_action(MatchAction::Redact {
                replacement: "[INVALID]".to_string(),
            })
            .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));

    let rule_error_match = RootRuleConfig::new(RegexRuleConfig::new("\\berror_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[ERROR]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));
    let scanner = ScannerBuilder::new(&[rule_valid_match, rule_invalid_match, rule_error_match])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content =
        "this is a content with a valid_match an invalid_match and an error_match".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 3);
    assert_eq!(
        content,
        "this is a content with a [VALID] an [INVALID] and an [ERROR]"
    );
    scanner.validate_matches(&mut matches);
    mock_service_valid.assert();
    mock_service_invalid.assert();
    mock_service_error.assert();
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
    assert_eq!(matches[1].match_status, MatchStatus::Invalid);
    assert_eq!(
        matches[2].match_status,
        MatchStatus::ValidationError(vec![ValidationError::UnknownResponseType(
            UnknownResponseTypeInfo {
                status_code: 500,
                body_length: 0,
                body_prefix: None,
            }
        )])
    );
}

#[test]
fn test_mock_multiple_http_validators_one_timeout() {
    let server_1 = MockServer::start();
    let server_2 = MockServer::start();

    // Simulate a slow server
    let _ = server_1.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer valid_match");
        then.status(200).delay(Duration::from_secs(5));
    });
    let _ = server_2.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer valid_match");
        then.status(200);
    });

    let server_url_1 = server_1.url("/").to_string();
    let server_url_2 = server_2.url("/").to_string();

    let rule_valid_match = RootRuleConfig::new(RegexRuleConfig::new("\\bvalid_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[VALID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttp(
            CustomHttpConfig::default()
                .with_endpoint("$HOST".to_string())
                .with_hosts(vec![server_url_1.clone(), server_url_2.clone()])
                .with_request_headers(BTreeMap::from([(
                    "authorization".to_string(),
                    "Bearer $MATCH".to_string(),
                )]))
                .with_valid_http_status_code(vec![HttpStatusCodeRange {
                    start: 200,
                    end: 300,
                }]),
        ));

    let scanner = ScannerBuilder::new(&[rule_valid_match])
        .with_return_matches(true)
        .build()
        .unwrap();
    let mut content = "this is a content with a valid_match".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "this is a content with a [VALID]");
    scanner.validate_matches(&mut matches);
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
}

#[test]
fn test_mock_http_timeout() {
    let server = MockServer::start();
    let _ = server.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer valid_match");
        then.status(200).delay(Duration::from_secs(3));
    });
    let mut http_config = CustomHttpConfig::default()
        .with_endpoint(server.url("/").to_string())
        .with_request_headers(BTreeMap::from([(
            "authorization".to_string(),
            "Bearer $MATCH".to_string(),
        )]));
    http_config.set_timeout_seconds(1);
    let rule_valid_match = RootRuleConfig::new(RegexRuleConfig::new("\\bvalid_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[VALID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttp(http_config));

    let scanner = ScannerBuilder::new(&[rule_valid_match])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "this is a content with a valid_match".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "this is a content with a [VALID]");
    scanner.validate_matches(&mut matches);
    // This will be in the form "Error making HTTP request: "
    match &matches[0].match_status {
        MatchStatus::ValidationError(errors)
            if matches!(errors.as_slice(), [ValidationError::HttpError(_)]) =>
        {
            let ValidationError::HttpError(HttpErrorInfo {
                status_code,
                message,
            }) = &errors[0]
            else {
                panic!("expected single HttpError");
            };
            assert!(message.starts_with("Error making HTTP request:"));
            assert_eq!(*status_code, 0u16);
        }
        _ => assert!(false),
    }
}

#[test]
fn test_matches_from_rule_without_validation_are_not_ignored() {
    let rule_valid_match = RootRuleConfig::new(RegexRuleConfig::new("\\bvalid_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[VALID]".to_string(),
        });

    let scanner = ScannerBuilder::new(&[rule_valid_match])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = "this is a content with a valid_match".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(content, "this is a content with a [VALID]");
    scanner.validate_matches(&mut matches);

    // Even though the match doesn't have a match-validator, it is still returned, with a `NotAvailable` status
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_status, MatchStatus::NotAvailable);
}

#[test]
fn test_mock_multiple_match_validators() {
    let server = MockServer::start();

    // Create a mock on the server.
    let mock_http_service_valid = server.mock(|when, then| {
        when.method(GET).path("/http-service");
        then.status(200);
    });
    let mock_aws_service_valid = server.mock(|when, then| {
        when.method(POST).path("/aws-service");
        then.status(200);
    });

    let rule_valid_match = RootRuleConfig::new(RegexRuleConfig::new("\\bvalid_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[VALID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttp(
            CustomHttpConfig::default()
                .with_endpoint(server.url("/http-service").to_string())
                .with_valid_http_status_code(vec![HttpStatusCodeRange {
                    start: 200,
                    end: 300,
                }]),
        ));

    let rule_aws_id = RootRuleConfig::new(RegexRuleConfig::new("\\baws_id\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[AWS_ID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsId));

    let rule_aws_secret = RootRuleConfig::new(RegexRuleConfig::new("\\baws_secret\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[AWS_SECRET]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsSecret(AwsConfig {
            aws_sts_endpoint: server.url("/aws-service").to_string(),
            forced_datetime_utc: None,
            timeout: Duration::from_secs(1),
        })));

    let scanner = ScannerBuilder::new(&[rule_valid_match, rule_aws_id, rule_aws_secret])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content =
        "this is a content with a valid_match an aws_id and an aws_secret".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 3);
    assert_eq!(
        content,
        "this is a content with a [VALID] an [AWS_ID] and an [AWS_SECRET]"
    );
    scanner.validate_matches(&mut matches);
    mock_http_service_valid.assert();
    mock_aws_service_valid.assert();
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
    assert_eq!(matches[1].match_status, MatchStatus::Valid);
    assert_eq!(matches[2].match_status, MatchStatus::Valid);
}

#[test]
fn test_mock_endpoint_with_multiple_hosts() {
    let server = MockServer::start();
    // Create a mock on the server.
    let mock_http_service_us = server.mock(|when, then| {
        when.method(GET).path("/us-service");
        then.status(200);
    });
    let mock_http_service_eu = server.mock(|when, then| {
        when.method(GET).path("/eu-service");
        then.status(403);
    });
    let rule_valid_match = RootRuleConfig::new(RegexRuleConfig::new("\\bvalid_match\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[VALID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttp(
            CustomHttpConfig::default()
                .with_endpoint(server.url("/$HOST-service").to_string())
                .with_hosts(vec!["us".to_string(), "eu".to_string()])
                .with_valid_http_status_code(vec![HttpStatusCodeRange {
                    start: 200,
                    end: 300,
                }]),
        ));

    let scanner = ScannerBuilder::new(&[rule_valid_match])
        .with_return_matches(true)
        .build()
        .unwrap();
    let mut content = "this is a content with a valid_match on multiple hosts".to_string();
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(
        content,
        "this is a content with a [VALID] on multiple hosts"
    );
    scanner.validate_matches(&mut matches);
    mock_http_service_us.assert();
    mock_http_service_eu.assert();
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
}

#[test]
fn test_mock_aws_validator() {
    let server = MockServer::start();
    let server_url = server.url("/").to_string();

    // Compute signature for valid match
    let datetime = chrono::Utc::now();

    let aws_id_valid = "AKIAYYB64AB3GAW3WH79";
    let aws_id_invalid = "AKIAYYB64AB3GAW3WH70";
    let aws_id_error = "AKIAYYB64AB3GAW3WH71";
    let aws_secret_1 = "uYd/WrqSWR6m7rkYsjqGnD3QsmO7hQjDFXPQHMVy";
    let aws_secret_2 = "uYd/WrqSWR6m7rkYsjqGnD3QsmO7hQjDFXPZHMVy";

    let (_, headers_valid) =
        generate_aws_headers_and_body(&datetime, server_url.as_str(), aws_id_valid, aws_secret_1);
    let valid_authorization = headers_valid.get("authorization").unwrap();
    let (_, headers_invalid) =
        generate_aws_headers_and_body(&datetime, server_url.as_str(), aws_id_invalid, aws_secret_1);
    let invalid_authorization_1 = headers_invalid.get("authorization").unwrap();
    let (_, headers_invalid) =
        generate_aws_headers_and_body(&datetime, server_url.as_str(), aws_id_valid, aws_secret_2);
    let invalid_authorization_2 = headers_invalid.get("authorization").unwrap();
    let (_, headers_error) =
        generate_aws_headers_and_body(&datetime, server_url.as_str(), aws_id_error, aws_secret_1);
    let error_authorization_1 = headers_error.get("authorization").unwrap();
    let (_, headers_error) =
        generate_aws_headers_and_body(&datetime, server_url.as_str(), aws_id_error, aws_secret_2);
    let error_authorization_2 = headers_error.get("authorization").unwrap();
    // Create a mock on the server.
    let mock_service_valid = server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .header("authorization", valid_authorization.to_str().unwrap());
        then.status(200);
    });
    let mock_service_invalid_1 = server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .header("authorization", invalid_authorization_1.to_str().unwrap());
        then.status(403);
    });
    let mock_service_invalid_2 = server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .header("authorization", invalid_authorization_2.to_str().unwrap());
        then.status(403);
    });
    let mock_service_error_1 = server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .header("authorization", error_authorization_1.to_str().unwrap());
        then.status(500);
    });
    let mock_service_error_2 = server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .header("authorization", error_authorization_2.to_str().unwrap());
        then.status(500);
    });
    let rule_aws_id = RootRuleConfig::new(RegexRuleConfig::new("AKIA[0-9A-Z]{16}").build())
        .match_action(MatchAction::Redact {
            replacement: "[AWS_ID]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsId));

    let rule_aws_secret = RootRuleConfig::new(
        RegexRuleConfig::new("[A-Za-z0-9/+]{40}")
            .with_proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: 30,
                included_keywords: vec!["aws_secret".to_string()],
                excluded_keywords: vec![],
            })
            .build(),
    )
    .third_party_active_checker(MatchValidationType::Aws(AwsType::AwsSecret(AwsConfig {
        aws_sts_endpoint: server_url.clone(),
        forced_datetime_utc: Some(datetime),
        timeout: Duration::from_secs(5),
    })))
    .match_action(MatchAction::Redact {
        replacement: "[AWS_SECRET]".to_string(),
    });

    let scanner = ScannerBuilder::new(&[rule_aws_id, rule_aws_secret])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content = fmt::format(format_args!(
        "content with a valid aws_id {aws_id_valid}, an invalid aws_id {aws_id_invalid}, an error aws_id {aws_id_error} and an aws_secret {aws_secret_1} and an other aws_secret {aws_secret_2}"
    ));
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 5);
    assert_eq!(
        content,
        "content with a valid aws_id [AWS_ID], an invalid aws_id [AWS_ID], an error aws_id [AWS_ID] and an aws_secret [AWS_SECRET] and an other aws_secret [AWS_SECRET]"
    );
    scanner.validate_matches(&mut matches);
    mock_service_valid.assert();
    mock_service_invalid_1.assert();
    mock_service_invalid_2.assert();
    mock_service_error_1.assert();
    mock_service_error_2.assert();
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
    assert_eq!(matches[1].match_status, MatchStatus::Invalid);
    match &matches[2].match_status {
        MatchStatus::ValidationError(errors) => {
            assert!(!errors.is_empty(), "expected at least one validation error");
            assert!(
                errors.iter().all(|error| matches!(
                    error,
                    ValidationError::HttpError(HttpErrorInfo { status_code: 500, message })
                    if message == "Unexpected HTTP status code"
                )),
                "expected all errors to be HTTP 500 unexpected status errors, got: {errors:?}"
            );
        }
        other => panic!("expected ValidationError, got {other:?}"),
    }
    assert_eq!(matches[3].match_status, MatchStatus::Valid);
    // ID1 + SECRET2 should be in error so it should contain error and not invalid
    match &matches[4].match_status {
        MatchStatus::ValidationError(errors) => {
            assert!(!errors.is_empty(), "expected at least one validation error");
            assert!(
                errors.iter().all(|error| matches!(
                    error,
                    ValidationError::HttpError(HttpErrorInfo { status_code: 500, message })
                    if message == "Unexpected HTTP status code"
                )),
                "expected all errors to be HTTP 500 unexpected status errors, got: {errors:?}"
            );
        }
        other => panic!("expected ValidationError, got {other:?}"),
    }
}

#[test]
fn test_match_pairing_end_to_end() {
    let server = MockServer::start();

    // Mock endpoint expects both the API key ($MATCH from main rule), client_subdomain,
    // and user_id from the paired validators in the URL path
    let mock_valid = server.mock(|when, then| {
        when.method(GET)
            .path("/api/acme_corp/USjohn/validate")
            .query_param("secret", "api_key_abc123");
        then.status(200).body(r#"{"status": "valid"}"#);
    });
    let mock_invalid = server.mock(|when, then| {
        when.method(GET)
            .path("/api/other_corp/USjohn/validate")
            .query_param("secret", "api_key_abc123");
        then.status(403);
    });

    // Create a rule that provides the client_subdomain parameter
    let rule_client_subdomain =
        RootRuleConfig::new(RegexRuleConfig::new("\\b[a-z_]+_corp\\b").build())
            .match_action(MatchAction::None)
            .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
                provides: Some(vec![PairedValidatorConfig {
                    kind: "vendor_xyz".to_string(),
                    name: "client_subdomain".to_string(),
                }]),
                calls: vec![],
                match_pairing: None,
            }));

    // Create a rule that provides the user_id parameter
    let rule_user_id = RootRuleConfig::new(RegexRuleConfig::new("\\bUS[a-z0-9]+\\b").build())
        .match_action(MatchAction::None)
        .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
            provides: Some(vec![PairedValidatorConfig {
                kind: "vendor_xyz".to_string(),
                name: "user_id".to_string(),
            }]),
            calls: vec![],
            match_pairing: None,
        }));

    // Create the main validation rule with match pairing
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "client_subdomain".to_string(),
        "$CLIENT_SUBDOMAIN".to_string(),
    );
    parameters.insert("user_id".to_string(), "$USER_ID".to_string());

    let http_config_v2 = CustomHttpConfigV2 {
        match_pairing: Some(MatchPairingConfig {
            kind: "vendor_xyz".to_string(),
            parameters,
        }),
        provides: None,
        calls: vec![HttpCallConfig {
            request: HttpRequestConfig {
                endpoint: TemplatedMatchString(format!(
                    "{}/api/$CLIENT_SUBDOMAIN/$USER_ID/validate?secret=$MATCH",
                    server.base_url()
                )),
                method: HttpMethod::Get,
                hosts: vec![],
                headers: BTreeMap::new(),
                body: None,
                timeout: Duration::from_secs(5),
            },
            response: HttpResponseConfig {
                conditions: vec![
                    ResponseCondition {
                        condition_type: ResponseConditionType::Valid,
                        status_code: Some(StatusCodeMatcher::Single(200)),
                        raw_body: None,
                        body: None,
                    },
                    ResponseCondition {
                        condition_type: ResponseConditionType::Invalid,
                        status_code: Some(StatusCodeMatcher::Single(403)),
                        raw_body: None,
                        body: None,
                    },
                ],
            },
        }],
    };

    let rule_api_key = RootRuleConfig::new(RegexRuleConfig::new("\\bapi_key_[a-z0-9]+\\b").build())
        .match_action(MatchAction::Redact {
            replacement: "[API_KEY]".to_string(),
        })
        .third_party_active_checker(MatchValidationType::CustomHttpV2(http_config_v2));

    let scanner = ScannerBuilder::new(&[rule_client_subdomain, rule_user_id, rule_api_key])
        .with_return_matches(true)
        .build()
        .unwrap();

    let mut content =
        "Client: acme_corp, API Key: api_key_abc123, another company: other_corp for user USjohn"
            .to_string();
    let mut matches = scanner.scan(&mut content).unwrap();

    // We expect 4 matches:
    // - acme_corp (client_subdomain provider)
    // - api_key_abc123 (main match to validate)
    // - USjohn (user_id provider)
    // - other_corp (another client_subdomain, but same rule)
    assert_eq!(matches.len(), 4);
    assert_eq!(
        content,
        "Client: acme_corp, API Key: [API_KEY], another company: other_corp for user USjohn"
    );

    scanner.validate_matches(&mut matches);

    let api_key_match = matches
        .iter()
        .find(|m| {
            m.match_value
                .as_ref()
                .map_or(false, |v| v.starts_with("api_key"))
        })
        .expect("Should find api_key match");
    let user_id_match = matches
        .iter()
        .find(|m| {
            m.match_value
                .as_ref()
                .map_or(false, |v| v.starts_with("US"))
        })
        .expect("Should find user_id match");
    let acme_client_subdomain_match = matches
        .iter()
        .find(|m| {
            m.match_value
                .as_ref()
                .map_or(false, |v| v.ends_with("acme_corp"))
        })
        .expect("Should find client_subdomain match");
    let other_client_subdomain_match = matches
        .iter()
        .find(|m| {
            m.match_value
                .as_ref()
                .map_or(false, |v| v.ends_with("other_corp"))
        })
        .expect("Should find client_subdomain match");

    // Both mocks should have been called
    mock_valid.assert();
    mock_invalid.assert();

    // The first pairing of the three secrets should have matched
    assert_eq!(api_key_match.match_status, MatchStatus::Valid);
    assert_eq!(user_id_match.match_status, MatchStatus::Valid);
    assert_eq!(acme_client_subdomain_match.match_status, MatchStatus::Valid);

    // The pairing with the other_corp should have been rejected, thus invalid
    assert_eq!(
        other_client_subdomain_match.match_status,
        MatchStatus::Invalid
    );
}

#[test]
fn test_match_pairing_incomplete_missing_paired_secret() {
    let server = MockServer::start();

    // Set up a mock that only matches when the subdomain is properly substituted
    // (not the literal "$CLIENT_SUBDOMAIN" string)
    let _mock = server.mock(|when, then| {
        when.method(GET)
            .path_matches(Regex::new(r"^/api/[a-z_]+_corp/validate$").unwrap())
            .query_param("secret", "api_key_abc123");
        then.status(200).body(r#"{"status": "valid"}"#);
    });

    // Rule provides client_subdomain
    let rule_client_subdomain =
        RootRuleConfig::new(RegexRuleConfig::new("\\b[a-z_]+_corp\\b").build())
            .match_action(MatchAction::None)
            .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
                provides: Some(vec![crate::PairedValidatorConfig {
                    kind: "vendor_xyz".to_string(),
                    name: "client_subdomain".to_string(),
                }]),
                calls: vec![],
                match_pairing: None,
            }));

    // Main validation rule with match pairing
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "client_subdomain".to_string(),
        "$CLIENT_SUBDOMAIN".to_string(),
    );

    let http_config_v2 = CustomHttpConfigV2 {
        match_pairing: Some(MatchPairingConfig {
            kind: "vendor_xyz".to_string(),
            parameters,
        }),
        provides: None,
        calls: vec![HttpCallConfig {
            request: HttpRequestConfig {
                endpoint: TemplatedMatchString(format!(
                    "{}/api/$CLIENT_SUBDOMAIN/validate?secret=$MATCH",
                    server.base_url()
                )),
                method: HttpMethod::Get,
                hosts: vec![],
                headers: BTreeMap::new(),
                body: None,
                timeout: Duration::from_secs(5),
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
    };

    let rule_main_validator =
        RootRuleConfig::new(RegexRuleConfig::new("\\bapi_key_[a-z0-9]+\\b").build())
            .match_action(MatchAction::Redact {
                replacement: "[API_KEY]".to_string(),
            })
            .third_party_active_checker(MatchValidationType::CustomHttpV2(http_config_v2));

    let scanner = ScannerBuilder::new(&[rule_client_subdomain, rule_main_validator])
        .with_return_matches(true)
        .build()
        .unwrap();

    fn get_matches_with_content(scanner: &Scanner, content: &str) -> Vec<RuleMatch> {
        let mut matches = scanner.scan(&mut content.to_string()).unwrap();
        scanner.validate_matches(&mut matches);
        matches
    }

    {
        // Content contains only the main secret, missing the paired secret
        let mut matches = get_matches_with_content(
            &scanner,
            "The secret is api_key_abc123 but no client subdomain",
        );

        // Should have exactly one match (the main secret)
        assert_eq!(matches.len(), 1);

        scanner.validate_matches(&mut matches);

        let main_match = matches.first().expect("Should find main match");
        assert!(matches!(
            main_match.match_status,
            MatchStatus::MissingDependentMatch
        ));

        // The mock should NOT have been called (since the path didn't match the pattern)
        _mock.assert_hits(0);
    }
    {
        // Content contains only the paired secret, missing the main secret
        let mut matches =
            get_matches_with_content(&scanner, "The client subdomain is acme_corp but no secret");

        // Should have exactly one match (the main secret)
        assert_eq!(matches.len(), 1);

        scanner.validate_matches(&mut matches);

        let main_match = matches.first().expect("Should find main match");
        assert!(matches!(main_match.match_status, MatchStatus::NotChecked));

        // The mock should NOT have been called (since the path didn't match the pattern)
        _mock.assert_hits(0);
    }
}

#[test]
fn test_match_pairing_rule_can_consume_and_provide() {
    let server = MockServer::start();

    let mock_api_key_valid = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/validate")
            .query_param("site", "ddsite_us")
            .header("DD-API-KEY", "ddapikey_valid123");
        then.status(200);
    });
    let mock_app_key_valid = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/validate")
            .header("DD-API-KEY", "ddapikey_valid123")
            .header("DD-APPLICATION-KEY", "ddappkey_validxyz");
        then.status(200);
    });

    let rule_dd_site = RootRuleConfig::new(RegexRuleConfig::new("\\bddsite_[a-z]+\\b").build())
        .match_action(MatchAction::None)
        .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
            provides: Some(vec![PairedValidatorConfig {
                kind: "datadog".to_string(),
                name: "dd_site".to_string(),
            }]),
            calls: vec![],
            match_pairing: None,
        }));

    let mut dd_site_parameters = BTreeMap::new();
    dd_site_parameters.insert("dd_site".to_string(), "$DD_SITE".to_string());

    let rule_dd_api_key =
        RootRuleConfig::new(RegexRuleConfig::new("\\bddapikey_[A-Za-z0-9]+\\b").build())
            .match_action(MatchAction::None)
            .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
                match_pairing: Some(MatchPairingConfig {
                    kind: "datadog".to_string(),
                    parameters: dd_site_parameters,
                }),
                provides: Some(vec![PairedValidatorConfig {
                    kind: "datadog".to_string(),
                    name: "api_key".to_string(),
                }]),
                calls: vec![HttpCallConfig {
                    request: HttpRequestConfig {
                        endpoint: TemplatedMatchString(format!(
                            "{}/api/v1/validate?site=$DD_SITE",
                            server.base_url()
                        )),
                        method: HttpMethod::Get,
                        hosts: vec![],
                        headers: BTreeMap::from([(
                            "DD-API-KEY".to_string(),
                            TemplatedMatchString("$MATCH".to_string()),
                        )]),
                        body: None,
                        timeout: Duration::from_secs(5),
                    },
                    response: HttpResponseConfig {
                        conditions: vec![
                            ResponseCondition {
                                condition_type: ResponseConditionType::Valid,
                                status_code: Some(StatusCodeMatcher::Single(200)),
                                raw_body: None,
                                body: None,
                            },
                            ResponseCondition {
                                condition_type: ResponseConditionType::Invalid,
                                status_code: Some(StatusCodeMatcher::Single(403)),
                                raw_body: None,
                                body: None,
                            },
                        ],
                    },
                }],
            }));

    let mut dd_api_key_parameters = BTreeMap::new();
    dd_api_key_parameters.insert("api_key".to_string(), "$DD_API_KEY".to_string());

    let rule_dd_app_key =
        RootRuleConfig::new(RegexRuleConfig::new("\\bddappkey_[A-Za-z0-9]+\\b").build())
            .match_action(MatchAction::None)
            .third_party_active_checker(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
                match_pairing: Some(MatchPairingConfig {
                    kind: "datadog".to_string(),
                    parameters: dd_api_key_parameters,
                }),
                provides: None,
                calls: vec![HttpCallConfig {
                    request: HttpRequestConfig {
                        endpoint: TemplatedMatchString(format!(
                            "{}/api/v1/validate",
                            server.base_url()
                        )),
                        method: HttpMethod::Get,
                        hosts: vec![],
                        headers: BTreeMap::from([
                            (
                                "DD-API-KEY".to_string(),
                                TemplatedMatchString("$DD_API_KEY".to_string()),
                            ),
                            (
                                "DD-APPLICATION-KEY".to_string(),
                                TemplatedMatchString("$MATCH".to_string()),
                            ),
                        ]),
                        body: None,
                        timeout: Duration::from_secs(5),
                    },
                    response: HttpResponseConfig {
                        conditions: vec![
                            ResponseCondition {
                                condition_type: ResponseConditionType::Valid,
                                status_code: Some(StatusCodeMatcher::Single(200)),
                                raw_body: None,
                                body: None,
                            },
                            ResponseCondition {
                                condition_type: ResponseConditionType::Invalid,
                                status_code: Some(StatusCodeMatcher::Single(403)),
                                raw_body: None,
                                body: None,
                            },
                        ],
                    },
                }],
            }));

    let scanner = ScannerBuilder::new(&[rule_dd_site, rule_dd_app_key, rule_dd_api_key])
        .with_return_matches(true)
        .build()
        .unwrap();

    fn get_status_by_rule_idx(matches: &[RuleMatch], rule_idx: usize) -> MatchStatus {
        matches
            .iter()
            .find(|m| m.rule_index == rule_idx)
            .unwrap_or_else(|| panic!("missing match for rule index {rule_idx}"))
            .match_status
            .clone()
    }

    fn scan_and_validate(scanner: &Scanner, content: &str) -> Vec<RuleMatch> {
        let mut matches = scanner.scan(&mut content.to_string()).unwrap();
        scanner.validate_matches(&mut matches);
        matches
    }

    {
        let matches = scan_and_validate(
            &scanner,
            "site=ddsite_us api_key=ddapikey_valid123 app_key=ddappkey_validxyz",
        );

        assert_eq!(get_status_by_rule_idx(&matches, 1), MatchStatus::Valid);
        assert_eq!(get_status_by_rule_idx(&matches, 2), MatchStatus::Valid);
        mock_api_key_valid.assert_hits(1);
        mock_app_key_valid.assert_hits(1);
    }

    {
        let matches = scan_and_validate(&scanner, "site=ddsite_us app_key=ddappkey_validxyz");

        assert_eq!(
            get_status_by_rule_idx(&matches, 1),
            MatchStatus::MissingDependentMatch
        );
        mock_api_key_valid.assert_hits(1);
        mock_app_key_valid.assert_hits(1);
    }

    {
        let matches = scan_and_validate(&scanner, "api_key=ddapikey_valid123");

        assert_eq!(
            get_status_by_rule_idx(&matches, 2),
            MatchStatus::MissingDependentMatch
        );
        mock_api_key_valid.assert_hits(1);
        mock_app_key_valid.assert_hits(1);
    }
}
