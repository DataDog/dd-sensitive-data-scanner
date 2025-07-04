use crate::match_validation::config::HttpStatusCodeRange;
use crate::match_validation::validator_utils::generate_aws_headers_and_body;
use crate::scanner::RootRuleConfig;
use crate::{
    AwsConfig, AwsType, CustomHttpConfig, InternalMatchValidationType, MatchAction, MatchStatus,
    MatchValidationType, ProximityKeywordsConfig, RegexRuleConfig, ScannerBuilder,
};
use httpmock::Method::{GET, POST};
use httpmock::MockServer;
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
    // Let's call validate and check that it panics
    let err = scanner.validate_matches(&mut rule_match);
    assert!(err.is_err());
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
    assert!(scanner.validate_matches(&mut matches).is_err());
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
    assert!(scanner.validate_matches(&mut matches).is_ok());
    mock_service_valid.assert();
    mock_service_invalid.assert();
    mock_service_error.assert();
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
    assert_eq!(matches[1].match_status, MatchStatus::Invalid);
    assert_eq!(
        matches[2].match_status,
        MatchStatus::Error("Unexpected HTTP status code 500".to_string())
    );
}

#[test]
fn test_mock_http_timeout() {
    let server = MockServer::start();
    let _ = server.mock(|when, then| {
        when.method(GET)
            .path("/")
            .header("authorization", "Bearer valid_match");
        then.status(200);
    });
    let mut http_config = CustomHttpConfig::default().with_endpoint(server.url("/").to_string());
    http_config.set_timeout_seconds(0);
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
    assert!(scanner.validate_matches(&mut matches).is_ok());
    // This will be in the form "Error making HTTP request: "
    match &matches[0].match_status {
        MatchStatus::Error(val) => {
            assert!(val.starts_with("Error making HTTP request:"));
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
    assert!(scanner.validate_matches(&mut matches).is_ok());

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
    assert!(scanner.validate_matches(&mut matches).is_ok());
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
    assert!(scanner.validate_matches(&mut matches).is_ok());
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
        "content with a valid aws_id {aws_id_valid}, an invalid aws_id {aws_id_invalid}, an error aws_id {aws_id_error} and an aws_secret {aws_secret_1} and an other aws_secret {aws_secret_2}"));
    let mut matches = scanner.scan(&mut content).unwrap();
    assert_eq!(matches.len(), 5);
    assert_eq!(
        content,
        "content with a valid aws_id [AWS_ID], an invalid aws_id [AWS_ID], an error aws_id [AWS_ID] and an aws_secret [AWS_SECRET] and an other aws_secret [AWS_SECRET]"
    );
    assert!(scanner.validate_matches(&mut matches).is_ok());
    mock_service_valid.assert();
    mock_service_invalid_1.assert();
    mock_service_invalid_2.assert();
    mock_service_error_1.assert();
    mock_service_error_2.assert();
    assert_eq!(matches[0].match_status, MatchStatus::Valid);
    assert_eq!(matches[1].match_status, MatchStatus::Invalid);
    assert_eq!(
        matches[2].match_status,
        MatchStatus::Error("Unexpected HTTP status code 500".to_string())
    );
    assert_eq!(matches[3].match_status, MatchStatus::Valid);
    // ID1 + SECRET2 should be in error so it should contain error and not invalid
    assert_eq!(
        matches[4].match_status,
        MatchStatus::Error("Unexpected HTTP status code 500".to_string())
    );
}
