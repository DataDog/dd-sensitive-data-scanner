use super::match_validator::MatchValidator;
use crate::match_validation::config_v2::ResponseConditionResult;
use crate::scanner::RootCompiledRule;
use crate::{
    CustomHttpConfigV2, HttpResponseConfig, match_validation::match_validator::RAYON_THREAD_POOL,
};
use crate::{MatchStatus, RuleMatch, match_validation::config::HttpMethod};
use ahash::AHashMap;
use lazy_static::lazy_static;
use reqwest::blocking::Response;
use std::error::Error as StdError;

lazy_static! {
    static ref BLOCKING_HTTP_CLIENT: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

pub struct HttpValidatorV2 {
    config: CustomHttpConfigV2,
}

impl HttpValidatorV2 {
    pub fn new_from_config(config: CustomHttpConfigV2) -> Self {
        HttpValidatorV2 { config }
    }
    fn handle_reqwest_response(
        &self,
        response_config: &HttpResponseConfig,
        match_status: &mut MatchStatus,
        val: Response,
    ) {
        // TODO: Do we want to keep this logic?
        // This looks at the response status code and decides what to do with it:
        // * Fail list -> Invalid match
        // * Succeed list -> Valid match
        // * Neither list -> Error match
        let status = val.status().as_u16();
        let body = val.text().unwrap_or_default();
        for response_condition in response_config.conditions.iter() {
            let result = response_condition.matches(status, &body);
            match result {
                ResponseConditionResult::Valid => {
                    *match_status = MatchStatus::Valid;
                    return;
                }
                ResponseConditionResult::Invalid => {
                    *match_status = MatchStatus::Invalid;
                    return;
                }
                ResponseConditionResult::NotChecked => {
                    continue;
                }
            }
        }
        *match_status = MatchStatus::Error(format!(
            "No response condition matched for status code {} and body of length {}",
            status,
            body.len()
        ));
    }
}

// TODO: Do we need an internal representation of the config?

impl MatchValidator for HttpValidatorV2 {
    fn validate(&self, matches: &mut Vec<RuleMatch>, _: &[RootCompiledRule]) {
        // build a map of match status per endpoint, per host, and per match_idx
        let mut match_status_per_endpoint_and_match: AHashMap<_, _> = matches
            .iter()
            .enumerate()
            .flat_map(|(idx, _)| {
                self.config.calls.iter().flat_map(move |endpoint| {
                    if endpoint.request.hosts.is_empty() {
                        // No hosts specified, use endpoint as-is
                        vec![((idx, endpoint, None), MatchStatus::NotChecked)]
                    } else {
                        // Generate one entry per host
                        endpoint
                            .request
                            .hosts
                            .iter()
                            .map(|host| {
                                ((idx, endpoint, Some(host.clone())), MatchStatus::NotChecked)
                            })
                            .collect::<Vec<_>>()
                    }
                })
            })
            .collect();

        RAYON_THREAD_POOL.install(|| {
            use rayon::prelude::*;

            match_status_per_endpoint_and_match.par_iter_mut().for_each(
                |((match_idx, endpoint_config, host_opt), match_status)| {
                    let rule_match = &matches[*match_idx];
                    let mut endpoint = endpoint_config.request.endpoint.with_rule_match(rule_match);
                    let rendered_host = host_opt
                        .as_ref()
                        .map(|host| host.with_rule_match(rule_match).to_string());

                    if let Some(ref host) = rendered_host {
                        endpoint = endpoint.with_host(host.as_str());
                    }
                    let mut request_builder = match endpoint_config.request.method {
                        HttpMethod::Get => BLOCKING_HTTP_CLIENT.get(endpoint.to_string()),
                        HttpMethod::Post => BLOCKING_HTTP_CLIENT.post(endpoint.to_string()),
                        HttpMethod::Put => BLOCKING_HTTP_CLIENT.put(endpoint.to_string()),
                        HttpMethod::Delete => BLOCKING_HTTP_CLIENT.delete(endpoint.to_string()),
                        HttpMethod::Patch => BLOCKING_HTTP_CLIENT.patch(endpoint.to_string()),
                    };
                    request_builder = request_builder.timeout(endpoint_config.request.timeout);

                    // Add headers
                    for (header_key, header_value) in &endpoint_config.request.headers {
                        let mut header_val = header_value.with_rule_match(rule_match);
                        if let Some(ref host) = rendered_host {
                            header_val = header_val.with_host(host.as_str());
                        }
                        request_builder =
                            request_builder.header(header_key, header_val.to_string());
                    }
                    let res = request_builder.send();
                    match res {
                        Ok(val) => {
                            self.handle_reqwest_response(
                                &endpoint_config.response,
                                match_status,
                                val,
                            );
                        }
                        Err(err) => {
                            let mut msg = format!("Error making HTTP request: {err}");
                            if err.is_timeout() {
                                msg.push_str(": timeout");
                            } else if err.is_connect() {
                                msg.push_str(": connect error");
                            }
                            if let Some(status) = err.status() {
                                msg.push_str(format!(": status {}", status.as_u16()).as_str());
                            }
                            if let Some(source) = StdError::source(&err) {
                                msg.push_str(format!(": {}", source).as_str());
                            }
                            *match_status = MatchStatus::Error(msg);
                        }
                    }
                },
            );
        });

        // Update the match status with this highest priority returned
        for ((match_idx, _, _), status) in match_status_per_endpoint_and_match {
            matches[match_idx].match_status.merge(status.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use crate::{
        HttpCallConfig, HttpRequestConfig, HttpResponseConfig, Path, ReplacementType,
        match_validation::config_v2::{
            BodyMatcher, ResponseCondition, ResponseConditionType, StatusCodeMatcher,
            TemplatedMatchString,
        },
    };

    use super::*;

    fn create_test_match(match_value: &str) -> RuleMatch {
        RuleMatch {
            rule_index: 0,
            path: Path::root(),
            replacement_type: ReplacementType::None,
            start_index: 0,
            end_index_exclusive: match_value.len(),
            shift_offset: 0,
            match_value: Some(match_value.to_string()),
            match_status: MatchStatus::NotChecked,
            keyword: None,
        }
    }

    fn create_test_config(
        endpoint: String,
        conditions: Vec<ResponseCondition>,
    ) -> CustomHttpConfigV2 {
        create_test_config_with_options(
            endpoint,
            HttpMethod::Get,
            BTreeMap::new(),
            conditions,
            Duration::from_secs(5),
        )
    }

    fn create_test_config_with_method(
        endpoint: String,
        method: HttpMethod,
        conditions: Vec<ResponseCondition>,
    ) -> CustomHttpConfigV2 {
        create_test_config_with_options(
            endpoint,
            method,
            BTreeMap::new(),
            conditions,
            Duration::from_secs(5),
        )
    }

    fn create_test_config_with_headers(
        endpoint: String,
        headers: BTreeMap<String, TemplatedMatchString>,
        conditions: Vec<ResponseCondition>,
    ) -> CustomHttpConfigV2 {
        create_test_config_with_options(
            endpoint,
            HttpMethod::Get,
            headers,
            conditions,
            Duration::from_secs(5),
        )
    }

    fn create_test_config_with_timeout(
        endpoint: String,
        conditions: Vec<ResponseCondition>,
        timeout: Duration,
    ) -> CustomHttpConfigV2 {
        create_test_config_with_options(
            endpoint,
            HttpMethod::Get,
            BTreeMap::new(),
            conditions,
            timeout,
        )
    }

    fn create_test_config_with_options(
        endpoint: String,
        method: HttpMethod,
        headers: BTreeMap<String, TemplatedMatchString>,
        conditions: Vec<ResponseCondition>,
        timeout: Duration,
    ) -> CustomHttpConfigV2 {
        CustomHttpConfigV2::default().with_call(create_http_call_config(
            endpoint, method, headers, conditions, timeout,
        ))
    }

    fn create_http_call_config(
        endpoint: String,
        method: HttpMethod,
        headers: BTreeMap<String, TemplatedMatchString>,
        conditions: Vec<ResponseCondition>,
        timeout: Duration,
    ) -> HttpCallConfig {
        create_http_call_config_with_hosts(endpoint, method, vec![], headers, conditions, timeout)
    }

    fn create_http_call_config_with_hosts(
        endpoint: String,
        method: HttpMethod,
        hosts: Vec<TemplatedMatchString>,
        headers: BTreeMap<String, TemplatedMatchString>,
        conditions: Vec<ResponseCondition>,
        timeout: Duration,
    ) -> HttpCallConfig {
        HttpCallConfig {
            request: HttpRequestConfig {
                endpoint: TemplatedMatchString(endpoint),
                hosts,
                method,
                headers,
                body: None,
                timeout,
            },
            response: HttpResponseConfig { conditions },
        }
    }

    #[test]
    fn test_http_validator_config_with_match_template_in_endpoint() {
        let config = create_test_config_with_timeout(
            "http://localhost/test?secret=$MATCH".to_string(),
            vec![],
            Duration::from_secs(10),
        );
        let rule_match = create_test_match("test");
        assert_eq!(
            config.calls[0]
                .request
                .endpoint
                .with_rule_match(&rule_match)
                .to_string(),
            "http://localhost/test?secret=test".to_string()
        );
    }

    #[test]
    fn test_http_validator_config_with_hosts() {
        let config = create_http_call_config_with_hosts(
            "http://$HOST/test".to_string(),
            HttpMethod::Get,
            vec![
                TemplatedMatchString("us".to_string()),
                TemplatedMatchString("eu".to_string()),
            ],
            BTreeMap::new(),
            vec![],
            Duration::from_secs(5),
        );
        let rule_match = create_test_match("test");

        // Test that with_host substitutes the host correctly
        let endpoint_with_match = config.request.endpoint.with_rule_match(&rule_match);
        assert_eq!(
            endpoint_with_match.with_host("us").to_string(),
            "http://us/test"
        );
        assert_eq!(
            endpoint_with_match.with_host("eu").to_string(),
            "http://eu/test"
        );
    }

    #[test]
    fn integration_test_valid_secret_status_200() {
        let server = httpmock::MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/api/validate")
                .query_param("secret", "valid_token_123");
            then.status(200).body(r#"{"status": "valid"}"#);
        });

        let config = create_test_config(
            format!("{}/api/validate?secret=$MATCH", server.base_url()),
            vec![ResponseCondition {
                condition_type: ResponseConditionType::Valid,
                status_code: Some(StatusCodeMatcher::Single(200)),
                raw_body: None,
                body: None,
            }],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("valid_token_123")];

        validator.validate(&mut matches, &[]);

        mock.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn integration_test_invalid_secret_status_401() {
        let server = httpmock::MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/api/validate")
                .query_param("secret", "invalid_token");
            then.status(401).body(r#"{"error": "unauthorized"}"#);
        });

        let config = create_test_config(
            format!("{}/api/validate?secret=$MATCH", server.base_url()),
            vec![ResponseCondition {
                condition_type: ResponseConditionType::Invalid,
                status_code: Some(StatusCodeMatcher::Single(401)),
                raw_body: None,
                body: None,
            }],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("invalid_token")];

        validator.validate(&mut matches, &[]);

        mock.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Invalid);
    }

    #[test]
    fn integration_test_status_code_range() {
        let server = httpmock::MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/api/check");
            then.status(403).body(r#"{"error": "forbidden"}"#);
        });

        let config = create_test_config(
            format!("{}/api/check", server.base_url()),
            vec![ResponseCondition {
                condition_type: ResponseConditionType::Invalid,
                status_code: Some(StatusCodeMatcher::Range {
                    start: 400,
                    end: 500,
                }),
                raw_body: None,
                body: None,
            }],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("test_secret")];

        validator.validate(&mut matches, &[]);

        mock.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Invalid);
    }

    #[test]
    fn integration_test_body_content_matching() {
        let server = httpmock::MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/verify");
            then.status(200)
                .body(r#"{"result": "success", "token_valid": true}"#);
        });

        let config = create_test_config_with_method(
            format!("{}/verify", server.base_url()),
            HttpMethod::Post,
            vec![ResponseCondition {
                condition_type: ResponseConditionType::Valid,
                status_code: Some(StatusCodeMatcher::Single(200)),
                raw_body: Some(BodyMatcher::Regex(r#"token_valid.*true"#.to_string())),
                body: None,
            }],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("api_key_xyz")];

        validator.validate(&mut matches, &[]);

        mock.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn integration_test_custom_headers() {
        let server = httpmock::MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/secure")
                .header("Authorization", "Bearer secret_token_456")
                .header("X-API-Key", "custom_key");
            then.status(200).body("OK");
        });

        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_string(),
            TemplatedMatchString("Bearer $MATCH".to_string()),
        );
        headers.insert(
            "X-API-Key".to_string(),
            TemplatedMatchString("custom_key".to_string()),
        );

        let config = create_test_config_with_headers(
            format!("{}/secure", server.base_url()),
            headers,
            vec![ResponseCondition {
                condition_type: ResponseConditionType::Valid,
                status_code: Some(StatusCodeMatcher::Single(200)),
                raw_body: None,
                body: None,
            }],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("secret_token_456")];

        validator.validate(&mut matches, &[]);

        mock.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn integration_test_multiple_conditions_body_based() {
        let server = httpmock::MockServer::start();

        let mock_invalid = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/check")
                .query_param("token", "token_xyz");
            then.status(200).body(r#"{"status": "invalid"}"#);
        });
        let mock_valid = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/check")
                .query_param("token", "token_abc");
            then.status(200).body(r#"{"status": "valid"}"#);
        });

        let config = create_test_config(
            format!("{}/check?token=$MATCH", server.base_url()),
            vec![
                ResponseCondition {
                    condition_type: ResponseConditionType::Valid,
                    status_code: None,
                    raw_body: Some(BodyMatcher::ExactMatch(
                        r#"{"status": "valid"}"#.to_string(),
                    )),
                    body: None,
                },
                ResponseCondition {
                    condition_type: ResponseConditionType::Invalid,
                    status_code: None,
                    raw_body: Some(BodyMatcher::Regex(r#"status.*invalid"#.to_string())),
                    body: None,
                },
            ],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![
            create_test_match("token_xyz"),
            create_test_match("token_abc"),
        ];

        validator.validate(&mut matches, &[]);

        mock_invalid.assert();
        mock_valid.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Invalid);
        assert_eq!(matches[1].match_status, MatchStatus::Valid);
    }

    #[test]
    fn integration_test_no_matching_condition_returns_error() {
        let server = httpmock::MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/api");
            then.status(500).body("Internal Server Error");
        });

        let config = create_test_config(
            format!("{}/api", server.base_url()),
            vec![
                ResponseCondition {
                    condition_type: ResponseConditionType::Valid,
                    status_code: Some(StatusCodeMatcher::Single(200)),
                    raw_body: None,
                    body: None,
                },
                ResponseCondition {
                    condition_type: ResponseConditionType::Invalid,
                    status_code: Some(StatusCodeMatcher::Range {
                        start: 400,
                        end: 500,
                    }),
                    raw_body: None,
                    body: None,
                },
            ],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("test_token")];

        validator.validate(&mut matches, &[]);

        mock.assert();
        match &matches[0].match_status {
            MatchStatus::Error(msg) => {
                assert!(msg.contains("No response condition matched"));
                assert!(msg.contains("500"));
            }
            _ => panic!(
                "Expected MatchStatus::Error but got {:?}",
                matches[0].match_status
            ),
        }
    }

    #[test]
    fn integration_test_timeout_handling() {
        let server = httpmock::MockServer::start();

        let _mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/slow");
            then.status(200).delay(Duration::from_secs(10)).body("OK");
        });

        let config = create_test_config_with_timeout(
            format!("{}/slow", server.base_url()),
            vec![ResponseCondition {
                condition_type: ResponseConditionType::Valid,
                status_code: Some(StatusCodeMatcher::Single(200)),
                raw_body: None,
                body: None,
            }],
            Duration::from_millis(100),
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("test_token")];

        validator.validate(&mut matches, &[]);

        match &matches[0].match_status {
            MatchStatus::Error(msg) => {
                assert!(msg.contains("timeout"));
            }
            _ => panic!(
                "Expected MatchStatus::Error with timeout but got {:?}",
                matches[0].match_status
            ),
        }
    }

    #[test]
    fn integration_test_multiple_matches_validated_in_parallel() {
        let server = httpmock::MockServer::start();

        let mock_valid = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/check")
                .query_param("token", "valid_123");
            then.status(200).body("Valid");
        });

        let mock_invalid = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/check")
                .query_param("token", "invalid_456");
            then.status(401).body("Invalid");
        });

        let config = create_test_config(
            format!("{}/check?token=$MATCH", server.base_url()),
            vec![
                ResponseCondition {
                    condition_type: ResponseConditionType::Valid,
                    status_code: Some(StatusCodeMatcher::Single(200)),
                    raw_body: None,
                    body: None,
                },
                ResponseCondition {
                    condition_type: ResponseConditionType::Invalid,
                    status_code: Some(StatusCodeMatcher::Single(401)),
                    raw_body: None,
                    body: None,
                },
            ],
        );

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![
            create_test_match("valid_123"),
            create_test_match("invalid_456"),
        ];

        validator.validate(&mut matches, &[]);

        mock_valid.assert();
        mock_invalid.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
        assert_eq!(matches[1].match_status, MatchStatus::Invalid);
    }

    #[test]
    fn integration_test_multiple_endpoints_first_valid_wins() {
        let server1 = httpmock::MockServer::start();
        let server2 = httpmock::MockServer::start();

        let mock1 = server1.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/api1");
            then.status(500).body("Error");
        });

        let mock2 = server2.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/api2");
            then.status(200).body("Success");
        });

        let conditions = vec![ResponseCondition {
            condition_type: ResponseConditionType::Valid,
            status_code: Some(StatusCodeMatcher::Single(200)),
            raw_body: None,
            body: None,
        }];

        let config = create_test_config(format!("{}/api1", server1.base_url()), conditions.clone())
            .with_call(create_http_call_config(
                format!("{}/api2", server2.base_url()),
                HttpMethod::Get,
                BTreeMap::new(),
                conditions,
                Duration::from_secs(5),
            ));

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("test_token")];

        validator.validate(&mut matches, &[]);

        mock1.assert();
        mock2.assert();
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn integration_test_multi_host_validation() {
        let server_us = httpmock::MockServer::start();
        let server_eu = httpmock::MockServer::start();

        // US endpoint returns valid
        let mock_us = server_us.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/api/check")
                .query_param("token", "test_token");
            then.status(200).body("Valid");
        });

        // EU endpoint returns invalid
        let mock_eu = server_eu.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/api/check")
                .query_param("token", "test_token");
            then.status(401).body("Invalid");
        });

        // Create config with multiple hosts
        let config = CustomHttpConfigV2::default().with_call(create_http_call_config_with_hosts(
            "http://$HOST/api/check?token=$MATCH".to_string(),
            HttpMethod::Get,
            vec![
                TemplatedMatchString(server_us.base_url().replace("http://", "")),
                TemplatedMatchString(server_eu.base_url().replace("http://", "")),
            ],
            BTreeMap::new(),
            vec![
                ResponseCondition {
                    condition_type: ResponseConditionType::Valid,
                    status_code: Some(StatusCodeMatcher::Single(200)),
                    raw_body: None,
                    body: None,
                },
                ResponseCondition {
                    condition_type: ResponseConditionType::Invalid,
                    status_code: Some(StatusCodeMatcher::Single(401)),
                    raw_body: None,
                    body: None,
                },
            ],
            Duration::from_secs(5),
        ));

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match("test_token")];

        validator.validate(&mut matches, &[]);

        // Both endpoints should have been called
        mock_us.assert();
        mock_eu.assert();

        // The match should be valid because one of the hosts returned valid
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn integration_test_templated_host() {
        let server = httpmock::MockServer::start();
        let server_url = server.base_url().replace("http://", "");

        // US endpoint returns valid
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/api/check")
                .query_param("token", server_url.as_str());
            then.status(200).body("Valid");
        });

        // Create config with multiple hosts
        let config = CustomHttpConfigV2::default().with_call(create_http_call_config_with_hosts(
            "http://$HOST/api/check?token=$MATCH".to_string(),
            HttpMethod::Get,
            vec![TemplatedMatchString("$MATCH".to_string())],
            BTreeMap::new(),
            vec![
                ResponseCondition {
                    condition_type: ResponseConditionType::Valid,
                    status_code: Some(StatusCodeMatcher::Single(200)),
                    raw_body: None,
                    body: None,
                },
                ResponseCondition {
                    condition_type: ResponseConditionType::Invalid,
                    status_code: Some(StatusCodeMatcher::Single(401)),
                    raw_body: None,
                    body: None,
                },
            ],
            Duration::from_secs(5),
        ));

        let validator = HttpValidatorV2::new_from_config(config);
        let mut matches = vec![create_test_match(server_url.as_str())];

        validator.validate(&mut matches, &[]);

        // Both endpoints should have been called
        mock.assert();

        // The match should be valid because one of the hosts returned valid
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn test_deserialization() {
        let config_str = r#"
        {
            "calls": [
                {
                    "request": {
                        "endpoint": "http://localhost/test1"
                    },
                    "response": {
                        "conditions": [
                            {
                                "type": "valid",
                                "status_code": 200
                            },
                            {
                                "type": "invalid",
                                "status_code": [400, 420]
                            },
                            {
                                "type": "invalid",
                                "body": {
                                    "message.stack[2].success.status": {
                                        "type": "ExactMatch",
                                        "config": "success"
                                    }
                                }
                            }
                        ]
                    }
                }
            ]
        }
        "#;
        let config: CustomHttpConfigV2 = serde_json::from_str(config_str).unwrap();
        assert_eq!(config.calls.len(), 1);
        assert_eq!(
            config.calls[0].request.endpoint.to_string(),
            "http://localhost/test1"
        );
        assert_eq!(config.calls[0].request.method, HttpMethod::Get);
        assert_eq!(config.calls[0].request.hosts, vec![]);
        assert_eq!(config.calls[0].request.timeout, Duration::from_secs(3));
        assert_eq!(config.calls[0].response.conditions.len(), 3);
        assert_eq!(
            config.calls[0].response.conditions[0].status_code,
            Some(StatusCodeMatcher::Single(200))
        );
        assert_eq!(
            config.calls[0].response.conditions[1].status_code,
            Some(StatusCodeMatcher::List(vec![400, 420])),
        );
        assert_eq!(
            config.calls[0].response.conditions[2].body,
            Some(BTreeMap::from([(
                "message.stack[2].success.status".to_string(),
                BodyMatcher::ExactMatch("success".to_string())
            )])),
        );
        let config_str = r#"
        {
            "calls": [
                {
                    "request": {
                        "endpoint": "http://$HOST/test1",
                        "hosts": ["us", "eu"]
                    },
                    "response": {
                        "conditions": []
                    }
                }
            ]
        }
        "#;
        let config: CustomHttpConfigV2 = serde_json::from_str(config_str).unwrap();
        assert_eq!(
            config.calls[0].request.hosts,
            vec![
                TemplatedMatchString("us".to_string()),
                TemplatedMatchString("eu".to_string())
            ]
        );
        let rule_match = create_test_match("test");
        let endpoint_with_match = config.calls[0]
            .request
            .endpoint
            .with_rule_match(&rule_match);
        assert_eq!(
            endpoint_with_match.with_host("us").to_string(),
            "http://us/test1"
        );
        assert_eq!(
            endpoint_with_match.with_host("eu").to_string(),
            "http://eu/test1"
        );
    }

    #[test]
    fn integration_test_different_http_methods() {
        let server = httpmock::MockServer::start();

        let mock_post = server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/validate");
            then.status(200).body("Valid");
        });

        let mock_put = server.mock(|when, then| {
            when.method(httpmock::Method::PUT).path("/update");
            then.status(200).body("Valid");
        });

        let mock_delete = server.mock(|when, then| {
            when.method(httpmock::Method::DELETE).path("/revoke");
            then.status(200).body("Valid");
        });

        for (method, path, mock) in [
            (HttpMethod::Post, "/validate", &mock_post),
            (HttpMethod::Put, "/update", &mock_put),
            (HttpMethod::Delete, "/revoke", &mock_delete),
        ] {
            let config = create_test_config_with_method(
                format!("{}{}", server.base_url(), path),
                method,
                vec![ResponseCondition {
                    condition_type: ResponseConditionType::Valid,
                    status_code: Some(StatusCodeMatcher::Single(200)),
                    raw_body: None,
                    body: None,
                }],
            );

            let validator = HttpValidatorV2::new_from_config(config);
            let mut matches = vec![create_test_match("token")];

            validator.validate(&mut matches, &[]);

            mock.assert();
            assert_eq!(matches[0].match_status, MatchStatus::Valid);
        }
    }
}
