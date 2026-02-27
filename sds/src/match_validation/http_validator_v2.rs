use super::match_validator::MatchValidator;
use crate::match_validation::config_v2::{ResponseConditionResult, TemplateVariable};
use crate::scanner::RootCompiledRule;
use crate::{
    CustomHttpConfigV2, HttpResponseConfig, match_validation::match_validator::RAYON_THREAD_POOL,
};
use crate::{MatchPairingConfig, MatchValidationType, TemplatedMatchString};
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
        *match_status = MatchStatus::Error(
            Some(status),
            format!(
                "No response condition matched for status code {} and body of length {}",
                status,
                body.len()
            ),
        );
    }
}

fn get_providing_matches_by_kind_and_name(
    matches: &[RuleMatch],
    rules: &[RootCompiledRule],
) -> AHashMap<(String, String), Vec<(String, usize)>> {
    matches
        .iter()
        .enumerate()
        .flat_map(|(match_idx, candidate_match)| {
            let Some(rule) = rules.get(candidate_match.rule_index) else {
                return Vec::new();
            };
            let Some(match_validation_type) = rule.match_validation_type.as_ref() else {
                return Vec::new();
            };
            match match_validation_type {
                MatchValidationType::CustomHttpV2(custom_http_config) => {
                    let Some(match_value) = candidate_match.match_value.as_ref() else {
                        return Vec::new();
                    };
                    custom_http_config
                        .provides
                        .as_ref()
                        .map(|provided_values| {
                            provided_values
                                .iter()
                                .map(|provided_value| {
                                    (
                                        (provided_value.kind.clone(), provided_value.name.clone()),
                                        (match_value.clone(), match_idx),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                }
                _ => Vec::new(),
            }
        })
        .fold(
            AHashMap::new(),
            |mut map, (kind_and_name, value_and_idx)| {
                map.entry(kind_and_name).or_default().push(value_and_idx);
                map
            },
        )
}

fn get_match_pairing_template_variables(
    match_pairing_config: &MatchPairingConfig,
    providing_matches_by_kind_and_name: &AHashMap<(String, String), Vec<(String, usize)>>,
) -> Vec<(TemplateVariable, usize)> {
    // Iterate over the match pairing config and add the required matches to the iterator
    // Returns (TemplateVariable, match_idx) pairs
    match_pairing_config
        .parameters
        .iter()
        .flat_map(|(name, template_name)| {
            if let Some(match_values_with_idx) = providing_matches_by_kind_and_name
                .get(&(match_pairing_config.kind.clone(), name.clone()))
            {
                match_values_with_idx
                    .iter()
                    .map(|(match_value, match_idx)| {
                        (
                            TemplateVariable {
                                name: template_name.to_string(),
                                value: match_value.to_string(),
                            },
                            *match_idx,
                        )
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        })
        .collect::<Vec<_>>()
}

/// Generate all combinations (cartesian product) of template variables
///
/// Given template variables with match indices like:
///   [(TemplateVariable{$CLIENT_SUBDOMAIN=acme_corp}, match_idx=0),
///    (TemplateVariable{$CLIENT_SUBDOMAIN=other_corp}, match_idx=2),
///    (TemplateVariable{$USER_ID=USjohn}, match_idx=1)]
///
/// Groups by parameter name:
///   $CLIENT_SUBDOMAIN: [(acme_corp, 0), (other_corp, 2)]
///   $USER_ID: [(USjohn, 1)]
///
/// Returns cartesian product with contributing match indices:
///   [
///     ([$CLIENT_SUBDOMAIN=acme_corp, $USER_ID=USjohn], [0, 1]),
///     ([$CLIENT_SUBDOMAIN=other_corp, $USER_ID=USjohn], [2, 1])
///   ]
fn generate_template_variable_combinations(
    template_variables_with_idx: &[(TemplateVariable, usize)],
) -> Vec<(Vec<TemplateVariable>, Vec<usize>)> {
    if template_variables_with_idx.is_empty() {
        return vec![(vec![], vec![])];
    }

    // Group template variables by their name, tracking match indices
    let mut grouped: AHashMap<String, Vec<(String, usize)>> = AHashMap::new();
    let mut param_order: Vec<String> = Vec::new();

    for (var, match_idx) in template_variables_with_idx {
        grouped
            .entry(var.name.clone())
            .or_insert_with(|| {
                param_order.push(var.name.clone());
                Vec::new()
            })
            .push((var.value.clone(), *match_idx));
    }

    // Generate cartesian product with match indices
    let mut result = vec![(vec![], vec![])];

    for param_name in param_order {
        if let Some(values_with_idx) = grouped.get(&param_name) {
            let mut new_result = Vec::new();
            for (combination, match_indices) in result {
                for (value, match_idx) in values_with_idx {
                    let mut new_combination = combination.clone();
                    let mut new_match_indices = match_indices.clone();
                    new_combination.push(TemplateVariable {
                        name: param_name.clone(),
                        value: value.clone(),
                    });
                    new_match_indices.push(*match_idx);
                    new_result.push((new_combination, new_match_indices));
                }
            }
            result = new_result;
        }
    }

    result
}

impl MatchValidator for HttpValidatorV2 {
    fn validate(&self, matches: &mut Vec<RuleMatch>, rules: &[RootCompiledRule]) {
        // Build up matches (the values themselves) that provide a secret to other matches
        // build a map of match status per endpoint, per host, and per match_idx
        let providing_matches_by_kind_and_name =
            get_providing_matches_by_kind_and_name(matches, rules);
        let mut match_status_per_endpoint_and_match: AHashMap<_, _> = matches
            .iter()
            .enumerate()
            .filter(|(_, rule_match)| {
                matches!(
                    rules
                        .get(rule_match.rule_index)
                        .and_then(|rule| rule.match_validation_type.as_ref()),
                    Some(MatchValidationType::CustomHttpV2(custom_http_config))
                        if !custom_http_config.calls.is_empty()
                )
            })
            .map(|(idx, rule_match)| {
                let template_variables = rules
                    .get(rule_match.rule_index)
                    .and_then(|rule| {
                        if let Some(MatchValidationType::CustomHttpV2(custom_http_config)) =
                            &rule.match_validation_type
                        {
                            custom_http_config
                                .match_pairing
                                .as_ref()
                                .map(|match_pairing_config| {
                                    get_match_pairing_template_variables(
                                        match_pairing_config,
                                        &providing_matches_by_kind_and_name,
                                    )
                                })
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();
                (idx, template_variables, rule_match)
            })
            .flat_map(move |(idx, template_variables, _rule_match)| {
                // Generate cartesian product of template variable values with contributing match indices
                let template_var_combinations =
                    generate_template_variable_combinations(&template_variables);

                self.config.calls.iter().flat_map(move |endpoint| {
                    let endpoint_host_opts: Vec<Option<TemplatedMatchString>> =
                        if endpoint.request.hosts.is_empty() {
                            vec![None]
                        } else {
                            endpoint
                                .request
                                .hosts
                                .iter()
                                .map(|h| Some(h.clone()))
                                .collect()
                        };

                    let combinations = template_var_combinations.clone();
                    endpoint_host_opts.into_iter().flat_map(move |host_opt| {
                        let combos = combinations.clone();
                        combos
                            .into_iter()
                            .map(move |(template_vars, contributing_matches)| {
                                (
                                    (
                                        idx,
                                        endpoint,
                                        host_opt.clone(),
                                        template_vars,
                                        contributing_matches,
                                    ),
                                    MatchStatus::NotChecked,
                                )
                            })
                    })
                })
            })
            .collect();

        RAYON_THREAD_POOL.install(|| {
            use rayon::prelude::*;

            match_status_per_endpoint_and_match.par_iter_mut().for_each(
                |(
                    (match_idx, endpoint_config, host_opt, template_vars, _contributing_matches),
                    match_status,
                )| {
                    let rule_match = &matches[*match_idx];
                    let mut endpoint = endpoint_config.request.endpoint.with_rule_match(rule_match);
                    let mut templated_host = host_opt
                        .as_ref()
                        .map(|host| host.with_rule_match(rule_match));
                    if self.config.match_pairing.is_some()
                        && !self
                            .config
                            .match_pairing
                            .as_ref()
                            .unwrap()
                            .is_fulfilled_by(template_vars)
                    {
                        *match_status = MatchStatus::Partial;
                        return;
                    }
                    // Apply ALL template variables to the same endpoint
                    for template_var in template_vars {
                        endpoint = endpoint.with_template_variable(template_var);
                        templated_host =
                            templated_host.map(|host| host.with_template_variable(template_var));
                    }
                    let rendered_host = templated_host.map(|host| host.to_string());
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
                        // Apply ALL template variables to the same header
                        for template_var in template_vars {
                            header_val = header_val.with_template_variable(template_var);
                        }
                        request_builder =
                            request_builder.header(header_key, header_val.to_string());
                    }
                    // Add request body with template substitution. For methods that can carry
                    // a body (POST/PUT/PATCH), always set one so reqwest emits Content-Length:
                    // omitting it causes some servers to reject the request with HTTP 411.
                    let body_requires_content_length = matches!(
                        endpoint_config.request.method,
                        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
                    );
                    if let Some(ref body_tpl) = endpoint_config.request.body {
                        let mut body_val = body_tpl.with_rule_match(rule_match);
                        if let Some(ref host) = rendered_host {
                            body_val = body_val.with_host(host.as_str());
                        }
                        for template_var in template_vars {
                            body_val = body_val.with_template_variable(template_var);
                        }
                        request_builder = request_builder.body(body_val.to_string());
                    } else if body_requires_content_length {
                        request_builder = request_builder.body("");
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
                            let code = err.status().map(|s| s.as_u16());
                            *match_status = MatchStatus::Error(code, msg);
                        }
                    }
                },
            );
        });

        // Update the match status with this highest priority returned
        for ((match_idx, _, _, _, contributing_matches), status) in
            match_status_per_endpoint_and_match
        {
            matches[match_idx].match_status.merge(status.clone());
            // Also update all contributing matches with the same status
            for contributing_idx in contributing_matches {
                matches[contributing_idx].match_status.merge(status.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use crate::{
        CompiledRule, MatchAction, Path, Precedence, ReplacementType, RootCompiledRule, Scope,
        match_validation::config_v2::{BodyMatcher, StatusCodeMatcher, TemplatedMatchString},
    };

    use super::*;

    struct MockCompiledRule;
    impl CompiledRule for MockCompiledRule {
        fn get_string_matches(
            &self,
            _content: &str,
            _path: &Path,
            _ctx: &mut crate::scanner::StringMatchesCtx,
        ) -> Result<crate::scanner::RuleStatus, crate::scanner::error::ScannerError> {
            Ok(crate::scanner::RuleStatus::Done)
        }
    }

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

    fn create_test_rule(config: CustomHttpConfigV2) -> RootCompiledRule {
        RootCompiledRule {
            inner: Box::new(MockCompiledRule),
            scope: Scope::all(),
            match_action: MatchAction::None,
            match_validation_type: Some(MatchValidationType::CustomHttpV2(config)),
            suppressions: None,
            precedence: Precedence::default(),
        }
    }

    fn config_from_yaml(config_yaml: &str) -> CustomHttpConfigV2 {
        serde_yaml::from_str(config_yaml).unwrap()
    }

    #[test]
    fn test_http_validator_config_with_match_template_in_endpoint() {
        let config = config_from_yaml(
            r#"
calls:
  - request:
      endpoint: "http://localhost/test?secret=$MATCH"
      method: GET
      timeout:
        secs: 10
        nanos: 0
    response:
      conditions: []
"#,
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
        let config = config_from_yaml(
            r#"
calls:
  - request:
      endpoint: "http://$HOST/test"
      method: GET
      hosts: ["us", "eu"]
    response:
      conditions: []
"#,
        );
        let rule_match = create_test_match("test");

        // Test that with_host substitutes the host correctly
        let endpoint_with_match = config.calls[0]
            .request
            .endpoint
            .with_rule_match(&rule_match);
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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/api/validate?secret=$MATCH"
      method: GET
    response:
      conditions:
        - type: valid
          status_code: 200
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("valid_token_123")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/api/validate?secret=$MATCH"
      method: GET
    response:
      conditions:
        - type: invalid
          status_code: 401
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("invalid_token")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/api/check"
      method: GET
    response:
      conditions:
        - type: invalid
          status_code:
            start: 400
            end: 500
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("test_secret")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/verify"
      method: POST
    response:
      conditions:
        - type: valid
          status_code: 200
          raw_body:
            type: Regex
            config: "token_valid.*true"
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("api_key_xyz")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/secure"
      method: GET
      headers:
        Authorization: "Bearer $MATCH"
        X-API-Key: "custom_key"
    response:
      conditions:
        - type: valid
          status_code: 200
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("secret_token_456")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/check?token=$MATCH"
      method: GET
    response:
      conditions:
        - type: valid
          raw_body:
            type: ExactMatch
            config: '{{"status": "valid"}}'
        - type: invalid
          raw_body:
            type: Regex
            config: "status.*invalid"
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![
            create_test_match("token_xyz"),
            create_test_match("token_abc"),
        ];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/api"
      method: GET
    response:
      conditions:
        - type: valid
          status_code: 200
        - type: invalid
          status_code:
            start: 400
            end: 500
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("test_token")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

        mock.assert();
        match &matches[0].match_status {
            MatchStatus::Error(code, msg) => {
                assert_eq!(*code, Some(500));
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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/slow"
      method: GET
      timeout:
        secs: 0
        nanos: 100000000
    response:
      conditions:
        - type: valid
          status_code: 200
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("test_token")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

        match &matches[0].match_status {
            MatchStatus::Error(_code, msg) => {
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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/check?token=$MATCH"
      method: GET
    response:
      conditions:
        - type: valid
          status_code: 200
        - type: invalid
          status_code: 401
"#,
                server.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![
            create_test_match("valid_123"),
            create_test_match("invalid_456"),
        ];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "{}/api1"
      method: GET
    response:
      conditions:
        - type: valid
          status_code: 200
  - request:
      endpoint: "{}/api2"
      method: GET
    response:
      conditions:
        - type: valid
          status_code: 200
"#,
                server1.base_url(),
                server2.base_url()
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("test_token")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            format!(
                r#"
calls:
  - request:
      endpoint: "http://$HOST/api/check?token=$MATCH"
      method: GET
      hosts:
        - "{}"
        - "{}"
    response:
      conditions:
        - type: valid
          status_code: 200
        - type: invalid
          status_code: 401
"#,
                server_us.base_url().replace("http://", ""),
                server_eu.base_url().replace("http://", "")
            )
            .as_str(),
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match("test_token")];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

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

        let config = config_from_yaml(
            r#"
calls:
  - request:
      endpoint: "http://$HOST/api/check?token=$MATCH"
      method: GET
      hosts:
        - "$MATCH"
    response:
      conditions:
        - type: valid
          status_code: 200
        - type: invalid
          status_code: 401
"#,
        );

        let validator = HttpValidatorV2::new_from_config(config.clone());
        let mut matches = vec![create_test_match(server_url.as_str())];
        let rules = vec![create_test_rule(config)];

        validator.validate(&mut matches, &rules);

        // Both endpoints should have been called
        mock.assert();

        // The match should be valid because one of the hosts returned valid
        assert_eq!(matches[0].match_status, MatchStatus::Valid);
    }

    #[test]
    fn test_deserialization() {
        let config_str = r#"
calls:
  - request:
      endpoint: "http://localhost/test1"
      method: GET
    response:
      conditions:
        - type: valid
          status_code: 200
        - type: invalid
          status_code: [400, 420]
        - type: invalid
          body:
            message.stack[2].success.status:
              type: ExactMatch
              config: success
        "#;
        let config: CustomHttpConfigV2 = serde_yaml::from_str(config_str).unwrap();
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
calls:
  - request:
      endpoint: "http://$HOST/test1"
      method: GET
      hosts: ["us", "eu"]
    response:
      conditions: []
        "#;
        let config: CustomHttpConfigV2 = serde_yaml::from_str(config_str).unwrap();
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
            ("POST", "/validate", &mock_post),
            ("PUT", "/update", &mock_put),
            ("DELETE", "/revoke", &mock_delete),
        ] {
            let config = config_from_yaml(
                format!(
                    r#"
calls:
  - request:
      endpoint: "{}{}"
      method: {}
    response:
      conditions:
        - type: valid
          status_code: 200
"#,
                    server.base_url(),
                    path,
                    method
                )
                .as_str(),
            );

            let validator = HttpValidatorV2::new_from_config(config.clone());
            let mut matches = vec![create_test_match("token")];
            let rules = vec![create_test_rule(config)];

            validator.validate(&mut matches, &rules);

            mock.assert();
            assert_eq!(matches[0].match_status, MatchStatus::Valid);
        }
    }

    #[test]
    fn test_get_providing_matches_includes_custom_http_v2_providers() {
        let provider_config = config_from_yaml(
            r#"
provides:
  - kind: "vendor_xyz"
    name: "client_subdomain"
calls:
  - request:
      endpoint: "http://localhost/validate?secret=$MATCH"
      method: GET
    response:
      conditions: []
"#,
        );

        let rules = vec![
            RootCompiledRule {
                inner: Box::new(MockCompiledRule),
                scope: Scope::all(),
                match_action: MatchAction::None,
                match_validation_type: Some(MatchValidationType::CustomHttpV2(provider_config)),
                suppressions: None,
                precedence: Precedence::default(),
            },
            RootCompiledRule {
                inner: Box::new(MockCompiledRule),
                scope: Scope::all(),
                match_action: MatchAction::None,
                match_validation_type: Some(MatchValidationType::CustomHttpV2(
                    CustomHttpConfigV2 {
                        provides: Some(vec![crate::PairedValidatorConfig {
                            kind: "vendor_xyz".to_string(),
                            name: "region".to_string(),
                        }]),
                        calls: vec![],
                        match_pairing: None,
                    },
                )),
                suppressions: None,
                precedence: Precedence::default(),
            },
        ];

        let matches = vec![
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: ReplacementType::None,
                start_index: 0,
                end_index_exclusive: 9,
                shift_offset: 0,
                match_value: Some("acme_corp".to_string()),
                match_status: MatchStatus::NotChecked,
                keyword: None,
            },
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: ReplacementType::None,
                start_index: 10,
                end_index_exclusive: 17,
                shift_offset: 0,
                match_value: Some("us_east".to_string()),
                match_status: MatchStatus::NotChecked,
                keyword: None,
            },
        ];

        let providing_matches = get_providing_matches_by_kind_and_name(&matches, &rules);

        assert_eq!(
            providing_matches.get(&("vendor_xyz".to_string(), "client_subdomain".to_string())),
            Some(&vec![("acme_corp".to_string(), 0)])
        );
        assert_eq!(
            providing_matches.get(&("vendor_xyz".to_string(), "region".to_string())),
            Some(&vec![("us_east".to_string(), 1)])
        );
    }

    #[test]
    fn integration_test_match_pairing_validation() {
        use crate::{
            MatchAction, PairedValidatorConfig, Precedence,
            scanner::{
                CompiledRule, RootCompiledRule, RuleResult, RuleStatus, StringMatchesCtx,
                scope::Scope,
            },
        };

        // Simple mock compiled rule that doesn't actually scan
        struct MockCompiledRule;
        impl CompiledRule for MockCompiledRule {
            fn get_string_matches(
                &self,
                _content: &str,
                _path: &Path,
                _ctx: &mut StringMatchesCtx,
            ) -> RuleResult {
                Ok(RuleStatus::Done)
            }
        }

        let server = httpmock::MockServer::start();

        // Note: Current implementation creates separate HTTP requests for each template variable
        // rather than combining them into a single request. This test validates the current behavior.
        // TODO: Update when match pairing is fully implemented to handle multiple parameters in one request.

        // Mock endpoint expects client_subdomain in the path
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/api/acme_corp/validate")
                .query_param("secret", "api_key_secret");
            then.status(200).body(r#"{"status": "valid"}"#);
        });

        let config = config_from_yaml(
            format!(
                r#"
calls:
- request:
    endpoint: "{}/api/$CLIENT_SUBDOMAIN/validate?secret=$MATCH"
    method: GET
  response:
    conditions:
      - type: valid
        status_code: 200
match_pairing:
  kind: "vendor_xyz"
  client_subdomain: "$CLIENT_SUBDOMAIN"
"#,
                server.base_url(),
            )
            .as_str(),
        );

        // Create scanner rules:
        // Rule 0: Main validator with CustomHttpV2 and match pairing
        // Rule 1: Paired validator providing "client_subdomain"
        let rules = vec![
            RootCompiledRule {
                inner: Box::new(MockCompiledRule),
                scope: Scope::all(),
                match_action: MatchAction::None,
                match_validation_type: Some(MatchValidationType::CustomHttpV2(config.clone())),
                suppressions: None,
                precedence: Precedence::default(),
            },
            RootCompiledRule {
                inner: Box::new(MockCompiledRule),
                scope: Scope::all(),
                match_action: MatchAction::None,
                match_validation_type: Some(MatchValidationType::CustomHttpV2(
                    CustomHttpConfigV2 {
                        provides: Some(vec![PairedValidatorConfig {
                            kind: "vendor_xyz".to_string(),
                            name: "client_subdomain".to_string(),
                        }]),
                        calls: vec![],
                        match_pairing: None,
                    },
                )),
                suppressions: None,
                precedence: Precedence::default(),
            },
        ];

        // Create all matches (both the main match and the providing match)
        // Note: In the real scanner integration, there's a design limitation where PairedValidator
        // matches are grouped separately and not passed to HttpValidatorV2. This test validates
        // the validator logic in isolation by passing all matches directly.
        let mut all_matches = vec![
            RuleMatch {
                rule_index: 0,
                path: Path::root(),
                replacement_type: ReplacementType::None,
                start_index: 0,
                end_index_exclusive: 14,
                shift_offset: 0,
                match_value: Some("api_key_secret".to_string()),
                match_status: MatchStatus::NotChecked,
                keyword: None,
            },
            RuleMatch {
                rule_index: 1,
                path: Path::root(),
                replacement_type: ReplacementType::None,
                start_index: 20,
                end_index_exclusive: 29,
                shift_offset: 0,
                match_value: Some("acme_corp".to_string()),
                match_status: MatchStatus::NotChecked,
                keyword: None,
            },
        ];

        let validator = HttpValidatorV2::new_from_config(config);
        validator.validate(&mut all_matches, &rules);

        // Verify the HTTP request was made with template variable substituted
        mock.assert();

        // The main match (rule_index 0) should be validated successfully
        assert_eq!(all_matches[0].match_status, MatchStatus::Valid);

        // The paired validator match (rule_index 1) should also receive Valid status because
        // it contributed to the successful validation of the main match. The status is
        // propagated from the main match to all contributing matches.
        assert_eq!(all_matches[1].match_status, MatchStatus::Valid);
    }
}
