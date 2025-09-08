use super::{
    config::{CustomHttpConfig, RequestHeader},
    match_validator::MatchValidator,
};
use crate::match_validation::match_validator::RAYON_THREAD_POOL;
use crate::{HttpValidatorOption, scanner::RootCompiledRule};
use crate::{MatchStatus, RuleMatch, match_validation::config::HttpMethod};
use ahash::AHashMap;
use lazy_static::lazy_static;
use reqwest::blocking::Response;
use std::error::Error as StdError;
use std::{fmt, ops::Range, time::Duration};

lazy_static! {
    static ref BLOCKING_HTTP_CLIENT: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

pub struct HttpValidator {
    config: InternalHttpValidatorConfig,
}

impl HttpValidator {
    pub fn new_from_config(config: CustomHttpConfig) -> Self {
        HttpValidator {
            config: InternalHttpValidatorConfig::from_custom_http_type(&config),
        }
    }
    fn handle_reqwest_response(&self, match_status: &mut MatchStatus, val: &Response) {
        // First check if this is in the valid status ranges
        for valid_range in &self.config.valid_http_status_code {
            if valid_range.contains(&val.status().as_u16()) {
                *match_status = MatchStatus::Valid;
                return;
            }
        }
        // Next check if this is in the invalid status ranges
        for invalid_range in &self.config.invalid_http_status_code {
            if invalid_range.contains(&val.status().as_u16()) {
                *match_status = MatchStatus::Invalid;
                return;
            }
        }
        // If it's not in either, then it's not available
        *match_status = MatchStatus::Error(fmt::format(format_args!(
            "Unexpected HTTP status code {}",
            val.status().as_u16()
        )));
    }
}

#[derive(Clone, Debug, PartialEq)]
struct InternalHttpValidatorConfig {
    endpoints: Vec<String>,
    method: HttpMethod,
    request_header: Vec<RequestHeader>,
    valid_http_status_code: Vec<Range<u16>>,
    invalid_http_status_code: Vec<Range<u16>>,
    options: HttpValidatorOption,
}

impl InternalHttpValidatorConfig {
    fn from_custom_http_type(custom_http_type: &CustomHttpConfig) -> Self {
        let endpoints = custom_http_type.get_endpoints().unwrap();

        let request_header = custom_http_type
            .request_headers
            .iter()
            .map(|(key, value)| RequestHeader {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect();

        let valid_http_status_code = custom_http_type
            .valid_http_status_code
            .iter()
            .map(|range| range.start..range.end)
            .collect();

        let invalid_http_status_code = custom_http_type
            .invalid_http_status_code
            .iter()
            .map(|range| range.start..range.end)
            .collect();

        let timeout = Duration::from_secs(custom_http_type.timeout_seconds as u64);

        Self {
            endpoints,
            method: custom_http_type.http_method.clone(),
            request_header,
            valid_http_status_code,
            invalid_http_status_code,
            options: HttpValidatorOption { timeout },
        }
    }
}

impl MatchValidator for HttpValidator {
    fn validate(&self, matches: &mut Vec<RuleMatch>, _: &[RootCompiledRule]) {
        // build a map of match status per endpoint and per match_idx
        let mut match_status_per_endpoint_and_match: AHashMap<_, _> = matches
            .iter()
            .enumerate()
            .flat_map(|(idx, _)| {
                self.config
                    .endpoints
                    .iter()
                    .map(move |endpoint| ((idx, endpoint), MatchStatus::NotChecked))
            })
            .collect();

        RAYON_THREAD_POOL.install(|| {
            use rayon::prelude::*;

            match_status_per_endpoint_and_match.par_iter_mut().for_each(
                |((match_idx, endpoint), match_status)| {
                    let match_value = matches[*match_idx].match_value.as_ref().unwrap();
                    let mut request_builder = match self.config.method {
                        HttpMethod::Get => BLOCKING_HTTP_CLIENT.get(*endpoint),
                        HttpMethod::Post => BLOCKING_HTTP_CLIENT.post(*endpoint),
                        HttpMethod::Put => BLOCKING_HTTP_CLIENT.put(*endpoint),
                        HttpMethod::Delete => BLOCKING_HTTP_CLIENT.delete(*endpoint),
                        HttpMethod::Patch => BLOCKING_HTTP_CLIENT.patch(*endpoint),
                    };
                    request_builder = request_builder.timeout(self.config.options.timeout);

                    // Add headers
                    for header in &self.config.request_header {
                        request_builder = request_builder
                            .header(&header.key, &header.get_value_with_match(match_value));
                    }
                    let res = request_builder.send();
                    match res {
                        Ok(val) => {
                            self.handle_reqwest_response(match_status, &val);
                        }
                        Err(err) => {
                            let mut msg = String::from(format!("Error making HTTP request: {err}"));
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
        for ((match_idx, _), status) in match_status_per_endpoint_and_match {
            matches[match_idx].match_status.merge(status.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_validator_config_no_hosts() {
        let endpoints = CustomHttpConfig::default()
            .with_endpoint("http://localhost/test".to_string())
            .with_hosts(vec![])
            .get_endpoints()
            .unwrap();
        assert_eq!(endpoints, vec!["http://localhost/test"]);
    }

    #[test]
    fn test_deserialization() {
        let config_str = r#"
        {
            "endpoint": "http://localhost/test1",
            "hosts": [],
            "http_method": "GET",
            "request_headers": {},
            "valid_http_status_code": [],
            "invalid_http_status_code": [],
            "timeout_seconds": 10
        }
        "#;
        let config: CustomHttpConfig = serde_json::from_str(config_str).unwrap();
        let endpoints = config.get_endpoints().unwrap();
        assert_eq!(endpoints, vec!["http://localhost/test1"]);

        let config_str = r#"
        {
            "endpoint": "http://$HOST/test1",
            "hosts": ["us", "eu"],
            "http_method": "GET",
            "request_headers": {},
            "valid_http_status_code": [],
            "invalid_http_status_code": [],
            "timeout_seconds": 10
        }
        "#;
        let config: CustomHttpConfig = serde_json::from_str(config_str).unwrap();
        let endpoints = config.get_endpoints().unwrap();
        assert_eq!(endpoints, vec!["http://us/test1", "http://eu/test1"]);
    }

    #[test]
    fn test_http_validator_config_with_hosts() {
        let endpoints = CustomHttpConfig::default()
            .with_endpoint("http://localhost/$HOST".to_string())
            .with_hosts(vec!["us".to_string(), "eu".to_string()])
            .get_endpoints()
            .unwrap();
        assert_eq!(
            endpoints,
            vec!["http://localhost/us", "http://localhost/eu"]
        );
    }

    #[test]
    fn test_http_validator_config_error_cases() {
        let error = CustomHttpConfig::default()
            .with_endpoint("http://localhost/$HOST".to_string())
            .with_hosts(vec![])
            .get_endpoints()
            .unwrap_err();
        assert_eq!(
            error,
            "Endpoint contains $HOST but no hosts are provided".to_string()
        );
    }

    #[test]
    fn test_http_validator_config_error_cases_with_hosts() {
        let error = CustomHttpConfig::default()
            .with_endpoint("http://localhost/test".to_string())
            .with_hosts(vec!["us".to_string()])
            .get_endpoints()
            .unwrap_err();
        assert_eq!(
            error,
            "Endpoint does not contain $HOST but hosts are provided".to_string()
        );
    }
    #[test]
    fn test_http_validator_builder_config_no_hosts() {
        let endpoints = CustomHttpConfig::default()
            .with_endpoint("http://localhost/test".to_string())
            .with_hosts(vec![])
            .get_endpoints()
            .unwrap();
        assert_eq!(endpoints, vec!["http://localhost/test"]);
    }

    #[test]
    fn test_http_validator_builder_config_with_hosts() {
        let endpoints = CustomHttpConfig::default()
            .with_endpoint("http://localhost/$HOST".to_string())
            .with_hosts(vec!["us".to_string(), "eu".to_string()])
            .get_endpoints()
            .unwrap();
        assert_eq!(
            endpoints,
            vec!["http://localhost/us", "http://localhost/eu"]
        );
    }
}
